//! Processes (P1-T13): an address space, a handle table with rights
//! (P1-S1), the program break, and a root and working directory. One
//! thread per process until clone(2) arrives. Every process belongs to a
//! compartment (P3-S1, ADR 0014), which fixes its root and numbers it.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use keel_core::compartment::{Compartment, Member};
use keel_core::errno::Errno;
use keel_core::handle::{Handle, HandleTable, Rights};
use keel_core::signal::{Pending, SignalState, ThreadSignals};
use keel_core::vfs::{Device, Ino, Kind};
use keel_hal::arch::x86_64::idt::TrapFrame;
use keel_hal::sched::{self, ThreadId};
use keel_hal::sync::IrqMutex;
use keel_hal::vm::AddressSpace;

use crate::exec::Loaded;

/// Most handles per process (Linux's default RLIMIT_NOFILE soft limit is
/// 1024; per compartment from Phase 3, SR-8).
pub const HANDLE_LIMIT: usize = 1024;

/// An open file: the node and the file position, shared by duplicates of
/// the handle (as Linux shares one `struct file`). It holds its node alive
/// (a pin, ADR 0022): whoever makes one pins the node first, under the
/// filesystem lock, and dropping it releases the pin, so a file unlinked
/// while open stays readable until its last description closes.
#[derive(Debug)]
pub struct OpenFile {
    pub node: Ino,
    pub kind: Kind,
    pub offset: u64,
    pub append: bool,
}

impl Drop for OpenFile {
    fn drop(&mut self) {
        let node = self.node;
        let _ = crate::fs::with(|fs| {
            fs.unpin(node);
            Ok(())
        });
    }
}

/// What a handle refers to.
#[derive(Clone)]
pub enum Object {
    File(Arc<IrqMutex<OpenFile>>),
}

/// Rights given to an open regular file or device, by access mode. Reading
/// also grants MAP_EXEC for compatibility (Linux lets any readable file be
/// mapped executable); compartment manifests can withhold it from Phase 3.
pub fn file_rights(read: bool, write: bool, kind: Kind) -> Rights {
    let mut rights = Rights::STAT | Rights::SEEK | Rights::DUPLICATE;
    if read {
        rights = rights | Rights::READ;
        if kind == Kind::File {
            rights = rights | Rights::MAP_EXEC;
        }
    }
    if write {
        rights = rights | Rights::WRITE;
    }
    if kind == Kind::Directory {
        // CREATE is granted by default, as MAP_EXEC is on files, for Linux
        // compatibility (creating through a directory descriptor needs no
        // write access there); compartment manifests can withhold it from
        // Phase 3 (ADR 0012).
        rights = rights | Rights::ENUMERATE | Rights::CREATE;
    }
    rights
}

pub struct Process {
    /// Its compartment and its PID there. Dropping the process gives the
    /// compartment's process slot back.
    pub member: Member,
    /// The address space; `None` once the process has exited (a zombie
    /// keeps only what its parent's wait4 needs).
    pub space: Option<Arc<AddressSpace>>,
    pub handles: HandleTable<Object>,
    /// Program break: start (fixed) and current end, both page-aligned
    /// in use; `brk` may be any address at or above `brk_start`.
    pub brk_start: u64,
    pub brk: u64,
    /// Lookups never leave `root`: the compartment's root (SR-4).
    pub root: Ino,
    pub cwd: Ino,
    /// The file mode creation mask (umask(2)); 022 for a process the
    /// kernel starts, as Linux's init_fs. fork and execve keep it.
    pub umask: u32,
    /// Its threads, by scheduler thread id (P3-T4). The first is the one
    /// it started with, whose TID is the PID.
    pub threads: BTreeMap<u64, ThreadInfo>,
    /// exit_group's status, once a thread has called it: the process's
    /// exit status, whatever its other threads end with.
    pub group_exit: Option<i64>,
    /// The signal that is ending it (SIGKILL, or a fault in one of its
    /// threads), for the wait status.
    pub killed_by: Option<i32>,
    /// Signal dispositions, shared by its threads (P3-T6, ADR 0020).
    pub signals: SignalState,
    /// Signals sent to the process as a whole (`shared_pending`): any
    /// thread that does not block one may take it.
    pub pending: Pending,
    /// The process that forked this one, if any (getppid, and where the
    /// exit status goes). Processes the kernel starts have none.
    pub parent: Option<Weak<IrqMutex<Process>>>,
    /// Children not yet reaped by wait4, alive or exited (zombies).
    pub children: Vec<Child>,
}

/// One thread of a process.
pub struct ThreadInfo {
    /// Its thread ID (gettid): the PID for the first thread, the next PID
    /// of the compartment for one created by clone.
    pub tid: u32,
    /// The compartment slot of a thread created by clone, held until the
    /// thread exits (threads count
    /// against the process limit, as Linux counts them against
    /// RLIMIT_NPROC). The first thread uses the process's own.
    _slot: Option<Member>,
    /// set_tid_address(2) and CLONE_CHILD_CLEARTID: at exit, 0 is written
    /// there and one waiter woken (Linux's mm_release, `kernel/fork.c`).
    pub clear_child_tid: u64,
    /// Its blocked mask, alternate stack and the signals sent to it alone.
    pub signals: ThreadSignals,
    /// Its last CPU fault, as Linux keeps `trap_nr`, `error_code` and
    /// `cr2` in the thread for the next signal frame's `trapno`, `err` and
    /// `cr2`.
    pub trap: Trap,
}

/// `thread.trap_nr`, `thread.error_code` and `thread.cr2`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Trap {
    pub trapno: u64,
    pub err: u64,
    pub cr2: u64,
}

impl ThreadInfo {
    fn first(tid: u32, signals: ThreadSignals) -> ThreadInfo {
        ThreadInfo {
            tid,
            _slot: None,
            clear_child_tid: 0,
            signals,
            trap: Trap::default(),
        }
    }
}

/// A child, as its parent sees it. An exited child (a zombie) keeps its
/// process object, and with it its compartment process slot, until its
/// parent reaps it: as on Linux, where a zombie still counts against
/// RLIMIT_NPROC, so exiting children cannot pile up without limit. Its
/// handles and address space are freed at exit.
pub struct Child {
    pub process: Arc<IrqMutex<Process>>,
    pub pid: u32,
    /// The wait status once it has exited (`wait_status`).
    pub status: Option<i32>,
}

/// Woken whenever a process exits, for wait4.
static CHILD_EXITS: sched::WaitQueue = sched::WaitQueue::new();

/// Processes by thread ID.
static PROCESSES: IrqMutex<BTreeMap<u64, Arc<IrqMutex<Process>>>> = IrqMutex::new(BTreeMap::new());

impl Process {
    /// Its PID inside its compartment (what getpid(2) returns).
    pub fn pid(&self) -> u32 {
        self.member.pid()
    }

    /// Its address space. Only a process that has exited has none, and it
    /// makes no more system calls.
    pub fn space(&self) -> Result<Arc<AddressSpace>, Errno> {
        self.space.clone().ok_or(Errno::EFAULT)
    }

    /// getppid(2): the parent's PID, or 0 if it has none or has gone (as
    /// Linux reports a parent outside the caller's PID namespace).
    pub fn parent_pid(&self) -> u32 {
        self.parent
            .as_ref()
            .and_then(Weak::upgrade)
            .map_or(0, |parent| parent.lock().pid())
    }
}

/// A started process.
#[derive(Clone, Copy, Debug)]
pub struct Spawned {
    /// Its PID inside its compartment.
    pub pid: u32,
    pub thread: ThreadId,
}

/// The console as stdin (read) and stdout/stderr (write).
fn console_handles(handles: &mut HandleTable<Object>) -> Result<(), Errno> {
    let console = crate::fs::lookup(b"/dev/console")?;
    let kind = Kind::Device(Device::Console);
    for (read, write) in [(true, false), (false, true), (false, true)] {
        crate::fs::with(|fs| {
            fs.pin(console);
            Ok(())
        })?;
        let file = OpenFile {
            node: console,
            kind,
            offset: 0,
            append: false,
        };
        handles.insert(Handle {
            object: Object::File(Arc::new(IrqMutex::new(file))),
            rights: file_rights(read, write, kind),
            close_on_exec: false,
        })?;
    }
    Ok(())
}

/// Starts a loaded program as a new process in the system compartment,
/// with the console on fds 0-2. The first process started gets PID 1.
pub fn spawn(name: &'static str, loaded: &Loaded) -> Result<Spawned, Errno> {
    spawn_in(&crate::compartment::system(), name, loaded)
}

/// Starts a loaded program as a new process in `compartment`, with the
/// console on fds 0-2: its root and working directory are the
/// compartment's root, and its PID is the compartment's next. EAGAIN at
/// the compartment's process limit; ENOMEM if what the loader populated
/// does not fit the compartment's memory limit. From then on its address
/// space is charged to the compartment's memory budget (P3-S4).
pub fn spawn_in(
    compartment: &Arc<Compartment>,
    name: &'static str,
    loaded: &Loaded,
) -> Result<Spawned, Errno> {
    let member = compartment.admit()?;
    loaded
        .space
        .attach_budget(compartment.memory().clone())
        .map_err(|_| Errno::ENOMEM)?;
    let mut handles = HandleTable::new(HANDLE_LIMIT);
    console_handles(&mut handles)?;
    let mut processes = PROCESSES.lock();
    let pid = member.pid();
    let root = compartment.root();
    let process = Process {
        member,
        space: Some(loaded.space.clone()),
        handles,
        brk_start: loaded.brk_start,
        brk: loaded.brk_start,
        root,
        cwd: root,
        umask: 0o022,
        signals: SignalState::new(),
        pending: Pending::new(),
        parent: None,
        children: Vec::new(),
        threads: BTreeMap::new(),
        group_exit: None,
        killed_by: None,
    };
    // PROCESSES stays locked (interrupts off) until the entry is in, so the
    // new thread cannot make a system call before its process exists.
    let thread = sched::spawn_user(name, loaded.space.clone(), loaded.entry, loaded.rsp, 0)
        .map_err(|_| Errno::ENOMEM)?;
    let mut process = process;
    process
        .threads
        .insert(thread.0, ThreadInfo::first(pid, ThreadSignals::new()));
    processes.insert(thread.0, Arc::new(IrqMutex::new(process)));
    Ok(Spawned { pid, thread })
}

/// The process of the running thread, if it has one.
pub fn current() -> Option<Arc<IrqMutex<Process>>> {
    PROCESSES.lock().get(&sched::current().0).cloned()
}

/// fork(2) (P3-T3): a new process in the caller's compartment (counted
/// against its process limit: EAGAIN), whose address space is the
/// caller's, shared copy-on-write (`AddressSpace::duplicate`) and charged
/// to the compartment's memory budget (ENOMEM), with copies of the
/// caller's handles (sharing the open files), signal dispositions, blocked
/// mask and alternate stack, program break, root and working directory.
/// Its thread starts with the caller's registers, FS/GS bases and FPU
/// state, except RAX = 0: fork returns 0 in the child and the child's PID
/// in the parent. As fork(2), the child has one thread (the caller's
/// copy), its clear_child_tid is not inherited and it has no children of
/// its own.
pub fn fork(p: &Arc<IrqMutex<Process>>, frame: &TrapFrame) -> Result<u64, Errno> {
    let (compartment, space, handles, signals, thread_signals, brk_start, brk, root, cwd, umask) = {
        let process = p.lock();
        (
            process.member.compartment().clone(),
            process.space()?,
            process.handles.clone(),
            process.signals.clone(),
            process
                .threads
                .get(&sched::current().0)
                .map_or_else(ThreadSignals::new, |t| t.signals.for_child(false)),
            process.brk_start,
            process.brk,
            process.root,
            process.cwd,
            process.umask,
        )
    };
    let member = compartment.admit()?;
    let child_space = space.duplicate().map_err(|_| Errno::ENOMEM)?;
    child_space
        .attach_budget(compartment.memory().clone())
        .map_err(|_| Errno::ENOMEM)?;
    let pid = member.pid();
    let child = Arc::new(IrqMutex::new(Process {
        member,
        space: Some(child_space.clone()),
        handles,
        brk_start,
        brk,
        root,
        cwd,
        umask,
        signals,
        pending: Pending::new(),
        parent: Some(Arc::downgrade(p)),
        children: Vec::new(),
        threads: BTreeMap::new(),
        group_exit: None,
        killed_by: None,
    }));
    let mut registers = *frame;
    registers.rax = 0;
    // PROCESSES stays locked (interrupts off) until the child is entered
    // and recorded in its parent, so it cannot run, or exit, before its
    // parent knows it.
    let mut processes = PROCESSES.lock();
    let thread =
        sched::spawn_user_copy("fork", child_space, registers, None).map_err(|_| Errno::ENOMEM)?;
    child
        .lock()
        .threads
        .insert(thread.0, ThreadInfo::first(pid, thread_signals));
    processes.insert(thread.0, child.clone());
    p.lock().children.push(Child {
        process: child,
        pid,
        status: None,
    });
    Ok(u64::from(pid))
}

/// Linux's clone flags (`include/uapi/linux/sched.h` at v6.12).
pub mod clone_flags {
    pub const CSIGNAL: u64 = 0xff;
    pub const CLONE_VM: u64 = 0x100;
    pub const CLONE_FS: u64 = 0x200;
    pub const CLONE_FILES: u64 = 0x400;
    pub const CLONE_SIGHAND: u64 = 0x800;
    pub const CLONE_THREAD: u64 = 0x1_0000;
    pub const CLONE_SYSVSEM: u64 = 0x4_0000;
    pub const CLONE_SETTLS: u64 = 0x8_0000;
    pub const CLONE_PARENT_SETTID: u64 = 0x10_0000;
    pub const CLONE_CHILD_CLEARTID: u64 = 0x20_0000;
    pub const CLONE_DETACHED: u64 = 0x40_0000;
    pub const CLONE_CHILD_SETTID: u64 = 0x100_0000;
}

/// clone(2) for a new thread in the caller's process (P3-T4): the flags
/// musl's pthread_create passes, and the Wine trace shows
/// (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
/// CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
/// CLONE_CHILD_CLEARTID, and CLONE_DETACHED, which Linux ignores), or
/// fewer of the optional ones. The thread takes a slot of the compartment
/// (EAGAIN), and its TID is the compartment's next PID. It starts with the
/// caller's registers except RAX = 0 and RSP = `stack` (if not 0), the
/// caller's FS/GS bases (FS = `tls` with CLONE_SETTLS; outside the user
/// half EPERM, as arch_prctl) and FPU state. CLONE_PARENT_SETTID and
/// CLONE_CHILD_SETTID write the TID to `parent_tid` and `child_tid`
/// (the same memory); CLONE_CHILD_CLEARTID makes `child_tid` its
/// clear_child_tid. Returns the TID.
pub fn clone_thread(
    p: &Arc<IrqMutex<Process>>,
    frame: &TrapFrame,
    flags: u64,
    stack: u64,
    parent_tid: u64,
    child_tid: u64,
    tls: u64,
) -> Result<u64, Errno> {
    use clone_flags::*;
    let fs_base = if flags & CLONE_SETTLS != 0 {
        if tls >= keel_core::vm::USER_END {
            return Err(Errno::EPERM);
        }
        Some(tls)
    } else {
        None
    };
    let (compartment, space, signals) = {
        let process = p.lock();
        (
            process.member.compartment().clone(),
            process.space()?,
            process
                .threads
                .get(&sched::current().0)
                .map_or_else(ThreadSignals::new, |t| t.signals.for_child(true)),
        )
    };
    let member = compartment.admit()?;
    let tid = member.pid();
    for (flag, address) in [
        (CLONE_PARENT_SETTID, parent_tid),
        (CLONE_CHILD_SETTID, child_tid),
    ] {
        if flags & flag != 0 {
            keel_hal::vm::copy_to_user(address, &tid.to_le_bytes()).map_err(|_| Errno::EFAULT)?;
        }
    }
    let mut registers = *frame;
    registers.rax = 0;
    if stack != 0 {
        registers.rsp = stack;
    }
    let mut processes = PROCESSES.lock();
    let thread =
        sched::spawn_user_copy("thread", space, registers, fs_base).map_err(|_| Errno::ENOMEM)?;
    p.lock().threads.insert(
        thread.0,
        ThreadInfo {
            tid,
            _slot: Some(member),
            clear_child_tid: if flags & CLONE_CHILD_CLEARTID != 0 {
                child_tid
            } else {
                0
            },
            signals,
            trap: Trap::default(),
        },
    );
    processes.insert(thread.0, p.clone());
    Ok(u64::from(tid))
}

/// exit_group(2): the process ends with `code` (its wait status), and
/// every other thread of it is asked to end (`sched::request_exit`). The
/// caller ends here. It takes the process by value and drops it first: a
/// thread that ends never unwinds, so a reference kept on its stack would
/// keep the process (and its compartment slot) alive for ever.
pub fn exit_group(p: Arc<IrqMutex<Process>>, code: i64) -> ! {
    let others: Vec<u64> = {
        let mut process = p.lock();
        process.group_exit.get_or_insert(code);
        let me = sched::current().0;
        process
            .threads
            .keys()
            .copied()
            .filter(|&t| t != me)
            .collect()
    };
    drop(p);
    for thread in others {
        sched::request_exit(ThreadId(thread), code);
    }
    sched::exit_with(code)
}

/// The process in the caller's compartment with PID `pid`, if it is
/// running.
fn find(compartment: &Arc<Compartment>, pid: u32) -> Option<Arc<IrqMutex<Process>>> {
    PROCESSES
        .lock()
        .values()
        .find(|p| {
            let p = p.lock();
            p.pid() == pid && Arc::ptr_eq(p.member.compartment(), compartment)
        })
        .cloned()
}

/// The running process in the caller's compartment with PID `pid`, if any
/// (kill(2) and tgkill(2) name processes this way).
pub fn find_in(compartment: &Arc<Compartment>, pid: u32) -> Option<Arc<IrqMutex<Process>>> {
    find(compartment, pid)
}

/// The thread with TID `tid` in `compartment`, and its process.
pub fn find_thread(
    compartment: &Arc<Compartment>,
    tid: u32,
) -> Option<(Arc<IrqMutex<Process>>, ThreadId)> {
    PROCESSES.lock().iter().find_map(|(&thread, p)| {
        let process = p.lock();
        (Arc::ptr_eq(process.member.compartment(), compartment)
            && process.threads.get(&thread).is_some_and(|t| t.tid == tid))
        .then(|| (p.clone(), ThreadId(thread)))
    })
}

/// Ends every thread of `target` because of `signal` (SIGKILL, or a
/// signal whose default action terminates): the wait status is the
/// signal.
pub fn kill_all_threads(target: &Arc<IrqMutex<Process>>, signal: i32) {
    let threads: Vec<u64> = {
        let mut t = target.lock();
        t.killed_by.get_or_insert(signal);
        t.threads.keys().copied().collect()
    };
    for thread in threads {
        sched::request_exit(ThreadId(thread), 128 + i64::from(signal));
    }
}

/// Exit hook, for every thread of a process. The thread leaves its
/// process: its clear_child_tid gets 0 and one futex waiter is woken
/// (only if other threads still share the memory, as Linux's mm_release),
/// and its compartment slot is given back. A thread ended by a fault ends
/// the whole process, as a fault's signal does on Linux. When the last
/// thread goes, the process exits: its handles, address space and own
/// children's records are dropped, and the wait status (the exit_group
/// code, or the last thread's; or the signal) goes to the parent's
/// record, if the parent is still there.
pub fn on_thread_exit(thread: ThreadId, status: i64, fault: Option<sched::UserFault>) {
    let Some(process) = PROCESSES.lock().remove(&thread.0) else {
        return;
    };
    crate::futex::forget(thread);
    let (info, others, space) = {
        let mut p = process.lock();
        if fault.is_some() {
            p.killed_by.get_or_insert(((status - 128) & 0x7f) as i32);
        }
        let info = p.threads.remove(&thread.0);
        let others: Vec<u64> = p.threads.keys().copied().collect();
        (info, others, p.space.clone())
    };
    if let (Some(info), Some(space)) = (&info, &space)
        && info.clear_child_tid != 0
        && !others.is_empty()
    {
        // The exiting thread is still running in this address space.
        let _ = keel_hal::vm::copy_to_user(info.clear_child_tid, &0u32.to_le_bytes());
        crate::futex::wake(space.id(), info.clear_child_tid, 1);
    }
    drop(info);
    if !others.is_empty() {
        if fault.is_some() {
            for other in others {
                sched::request_exit(ThreadId(other), status);
            }
        }
        return;
    }
    let (handles, space, children, parent, code, signal) = {
        let mut p = process.lock();
        (
            core::mem::replace(&mut p.handles, HandleTable::new(0)),
            p.space.take(),
            core::mem::take(&mut p.children),
            p.parent.clone(),
            p.group_exit.unwrap_or(status),
            p.killed_by,
        )
    };
    drop((handles, space, children));
    let wait_status = match signal {
        Some(signal) => signal & 0x7f,
        None => ((code & 0xff) << 8) as i32,
    };
    if let Some(parent) = parent.as_ref().and_then(Weak::upgrade) {
        let mut parent = parent.lock();
        if let Some(child) = parent
            .children
            .iter_mut()
            .find(|c| Arc::ptr_eq(&c.process, &process))
        {
            child.status = Some(wait_status);
        }
    }
    CHILD_EXITS.wake_all();
}

/// The TID of the running thread (gettid), and its clear_child_tid slot.
pub fn with_current_thread<R>(
    p: &Arc<IrqMutex<Process>>,
    f: impl FnOnce(&mut ThreadInfo) -> R,
) -> Option<R> {
    p.lock().threads.get_mut(&sched::current().0).map(f)
}

/// Asks every thread of `p` but the running one to end (execve replaces
/// the program; Linux's de_thread). They leave as they exit.
pub fn end_other_threads(p: &Arc<IrqMutex<Process>>) {
    let me = sched::current().0;
    let others: Vec<u64> = p
        .lock()
        .threads
        .keys()
        .copied()
        .filter(|&t| t != me)
        .collect();
    for thread in others {
        sched::request_exit(ThreadId(thread), 0);
    }
}

/// What wait4 is waiting for: a child with this PID, or any child.
#[derive(Clone, Copy, Debug)]
pub enum WaitFor {
    Any,
    Pid(u32),
}

/// wait4's core: reaps an exited child matching `which` and returns its
/// PID and wait status. ECHILD if no child matches; `Ok(None)` if one
/// matches but none has exited and `block` is false (WNOHANG); otherwise
/// blocks until one exits. Reaping drops the zombie, giving its
/// compartment slot back.
pub fn wait(
    p: &Arc<IrqMutex<Process>>,
    which: WaitFor,
    block: bool,
) -> Result<Option<(u32, i32)>, Errno> {
    let matches = move |c: &Child| match which {
        WaitFor::Any => true,
        WaitFor::Pid(pid) => c.pid == pid,
    };
    let mut result = Ok(None);
    let mut try_reap = || {
        let mut process = p.lock();
        if !process.children.iter().any(&matches) {
            result = Err(Errno::ECHILD);
            return true;
        }
        let Some(index) = process
            .children
            .iter()
            .position(|c| matches(c) && c.status.is_some())
        else {
            return false;
        };
        let child = process.children.remove(index);
        result = Ok(child.status.map(|status| (child.pid, status)));
        drop(process);
        drop(child);
        true
    };
    if block {
        if !CHILD_EXITS.wait_until(&mut try_reap) {
            // wait(2): "EINTR: WNOHANG was not set and an unblocked
            // signal or a SIGCHLD was caught".
            return Err(Errno::EINTR);
        }
    } else {
        try_reap();
    }
    result
}

/// Number of live processes (tests).
pub fn count() -> usize {
    PROCESSES.lock().len()
}
