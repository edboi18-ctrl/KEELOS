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
use keel_core::signal::SignalState;
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
/// the handle (as Linux shares one `struct file`).
#[derive(Debug)]
pub struct OpenFile {
    pub node: Ino,
    pub kind: Kind,
    pub offset: u64,
    pub append: bool,
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
    /// set_tid_address(2): where the TID is cleared at thread exit (used
    /// with futexes once threads exist; stored only for now).
    pub clear_child_tid: u64,
    /// Signal dispositions, blocked mask and alternate stack, recorded
    /// only until delivery arrives (P3-T6).
    pub signals: SignalState,
    /// The process that forked this one, if any (getppid, and where the
    /// exit status goes). Processes the kernel starts have none.
    pub parent: Option<Weak<IrqMutex<Process>>>,
    /// Children not yet reaped by wait4, alive or exited (zombies).
    pub children: Vec<Child>,
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

/// The wait status of an exit, as Linux encodes it (`kernel/exit.c` at
/// v6.12): `(code & 0xff) << 8` for exit(2) and exit_group(2); the signal
/// number for death by a signal. Keel records a fault's status as 128 +
/// the signal Linux would send (`hal::syscall::status_for`), so that is
/// turned back into the signal.
pub fn wait_status(status: i64, fault: Option<sched::UserFault>) -> i32 {
    match fault {
        Some(_) => ((status - 128) & 0x7f) as i32,
        None => ((status & 0xff) << 8) as i32,
    }
}

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
        clear_child_tid: 0,
        signals: SignalState::new(),
        parent: None,
        children: Vec::new(),
    };
    // PROCESSES stays locked (interrupts off) until the entry is in, so the
    // new thread cannot make a system call before its process exists.
    let thread = sched::spawn_user(name, loaded.space.clone(), loaded.entry, loaded.rsp, 0)
        .map_err(|_| Errno::ENOMEM)?;
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
/// in the parent. As fork(2), the child's clear_child_tid is not
/// inherited and it has no children of its own.
pub fn fork(p: &Arc<IrqMutex<Process>>, frame: &TrapFrame) -> Result<u64, Errno> {
    let (compartment, space, handles, signals, brk_start, brk, root, cwd) = {
        let process = p.lock();
        (
            process.member.compartment().clone(),
            process.space()?,
            process.handles.clone(),
            process.signals.clone(),
            process.brk_start,
            process.brk,
            process.root,
            process.cwd,
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
        clear_child_tid: 0,
        signals,
        parent: Some(Arc::downgrade(p)),
        children: Vec::new(),
    }));
    let mut registers = *frame;
    registers.rax = 0;
    // PROCESSES stays locked (interrupts off) until the child is entered
    // and recorded in its parent, so it cannot run, or exit, before its
    // parent knows it.
    let mut processes = PROCESSES.lock();
    let thread =
        sched::spawn_user_copy("fork", child_space, registers).map_err(|_| Errno::ENOMEM)?;
    processes.insert(thread.0, child.clone());
    p.lock().children.push(Child {
        process: child,
        pid,
        status: None,
    });
    Ok(u64::from(pid))
}

/// Exit hook: the process is gone from the running set. Its handles,
/// address space and own children's records are dropped (closing its
/// files; orphaned zombies give their slots back). Its parent, if it is
/// still there, records the wait status in the child's entry and is
/// woken; without a parent the process is dropped whole. The address
/// space lives until the thread itself is reaped.
pub fn on_thread_exit(thread: ThreadId, status: i64, fault: Option<sched::UserFault>) {
    let Some(process) = PROCESSES.lock().remove(&thread.0) else {
        return;
    };
    let (handles, space, children, parent) = {
        let mut p = process.lock();
        (
            core::mem::replace(&mut p.handles, HandleTable::new(0)),
            p.space.take(),
            core::mem::take(&mut p.children),
            p.parent.clone(),
        )
    };
    drop((handles, space, children));
    if let Some(parent) = parent.as_ref().and_then(Weak::upgrade) {
        let mut parent = parent.lock();
        if let Some(child) = parent
            .children
            .iter_mut()
            .find(|c| Arc::ptr_eq(&c.process, &process))
        {
            child.status = Some(wait_status(status, fault));
        }
    }
    CHILD_EXITS.wake_all();
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
        CHILD_EXITS.wait_until(&mut try_reap);
    } else {
        try_reap();
    }
    result
}

/// Number of live processes (tests).
pub fn count() -> usize {
    PROCESSES.lock().len()
}
