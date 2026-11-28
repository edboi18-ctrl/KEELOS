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
    /// The status flags F_GETFL reports (`f_flags`): the access mode and
    /// the open flags that stay with the description (O_APPEND,
    /// O_NONBLOCK, O_DIRECT, O_NOATIME, O_LARGEFILE, which open always
    /// sets on 64-bit: `force_o_largefile`). `append` mirrors O_APPEND.
    pub status: u64,
    /// For `/proc/<pid>/[task/<tid>/]comm` (ADR 0024): the thread a write
    /// names, if the opener may name it (a thread of its own process, as
    /// Linux's `comm_write` requires; else writes are EINVAL).
    pub comm: Option<CommTarget>,
    /// The terminal end, for a terminal (`/dev/console`, `/dev/ptmx`,
    /// `/dev/pts/N`; ADR 0029).
    pub tty: Option<Arc<crate::tty::TtyOpen>>,
    /// For a procfs directory opened to be listed (ADR 0037): which one.
    /// Its `node` is then a detached placeholder.
    pub proc: Option<keel_core::procfs::Node>,
}

/// The thread a `comm` file renames.
#[derive(Debug)]
pub struct CommTarget {
    pub process: Weak<IrqMutex<Process>>,
    /// The scheduler thread ID (the key of `Process::threads`).
    pub thread: u64,
    /// Whether writes are allowed (the opener's own process).
    pub own: bool,
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
    /// One end of a pipe (P3-T10, ADR 0025).
    Pipe(Arc<crate::ready::PipeEnd>),
    /// An eventfd (P3-T10, ADR 0025).
    EventFd(Arc<crate::ready::EventFile>),
    /// An epoll instance (P3-T10, ADR 0026).
    Epoll(Arc<crate::epoll::EpollFile>),
    /// A Unix domain socket (P3-T11, ADR 0027).
    Socket(Arc<crate::socket::Socket>),
    /// A compartment factory (P3-S2, ADR 0040).
    Factory(Arc<crate::native::Factory>),
    /// A compartment its creator holds (P3-S2, ADR 0040).
    Compartment(Arc<crate::native::CompartmentHandle>),
    /// An open audit log (P3-S6, ADR 0045).
    Audit(Arc<crate::audit::AuditReader>),
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
    /// The program's path from the process root, as `/proc/<pid>/exe`
    /// reads (ADR 0024).
    pub exe: Vec<u8>,
    /// The file mode creation mask (umask(2)); 022 for a process the
    /// kernel starts, as Linux's init_fs. fork and execve keep it.
    pub umask: u32,
    /// Who owns its POSIX record locks (Linux's `current->files`): unique
    /// to the process, so a forked child has its own (fcntl(2): "record
    /// locks are not inherited by a child created via fork").
    pub lock_owner: u64,
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
    /// Its process group and session (P3-T12, ADR 0030), PIDs of its
    /// compartment. A process the kernel starts is in session 0 and group
    /// 0, as Linux's init begins, so it can call setsid.
    pub pgid: u32,
    pub sid: u32,
    /// `signal->leader`: it made its session with setsid.
    pub leader: bool,
    /// It has called execve (Linux's PF_FORKNOEXEC cleared): its parent
    /// can no longer change its group (setpgid EACCES).
    pub execed: bool,
    /// Its controlling terminal (`signal->tty`), shared by its threads.
    pub ctty: Option<crate::tty::Ctty>,
    /// `signal->tty_old_pgrp`: a leader whose terminal was hung up keeps
    /// its foreground group, which gets SIGHUP and SIGCONT when the leader
    /// exits.
    pub old_pgrp: Option<u32>,
    /// Stopped by a stop signal (`SIGNAL_STOP_STOPPED`; ADR 0031): its
    /// threads wait until SIGCONT or SIGKILL.
    pub stopped: bool,
    /// The stop signal, until wait4's WUNTRACED reports it
    /// (`group_exit_code`).
    pub stop_report: Option<i32>,
    /// Continued, until wait4's WCONTINUED reports it
    /// (`SIGNAL_STOP_CONTINUED`).
    pub continue_report: bool,
    /// A vfork child's `vfork_done` (ADR 0034): set, and the parent woken,
    /// when it execs or exits.
    pub vfork_done: Option<Arc<core::sync::atomic::AtomicBool>>,
    /// Its argv as its program was started with, each string with its
    /// NUL, as `/proc/<pid>/cmdline` reads (ADR 0037). Linux reads the
    /// process's own memory there, so a program that rewrites its argv
    /// changes it; Keel keeps what exec gave. fork copies it.
    pub cmdline: Vec<u8>,
    /// When it was made (fork or spawn), in nanoseconds since boot
    /// (`start_boottime`).
    pub started: u64,
    /// The initial stack pointer exec gave it (`mm->start_stack`).
    pub start_stack: u64,
    /// The first thread's name once that thread has exited, for a zombie's
    /// stat.
    pub exit_comm: Vec<u8>,
    /// A zombie's wait status (`exit_code`).
    pub exit_status: Option<i32>,
}

/// Woken when a vfork child execs or exits (`complete_vfork_done`).
static VFORK_DONE: sched::WaitQueue = sched::WaitQueue::new();

/// `mm_release`'s `complete_vfork_done`: a vfork child no longer uses its
/// parent's memory, because it has exec'd or is exiting; its parent goes on.
pub fn release_vfork(p: &Arc<IrqMutex<Process>>) {
    if let Some(done) = p.lock().vfork_done.take() {
        done.store(true, core::sync::atomic::Ordering::SeqCst);
        VFORK_DONE.wake_all();
    }
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
    /// Its name (`comm`, at most 15 bytes: TASK_COMM_LEN 16 with the
    /// NUL), as `/proc/<pid>/task/<tid>/comm` and prctl PR_GET_NAME give
    /// it: the program's base name at spawn and execve, the creator's for
    /// a new thread or a forked child.
    pub comm: Vec<u8>,
    /// `restart_block`: what restart_syscall resumes (ADR 0033).
    pub restart: Option<crate::sleep::Restart>,
}

/// A thread name from a path: its last component, cut to 15 bytes
/// (`__set_task_comm(me, kbasename(bprm->filename))`, `fs/exec.c`).
pub fn comm_of(path: &[u8]) -> Vec<u8> {
    let base = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    base[..base.len().min(15)].to_vec()
}

/// `thread.trap_nr`, `thread.error_code` and `thread.cr2`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Trap {
    pub trapno: u64,
    pub err: u64,
    pub cr2: u64,
}

impl ThreadInfo {
    fn first(tid: u32, signals: ThreadSignals, comm: Vec<u8>) -> ThreadInfo {
        ThreadInfo {
            tid,
            _slot: None,
            clear_child_tid: 0,
            signals,
            trap: Trap::default(),
            comm,
            restart: None,
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

/// Woken whenever a process exits, stops or continues, for wait4.
static CHILD_EXITS: sched::WaitQueue = sched::WaitQueue::new();

/// Wakes wait4's waiters (`__wake_up_parent`).
pub fn wake_waiters() {
    CHILD_EXITS.wake_all();
}

/// Lock owners, one per process, never reused.
fn new_lock_owner() -> u64 {
    static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
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
    console_handles_as(handles, &[(true, false), (false, true), (false, true)])
}

/// The console, once for each (read, write) in `modes`, in order.
fn console_handles_as(
    handles: &mut HandleTable<Object>,
    modes: &[(bool, bool)],
) -> Result<(), Errno> {
    let console = crate::fs::lookup(b"/dev/console")?;
    let kind = Kind::Device(Device::Console);
    for &(read, write) in modes {
        crate::fs::with(|fs| {
            fs.pin(console);
            Ok(())
        })?;
        let file = OpenFile {
            node: console,
            kind,
            offset: 0,
            append: false,
            // As the kernel opens the console for init: O_LARGEFILE, read
            // or write as the descriptor is.
            status: crate::abi::O_LARGEFILE | if write { crate::abi::O_WRONLY } else { 0 },
            comm: None,
            proc: None,
            tty: Some(Arc::new(crate::tty::TtyOpen {
                line: crate::tty::Line::Console,
            })),
        };
        handles.insert(Handle {
            object: Object::File(Arc::new(IrqMutex::new(file))),
            rights: file_rights(read, write, kind),
            close_on_exec: false,
        })?;
    }
    Ok(())
}

/// Standard input and output from tmpfs files (the conformance tests,
/// ADR 0039): fd 0 reads `stdin` from its start, fd 1 writes `stdout`, fd
/// 2 is the console. Each open pins its node, as open(2) does.
fn file_handles(handles: &mut HandleTable<Object>, stdin: Ino, stdout: Ino) -> Result<(), Errno> {
    for (node, write) in [(stdin, false), (stdout, true)] {
        crate::fs::with(|fs| {
            fs.pin(node);
            Ok(())
        })?;
        let file = OpenFile {
            node,
            kind: Kind::File,
            offset: 0,
            append: false,
            status: crate::abi::O_LARGEFILE | if write { crate::abi::O_WRONLY } else { 0 },
            comm: None,
            proc: None,
            tty: None,
        };
        handles.insert(Handle {
            object: Object::File(Arc::new(IrqMutex::new(file))),
            rights: file_rights(!write, write, Kind::File),
            close_on_exec: false,
        })?;
    }
    console_handles_as(handles, &[(false, true)])
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
    spawn_in_with(compartment, name, loaded, None)
}

/// As [`spawn_in`], with standard input and output from the tmpfs files
/// `stdio` (input, output) instead of the console; standard error stays
/// the console.
pub fn spawn_in_with(
    compartment: &Arc<Compartment>,
    name: &'static str,
    loaded: &Loaded,
    stdio: Option<(Ino, Ino)>,
) -> Result<Spawned, Errno> {
    let mut handles = HandleTable::new(HANDLE_LIMIT);
    match stdio {
        Some((stdin, stdout)) => file_handles(&mut handles, stdin, stdout)?,
        None => console_handles(&mut handles)?,
    }
    spawn_in_handles(compartment, name, loaded, handles)
}

/// The console on fds 0 to 2 and `extra` at fd 3: keel-init's start, with
/// the factory (ADR 0040).
pub fn spawn_with_fd3(
    name: &'static str,
    loaded: &Loaded,
    extra: Handle<Object>,
) -> Result<Spawned, Errno> {
    let mut handles = HandleTable::new(HANDLE_LIMIT);
    console_handles(&mut handles)?;
    handles.place(3, extra)?;
    spawn_in_handles(&crate::compartment::system(), name, loaded, handles)
}

/// As [`spawn_in`], with `handles` as the new process's descriptors.
pub fn spawn_in_handles(
    compartment: &Arc<Compartment>,
    name: &'static str,
    loaded: &Loaded,
    mut handles: HandleTable<Object>,
) -> Result<Spawned, Errno> {
    // Its compartment's descriptor limit (ADR 0042); fork copies the
    // table, limit and all.
    handles.lower_limit(compartment.limits().handles)?;
    let member = compartment.admit()?;
    loaded
        .space
        .attach_budget(compartment.memory().clone())
        .map_err(|_| Errno::ENOMEM)?;
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
        lock_owner: new_lock_owner(),
        exe: loaded.path.clone(),
        signals: SignalState::new(),
        pending: Pending::new(),
        parent: None,
        children: Vec::new(),
        threads: BTreeMap::new(),
        group_exit: None,
        killed_by: None,
        pgid: 0,
        sid: 0,
        leader: false,
        execed: true,
        ctty: None,
        old_pgrp: None,
        stopped: false,
        stop_report: None,
        continue_report: false,
        vfork_done: None,
        cmdline: loaded.cmdline.clone(),
        started: keel_hal::time::monotonic_nanos(),
        start_stack: loaded.rsp,
        exit_comm: Vec::new(),
        exit_status: None,
    };
    // PROCESSES stays locked (interrupts off) until the entry is in, so the
    // new thread cannot make a system call before its process exists.
    let thread = sched::spawn_user(
        name,
        loaded.space.clone(),
        loaded.entry,
        loaded.rsp,
        0,
        compartment.id(),
    )
    .map_err(|_| Errno::ENOMEM)?;
    let mut process = process;
    process.threads.insert(
        thread.0,
        ThreadInfo::first(pid, ThreadSignals::new(), comm_of(&loaded.path)),
    );
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
    fork_with(p, frame, Vfork::No)
}

/// How a fork treats the parent's memory and the calling thread
/// (`kernel_clone`'s CLONE_VM and CLONE_VFORK).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Vfork {
    /// fork: a copy-on-write copy; the parent goes on.
    No,
    /// CLONE_VFORK alone: a copy, and the calling thread waits until the
    /// child execs or exits.
    Copy,
    /// vfork(2), CLONE_VM | CLONE_VFORK: the child uses the parent's
    /// address space itself, and the calling thread waits as for `Copy`.
    Share,
}

/// vfork(2) and clone with CLONE_VFORK (ADR 0034), as `kernel_clone`:
/// a child as fork makes, but with `Vfork::Share` it runs in the parent's
/// own address space (on `stack`, or the parent's stack if 0), and the
/// calling thread waits, killable only (`wait_for_vfork_done`:
/// TASK_KILLABLE), until the child execs or exits. Signals sent to the
/// parent meanwhile are taken after.
pub fn vfork(
    p: &Arc<IrqMutex<Process>>,
    frame: &TrapFrame,
    mode: Vfork,
    stack: u64,
) -> Result<u64, Errno> {
    let mut registers = *frame;
    if stack != 0 {
        registers.rsp = stack;
    }
    fork_with(p, &registers, mode)
}

fn fork_with(p: &Arc<IrqMutex<Process>>, frame: &TrapFrame, mode: Vfork) -> Result<u64, Errno> {
    let (
        compartment,
        space,
        handles,
        signals,
        thread_signals,
        brk_start,
        brk,
        root,
        cwd,
        umask,
        exe,
        comm,
        (pgid, sid, ctty),
        (cmdline, start_stack),
    ) = {
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
            process.exe.clone(),
            process
                .threads
                .get(&sched::current().0)
                .map_or_else(Vec::new, |t| t.comm.clone()),
            // copy_process: the group, session and controlling terminal
            // are inherited; a child is never a session leader.
            (process.pgid, process.sid, process.ctty.clone()),
            (process.cmdline.clone(), process.start_stack),
        )
    };
    let member = compartment.admit()?;
    let child_space = if mode == Vfork::Share {
        // The same address space, already charged to the compartment.
        space
    } else {
        let copy = space.duplicate().map_err(|_| Errno::ENOMEM)?;
        copy.attach_budget(compartment.memory().clone())
            .map_err(|_| Errno::ENOMEM)?;
        copy
    };
    let done = (mode != Vfork::No).then(|| Arc::new(core::sync::atomic::AtomicBool::new(false)));
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
        lock_owner: new_lock_owner(),
        exe,
        signals,
        pending: Pending::new(),
        parent: Some(Arc::downgrade(p)),
        children: Vec::new(),
        threads: BTreeMap::new(),
        group_exit: None,
        killed_by: None,
        pgid,
        sid,
        leader: false,
        execed: false,
        ctty,
        old_pgrp: None,
        stopped: false,
        stop_report: None,
        continue_report: false,
        vfork_done: done.clone(),
        cmdline,
        started: keel_hal::time::monotonic_nanos(),
        start_stack,
        exit_comm: Vec::new(),
        exit_status: None,
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
        .insert(thread.0, ThreadInfo::first(pid, thread_signals, comm));
    processes.insert(thread.0, child.clone());
    // A SIGKILL to the parent while the child was made (its sender's list
    // of processes may predate the child) takes the child too, as Linux's
    // copy_process checks fatal_signal_pending under the lock kill also
    // holds (`kernel/fork.c`: "Let kill terminate clone/fork in the
    // middle"). Checked here, under the process table's lock and after
    // the child is in it, so either the sender's list has the child or
    // the parent's mark is seen (`kill_every` lists again after sending).
    let killed = {
        let mut parent = p.lock();
        parent.children.push(Child {
            process: child.clone(),
            pid,
            status: None,
        });
        parent.killed_by
    };
    // Before the table is unlocked: unlocking enables interrupts, and
    // the child, run first, could fork a grandchild while not yet marked,
    // which would outlive it (`compartment.kill_during_fork`). The order
    // table, process, scheduler is the one fork already takes.
    if let Some(signal) = killed {
        kill_all_threads(&child, signal);
    }
    drop(processes);
    if let Some(done) = done {
        VFORK_DONE.wait_until(|| {
            done.load(core::sync::atomic::Ordering::SeqCst) || sched::exit_requested().is_some()
        });
    }
    Ok(u64::from(pid))
}

/// Linux's clone flags (`include/uapi/linux/sched.h` at v6.12).
pub mod clone_flags {
    pub const CSIGNAL: u64 = 0xff;
    pub const CLONE_VM: u64 = 0x100;
    pub const CLONE_FS: u64 = 0x200;
    pub const CLONE_FILES: u64 = 0x400;
    pub const CLONE_SIGHAND: u64 = 0x800;
    pub const CLONE_VFORK: u64 = 0x4000;
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
    let (compartment, space, signals, comm) = {
        let process = p.lock();
        let me = process.threads.get(&sched::current().0);
        (
            process.member.compartment().clone(),
            process.space()?,
            me.map_or_else(ThreadSignals::new, |t| t.signals.for_child(true)),
            me.map_or_else(Vec::new, |t| t.comm.clone()),
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
    let mut process = p.lock();
    // SIGKILL may have come while the thread was made: it listed the
    // threads, under this lock, before this one was there. The new thread
    // goes with the rest (Linux: copy_process's "Let kill terminate
    // clone/fork in the middle", `kernel/fork.c`).
    let killed = process.killed_by;
    process.threads.insert(
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
            comm,
            restart: None,
        },
    );
    drop(process);
    processes.insert(thread.0, p.clone());
    // Before the table is unlocked, as for fork.
    if let Some(signal) = killed {
        sched::request_exit(thread, 128 + i64::from(signal));
    }
    drop(processes);
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

/// The running processes of `compartment` for which `pick` holds, each
/// once (the table has an entry per thread). `pick` runs with the process
/// locked, so it must not lock it again.
pub fn members(
    compartment: &Arc<Compartment>,
    mut pick: impl FnMut(&Process) -> bool,
) -> Vec<Arc<IrqMutex<Process>>> {
    let mut found: Vec<Arc<IrqMutex<Process>>> = Vec::new();
    for p in PROCESSES.lock().values() {
        if found.iter().any(|f| Arc::ptr_eq(f, p)) {
            continue;
        }
        let chosen = {
            let q = p.lock();
            Arc::ptr_eq(q.member.compartment(), compartment) && pick(&q)
        };
        if chosen {
            found.push(p.clone());
        }
    }
    found
}

/// The zombies of `compartment` that `pick` chooses: children that have
/// exited and that their parent has not reaped. That includes a child
/// between its last thread's exit and its parent's record of its status:
/// `on_thread_exit` takes it out of the process table first, and until
/// the record is made it would otherwise be nowhere. Linux has no such
/// window (the task stays hashed until `release_task`, so kill(2) finds
/// it throughout), which the stress test found. Linux keeps a zombie in
/// its group and session until it is reaped (`release_task` ->
/// `__exit_signal` -> `__unhash_process` detaches its PIDTYPE_PGID and
/// PIDTYPE_SID links), so a group whose members have all exited still
/// exists for setpgid, TIOCSPGRP and kill until then.
pub fn zombies(
    compartment: &Arc<Compartment>,
    mut pick: impl FnMut(&Process) -> bool,
) -> Vec<Arc<IrqMutex<Process>>> {
    let mut found = Vec::new();
    for parent in members(compartment, |_| true) {
        let exited: Vec<Arc<IrqMutex<Process>>> = parent
            .lock()
            .children
            .iter()
            .filter(|c| c.status.is_some() || c.process.lock().threads.is_empty())
            .map(|c| c.process.clone())
            .collect();
        for z in exited {
            if pick(&z.lock()) {
                found.push(z);
            }
        }
    }
    found
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

/// SIGKILL to every process of `compartment` for which `pick` holds,
/// until none is left that has not been sent it. One pass is not
/// enough: a fork that completes after the pass listed the processes,
/// but before its parent was sent SIGKILL, leaves a child the list
/// missed (found by the in-compartment fuzzer, ADR 0047). Listing again
/// after sending finds it; a fork that completes later still sees its
/// parent killed and kills the child itself (`fork_with`). Linux holds
/// tasklist_lock across the walk instead (`kill_something_info`,
/// `kernel/signal.c`), which copy_process also takes. Returns how many
/// were sent it.
pub fn kill_every(compartment: &Arc<Compartment>, pick: impl Fn(&Process) -> bool) -> usize {
    let mut sent: Vec<Arc<IrqMutex<Process>>> = Vec::new();
    loop {
        let new: Vec<_> = members(compartment, &pick)
            .into_iter()
            .filter(|q| !sent.iter().any(|s| Arc::ptr_eq(s, q)))
            .collect();
        if new.is_empty() {
            return sent.len();
        }
        for target in &new {
            crate::signal::send_to_process(
                target,
                keel_core::signal::SigInfo::kernel(SIGKILL_NUMBER),
            );
        }
        sent.extend(new);
    }
}

const SIGKILL_NUMBER: i32 = keel_core::signal::SIGKILL;

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
    // The thread leaves its process before it leaves the process table:
    // the other way round, a process whose last thread was going was for
    // a moment in neither, and kill(2) of it was ESRCH (found by the
    // stress test, ADR 0038). This way it is always in the table, in its
    // parent's list of zombies (no threads left), or reaped.
    let Some(process) = PROCESSES.lock().get(&thread.0).cloned() else {
        return;
    };
    crate::futex::forget(thread);
    let (info, others, space) = {
        let mut p = process.lock();
        if fault.is_some() {
            p.killed_by.get_or_insert(((status - 128) & 0x7f) as i32);
        }
        let info = p.threads.remove(&thread.0);
        if let Some(info) = &info
            && info.tid == p.pid()
        {
            p.exit_comm = info.comm.clone();
        }
        let others: Vec<u64> = p.threads.keys().copied().collect();
        (info, others, p.space.clone())
    };
    PROCESSES.lock().remove(&thread.0);
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
    // A vfork child no longer uses its parent's memory (`mm_release`).
    release_vfork(&process);
    let (handles, space, children, parent, code, signal, owner) = {
        let mut p = process.lock();
        (
            core::mem::replace(&mut p.handles, HandleTable::new(0)),
            p.space.take(),
            core::mem::take(&mut p.children),
            p.parent.clone(),
            p.group_exit.unwrap_or(status),
            p.killed_by,
            p.lock_owner,
        )
    };
    let live_children: Vec<Arc<IrqMutex<Process>>> = children
        .iter()
        .filter(|c| c.status.is_none())
        .map(|c| c.process.clone())
        .collect();
    drop((handles, space, children));
    // disassociate_ctty(1): a session leader's terminal is hung up.
    crate::tty::on_exit(&process);
    // Its record locks go with it.
    crate::fscalls::release_locks(owner, None);
    let parent = parent.as_ref().and_then(Weak::upgrade);
    // kill_orphaned_pgrp: groups this exit orphans get SIGHUP and SIGCONT
    // if they have stopped members.
    crate::jobs::orphan_at_exit(&process, parent.as_ref(), &live_children);
    drop(live_children);
    let wait_status = match signal {
        Some(signal) => signal & 0x7f,
        None => ((code & 0xff) << 8) as i32,
    };
    {
        let mut q = process.lock();
        q.exit_status = Some(wait_status);
        // A compartment's PID 1 started by the native interface has no
        // parent: its status is kept for `compartment_wait` (ADR 0040).
        if q.parent.is_none() && q.pid() == 1 {
            q.member.compartment().set_lead_status(wait_status);
        }
    }
    if let Some(parent) = parent {
        // do_notify_parent: SIGCHLD (CLD_KILLED with the signal, or
        // CLD_EXITED with the code) unless the parent ignores it; a parent
        // that ignores SIGCHLD or set SA_NOCLDWAIT does not keep the
        // zombie (autoreap).
        let (code, status) = match signal {
            Some(s) => (keel_core::signal::CLD_KILLED, s),
            None => (keel_core::signal::CLD_EXITED, (code & 0xff) as i32),
        };
        let pid = process.lock().pid();
        let (send, reaped) = {
            let mut q = parent.lock();
            let action = q.signals.action(keel_core::signal::SIGCHLD);
            let ignore = action.is_some_and(|a| a.handler == keel_core::signal::SIG_IGN);
            let nowait = action.is_some_and(|a| a.flags & keel_core::signal::SA_NOCLDWAIT != 0);
            let index = q
                .children
                .iter()
                .position(|c| Arc::ptr_eq(&c.process, &process));
            let reaped = match index {
                Some(i) if ignore || nowait => Some(q.children.remove(i)),
                Some(i) => {
                    q.children[i].status = Some(wait_status);
                    None
                }
                None => None,
            };
            (!ignore, reaped)
        };
        drop(reaped);
        if send {
            crate::signal::send_to_process(
                &parent,
                keel_core::signal::SigInfo::child(code, pid, status),
            );
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

/// What wait4 is waiting for: a child with this PID, any child, or a
/// child in this process group (its group when wait4 looks).
#[derive(Clone, Copy, Debug)]
pub enum WaitFor {
    Any,
    Pid(u32),
    Group(u32),
}

/// What wait4 reports besides exits: WUNTRACED (a child's stop, once)
/// and WCONTINUED (its continuing, once).
#[derive(Clone, Copy, Debug, Default)]
pub struct WaitAlso {
    pub stopped: bool,
    pub continued: bool,
}

/// wait4's core (`wait_consider_task`): the first child matching `which`
/// with something to report, in the order they were made: an exit reaps
/// it; with `also`, a stop it has not reported (status `sig << 8 | 0x7f`)
/// or its continuing (0xffff). Returns its PID and wait status. ECHILD if
/// no child matches; `Ok(None)` if one matches but has nothing to report
/// and `block` is false (WNOHANG); otherwise blocks (a signal:
/// ERESTARTSYS, as `do_wait`). Reaping drops the zombie, giving its
/// compartment slot back.
pub fn wait(
    p: &Arc<IrqMutex<Process>>,
    which: WaitFor,
    also: WaitAlso,
    block: bool,
) -> Result<Option<(u32, i32)>, Errno> {
    // The parent is locked while this runs; a child is another process.
    let matches = move |c: &Child| match which {
        WaitFor::Any => true,
        WaitFor::Pid(pid) => c.pid == pid,
        WaitFor::Group(pgid) => c.process.lock().pgid == pgid,
    };
    let mut result = Ok(None);
    let mut try_reap = || {
        let mut process = p.lock();
        if !process.children.iter().any(&matches) {
            result = Err(Errno::ECHILD);
            return true;
        }
        for index in 0..process.children.len() {
            let c = &process.children[index];
            if !matches(c) {
                continue;
            }
            if c.status.is_some() {
                let child = process.children.remove(index);
                result = Ok(child.status.map(|status| (child.pid, status)));
                drop(process);
                drop(child);
                return true;
            }
            let mut q = c.process.lock();
            if also.stopped
                && q.stopped
                && let Some(signal) = q.stop_report.take()
            {
                result = Ok(Some((c.pid, (signal << 8) | 0x7f)));
                return true;
            }
            if also.continued && q.continue_report {
                q.continue_report = false;
                result = Ok(Some((c.pid, 0xffff)));
                return true;
            }
        }
        false
    };
    if block {
        if !CHILD_EXITS.wait_until(&mut try_reap) {
            // wait(2): "EINTR: WNOHANG was not set and an unblocked
            // signal or a SIGCHLD was caught"; restarted if no handler
            // runs or it has SA_RESTART.
            return Err(Errno::ERESTARTSYS);
        }
    } else {
        try_reap();
    }
    result
}

/// Waits until `compartment` has no process left (ADR 0040). A
/// process's slot is given back when its last reference goes, which can
/// be after the exit that wakes this queue, or when a parent reaps a
/// zombie, which wakes nothing: so the condition is looked at again every
/// 50 ms as well. False if a signal or an exit request ended the wait.
pub fn wait_until_empty(compartment: &Arc<Compartment>) -> bool {
    loop {
        let deadline = keel_hal::time::monotonic_nanos() + 50_000_000;
        let waited =
            CHILD_EXITS.wait_until_deadline(|| compartment.processes() == 0, Some(deadline));
        if compartment.processes() == 0 {
            return true;
        }
        if waited == sched::Waited::Interrupted {
            return false;
        }
    }
}

/// Number of live processes (tests).
pub fn count() -> usize {
    PROCESSES.lock().len()
}
