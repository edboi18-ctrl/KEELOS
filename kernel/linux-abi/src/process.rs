//! Processes (P1-T13): an address space, a handle table with rights
//! (P1-S1), the program break, and a root and working directory. One
//! thread per process until clone(2) arrives. Every process belongs to a
//! compartment (P3-S1, ADR 0014), which fixes its root and numbers it.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use keel_core::compartment::{Compartment, Member};
use keel_core::errno::Errno;
use keel_core::handle::{Handle, HandleTable, Rights};
use keel_core::signal::SignalState;
use keel_core::vfs::{Device, Ino, Kind};
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
    pub space: Arc<AddressSpace>,
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
}

/// Processes by thread ID.
static PROCESSES: IrqMutex<BTreeMap<u64, Arc<IrqMutex<Process>>>> = IrqMutex::new(BTreeMap::new());

impl Process {
    /// Its PID inside its compartment (what getpid(2) returns).
    pub fn pid(&self) -> u32 {
        self.member.pid()
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
/// the compartment's process limit.
pub fn spawn_in(
    compartment: &Arc<Compartment>,
    name: &'static str,
    loaded: &Loaded,
) -> Result<Spawned, Errno> {
    let member = compartment.admit()?;
    let mut handles = HandleTable::new(HANDLE_LIMIT);
    console_handles(&mut handles)?;
    let mut processes = PROCESSES.lock();
    let pid = member.pid();
    let root = compartment.root();
    let process = Process {
        member,
        space: loaded.space.clone(),
        handles,
        brk_start: loaded.brk_start,
        brk: loaded.brk_start,
        root,
        cwd: root,
        clear_child_tid: 0,
        signals: SignalState::new(),
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

/// Exit hook: drops the process (closing its handles) when its thread
/// ends. The address space lives until the thread itself is reaped.
pub fn on_thread_exit(thread: ThreadId) {
    let process = PROCESSES.lock().remove(&thread.0);
    drop(process);
}

/// Number of live processes (tests).
pub fn count() -> usize {
    PROCESSES.lock().len()
}
