//! The native launch interface (P3-S2, ADR 0040): seven calls, numbered
//! from [`BASE`], outside the Linux ABI, that create and run compartments.
//! Only a caller holding a factory handle can create one; the kernel
//! gives the first factory to `/sbin/keel-init` alone.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keel_core::compartment::{Compartment, Limits};
use keel_core::errno::Errno;
use keel_core::handle::{Handle, HandleTable, Rights};
use keel_core::vfs::{Device, Kind};
use keel_hal::sync::IrqMutex;
use keel_hal::vm::{copy_from_user, copy_to_user};

use crate::process::{self, Object, Process};
use crate::syscall::{SysResult, fault, object, user_path};

type ProcessRef = Arc<IrqMutex<Process>>;

/// The first native call's number: above Linux's x86-64 numbers, below
/// the x32 bit (0x4000_0000), which Keel refuses.
pub const BASE: u64 = 0x1000_0000;
/// How many native calls there are.
pub const COUNT: u64 = 9;

/// A compartment factory: creates compartments whose limits fit beneath
/// its ceiling.
#[derive(Debug)]
pub struct Factory {
    ceiling: Limits,
}

/// A compartment, as its creator holds it.
#[derive(Debug)]
pub struct CompartmentHandle {
    compartment: Arc<Compartment>,
}

impl CompartmentHandle {
    pub fn compartment(&self) -> &Arc<Compartment> {
        &self.compartment
    }
}

/// The rights a new factory handle has.
const FACTORY_RIGHTS: Rights = Rights::CREATE.union(Rights::DUPLICATE).union(Rights::STAT);
/// The rights a new compartment handle has.
const COMPARTMENT_RIGHTS: Rights = Rights::GRANT
    .union(Rights::CREATE)
    .union(Rights::SIGNAL)
    .union(Rights::STAT)
    .union(Rights::WAIT)
    .union(Rights::DUPLICATE);

/// The factory the kernel gives keel-init: the kernel's own ceiling (no
/// limit), close-on-exec, so nothing keel-init runs inherits it.
pub fn root_factory() -> Handle<Object> {
    Handle {
        object: Object::Factory(Arc::new(Factory {
            ceiling: Limits::UNLIMITED,
        })),
        // Only this factory can open the audit log (ADR 0045): a derived
        // one gets FACTORY_RIGHTS, and restrict removes rights only.
        rights: FACTORY_RIGHTS.union(Rights::AUDIT),
        close_on_exec: true,
    }
}

/// Reads a 40-byte limits structure (ADR 0040): processes (u32), 4
/// reserved bytes, memory bytes, tmpfs bytes, tmpfs nodes (u64 each), 8
/// reserved bytes. Reserved bytes must be 0 (EINVAL); so must not the
/// process limit. `u64::MAX` (`u32::MAX` for processes) is no limit.
fn read_limits(address: u64) -> Result<Limits, Errno> {
    let mut b = [0u8; 40];
    copy_from_user(&mut b, address).map_err(fault)?;
    let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]));
    let processes = u32::from_le_bytes(b[0..4].try_into().unwrap_or([0; 4]));
    // Bytes 4 to 7: the allowlist profile's number (ADR 0041), 0 the
    // default. An unknown one is EINVAL, as any field out of range.
    let profile =
        keel_core::profile::by_id(u32::from_le_bytes(b[4..8].try_into().unwrap_or([0xff; 4])))
            .ok_or(Errno::EINVAL)?;
    // Bytes 32 to 35: descriptors per process (ADR 0042), 0 for the
    // kernel's own limit; 36 to 39 reserved.
    let handles = u32::from_le_bytes(b[32..36].try_into().unwrap_or([0; 4]));
    if b[36..40] != [0; 4] || processes == 0 {
        return Err(Errno::EINVAL);
    }
    let unlimited_or = |v: u64, f: fn(u64) -> usize| if v == u64::MAX { usize::MAX } else { f(v) };
    Ok(Limits {
        processes,
        memory_frames: unlimited_or(u64_at(8), |v| (v / 4096) as usize),
        tmpfs_bytes: unlimited_or(u64_at(16), |v| v as usize),
        tmpfs_nodes: unlimited_or(u64_at(24), |v| v as usize),
        handles: if handles == 0 {
            usize::MAX
        } else {
            handles as usize
        },
        profile,
    })
}

fn insert(p: &ProcessRef, object: Object, rights: Rights) -> SysResult {
    let fd = p.lock().handles.insert(Handle {
        object,
        rights,
        close_on_exec: false,
    })?;
    Ok(fd as u64)
}

/// The factory behind `fd`, if it has `rights`. EBADF otherwise, as for
/// any handle without the right (SR-1).
fn factory(p: &ProcessRef, fd: i32, rights: Rights) -> Result<Arc<Factory>, Errno> {
    match object(p, fd, rights)? {
        Object::Factory(f) => Ok(f),
        _ => Err(Errno::EBADF),
    }
}

fn compartment(p: &ProcessRef, fd: i32, rights: Rights) -> Result<Arc<Compartment>, Errno> {
    match object(p, fd, rights)? {
        Object::Compartment(c) => Ok(c.compartment.clone()),
        _ => Err(Errno::EBADF),
    }
}

/// Dispatches native call `BASE + n`.
pub fn dispatch(p: &ProcessRef, n: u64, a: &[u64; 6]) -> SysResult {
    let fd = |i: usize| a[i] as u32 as i32;
    match n {
        0 => restrict(p, fd(0), a[1]),
        1 => factory_derive(p, fd(0), a[1]),
        2 => compartment_create(p, fd(0), fd(1), a[2]),
        3 => grant_device(p, fd(0), a[1]),
        4 => spawn(p, fd(0), a[1], a[2], a[3], a[4]),
        5 => kill(p, fd(0), a[1]),
        6 => wait(p, fd(0), a[1], a[2]),
        7 => audit_open(p, fd(0)),
        8 => layer(p, fd(0), fd(1), fd(2)),
        _ => Err(Errno::ENOSYS),
    }
}

/// `restrict(fd, rights)`: a new descriptor for the same object, with the
/// rights it had and `rights` both. Needs DUPLICATE.
fn restrict(p: &ProcessRef, fd: i32, mask: u64) -> SysResult {
    let mask = u32::try_from(mask)
        .ok()
        .and_then(Rights::from_bits)
        .ok_or(Errno::EINVAL)?;
    let new = p.lock().handles.duplicate(fd, mask)?;
    Ok(new as u64)
}

/// `factory_derive(factory, limits*)`: a factory whose ceiling is `limits`,
/// which must fit beneath this one's (EPERM). Needs CREATE.
fn factory_derive(p: &ProcessRef, fd: i32, limits: u64) -> SysResult {
    let parent = factory(p, fd, Rights::CREATE)?;
    let ceiling = read_limits(limits)?;
    if !ceiling.fits_within(&parent.ceiling) {
        return Err(denied(p, "factory_derive", 1));
    }
    insert(
        p,
        Object::Factory(Arc::new(Factory { ceiling })),
        FACTORY_RIGHTS,
    )
}

/// `compartment_create(factory, rootfd, limits*)`: an empty compartment
/// rooted at the directory `rootfd` names. Needs CREATE on the factory
/// and ENUMERATE on `rootfd`.
fn compartment_create(p: &ProcessRef, fd: i32, root: i32, limits: u64) -> SysResult {
    let factory = factory(p, fd, Rights::CREATE)?;
    let limits = read_limits(limits)?;
    if !limits.fits_within(&factory.ceiling) {
        return Err(denied(p, "compartment_create", 2));
    }
    // The type first (ENOTDIR), then the right (EBADF), as `directory`
    // in fscalls checks a directory handle (`iterate_dir`'s order).
    let dir = match object(p, root, Rights::NONE)? {
        Object::File(file) => {
            let f = file.lock();
            if f.kind != Kind::Directory || f.proc.is_some() {
                return Err(Errno::ENOTDIR);
            }
            f.node
        }
        _ => return Err(Errno::ENOTDIR),
    };
    object(p, root, Rights::ENUMERATE)?;
    let compartment = crate::compartment::create_at(dir, limits)?;
    insert(
        p,
        Object::Compartment(Arc::new(CompartmentHandle { compartment })),
        COMPARTMENT_RIGHTS,
    )
}

/// `compartment_grant_device(c, device)`: `/dev/<name>` in the
/// compartment's tree; already that device, nothing changes; something
/// else there, EEXIST. `/dev` must exist (ENOENT); ptmx also makes
/// `/dev/pts` if it is not there. Needs GRANT.
fn grant_device(p: &ProcessRef, fd: i32, code: u64) -> SysResult {
    let c = compartment(p, fd, Rights::GRANT)?;
    let (name, device): (&[u8], Device) = match code {
        1 => (b"null", Device::Null),
        2 => (b"zero", Device::Zero),
        3 => (b"urandom", Device::Urandom),
        4 => (b"tty", Device::Tty),
        5 => (b"ptmx", Device::Ptmx),
        _ => return Err(Errno::EINVAL),
    };
    let root = c.root();
    crate::fs::with(|fs| {
        let dev = fs.lookup(root, root, b"/dev")?;
        if fs.kind(dev)? != Kind::Directory {
            return Err(Errno::ENOTDIR);
        }
        // Granting a device that is already there is no change: a node of
        // that device can only have come from an earlier grant, since a
        // compartment cannot make device nodes (ADR 0035), and the tree
        // outlives the compartment, so an application launched again
        // finds its grants. Anything else under the name is EEXIST.
        match fs.lookup(root, dev, name) {
            Ok(ino) if fs.kind(ino)? == Kind::Device(device) => {}
            Ok(_) => return Err(Errno::EEXIST),
            Err(Errno::ENOENT) => {
                fs.create_device(dev, name, device)?;
            }
            Err(e) => return Err(e),
        }
        if device == Device::Ptmx {
            match fs.create_dir(dev, b"pts", 0o755) {
                Ok(_) | Err(Errno::EEXIST) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })?;
    // SR-11: every grant is in the audit log (ADR 0045).
    crate::audit::record(keel_core::audit::Event::Granted {
        compartment: c.id(),
        by: crate::audit::actor(Some(p)),
        device: core::str::from_utf8(name).unwrap_or("?"),
    });
    Ok(0)
}

/// A native call above its factory's ceiling: EPERM, and a denial in the
/// audit log for the caller's compartment (ADR 0045).
fn denied(p: &ProcessRef, what: &'static str, n: u64) -> Errno {
    let (compartment, pid) = {
        let process = p.lock();
        (process.member.compartment().clone(), process.pid())
    };
    crate::audit::denied(&compartment, pid, what, BASE + n, None, Errno::EPERM);
    Errno::EPERM
}

/// A directory handle's node, needing `rights` (ENOTDIR for anything but
/// a directory, checked first, as `compartment_create` does).
fn directory_node(p: &ProcessRef, fd: i32, rights: Rights) -> Result<keel_core::vfs::Ino, Errno> {
    let node = match object(p, fd, Rights::NONE)? {
        Object::File(file) => {
            let f = file.lock();
            if f.kind != Kind::Directory || f.proc.is_some() {
                return Err(Errno::ENOTDIR);
            }
            f.node
        }
        _ => return Err(Errno::ENOTDIR),
    };
    object(p, fd, rights)?;
    Ok(node)
}

/// `layer(factory, into, from)` (ADR 0046): makes the tree under
/// directory `from` a read-only image for good (EBUSY if a node in it is
/// open or mapped), then lays it over directory `into`: `into` gets its
/// own copies of the image's directories, and names the image's other
/// nodes until a compartment rooted there changes one, which gets its own
/// copy then. Names `into` has are replaced, so a template prefix laid
/// after a base overrides it. Needs CREATE on the factory, ENUMERATE on
/// `from`, and CREATE on `into`, which must not be part of an image
/// (EROFS). The private directories and copies are charged to the
/// caller's compartment.
fn layer(p: &ProcessRef, factory_fd: i32, into: i32, from: i32) -> SysResult {
    factory(p, factory_fd, Rights::CREATE)?;
    let into = directory_node(p, into, Rights::CREATE)?;
    let from = directory_node(p, from, Rights::ENUMERATE)?;
    if into == from {
        return Err(Errno::EINVAL);
    }
    let quota = crate::syscall::quota_of(p);
    crate::fs::with(|fs| {
        if fs.is_frozen(into)? {
            return Err(Errno::EROFS);
        }
        // An image that would hold the tree it is laid over could never
        // be frozen safely: `into` beneath `from` is EINVAL.
        if fs.is_beneath(from, into) {
            return Err(Errno::EINVAL);
        }
        fs.freeze(from)?;
        fs.layer(into, from, quota.as_ref())
    })?;
    Ok(0)
}

/// `audit_open(factory)`: an audit handle (ADR 0045), read with read(2),
/// from the oldest record the log keeps. Needs AUDIT, which only the root
/// factory has.
fn audit_open(p: &ProcessRef, fd: i32) -> SysResult {
    factory(p, fd, Rights::AUDIT)?;
    insert(
        p,
        Object::Audit(Arc::new(crate::audit::AuditReader::new())),
        Rights::READ.union(Rights::STAT).union(Rights::DUPLICATE),
    )
}

/// `compartment_spawn(c, path*, argv**, envp**, stdio*)`: the program at
/// `path`, looked up beneath the compartment's root, as a new process in
/// it. Its fds 0 to 2 are the caller's `stdio[0..3]` (each needing
/// DUPLICATE; -1 leaves one closed), and it has nothing else. A factory
/// or compartment handle is EPERM. Returns its PID. Needs CREATE.
fn spawn(p: &ProcessRef, fd: i32, path: u64, argv: u64, envp: u64, stdio: u64) -> SysResult {
    let c = compartment(p, fd, Rights::CREATE)?;
    let path = user_path(path)?;
    let mut budget = crate::exec::ARG_LIMIT;
    let args = crate::syscall::user_strings(argv, &mut budget)?;
    let env = crate::syscall::user_strings(envp, &mut budget)?;
    let mut fds = [0u8; 12];
    copy_from_user(&mut fds, stdio).map_err(fault)?;
    let mut handles = HandleTable::new(process::HANDLE_LIMIT);
    for i in 0..3 {
        let given = i32::from_le_bytes(fds[i * 4..i * 4 + 4].try_into().unwrap_or([0; 4]));
        if given == -1 {
            continue;
        }
        let (object, rights) = {
            let process = p.lock();
            let rights = process.handles.rights(given)?;
            (
                process.handles.get(given, Rights::DUPLICATE)?.clone(),
                rights,
            )
        };
        if matches!(
            object,
            Object::Factory(_) | Object::Compartment(_) | Object::Audit(_)
        ) {
            return Err(Errno::EPERM);
        }
        handles.place(
            i as i32,
            Handle {
                object,
                rights,
                close_on_exec: false,
            },
        )?;
    }
    let root = c.root();
    let file = crate::fs::with(|fs| {
        let ino = fs.lookup(root, root, &path)?;
        if fs.kind(ino)? != Kind::File {
            return Err(Errno::EACCES);
        }
        fs.contents(ino)
    })?;
    let mut argv: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    if argv.is_empty() {
        argv.push(b"");
    }
    let envp: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
    let loaded = crate::exec::load_in(root, &file, &path, &argv, &envp).map_err(|e| e.errno())?;
    let spawned = process::spawn_in_handles(&c, "compartment", &loaded, handles)?;
    Ok(u64::from(spawned.pid))
}

/// `compartment_kill(c, signal)`: `signal` to every process in the
/// compartment (signal 0 only checks the handle). Needs SIGNAL.
fn kill(p: &ProcessRef, fd: i32, signal: u64) -> SysResult {
    use keel_core::signal::{NSIG, SigInfo};
    let c = compartment(p, fd, Rights::SIGNAL)?;
    let signal = i32::try_from(signal).map_err(|_| Errno::EINVAL)?;
    if !(0..=NSIG as i32).contains(&signal) {
        return Err(Errno::EINVAL);
    }
    if signal != 0 {
        for target in process::members(&c, |_| true) {
            crate::signal::send_to_process(&target, SigInfo::kernel(signal));
        }
    }
    Ok(0)
}

/// `compartment_wait(c, usage*, flags)`: fills `usage` (40 bytes:
/// processes u32, PID 1's wait status i32 or -1, memory bytes, tmpfs bytes
/// and nodes u64 each, 8 reserved bytes written 0). Without WNOHANG (1)
/// it first waits until no process is left (WAIT); with it, needs STAT. A
/// signal ends the wait (ERESTARTSYS). Other flags are EINVAL.
fn wait(p: &ProcessRef, fd: i32, usage: u64, flags: u64) -> SysResult {
    const WNOHANG: u64 = 1;
    if flags & !WNOHANG != 0 {
        return Err(Errno::EINVAL);
    }
    let block = flags & WNOHANG == 0;
    let c = compartment(p, fd, if block { Rights::WAIT } else { Rights::STAT })?;
    if block && !process::wait_until_empty(&c) {
        return Err(Errno::ERESTARTSYS);
    }
    let mut b = [0u8; 40];
    b[0..4].copy_from_slice(&c.processes().to_le_bytes());
    b[4..8].copy_from_slice(&c.lead_status().unwrap_or(-1).to_le_bytes());
    b[8..16].copy_from_slice(&((c.memory().used() as u64) * 4096).to_le_bytes());
    let (bytes, nodes) = c
        .tmpfs()
        .map_or((0, 0), |q| (q.bytes.used() as u64, q.nodes.used() as u64));
    b[16..24].copy_from_slice(&bytes.to_le_bytes());
    b[24..32].copy_from_slice(&nodes.to_le_bytes());
    copy_to_user(usage, &b).map_err(fault)?;
    Ok(0)
}
