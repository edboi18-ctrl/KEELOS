//! The Linux x86-64 system calls (P1-T13), on handles with rights (P1-S1).
//!
//! Each handler states the right it needs from the handle (`get(fd, R)`).
//! Unknown calls, flags and requests fail closed (SR-10). User memory is
//! touched only through `keel_hal::vm::copy_to_user`/`copy_from_user`
//! (SR-13); every user-supplied length is checked and capped (SR-19). No
//! lock is held while user memory is copied, so a page fault during the
//! copy cannot deadlock.

use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use keel_core::errno::Errno;
use keel_core::handle::{Handle, Rights};
use keel_core::vfs::{Device, Kind, PATH_MAX};
use keel_core::vm::{PAGE, Placement, Prot, USER_END, VmError};
use keel_hal::sched::{self, SegmentBase};
use keel_hal::sync::IrqMutex;
use keel_hal::syscall::SyscallArgs;
use keel_hal::vm::{AsError, copy_from_user, copy_to_user};
use keel_hal::{console, kprintln, random, time};

use crate::abi::*;
use crate::fs;
use crate::names;
use crate::process::{self, Object, OpenFile, Process, file_rights};

/// Linux x86-64 numbers (`arch/x86/entry/syscalls/syscall_64.tbl`, v6.12).
pub mod nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const CLOSE: u64 = 3;
    pub const FSTAT: u64 = 5;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
    pub const BRK: u64 = 12;
    pub const IOCTL: u64 = 16;
    pub const WRITEV: u64 = 20;
    pub const EXIT: u64 = 60;
    pub const ARCH_PRCTL: u64 = 158;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const EXIT_GROUP: u64 = 231;
    pub const OPENAT: u64 = 257;
    pub const GETRANDOM: u64 = 318;
    /// Keel self-test call outside the Linux range: returns `rdi + 1`.
    /// Removed before Phase 1 acceptance.
    pub const KEEL_TEST_ADD_ONE: u64 = 0x1000;
}

/// Size of the kernel buffer user data passes through.
const CHUNK: usize = 4096;

type SysResult = Result<u64, Errno>;

/// Registers the handler and the exit hook. Call once at boot.
pub fn init() {
    keel_hal::syscall::set_handler(handle);
    sched::set_exit_hook(process::on_thread_exit);
}

static LOGGED: IrqMutex<BTreeSet<u64>> = IrqMutex::new(BTreeSet::new());

/// The system-call entry point.
pub fn handle(call: &SyscallArgs) -> i64 {
    let a = call.args;
    // `int` arguments use the low 32 bits only, as on Linux.
    let fd = a[0] as u32 as i32;
    let result: SysResult = match call.number {
        nr::EXIT | nr::EXIT_GROUP => sched::exit_with((a[0] & 0xff) as i64),
        nr::KEEL_TEST_ADD_ONE => Ok(a[0].wrapping_add(1)),
        _ => match process::current() {
            Some(p) => match call.number {
                nr::READ => read(&p, fd, a[1], a[2]),
                nr::WRITE => write(&p, fd, a[1], a[2]),
                nr::WRITEV => writev(&p, fd, a[1], a[2]),
                nr::CLOSE => close(&p, fd),
                nr::FSTAT => fstat(&p, fd, a[1]),
                nr::OPENAT => openat(&p, fd, a[1], a[2], a[3]),
                nr::MMAP => mmap(&p, a[0], a[1], a[2], a[3], a[4] as u32 as i32, a[5]),
                nr::MUNMAP => munmap(&p, a[0], a[1]),
                nr::MPROTECT => mprotect(&p, a[0], a[1], a[2]),
                nr::BRK => Ok(brk(&p, a[0])),
                nr::IOCTL => ioctl(&p, fd, a[1] as u32, a[2]),
                nr::ARCH_PRCTL => arch_prctl(a[0], a[1]),
                nr::SET_TID_ADDRESS => Ok(set_tid_address(&p, a[0])),
                nr::CLOCK_GETTIME => clock_gettime(a[0] as u32 as u64, a[1]),
                nr::GETRANDOM => getrandom(a[0], a[1], a[2] as u32 as u64),
                number => unimplemented(number, &a),
            },
            // Threads without a process (kernel self-test programs) get
            // only exit and the test call.
            None => unimplemented(call.number, &a),
        },
    };
    match result {
        Ok(value) => value as i64,
        Err(errno) => errno.to_return(),
    }
}

fn unimplemented(number: u64, a: &[u64; 6]) -> SysResult {
    if LOGGED.lock().insert(number) {
        kprintln!(
            "syscall: {} ({number}) not implemented; args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} -> ENOSYS",
            names::name(number).unwrap_or("unknown"),
            a[0],
            a[1],
            a[2],
            a[3],
            a[4],
            a[5]
        );
    }
    Err(Errno::ENOSYS)
}

fn fault<T>(_: T) -> Errno {
    Errno::EFAULT
}

fn vm_error(error: AsError) -> Errno {
    match error {
        AsError::Vm(VmError::Invalid) => Errno::EINVAL,
        AsError::Vm(VmError::NoMemory) | AsError::OutOfMemory => Errno::ENOMEM,
        AsError::Vm(VmError::Exists) => Errno::EEXIST,
        AsError::Vm(VmError::WriteExec) => Errno::EACCES,
    }
}

/// The open file behind `fd`, if the handle has `required`.
fn file(
    p: &Arc<IrqMutex<Process>>,
    fd: i32,
    required: Rights,
) -> Result<Arc<IrqMutex<OpenFile>>, Errno> {
    match p.lock().handles.get(fd, required)? {
        Object::File(file) => Ok(file.clone()),
    }
}

/// Copies a NUL-terminated path from user memory, one page at a time so a
/// string ending just before an unmapped page is still read.
fn user_path(address: u64) -> Result<Vec<u8>, Errno> {
    let mut path = Vec::new();
    let mut at = address;
    loop {
        let room = (PAGE - at % PAGE) as usize;
        let take = room.min(PATH_MAX - path.len());
        let mut buf = [0u8; PAGE as usize];
        copy_from_user(&mut buf[..take], at).map_err(fault)?;
        if let Some(end) = buf[..take].iter().position(|&b| b == 0) {
            path.extend_from_slice(&buf[..end]);
            return Ok(path);
        }
        path.extend_from_slice(&buf[..take]);
        if path.len() >= PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        at = at.checked_add(take as u64).ok_or(Errno::EFAULT)?;
    }
}

fn read(p: &Arc<IrqMutex<Process>>, fd: i32, buf: u64, count: u64) -> SysResult {
    let file = file(p, fd, Rights::READ)?;
    let count = count.min(MAX_RW_COUNT) as usize;
    let mut chunk = vec![0u8; CHUNK.min(count)];
    let mut done = 0usize;
    while done < count {
        let want = (count - done).min(CHUNK);
        let n = {
            let mut f = file.lock();
            let n = match f.kind {
                Kind::File => fs::with(|fs| fs.read(f.node, f.offset, &mut chunk[..want]))?,
                Kind::Directory => return Err(Errno::EISDIR),
                Kind::Device(device) => fs::device_read(device, &mut chunk[..want]),
            };
            if f.kind == Kind::File {
                f.offset += n as u64;
            }
            n
        };
        if n == 0 {
            break;
        }
        if copy_to_user(buf + done as u64, &chunk[..n]).is_err() {
            return if done == 0 {
                Err(Errno::EFAULT)
            } else {
                Ok(done as u64)
            };
        }
        done += n;
        if n < want {
            break;
        }
    }
    Ok(done as u64)
}

/// Writes `count` bytes from user memory at `buf` to an open file.
fn write_to(file: &Arc<IrqMutex<OpenFile>>, buf: u64, count: u64) -> SysResult {
    let count = count.min(MAX_RW_COUNT) as usize;
    let mut chunk = vec![0u8; CHUNK.min(count)];
    let mut done = 0usize;
    while done < count {
        let want = (count - done).min(CHUNK);
        if copy_from_user(&mut chunk[..want], buf + done as u64).is_err() {
            return if done == 0 {
                Err(Errno::EFAULT)
            } else {
                Ok(done as u64)
            };
        }
        let written = {
            let mut f = file.lock();
            match f.kind {
                Kind::File => {
                    let (node, append, offset) = (f.node, f.append, f.offset);
                    let result = fs::with(|fs| {
                        let at = if append { fs.stat(node)?.size } else { offset };
                        let n = fs.write(node, at, &chunk[..want])?;
                        Ok((n, at + n as u64))
                    });
                    match result {
                        Ok((n, end)) => {
                            f.offset = end;
                            n
                        }
                        // ENOSPC and the like: report what was written.
                        Err(error) if done == 0 => return Err(error),
                        Err(_) => break,
                    }
                }
                Kind::Directory => return Err(Errno::EISDIR),
                Kind::Device(device) => fs::device_write(device, &chunk[..want]),
            }
        };
        done += written;
        if written < want {
            break;
        }
    }
    Ok(done as u64)
}

fn write(p: &Arc<IrqMutex<Process>>, fd: i32, buf: u64, count: u64) -> SysResult {
    let file = file(p, fd, Rights::WRITE)?;
    write_to(&file, buf, count)
}

fn writev(p: &Arc<IrqMutex<Process>>, fd: i32, iov: u64, count: u64) -> SysResult {
    let file = file(p, fd, Rights::WRITE)?;
    if count > UIO_MAXIOV {
        return Err(Errno::EINVAL);
    }
    let mut raw = vec![0u8; count as usize * 16];
    copy_from_user(&mut raw, iov).map_err(fault)?;
    // struct iovec: base pointer, then length (both 64-bit).
    let vectors: Vec<(u64, u64)> = raw
        .as_chunks::<16>()
        .0
        .iter()
        .map(|v| {
            let (base, len) = v.split_at(8);
            let word = |b: &[u8]| u64::from_le_bytes(b.try_into().unwrap_or_default());
            (word(base), word(len))
        })
        .collect();
    // A length that is negative as ssize_t, or a total that overflows it,
    // is EINVAL (writev(2)).
    let mut total = 0u64;
    for &(_, len) in &vectors {
        total = total
            .checked_add(len)
            .filter(|&t| t <= i64::MAX as u64)
            .ok_or(Errno::EINVAL)?;
    }
    let mut done = 0u64;
    for (base, len) in vectors {
        let len = len.min(MAX_RW_COUNT - done);
        match write_to(&file, base, len) {
            Ok(n) => {
                done += n;
                if n < len {
                    break;
                }
            }
            Err(error) if done == 0 => return Err(error),
            Err(_) => break,
        }
        if done >= MAX_RW_COUNT {
            break;
        }
    }
    Ok(done)
}

fn close(p: &Arc<IrqMutex<Process>>, fd: i32) -> SysResult {
    // Closing needs no right: the handle is the caller's own.
    p.lock().handles.close(fd).map(|_| 0)
}

fn fstat(p: &Arc<IrqMutex<Process>>, fd: i32, buf: u64) -> SysResult {
    let node = file(p, fd, Rights::STAT)?.lock().node;
    let stat = fs::with(|fs| fs.stat(node))?;
    copy_to_user(buf, &stat_bytes(&stat)).map_err(fault)?;
    Ok(0)
}

fn openat(p: &Arc<IrqMutex<Process>>, dirfd: i32, path: u64, flags: u64, mode: u64) -> SysResult {
    if flags & !O_KNOWN != 0 || flags & O_ACCMODE == O_ACCMODE {
        return Err(Errno::EINVAL);
    }
    let path = user_path(path)?;
    let (root, cwd) = {
        let process = p.lock();
        (process.root, process.cwd)
    };
    let base = if dirfd == AT_FDCWD || path.first() == Some(&b'/') {
        cwd
    } else {
        // Lookup relative to a directory handle needs ENUMERATE on it.
        let dir = file(p, dirfd, Rights::ENUMERATE)?;
        let dir = dir.lock();
        if dir.kind != Kind::Directory {
            return Err(Errno::ENOTDIR);
        }
        dir.node
    };
    let access = flags & O_ACCMODE;
    let (read, write) = (access != O_WRONLY, access != O_RDONLY);
    let node = fs::with(|fs| {
        let node = match fs.lookup(root, base, &path) {
            Ok(_) if flags & O_CREAT != 0 && flags & O_EXCL != 0 => return Err(Errno::EEXIST),
            Ok(node) => node,
            Err(Errno::ENOENT) if flags & O_CREAT != 0 => {
                let (dir, name) = fs.lookup_parent(root, base, &path)?;
                // umask 022 until umask(2) exists.
                fs.create_file(dir, name, (mode as u32) & 0o7777 & !0o022)?
            }
            Err(error) => return Err(error),
        };
        let kind = fs.kind(node)?;
        if kind == Kind::Directory && (write || flags & O_CREAT != 0) {
            return Err(Errno::EISDIR);
        }
        if kind != Kind::Directory && flags & O_DIRECTORY != 0 {
            return Err(Errno::ENOTDIR);
        }
        if kind == Kind::File && write && flags & O_TRUNC != 0 {
            fs.set_len(node, 0)?;
        }
        Ok((node, kind))
    })?;
    let (node, kind) = node;
    let open = OpenFile {
        node,
        kind,
        offset: 0,
        append: flags & O_APPEND != 0,
    };
    let handle = Handle {
        object: Object::File(Arc::new(IrqMutex::new(open))),
        rights: file_rights(read, write, kind),
        close_on_exec: flags & O_CLOEXEC != 0,
    };
    let fd = p.lock().handles.insert(handle)?;
    Ok(fd as u64)
}

fn prot(bits: u64) -> Result<Prot, Errno> {
    if bits & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    Ok(Prot {
        read: bits & PROT_READ != 0,
        write: bits & PROT_WRITE != 0,
        exec: bits & PROT_EXEC != 0,
    })
}

/// Rounds a user length up to whole pages; 0 and overflow are errors.
fn page_length(length: u64) -> Result<u64, Errno> {
    if length == 0 {
        return Err(Errno::EINVAL);
    }
    length
        .checked_next_multiple_of(PAGE)
        .filter(|&l| l <= USER_END)
        .ok_or(Errno::ENOMEM)
}

fn mmap(
    p: &Arc<IrqMutex<Process>>,
    address: u64,
    length: u64,
    protection: u64,
    flags: u64,
    fd: i32,
    offset: u64,
) -> SysResult {
    if flags & !MAP_KNOWN != 0 || !offset.is_multiple_of(PAGE) {
        return Err(Errno::EINVAL);
    }
    let prot = prot(protection)?;
    let length = page_length(length)?;
    if flags & MAP_TYPE != MAP_PRIVATE {
        // Shared mappings arrive with fork and file mappings (Phase 3).
        return Err(Errno::EINVAL);
    }
    if flags & MAP_ANONYMOUS == 0 {
        // File mappings arrive with P3-T7; check the handle first so a bad
        // descriptor still reports EBADF, then refuse.
        let needs = if prot.exec {
            Rights::READ | Rights::MAP_EXEC
        } else {
            Rights::READ
        };
        file(p, fd, needs)?;
        return Err(Errno::ENODEV);
    }
    let placement = if flags & MAP_FIXED_NOREPLACE != 0 {
        Placement::FixedNoReplace(address)
    } else if flags & MAP_FIXED != 0 {
        Placement::Fixed(address)
    } else {
        Placement::Anywhere {
            hint: address & !(PAGE - 1),
        }
    };
    let space = p.lock().space.clone();
    space.map(placement, length, prot).map_err(vm_error)
}

fn munmap(p: &Arc<IrqMutex<Process>>, address: u64, length: u64) -> SysResult {
    if !address.is_multiple_of(PAGE) {
        return Err(Errno::EINVAL);
    }
    let length = page_length(length).map_err(|_| Errno::EINVAL)?;
    let space = p.lock().space.clone();
    space.unmap(address, length).map_err(vm_error).map(|_| 0)
}

fn mprotect(p: &Arc<IrqMutex<Process>>, address: u64, length: u64, protection: u64) -> SysResult {
    let prot = prot(protection)?;
    if !address.is_multiple_of(PAGE) {
        return Err(Errno::EINVAL);
    }
    if length == 0 {
        return Ok(0);
    }
    let length = page_length(length)?;
    let space = p.lock().space.clone();
    space
        .protect(address, length, prot)
        .map_err(vm_error)
        .map(|_| 0)
}

/// brk(2): returns the new break, or the old one if the request cannot be
/// met (the Linux system call never returns an error).
fn brk(p: &Arc<IrqMutex<Process>>, requested: u64) -> u64 {
    let (space, start, current) = {
        let process = p.lock();
        (process.space.clone(), process.brk_start, process.brk)
    };
    if requested < start || requested >= USER_END {
        return current;
    }
    let old_end = current.next_multiple_of(PAGE);
    let new_end = requested.next_multiple_of(PAGE);
    let ok = if new_end > old_end {
        // Never over another mapping.
        space
            .map(
                Placement::FixedNoReplace(old_end),
                new_end - old_end,
                Prot::READ_WRITE,
            )
            .is_ok()
    } else if new_end < old_end {
        space.unmap(new_end, old_end - new_end).is_ok()
    } else {
        true
    };
    if !ok {
        return current;
    }
    p.lock().brk = requested;
    requested
}

fn ioctl(p: &Arc<IrqMutex<Process>>, fd: i32, request: u32, argument: u64) -> SysResult {
    let file = file(p, fd, Rights::STAT)?;
    if file.lock().kind != Kind::Device(Device::Console) {
        return Err(Errno::ENOTTY);
    }
    match request {
        TCGETS => copy_to_user(argument, &std_termios_bytes()).map_err(fault)?,
        TIOCGWINSZ => {
            let (cols, rows) = console::framebuffer_size_chars().unwrap_or((80, 25));
            let rows = u16::try_from(rows).unwrap_or(u16::MAX);
            let cols = u16::try_from(cols).unwrap_or(u16::MAX);
            copy_to_user(argument, &winsize_bytes(rows, cols)).map_err(fault)?
        }
        // Terminal control (TCSETS, TIOCSPGRP, ...) arrives with the TTY
        // layer; anything else is not a terminal request (SR-10).
        _ => return Err(Errno::ENOTTY),
    }
    Ok(0)
}

fn arch_prctl(code: u64, address: u64) -> SysResult {
    let which = match code {
        ARCH_SET_FS | ARCH_GET_FS => SegmentBase::Fs,
        ARCH_SET_GS | ARCH_GET_GS => SegmentBase::Gs,
        _ => return Err(Errno::EINVAL),
    };
    if code == ARCH_SET_FS || code == ARCH_SET_GS {
        // Only user addresses (Linux: EPERM at or above TASK_SIZE_MAX).
        sched::set_user_base(which, address).map_err(|_| Errno::EPERM)?;
    } else {
        copy_to_user(address, &sched::user_base(which).to_le_bytes()).map_err(fault)?;
    }
    Ok(0)
}

fn set_tid_address(p: &Arc<IrqMutex<Process>>, address: u64) -> u64 {
    let mut process = p.lock();
    process.clear_child_tid = address;
    // One thread per process: its TID is the PID.
    u64::from(process.pid)
}

fn clock_gettime(clock: u64, buf: u64) -> SysResult {
    let nanos = match clock {
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            time::monotonic_nanos()
        }
        // No real-time clock yet: the realtime clocks count from the
        // epoch as if the machine booted at 1970-01-01 (documented in
        // docs/syscalls.md until the RTC is read).
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => time::monotonic_nanos(),
        _ => return Err(Errno::EINVAL),
    };
    copy_to_user(buf, &timespec_bytes(nanos)).map_err(fault)?;
    Ok(0)
}

fn getrandom(buf: u64, count: u64, flags: u64) -> SysResult {
    if flags & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0
        || flags & (GRND_RANDOM | GRND_INSECURE) == (GRND_RANDOM | GRND_INSECURE)
    {
        return Err(Errno::EINVAL);
    }
    let count = count.min(MAX_RW_COUNT) as usize;
    let mut chunk = [0u8; 256];
    let mut done = 0usize;
    while done < count {
        let n = (count - done).min(chunk.len());
        random::fill(&mut chunk[..n]);
        if copy_to_user(buf + done as u64, &chunk[..n]).is_err() {
            return if done == 0 {
                Err(Errno::EFAULT)
            } else {
                Ok(done as u64)
            };
        }
        done += n;
    }
    Ok(done as u64)
}
