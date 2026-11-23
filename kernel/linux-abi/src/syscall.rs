//! The Linux x86-64 system calls (P1-T13), on handles with rights (P1-S1).
//!
//! Each handler states the right it needs from the handle (`get(fd, R)`).
//! Unknown calls, flags and requests fail closed (SR-10). User memory is
//! touched only through `keel_hal::vm::copy_to_user`/`copy_from_user`
//! (SR-13); every user-supplied length is checked and capped (SR-19). No
//! lock is held while user memory is copied, so a page fault during the
//! copy cannot deadlock.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use keel_core::errno::Errno;

use keel_core::handle::{Handle, Refusal, Rights};
use keel_core::vfs::{Device, Kind, PATH_MAX};
use keel_core::vm::{Backing, PAGE, Placement, Prot, USER_END, VmError};
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
    pub const OPEN: u64 = 2;
    pub const CLOSE: u64 = 3;
    pub const FSTAT: u64 = 5;
    pub const POLL: u64 = 7;
    pub const MMAP: u64 = 9;
    pub const MPROTECT: u64 = 10;
    pub const MUNMAP: u64 = 11;
    pub const BRK: u64 = 12;
    pub const RT_SIGACTION: u64 = 13;
    pub const RT_SIGPROCMASK: u64 = 14;
    pub const IOCTL: u64 = 16;
    pub const PREAD64: u64 = 17;
    pub const WRITEV: u64 = 20;
    pub const GETPID: u64 = 39;
    pub const EXECVE: u64 = 59;
    pub const EXIT: u64 = 60;
    pub const FCNTL: u64 = 72;
    pub const SIGALTSTACK: u64 = 131;
    pub const ARCH_PRCTL: u64 = 158;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const EXIT_GROUP: u64 = 231;
    pub const OPENAT: u64 = 257;
    pub const GETRANDOM: u64 = 318;
}

/// Size of the kernel buffer user data passes through.
const CHUNK: usize = 4096;

type SysResult = Result<u64, Errno>;

/// Registers the handler and the exit hook. Call once at boot.
pub fn init() {
    keel_hal::syscall::set_handler(handle);
    keel_hal::vm::set_file_reader(read_mapped_page);
    sched::set_exit_hook(process::on_thread_exit);
}

/// Which unimplemented numbers below TABLE_SIZE have been logged: a fixed
/// bitmap, so no sequence of calls can make it grow. Numbers at or above
/// TABLE_SIZE are logged once in all (F-0005: one entry per distinct
/// 64-bit number let a program grow kernel memory and flood the serial
/// line without limit).
static LOGGED: IrqMutex<([u64; TABLE_SIZE as usize / 64], bool)> =
    IrqMutex::new(([0; TABLE_SIZE as usize / 64], false));

type ProcessRef = Arc<IrqMutex<Process>>;
/// A table entry: the process and the six raw arguments.
type Handler = fn(&ProcessRef, &[u64; 6]) -> SysResult;

/// Size of the system-call table: every Linux x86-64 number below the
/// x32 range (512).
const TABLE_SIZE: u64 = 512;

/// The system calls, indexed by number, as Linux's `sys_call_table`.
/// `int` arguments use their low 32 bits, as on Linux.
static TABLE: [Option<Handler>; TABLE_SIZE as usize] = {
    let mut t: [Option<Handler>; TABLE_SIZE as usize] = [None; TABLE_SIZE as usize];
    t[nr::READ as usize] = Some(|p, a| read(p, a[0] as u32 as i32, a[1], a[2]));
    t[nr::WRITE as usize] = Some(|p, a| write(p, a[0] as u32 as i32, a[1], a[2]));
    t[nr::WRITEV as usize] = Some(|p, a| writev(p, a[0] as u32 as i32, a[1], a[2]));
    t[nr::CLOSE as usize] = Some(|p, a| close(p, a[0] as u32 as i32));
    t[nr::FSTAT as usize] = Some(|p, a| fstat(p, a[0] as u32 as i32, a[1]));
    t[nr::POLL as usize] = Some(|p, a| poll(p, a[0], a[1] as u32, a[2] as u32 as i32));
    t[nr::OPENAT as usize] = Some(|p, a| openat(p, a[0] as u32 as i32, a[1], a[2], a[3]));
    // open(2) is openat(AT_FDCWD, ...), as Linux's sys_open (`fs/open.c`),
    // which also sets O_LARGEFILE on 64-bit (no effect here).
    t[nr::OPEN as usize] = Some(|p, a| openat(p, AT_FDCWD, a[0], a[1] | O_LARGEFILE, a[2]));
    t[nr::PREAD64 as usize] = Some(|p, a| pread64(p, a[0] as u32 as i32, a[1], a[2], a[3]));
    t[nr::FCNTL as usize] = Some(|p, a| fcntl(p, a[0] as u32 as i32, a[1] as u32, a[2]));
    t[nr::EXECVE as usize] = Some(|p, a| execve(p, a[0], a[1], a[2]));
    t[nr::MMAP as usize] = Some(|p, a| mmap(p, a[0], a[1], a[2], a[3], a[4] as u32 as i32, a[5]));
    t[nr::MUNMAP as usize] = Some(|p, a| munmap(p, a[0], a[1]));
    t[nr::MPROTECT as usize] = Some(|p, a| mprotect(p, a[0], a[1], a[2]));
    t[nr::BRK as usize] = Some(|p, a| Ok(brk(p, a[0])));
    t[nr::RT_SIGACTION as usize] =
        Some(|p, a| rt_sigaction(p, a[0] as u32 as i32, a[1], a[2], a[3]));
    t[nr::RT_SIGPROCMASK as usize] =
        Some(|p, a| rt_sigprocmask(p, a[0] as u32 as i32, a[1], a[2], a[3]));
    t[nr::IOCTL as usize] = Some(|p, a| ioctl(p, a[0] as u32 as i32, a[1] as u32, a[2]));
    t[nr::ARCH_PRCTL as usize] = Some(|_, a| arch_prctl(a[0], a[1]));
    t[nr::SET_TID_ADDRESS as usize] = Some(|p, a| Ok(set_tid_address(p, a[0])));
    t[nr::GETPID as usize] = Some(|p, _| Ok(u64::from(p.lock().pid())));
    t[nr::CLOCK_GETTIME as usize] = Some(|_, a| clock_gettime(a[0] as u32 as u64, a[1]));
    t[nr::GETRANDOM as usize] = Some(|_, a| getrandom(a[0], a[1], a[2] as u32 as u64));
    t
};

/// System calls made since boot (the fuzzer reports it).
static CALLS: AtomicU64 = AtomicU64::new(0);

pub fn count() -> u64 {
    CALLS.load(Ordering::Relaxed)
}

/// When on (the fuzzer turns it on), calls that take over a second are
/// logged with their arguments, the first `SLOW_LOG_MAX` of them.
static SLOW_LOG: AtomicBool = AtomicBool::new(false);
static SLOW_LOGGED: AtomicU64 = AtomicU64::new(0);
const SLOW_LOG_MAX: u64 = 20;
const SLOW_NS: u64 = 1_000_000_000;

/// Lines the unimplemented-call log has printed (F-0005's regression
/// test checks it stays bounded).
static UNIMPLEMENTED_LINES: AtomicU64 = AtomicU64::new(0);

pub fn unimplemented_lines() -> u64 {
    UNIMPLEMENTED_LINES.load(Ordering::Relaxed)
}

pub fn set_slow_log(on: bool) {
    SLOW_LOG.store(on, Ordering::Relaxed);
}

/// The system-call entry point.
pub fn handle(call: &SyscallArgs) -> i64 {
    CALLS.fetch_add(1, Ordering::Relaxed);
    if !SLOW_LOG.load(Ordering::Relaxed) {
        return dispatch(call);
    }
    let start = time::monotonic_nanos();
    let result = dispatch(call);
    let took = time::monotonic_nanos() - start;
    if took > SLOW_NS && SLOW_LOGGED.fetch_add(1, Ordering::Relaxed) < SLOW_LOG_MAX {
        let a = call.args;
        kprintln!(
            "syscall: slow: {} ({}) took {} ms; args {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} -> {result:#x}",
            names::name(call.number).unwrap_or("unknown"),
            call.number,
            took / 1_000_000,
            a[0],
            a[1],
            a[2],
            a[3],
            a[4],
            a[5]
        );
    }
    result
}

/// System calls refused with ENOMEM because only the kernel's reserve
/// was free.
static RESERVE_REFUSALS: AtomicU64 = AtomicU64::new(0);

/// How many system calls have been refused to protect the kernel's
/// reserve (for tests).
pub fn reserve_refusals() -> u64 {
    RESERVE_REFUSALS.load(Ordering::Relaxed)
}

/// Whether a call may run when only the kernel's frame reserve is free.
/// Almost every call can make the kernel allocate on the caller's behalf
/// (a mapping, a node, a buffer, a handle), and the kernel's own
/// allocations cannot fail gracefully, so a call that could take the last
/// frames is refused first with ENOMEM (F-0011; `memory::user_reserve`,
/// which already does this for user page faults). Exempt: `close` and
/// `munmap` free memory, so a program can recover; `brk` never returns an
/// error (it reports the old break), and its mapping is checked by the
/// same cap as any other. `getpid` allocates nothing and getpid(2) says it
/// is "always successful".
fn may_run_on_reserve(number: u64) -> bool {
    matches!(number, nr::CLOSE | nr::MUNMAP | nr::BRK | nr::GETPID)
}

fn dispatch(call: &SyscallArgs) -> i64 {
    let a = call.args;
    let number = call.number;
    let result: SysResult = match number {
        nr::EXIT | nr::EXIT_GROUP => sched::exit_with((a[0] & 0xff) as i64),
        // Outside the table: it also needs the caller's stack pointer.
        nr::SIGALTSTACK => match process::current() {
            Some(p) => sigaltstack(&p, a[0], a[1], call.user_rsp),
            None => unimplemented(number, &a),
        },
        _ if number < TABLE_SIZE => {
            // Spectre v1: the number is user-controlled; clamp it without
            // a branch before indexing (Linux does the same with
            // array_index_nospec in do_syscall_64).
            let index = keel_hal::arch::x86_64::cpu::index_nospec(number, TABLE_SIZE) as usize;
            match (TABLE[index], process::current()) {
                (Some(_), Some(_))
                    if !may_run_on_reserve(number)
                        && keel_hal::memory::free_frames() <= keel_hal::memory::user_reserve() =>
                {
                    RESERVE_REFUSALS.fetch_add(1, Ordering::Relaxed);
                    Err(Errno::ENOMEM)
                }
                (Some(handler), Some(p)) => handler(&p, &a),
                // Threads without a process (kernel self-test programs) get
                // only exit; everything else is ENOSYS.
                _ => unimplemented(number, &a),
            }
        }
        _ => unimplemented(number, &a),
    };
    match result {
        Ok(value) => value as i64,
        Err(errno) => errno.to_return(),
    }
}

fn unimplemented(number: u64, a: &[u64; 6]) -> SysResult {
    let first = {
        let mut logged = LOGGED.lock();
        if number < TABLE_SIZE {
            let (word, bit) = ((number / 64) as usize, 1u64 << (number % 64));
            let first = logged.0[word] & bit == 0;
            logged.0[word] |= bit;
            first
        } else {
            !core::mem::replace(&mut logged.1, true)
        }
    };
    if first {
        UNIMPLEMENTED_LINES.fetch_add(1, Ordering::Relaxed);
    }
    if first && number >= TABLE_SIZE {
        kprintln!(
            "syscall: {number:#x} is outside the table (0-{}); not implemented -> ENOSYS. Further numbers outside the table are not logged.",
            TABLE_SIZE - 1
        );
    } else if first {
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
        AsError::Vm(VmError::WriteExec | VmError::NotExecutable) => Errno::EACCES,
        AsError::Vm(VmError::BadOffset) => Errno::EINVAL,
    }
}

/// System calls refused because a handle lacked a right (not because the
/// descriptor was bad). Security acceptance P1 item 4 checks it moves.
static RIGHTS_REFUSALS: AtomicU64 = AtomicU64::new(0);

/// How many calls the rights check has refused since boot.
pub fn rights_refusals() -> u64 {
    RIGHTS_REFUSALS.load(Ordering::Relaxed)
}

/// The open file behind `fd`, if the handle has `required`. Every system
/// call that acts on a descriptor's object comes through here.
fn file(
    p: &Arc<IrqMutex<Process>>,
    fd: i32,
    required: Rights,
) -> Result<Arc<IrqMutex<OpenFile>>, Errno> {
    match p.lock().handles.check(fd, required) {
        Ok(Object::File(file)) => Ok(file.clone()),
        Err(Refusal::MissingRights { .. }) => {
            RIGHTS_REFUSALS.fetch_add(1, Ordering::Relaxed);
            Err(Errno::EBADF)
        }
        Err(Refusal::NoHandle) => Err(Errno::EBADF),
    }
}

/// Copies a NUL-terminated path from user memory, one page at a time so a
/// string ending just before an unmapped page is still read.
fn user_path(address: u64) -> Result<Vec<u8>, Errno> {
    user_string(address, PATH_MAX, Errno::ENAMETOOLONG)
}

/// A NUL-terminated string from user memory, read a page at a time. With
/// its NUL it must fit in `max` bytes, else `too_long`.
fn user_string(address: u64, max: usize, too_long: Errno) -> Result<Vec<u8>, Errno> {
    let mut path = Vec::new();
    let mut at = address;
    loop {
        let room = (PAGE - at % PAGE) as usize;
        let take = room.min(max - path.len());
        let mut buf = [0u8; PAGE as usize];
        copy_from_user(&mut buf[..take], at).map_err(fault)?;
        if let Some(end) = buf[..take].iter().position(|&b| b == 0) {
            path.extend_from_slice(&buf[..end]);
            return Ok(path);
        }
        path.extend_from_slice(&buf[..take]);
        if path.len() >= max {
            return Err(too_long);
        }
        at = at.checked_add(take as u64).ok_or(Errno::EFAULT)?;
    }
}

fn read(p: &Arc<IrqMutex<Process>>, fd: i32, buf: u64, count: u64) -> SysResult {
    read_at(p, fd, buf, count, None)
}

/// Longest argument or environment string, its NUL included: Linux's
/// MAX_ARG_STRLEN, 32 pages (`include/uapi/linux/binfmts.h`).
const MAX_ARG_STRLEN: usize = 32 * PAGE as usize;

/// The strings of a NULL-terminated array of string pointers in user
/// memory (execve's argv or envp). A NULL array is empty, as on Linux.
/// The pointers (8 bytes each) and the strings together must fit the
/// initial-stack limit (`exec::ARG_LIMIT`), else E2BIG, checked as they
/// are read, so a huge array is refused without being read in full.
fn user_strings(array: u64, budget: &mut usize) -> Result<Vec<Vec<u8>>, Errno> {
    let mut strings = Vec::new();
    if array == 0 {
        return Ok(strings);
    }
    loop {
        let at = array
            .checked_add(strings.len() as u64 * 8)
            .ok_or(Errno::EFAULT)?;
        let mut pointer = [0u8; 8];
        copy_from_user(&mut pointer, at).map_err(fault)?;
        let pointer = u64::from_le_bytes(pointer);
        if pointer == 0 {
            return Ok(strings);
        }
        let string = user_string(pointer, MAX_ARG_STRLEN, Errno::E2BIG)?;
        *budget = budget
            .checked_sub(string.len() + 1 + 8)
            .ok_or(Errno::E2BIG)?;
        strings.push(string);
    }
}

/// execve(2) (P3-T3): replaces the calling process's program. Everything
/// that can fail is done first, leaving the process as it was: reading
/// the path and the argument and environment strings, finding the file
/// (from the process's root and working directory, so a compartment can
/// only run what is in its tree), loading it and its interpreter into a
/// new address space (`exec::load_in`, ADR 0015), and charging that
/// space to the compartment's memory budget. Then, as Linux's
/// begin_new_exec (`fs/exec.c` at v6.12): the new address space and
/// program break, close-on-exec handles closed, caught signals reset and
/// the alternate stack dropped (the blocked mask is kept), FS/GS bases and
/// FPU state reset (`sched::exec_current`). The call "returns" into the
/// new program.
///
/// As Linux: an empty argv gets "" as argv[0] (`do_execveat_common`,
/// since 5.18); a string longer than MAX_ARG_STRLEN, or arguments that do
/// not fit the stack, are E2BIG; a file that is not a regular file is
/// EACCES; an unusable program ENOEXEC and an unusable interpreter
/// ELIBBAD. Mode bits grant nothing (SR-6), so no execute bit is checked.
fn execve(p: &Arc<IrqMutex<Process>>, path: u64, argv: u64, envp: u64) -> SysResult {
    let path = user_path(path)?;
    let mut budget = crate::exec::ARG_LIMIT;
    let mut args = user_strings(argv, &mut budget)?;
    let env = user_strings(envp, &mut budget)?;
    if args.is_empty() {
        args.push(Vec::new());
    }
    let (root, cwd, compartment) = {
        let process = p.lock();
        (
            process.root,
            process.cwd,
            process.member.compartment().clone(),
        )
    };
    let file = fs::with(|fs| {
        let ino = fs.lookup(root, cwd, &path)?;
        if fs.kind(ino)? != Kind::File {
            return Err(Errno::EACCES);
        }
        fs.contents(ino)
    })?;
    let args: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    let env: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
    let loaded = crate::exec::load_in(root, &file, &path, &args, &env).map_err(|e| e.errno())?;
    loaded
        .space
        .attach_budget(compartment.memory().clone())
        .map_err(|_| Errno::ENOMEM)?;

    // No failure past this point: the old program is gone.
    let (old_space, closed) = {
        let mut process = p.lock();
        let old = core::mem::replace(&mut process.space, loaded.space.clone());
        process.brk_start = loaded.brk_start;
        process.brk = loaded.brk_start;
        process.clear_child_tid = 0;
        process.signals.reset_for_exec();
        (old, process.handles.take_close_on_exec())
    };
    // Closed outside the process lock, as close(2) does.
    drop(closed);
    // The thread switches to the new space here; only then may the old
    // one (still the CPU's until now) be dropped.
    let switched = sched::exec_current(loaded.space, loaded.entry, loaded.rsp);
    drop(old_space);
    if switched.is_err() {
        // Past the point of no return there is nothing to return to: as
        // Linux's bprm_execve (force_fatal_sig(SIGSEGV), `fs/exec.c`), the
        // thread ends as if by SIGSEGV.
        sched::exit_with(128 + 11);
    }
    Ok(0)
}

/// fcntl(2), the descriptor flags only (more commands as the trace needs
/// them). As Linux's do_fcntl (`fs/fcntl.c` at v6.12): F_GETFD returns
/// FD_CLOEXEC if set; F_SETFD sets it from `arg & FD_CLOEXEC`; any other
/// command is EINVAL. musl's open() calls F_SETFD after O_CLOEXEC
/// (`src/fcntl/open.c`). No rights needed: the flag belongs to the
/// caller's own handle table.
fn fcntl(p: &Arc<IrqMutex<Process>>, fd: i32, cmd: u32, arg: u64) -> SysResult {
    const F_GETFD: u32 = 1;
    const F_SETFD: u32 = 2;
    const FD_CLOEXEC: u64 = 1;
    let mut process = p.lock();
    match cmd {
        F_GETFD => Ok(if process.handles.close_on_exec(fd)? {
            FD_CLOEXEC
        } else {
            0
        }),
        F_SETFD => {
            // `argi = (int)arg` in Linux: only the low 32 bits count.
            process
                .handles
                .set_close_on_exec(fd, (arg as u32 as u64) & FD_CLOEXEC != 0)?;
            Ok(0)
        }
        _ => {
            // Still checks the descriptor first, as Linux's fdget does.
            process.handles.rights(fd)?;
            Err(Errno::EINVAL)
        }
    }
}

/// pread64(2): reads at `offset` without moving the file position
/// ("The file offset is not changed", pread(2)). As Linux's ksys_pread64
/// (`fs/read_write.c` at v6.12): a negative offset is EINVAL, a missing
/// descriptor EBADF, and a file opened non-seekable ESPIPE. Of Keel's
/// files only the console is: tty_open calls nonseekable_open
/// (`drivers/tty/tty_io.c`), while /dev/null, /dev/zero and /dev/urandom
/// keep FMODE_PREAD.
fn pread64(p: &Arc<IrqMutex<Process>>, fd: i32, buf: u64, count: u64, offset: u64) -> SysResult {
    if (offset as i64) < 0 {
        return Err(Errno::EINVAL);
    }
    read_at(p, fd, buf, count, Some(offset))
}

/// read(2) from the file position, or pread64(2) from `at`.
fn read_at(
    p: &Arc<IrqMutex<Process>>,
    fd: i32,
    buf: u64,
    count: u64,
    at: Option<u64>,
) -> SysResult {
    let file = file(p, fd, Rights::READ)?;
    if at.is_some() && file.lock().kind == Kind::Device(Device::Console) {
        return Err(Errno::ESPIPE);
    }
    let count = count.min(MAX_RW_COUNT) as usize;
    let mut chunk = vec![0u8; CHUNK.min(count)];
    let mut done = 0usize;
    while done < count {
        let want = (count - done).min(CHUNK);
        let kind = file.lock().kind;
        let n = match kind {
            Kind::File => {
                let mut f = file.lock();
                let from = match at {
                    Some(at) => at.saturating_add(done as u64),
                    None => f.offset,
                };
                let n = fs::with(|fs| fs.read(f.node, from, &mut chunk[..want]))?;
                if at.is_none() {
                    f.offset += n as u64;
                }
                n
            }
            Kind::Directory => return Err(Errno::EISDIR),
            // No lock held: a console read can wait for the keyboard.
            Kind::Device(device) => fs::device_read(device, &mut chunk[..want]),
        };
        // A terminal read returns at most one line.
        if kind == Kind::Device(Device::Console) {
            if n > 0 && copy_to_user(buf, &chunk[..n]).is_err() {
                return Err(Errno::EFAULT);
            }
            return Ok(n as u64);
        }
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
/// The tmpfs quota of the process's compartment, if it has one (P3-S4).
fn quota_of(p: &Arc<IrqMutex<Process>>) -> Option<Arc<keel_core::compartment::Quota>> {
    p.lock().member.compartment().tmpfs().cloned()
}

/// Writes user memory to an open file. File growth is charged to `quota`
/// (the writer's compartment), as `vfs::Fs::write_as` decides.
fn write_to(
    file: &Arc<IrqMutex<OpenFile>>,
    buf: u64,
    count: u64,
    quota: Option<&Arc<keel_core::compartment::Quota>>,
) -> SysResult {
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
        // A device has no file position, so its write runs without the
        // file's lock (an IrqMutex): a console write can take a long time on
        // a real UART and must not keep interrupts off (audit 2, A3).
        let kind = file.lock().kind;
        if let Kind::Device(device) = kind {
            let written = fs::device_write(device, &chunk[..want]);
            done += written;
            if written < want {
                break;
            }
            continue;
        }
        let written = {
            let mut f = file.lock();
            match f.kind {
                Kind::File => {
                    let (node, append, offset) = (f.node, f.append, f.offset);
                    let result = fs::with(|fs| {
                        let at = if append { fs.stat(node)?.size } else { offset };
                        let n = fs.write_as(node, at, &chunk[..want], quota)?;
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
    write_to(&file, buf, count, quota_of(p).as_ref())
}

fn writev(p: &Arc<IrqMutex<Process>>, fd: i32, iov: u64, count: u64) -> SysResult {
    let file = file(p, fd, Rights::WRITE)?;
    let quota = quota_of(p);
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
        match write_to(&file, base, len, quota.as_ref()) {
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
    // Where the lookup starts and where `..` stops (ADR 0012). With
    // AT_FDCWD or an absolute path: the process's working directory and
    // root, its ambient authority until compartments exist. Relative to a
    // directory handle: that directory, which is also the root, so `..`
    // cannot climb above it (as Linux's openat2 RESOLVE_IN_ROOT; plain
    // Linux openat would let it). A handle to /a/b then reaches only what
    // is beneath /a/b (audit 2, A6).
    let (root, base) = if dirfd == AT_FDCWD || path.first() == Some(&b'/') {
        (root, cwd)
    } else {
        // Lookup needs ENUMERATE on the directory; creating needs CREATE.
        let needs = if flags & O_CREAT != 0 {
            Rights::ENUMERATE | Rights::CREATE
        } else {
            Rights::ENUMERATE
        };
        let dir = file(p, dirfd, needs)?;
        let dir = dir.lock();
        if dir.kind != Kind::Directory {
            return Err(Errno::ENOTDIR);
        }
        (dir.node, dir.node)
    };
    let access = flags & O_ACCMODE;
    let (read, write) = (access != O_WRONLY, access != O_RDONLY);
    let quota = quota_of(p);
    let node = fs::with(|fs| {
        let node = match fs.lookup(root, base, &path) {
            Ok(_) if flags & O_CREAT != 0 && flags & O_EXCL != 0 => return Err(Errno::EEXIST),
            Ok(node) => node,
            Err(Errno::ENOENT) if flags & O_CREAT != 0 => {
                let (dir, name) = fs.lookup_parent(root, base, &path)?;
                // umask 022 until umask(2) exists.
                fs.create_file_as(dir, name, (mode as u32) & 0o7777 & !0o022, quota.as_ref())?
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
            fs.set_len_as(node, 0, quota.as_ref())?;
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
    // A private file mapping (P3-T7). The handle must allow reading, and
    // mapping executable if PROT_EXEC is asked for; whether it allows
    // MAP_EXEC is recorded, so mprotect cannot add PROT_EXEC later
    // without it (EACCES, as mprotect(2) for a file that may not be
    // executed). Regular files only: /dev/zero maps as anonymous memory,
    // as on Linux, and anything else is ENODEV ("The underlying filesystem
    // of the specified file does not support memory mapping", mmap(2)).
    //
    // Errors as mmap(2): no handle EBADF; a handle not open for reading
    // EACCES ("a file mapping was requested, but fd is not open for
    // reading"); PROT_EXEC without MAP_EXEC EPERM (as for "a filesystem
    // that was mounted no-exec").
    let mut backing = None;
    if flags & MAP_ANONYMOUS == 0 {
        let open = file(p, fd, Rights::NONE)?;
        let (may_read, may_exec) = {
            let process = p.lock();
            (
                process.handles.check(fd, Rights::READ).is_ok(),
                process.handles.check(fd, Rights::MAP_EXEC).is_ok(),
            )
        };
        if !may_read || (prot.exec && !may_exec) {
            RIGHTS_REFUSALS.fetch_add(1, Ordering::Relaxed);
            return Err(if may_read {
                Errno::EPERM
            } else {
                Errno::EACCES
            });
        }
        let (kind, node) = {
            let f = open.lock();
            (f.kind, f.node)
        };
        match kind {
            Kind::File => {
                backing = Some(Backing {
                    object: u64::from(node),
                    offset,
                    may_exec,
                });
            }
            Kind::Device(Device::Zero) => {}
            _ => return Err(Errno::ENODEV),
        }
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
    match backing {
        Some(backing) => space.map_file(placement, length, prot, backing),
        None => space.map(placement, length, prot),
    }
    .map_err(vm_error)
}

/// The `FileReader` for private file mappings: one page of the file at
/// `object` (an inode) from `offset`. `None` at or past the end of the
/// file (SIGBUS on Linux). Runs in the page-fault path, so it allocates
/// nothing; it takes only the filesystem lock.
fn read_mapped_page(object: u64, offset: u64, page: &mut [u8; 4096]) -> Option<usize> {
    let ino = keel_core::vfs::Ino::try_from(object).ok()?;
    fs::with(|fs| {
        if offset >= fs.stat(ino)?.size {
            return Ok(None);
        }
        fs.read(ino, offset, page).map(Some)
    })
    .ok()
    .flatten()
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
    u64::from(process.pid())
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
    // One draw from the generator per call, as Linux (F-0010): the
    // stream then produces every chunk without the generator's lock.
    let (mut stream, _) = random::stream();
    let mut chunk = [0u8; 256];
    let mut done = 0usize;
    while done < count {
        let n = (count - done).min(chunk.len());
        stream.fill(&mut chunk[..n]);
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

/// Longest wait between readiness checks in a blocking poll. Phase 1 has
/// no readiness notification (P3-T10 adds one), so a poll that must wait
/// re-checks its files at this interval until one is ready or the timeout
/// passes.
const POLL_INTERVAL_MS: u64 = 10;

/// What `file` is ready for, as `vfs_poll` would report it, limited to
/// what the handle's rights allow (SR-1): readable only through a handle
/// with READ, writable only through one with WRITE. Linux reports both
/// whatever the access mode; Keel does not reveal readiness for an
/// operation the handle cannot perform (docs/syscalls.md).
fn poll_ready(file: &Arc<IrqMutex<OpenFile>>, rights: Rights) -> u16 {
    use keel_core::poll::*;
    // Copy the kind out: the file lock is not held while the terminal's
    // is taken.
    let kind = file.lock().kind;
    let ready = match kind {
        // n_tty_poll: writable while output has room (console output never
        // waits); readable once a line or end of file is ready.
        Kind::Device(Device::Console) => {
            let input = if crate::tty::readable() {
                POLLIN | POLLRDNORM
            } else {
                0
            };
            input | POLLOUT | POLLWRNORM
        }
        // Regular files, directories, /dev/null, /dev/zero and
        // /dev/urandom have no poll method: DEFAULT_POLLMASK.
        _ => DEFAULT_POLLMASK,
    };
    let mut allowed = POLLERR | POLLHUP;
    if rights.contains(Rights::READ) {
        allowed |= POLLIN | POLLRDNORM | POLLPRI;
    }
    if rights.contains(Rights::WRITE) {
        allowed |= POLLOUT | POLLWRNORM;
    }
    ready & allowed
}

/// poll(2) (`fs/select.c`, `do_sys_poll`): EINVAL above the handle limit
/// (Linux: RLIMIT_NOFILE); EFAULT if the array cannot be read, or its
/// `revents` written back; otherwise the number of entries with events.
/// A negative timeout waits without limit.
fn poll(p: &Arc<IrqMutex<Process>>, fds: u64, nfds: u32, timeout_ms: i32) -> SysResult {
    use keel_core::poll::{POLLFD_SIZE, PollFd, REVENTS_OFFSET, revents};
    if nfds as usize > process::HANDLE_LIMIT {
        return Err(Errno::EINVAL);
    }
    let mut raw = vec![0u8; nfds as usize * POLLFD_SIZE];
    copy_from_user(&mut raw, fds).map_err(fault)?;
    let entries: Vec<PollFd> = raw
        .as_chunks::<POLLFD_SIZE>()
        .0
        .iter()
        .map(PollFd::from_bytes)
        .collect();
    let deadline = u64::try_from(timeout_ms)
        .ok()
        .map(|ms| time::monotonic_nanos().saturating_add(ms.saturating_mul(1_000_000)));
    let mut results = vec![0u16; entries.len()];
    loop {
        let mut count = 0u64;
        for (entry, result) in entries.iter().zip(results.iter_mut()) {
            // A negative fd is skipped without a lookup; any other number
            // either names an open handle or gets POLLNVAL.
            let handle = (entry.fd >= 0)
                .then(|| {
                    let process = p.lock();
                    let object = process.handles.get(entry.fd, Rights::NONE).ok()?.clone();
                    Some((object, process.handles.rights(entry.fd).ok()?))
                })
                .flatten();
            let ready = handle.map(|(Object::File(file), rights)| poll_ready(&file, rights));
            *result = revents(entry.fd, entry.events, ready);
            if *result != 0 {
                count += 1;
            }
        }
        let now = time::monotonic_nanos();
        let expired = deadline.is_some_and(|d| now >= d);
        if count > 0 || expired {
            for (i, result) in results.iter().enumerate() {
                let at = fds + (i * POLLFD_SIZE + REVENTS_OFFSET) as u64;
                copy_to_user(at, &result.to_le_bytes()).map_err(fault)?;
            }
            return Ok(count);
        }
        let wait_ms = deadline.map_or(POLL_INTERVAL_MS, |d| {
            (d - now).div_ceil(1_000_000).clamp(1, POLL_INTERVAL_MS)
        });
        sched::sleep_ms(wait_ms);
    }
}

/// rt_sigaction(2): records the action (no delivery until P3-T6). The
/// order is Linux's: size check, copy in (EFAULT), validate and set, copy
/// the old action out (EFAULT, after the change took effect).
fn rt_sigaction(
    p: &Arc<IrqMutex<Process>>,
    sig: i32,
    act: u64,
    oldact: u64,
    sigsetsize: u64,
) -> SysResult {
    use keel_core::signal::{SIGACTION_SIZE, SIGSET_SIZE, SigAction};
    if sigsetsize != SIGSET_SIZE {
        return Err(Errno::EINVAL);
    }
    let new = if act != 0 {
        let mut b = [0u8; SIGACTION_SIZE];
        copy_from_user(&mut b, act).map_err(fault)?;
        Some(SigAction::from_bytes(&b))
    } else {
        None
    };
    let old = p.lock().signals.sigaction(sig, new)?;
    if oldact != 0 {
        copy_to_user(oldact, &old.to_bytes()).map_err(fault)?;
    }
    Ok(0)
}

/// rt_sigprocmask(2): records the blocked mask.
fn rt_sigprocmask(
    p: &Arc<IrqMutex<Process>>,
    how: i32,
    set: u64,
    oldset: u64,
    sigsetsize: u64,
) -> SysResult {
    use keel_core::signal::SIGSET_SIZE;
    if sigsetsize != SIGSET_SIZE {
        return Err(Errno::EINVAL);
    }
    let new = if set != 0 {
        let mut b = [0u8; 8];
        copy_from_user(&mut b, set).map_err(fault)?;
        Some(u64::from_le_bytes(b))
    } else {
        None
    };
    let old = p.lock().signals.sigprocmask(how, new)?;
    if oldset != 0 {
        copy_to_user(oldset, &old.to_le_bytes()).map_err(fault)?;
    }
    Ok(0)
}

/// sigaltstack(2): records the alternate signal stack. `user_rsp` decides
/// whether the caller runs on it (then a change is EPERM).
fn sigaltstack(p: &Arc<IrqMutex<Process>>, ss: u64, old_ss: u64, user_rsp: u64) -> SysResult {
    use keel_core::signal::{AltStack, STACK_T_SIZE};
    let new = if ss != 0 {
        let mut b = [0u8; STACK_T_SIZE];
        copy_from_user(&mut b, ss).map_err(fault)?;
        Some(AltStack::from_bytes(&b))
    } else {
        None
    };
    let old = p.lock().signals.sigaltstack(new, user_rsp)?;
    if old_ss != 0 {
        copy_to_user(old_ss, &old.to_bytes()).map_err(fault)?;
    }
    Ok(0)
}
