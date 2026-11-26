//! Safe wrappers for the system calls Keel's own programs use, including
//! ways to pass deliberately bad pointers (for the hostile-pointer tests)
//! without `unsafe` in the program.
//!
//! Every function returns the raw result: a value, or `-errno`.
//!
//! Soundness rests on one rule: the kernel only ever writes to memory the
//! program has lent it right now, as a `&mut` slice, or to memory no Rust
//! object occupies (a [`Hostile`] address or an owned [`Region`]).

use core::ffi::CStr;

use crate::{syscall3, syscall6};

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
    pub const FCNTL: u64 = 72;
    pub const FTRUNCATE: u64 = 77;
    pub const UNLINK: u64 = 87;
    pub const WRITEV: u64 = 20;
    pub const GETPID: u64 = 39;
    pub const CLONE: u64 = 56;
    pub const FORK: u64 = 57;
    pub const KILL: u64 = 62;
    pub const GETTID: u64 = 186;
    pub const FUTEX: u64 = 202;
    pub const EXECVE: u64 = 59;
    pub const WAIT4: u64 = 61;
    pub const GETPPID: u64 = 110;
    pub const SIGALTSTACK: u64 = 131;
    pub const ARCH_PRCTL: u64 = 158;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const OPENAT: u64 = 257;
    pub const GETRANDOM: u64 = 318;
}

pub const AT_FDCWD: i32 = -100;
pub const O_RDONLY: u64 = 0;
pub const O_CLOEXEC: u64 = 0o2000000;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREAT: u64 = 0o100;
pub const O_EXCL: u64 = 0o200;
pub const PROT_READ: u64 = 1;
pub const PROT_WRITE: u64 = 2;
pub const PROT_EXEC: u64 = 4;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_NORESERVE: u64 = 0x4000;
/// arch_prctl codes (`arch/x86/include/uapi/asm/prctl.h`, v6.12).
pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;

/// Top of the user half: nothing of a program is ever at or above it.
const USER_END: u64 = 0x0000_7FFF_FFFF_F000;
/// Below this nothing is ever mapped (Linux's default `mmap_min_addr` is
/// 64 KiB; Keel's USER_START is 0x1_0000).
const LOW_LIMIT: u64 = 0x1_0000;

/// An address that can never hold anything of this program: in the
/// lowest 64 KiB, or at or above the top of the user half (kernel
/// addresses and non-canonical ones). Safe to give the kernel as an
/// output buffer: if it wrote there, no Rust object would change.
#[derive(Clone, Copy, Debug)]
pub struct Hostile(u64);

impl Hostile {
    pub fn new(address: u64) -> Option<Hostile> {
        (!(LOW_LIMIT..USER_END).contains(&address)).then_some(Hostile(address))
    }

    pub fn address(self) -> u64 {
        self.0
    }
}

fn call3(number: u64, a: u64, b: u64, c: u64) -> i64 {
    // SAFETY: every caller in this module passes only pointers to memory
    // it may lend the kernel (see the module comment).
    unsafe { syscall3(number, a, b, c) }
}

fn call6(number: u64, a: [u64; 6]) -> i64 {
    // SAFETY: as `call3`.
    unsafe { syscall6(number, a) }
}

pub fn write(fd: i32, data: &[u8]) -> i64 {
    call3(
        nr::WRITE,
        fd as u64,
        data.as_ptr() as u64,
        data.len() as u64,
    )
}

/// write(2) from an address the kernel may refuse to read.
pub fn write_from(fd: i32, source: Hostile, len: u64) -> i64 {
    call3(nr::WRITE, fd as u64, source.0, len)
}

pub fn read(fd: i32, buf: &mut [u8]) -> i64 {
    call3(
        nr::READ,
        fd as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )
}

pub fn read_into(fd: i32, target: Hostile, len: u64) -> i64 {
    call3(nr::READ, fd as u64, target.0, len)
}

/// writev(2) of up to 8 buffers.
pub fn writev(fd: i32, parts: &[&[u8]]) -> i64 {
    let mut iov = [[0u64; 2]; 8];
    let n = parts.len().min(8);
    for (slot, part) in iov.iter_mut().zip(parts) {
        *slot = [part.as_ptr() as u64, part.len() as u64];
    }
    call3(nr::WRITEV, fd as u64, iov.as_ptr() as u64, n as u64)
}

/// writev(2) with the iovec array itself at a hostile address.
pub fn writev_from(fd: i32, iov: Hostile, count: u64) -> i64 {
    call3(nr::WRITEV, fd as u64, iov.0, count)
}

/// writev(2) of one buffer whose base is hostile.
pub fn writev_hostile_base(fd: i32, base: Hostile, len: u64) -> i64 {
    let iov = [[base.0, len]];
    call3(nr::WRITEV, fd as u64, iov.as_ptr() as u64, 1)
}

pub fn openat(dirfd: i32, path: &CStr, flags: u64, mode: u64) -> i64 {
    call6(
        nr::OPENAT,
        [dirfd as u64, path.as_ptr() as u64, flags, mode, 0, 0],
    )
}

pub fn openat_from(path: Hostile, flags: u64) -> i64 {
    call6(nr::OPENAT, [AT_FDCWD as u64, path.0, flags, 0, 0, 0])
}

/// fork(2): the child's PID in the parent, 0 in the child, or -errno.
/// The child continues with a copy of this program's memory and state,
/// so nothing in Rust's model is affected: each process has its own.
pub fn fork() -> i64 {
    call3(nr::FORK, 0, 0, 0)
}

/// The two vfork helpers below. No Rust code runs in a vfork child: it
/// shares the parent's memory and, here, its stack, which compiled code
/// could overwrite under the parent (as musl writes vfork in assembly).
/// So each child path is all assembly and uses no stack at all.
///
/// Assembly reasoning (spec section 1, rule 4) for `vfork_then_exit_raw`
/// Entry state (psABI 1.0 section 3.2.3, System V calling convention):
///   RDI = the system call number (58 vfork, or 56 clone), RSI = clone's
///   flags (vfork ignores them), RDX = a pointer to a 16-byte timespec,
///   RCX = a pointer to a 32-bit flag, R8D = the child's exit code. RSP is
///   8 mod 16 (a `call` just pushed the return address). RBX, RBP and
///   R12 to R15 must be preserved.
/// Instructions:
///   - `push r12`, `push r13`, `push r14`: save the callee-saved registers
///     this uses.
///   - `mov r12, rdx`, `mov r13, rcx`, `mov r14, r8`: keep the child's
///     arguments where SYSCALL leaves them alone. Linux's SYSCALL returns
///     with every register as it was except RAX (the result), RCX and R11
///     (`entry_SYSCALL_64`, arch/x86/entry/entry_64.S; `man 2 syscall`),
///     and Keel's entry stub does the same; RDX and R8 are about to carry
///     clone's arguments.
///   - `mov rax, rdi`: the number. `mov rdi, rsi`, `xor esi, esi`,
///     `xor edx, edx`, `xor r10d, r10d`, `xor r8d, r8d`: clone's x86-64
///     arguments (flags, newsp 0 = the same stack, parent_tid, child_tid,
///     tls; `kernel/fork.c`, no CLONE_BACKWARDS on x86-64). A 32-bit write
///     zero-extends into the whole register (SDM Vol. 1 section 3.4.1.1).
///   - `syscall`: RAX is the child's PID in the parent, 0 in the child,
///     -errno if nothing was made.
///   - `test rax, rax`, `jz 2f`: the child goes to 2.
///   - Parent (or failure): `pop r14`, `pop r13`, `pop r12` restore the
///     saved registers in reverse order, and `ret` returns RAX.
///   - Child, at 2, using no stack: `mov rdi, r12`, `xor esi, esi`,
///     `mov eax, 35`, `syscall`: nanosleep(ts, NULL). `mov dword ptr
///     [r13], 1`: sets the flag in the memory the child has (the parent's
///     own with CLONE_VM, a copy without). `mov edi, r14d`, `mov eax, 231`,
///     `syscall`: exit_group(code), which does not return; `ud2` would
///     trap if it did.
///
/// Exit state (parent): RAX the result; RSP, RBX, RBP, R12 to R15 as at
///   entry.
#[unsafe(naked)]
unsafe extern "C" fn vfork_then_exit_raw(
    number: u64,
    flags: u64,
    nap: *const u8,
    flag: *const u32,
    code: u64,
) -> i64 {
    core::arch::naked_asm!(
        "push r12",
        "push r13",
        "push r14",
        "mov r12, rdx",
        "mov r13, rcx",
        "mov r14, r8",
        "mov rax, rdi",
        "mov rdi, rsi",
        "xor esi, esi",
        "xor edx, edx",
        "xor r10d, r10d",
        "xor r8d, r8d",
        "syscall",
        "test rax, rax",
        "jz 2f",
        "pop r14",
        "pop r13",
        "pop r12",
        "ret",
        "2:",
        "mov rdi, r12",
        "xor esi, esi",
        "mov eax, 35",
        "syscall",
        "mov dword ptr [r13], 1",
        "mov edi, r14d",
        "mov eax, 231",
        "syscall",
        "ud2",
    )
}

/// Assembly reasoning (spec section 1, rule 4) for `vfork_exec_raw`
/// Entry state: RDI = the path, RSI = a NULL-terminated argv array, RDX =
///   a NULL-terminated envp array (execve's own argument registers);
///   RSP 8 mod 16.
/// Instructions:
///   - `mov eax, 58`, `syscall`: vfork. RDI, RSI and RDX come back
///     unchanged in both processes (SYSCALL changes only RAX, RCX, R11).
///   - `test rax, rax`, `jnz 1f`: the parent, or a failure, returns RAX
///     at 1 (`ret`; nothing was pushed).
///   - Child, using no stack: `mov eax, 59`, `syscall`: execve(path, argv,
///     envp), which does not return if it succeeds. If it fails:
///     `mov edi, 127`, `mov eax, 231`, `syscall`: exit_group(127), as a
///     shell reports a command it could not run; `ud2` if that returned.
///
/// Exit state (parent): RAX the child's PID or -errno; RSP as at entry.
#[unsafe(naked)]
unsafe extern "C" fn vfork_exec_raw(path: *const u8, argv: *const u64, envp: *const u64) -> i64 {
    core::arch::naked_asm!(
        "mov eax, 58",
        "syscall",
        "test rax, rax",
        "jnz 1f",
        "mov eax, 59",
        "syscall",
        "mov edi, 127",
        "mov eax, 231",
        "syscall",
        "ud2",
        "1:",
        "ret",
    )
}

/// vfork(2) (`clone` None) or clone(2) with `clone` as its flags (with
/// CLONE_VFORK, and SIGCHLD in the low byte), where the child sleeps for
/// `nap`, sets `flag` to 1 and exits with `code`. Returns the child's PID
/// or -errno. With CLONE_VM the flag is the parent's own.
pub fn vfork_then_exit(
    clone: Option<u64>,
    nap: &[u8; 16],
    flag: &core::sync::atomic::AtomicU32,
    code: u8,
) -> i64 {
    let (number, flags) = match clone {
        None => (58, 0),
        Some(flags) => (56, flags),
    };
    // SAFETY: the child runs only the assembly above, which reads `nap`
    // and writes `flag` (an atomic, so a write from another process is
    // sound: the parent reads it with an atomic load after the kernel has
    // let it go on) and touches no other memory, no stack included; it
    // ends with exit_group. The parent returns normally.
    unsafe {
        vfork_then_exit_raw(
            number,
            flags,
            nap.as_ptr(),
            flag.as_ptr() as *const u32,
            u64::from(code),
        )
    }
}

/// vfork(2), and execve(2) of `path` with `argv` and `envp` in the child
/// (exit status 127 if that fails). Returns the child's PID or -errno.
pub fn vfork_exec(path: &CStr, argv: &[&CStr], envp: &[&CStr]) -> i64 {
    let mut args = [0u64; EXECVE_MAX];
    let mut env = [0u64; EXECVE_MAX];
    if argv.len() >= EXECVE_MAX || envp.len() >= EXECVE_MAX {
        return -7; // E2BIG
    }
    for (slot, arg) in args.iter_mut().zip(argv) {
        *slot = arg.as_ptr() as u64;
    }
    for (slot, var) in env.iter_mut().zip(envp) {
        *slot = var.as_ptr() as u64;
    }
    // SAFETY: the child runs only the assembly above: execve with these
    // NULL-terminated arrays of pointers to NUL-terminated strings, all
    // alive in this frame until the parent goes on (vfork shares them),
    // then exit_group. No Rust code and no stack are used in the child.
    unsafe { vfork_exec_raw(path.as_ptr().cast(), args.as_ptr(), env.as_ptr()) }
}

/// mknodat(2).
pub fn mknodat(dirfd: i32, path: &CStr, mode: u32, dev: u64) -> i64 {
    call6(
        259,
        [
            dirfd as u32 as u64,
            path.as_ptr() as u64,
            u64::from(mode),
            dev,
            0,
            0,
        ],
    )
}

/// mknod(2).
pub fn mknod(path: &CStr, mode: u32, dev: u64) -> i64 {
    call3(133, path.as_ptr() as u64, u64::from(mode), dev)
}

/// getuid(2), getgid(2), geteuid(2) and getegid(2), by number (102, 104,
/// 107, 108).
pub fn get_id(number: u64) -> i64 {
    if ![102, 104, 107, 108].contains(&number) {
        return -22;
    }
    call3(number, 0, 0, 0)
}

/// getresuid(2) (`group` false) or getresgid(2): real, effective, saved.
pub fn getres_ids(group: bool, ids: &mut [u32; 3]) -> i64 {
    let [a, b, c] = ids;
    call3(
        if group { 120 } else { 118 },
        a as *mut u32 as u64,
        b as *mut u32 as u64,
        c as *mut u32 as u64,
    )
}

/// getresuid(2) with hostile pointers.
pub fn getresuid_from(at: [Hostile; 3]) -> i64 {
    let [a, b, c] = at;
    call3(118, a.0, b.0, c.0)
}

/// wait4(2) with the status written to `status` and no rusage.
pub fn wait4(pid: i32, status: &mut i32, options: u32) -> i64 {
    call6(
        nr::WAIT4,
        [
            pid as u32 as u64,
            status as *mut i32 as u64,
            u64::from(options),
            0,
            0,
            0,
        ],
    )
}

/// kill(2).
pub fn kill(pid: i32, signal: i32) -> i64 {
    call3(nr::KILL, pid as u32 as u64, signal as u32 as u64, 0)
}

/// gettid(2).
pub fn gettid() -> i64 {
    call3(nr::GETTID, 0, 0, 0)
}

/// clone(2) with flags that are refused before anything is created (the
/// kernel checks them first), for testing those refusals. Any other use
/// would start a thread on this program's stack: not offered.
pub fn clone_refused(flags: u64) -> i64 {
    const CLONE_VM: u64 = 0x100;
    const CLONE_SIGHAND: u64 = 0x800;
    const CLONE_THREAD: u64 = 0x1_0000;
    let thread_without_sighand = flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0;
    let sighand_without_vm = flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0;
    if !(thread_without_sighand || sighand_without_vm) {
        return -22;
    }
    call6(nr::CLONE, [flags, 0, 0, 0, 0, 0])
}

/// futex(2) on `word`, a u32 this program owns. `timeout` is a relative
/// timespec (seconds, nanoseconds) for FUTEX_WAIT.
pub fn futex(
    word: &core::sync::atomic::AtomicU32,
    op: u32,
    val: u32,
    timeout: Option<&[i64; 2]>,
) -> i64 {
    let timeout = timeout.map_or(0, |t| t.as_ptr() as u64);
    call6(
        nr::FUTEX,
        [
            word.as_ptr() as u64,
            u64::from(op),
            u64::from(val),
            timeout,
            0,
            0,
        ],
    )
}

/// futex(2) with an address that is not 4-byte aligned (EINVAL), inside
/// `buf`.
pub fn futex_misaligned(buf: &[u8; 8], op: u32) -> i64 {
    call6(
        nr::FUTEX,
        [buf.as_ptr() as u64 + 1, u64::from(op), 0, 0, 0, 0],
    )
}

/// FUTEX_CMP_REQUEUE from `from` to `to` (both this program's).
pub fn futex_cmp_requeue(
    from: &core::sync::atomic::AtomicU32,
    to: &core::sync::atomic::AtomicU32,
    wake: u32,
    requeue: u32,
    expected: u32,
) -> i64 {
    call6(
        nr::FUTEX,
        [
            from.as_ptr() as u64,
            4 | 128,
            u64::from(wake),
            u64::from(requeue),
            to.as_ptr() as u64,
            u64::from(expected),
        ],
    )
}

/// getppid(2).
/// setpgid(2).
pub fn setpgid(pid: i32, pgid: i32) -> i64 {
    call3(109, pid as u64, pgid as u64, 0)
}

/// getpgrp(2).
pub fn getpgrp() -> i64 {
    call3(111, 0, 0, 0)
}

/// setsid(2).
pub fn setsid() -> i64 {
    call3(112, 0, 0, 0)
}

/// getpgid(2).
pub fn getpgid(pid: i32) -> i64 {
    call3(121, pid as u64, 0, 0)
}

/// getsid(2).
pub fn getsid(pid: i32) -> i64 {
    call3(124, pid as u64, 0, 0)
}

pub fn getppid() -> i64 {
    call3(nr::GETPPID, 0, 0, 0)
}

/// execve(2) of `path` with these arguments (`None`: a NULL argv) and
/// environment, at most 15 of each. Returns only on failure, with -errno;
/// on success this program is replaced, so no Rust state of it survives.
/// Limit on argv and envp entries for [`execve`] (each list keeps one slot
/// for its NULL).
pub const EXECVE_MAX: usize = 64;

pub fn execve(path: &CStr, argv: Option<&[&CStr]>, envp: &[&CStr]) -> i64 {
    let mut args = [0u64; EXECVE_MAX];
    let mut env = [0u64; EXECVE_MAX];
    let Some(argv_list) = argv
        .map_or(Some(&[][..]), Some)
        .filter(|a| a.len() < EXECVE_MAX)
    else {
        return -7; // E2BIG
    };
    if envp.len() >= EXECVE_MAX {
        return -7;
    }
    for (slot, arg) in args.iter_mut().zip(argv_list) {
        *slot = arg.as_ptr() as u64;
    }
    for (slot, var) in env.iter_mut().zip(envp) {
        *slot = var.as_ptr() as u64;
    }
    let argv_ptr = if argv.is_some() {
        args.as_ptr() as u64
    } else {
        0
    };
    call3(
        nr::EXECVE,
        path.as_ptr() as u64,
        argv_ptr,
        env.as_ptr() as u64,
    )
}

/// execve(2) with the path at a hostile address (and no arguments).
pub fn execve_from(path: Hostile) -> i64 {
    call3(nr::EXECVE, path.0, 0, 0)
}

/// The FS base (arch_prctl ARCH_GET_FS), or -errno.
pub fn fs_base() -> Result<u64, i64> {
    let mut base = 0u64;
    let r = call3(nr::ARCH_PRCTL, ARCH_GET_FS, &raw mut base as u64, 0);
    if r < 0 { Err(r) } else { Ok(base) }
}

/// The GS base (arch_prctl ARCH_GET_GS, 0x1004), or -errno.
pub fn gs_base() -> Result<u64, i64> {
    let mut base = 0u64;
    let r = call3(nr::ARCH_PRCTL, 0x1004, &raw mut base as u64, 0);
    if r < 0 { Err(r) } else { Ok(base) }
}

/// fcntl(2) with an integer argument.
pub fn fcntl(fd: i32, cmd: u32, arg: u64) -> i64 {
    call3(nr::FCNTL, fd as u64, u64::from(cmd), arg)
}

/// open(2), the legacy call musl uses on x86-64.
pub fn open(path: &CStr, flags: u64, mode: u64) -> i64 {
    call3(nr::OPEN, path.as_ptr() as u64, flags, mode)
}

/// pread64(2) into `buf` from file offset `offset` (as an `off_t`: a value
/// above `i64::MAX` is a negative offset).
pub fn pread(fd: i32, buf: &mut [u8], offset: u64) -> i64 {
    call6(
        nr::PREAD64,
        [
            fd as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            offset,
            0,
            0,
        ],
    )
}

/// ftruncate(2).
pub fn ftruncate(fd: i32, length: i64) -> i64 {
    call3(nr::FTRUNCATE, fd as u64, length as u64, 0)
}

/// unlink(2).
pub fn unlink(path: &CStr) -> i64 {
    call3(nr::UNLINK, path.as_ptr() as u64, 0, 0)
}

pub fn close(fd: i32) -> i64 {
    call3(nr::CLOSE, fd as u64, 0, 0)
}

pub fn fstat(fd: i32, buf: &mut [u8; 144]) -> i64 {
    call3(nr::FSTAT, fd as u64, buf.as_mut_ptr() as u64, 0)
}

// Filesystem calls (P3-T8). Each lends the kernel only the buffers and
// strings it is given. Numbers from Linux's syscall_64.tbl.

/// newfstatat(2) into a 144-byte `struct stat`.
pub fn fstatat(dirfd: i32, path: &CStr, buf: &mut [u8; 144], flags: u32) -> i64 {
    call6(
        262,
        [
            dirfd as u64,
            path.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            u64::from(flags),
            0,
            0,
        ],
    )
}

/// stat(2) and lstat(2).
pub fn stat(path: &CStr, buf: &mut [u8; 144]) -> i64 {
    call3(4, path.as_ptr() as u64, buf.as_mut_ptr() as u64, 0)
}

pub fn lstat(path: &CStr, buf: &mut [u8; 144]) -> i64 {
    call3(6, path.as_ptr() as u64, buf.as_mut_ptr() as u64, 0)
}

pub fn lseek(fd: i32, offset: i64, whence: u32) -> i64 {
    call3(8, fd as u64, offset as u64, u64::from(whence))
}

pub fn access(path: &CStr, mode: u32) -> i64 {
    call3(21, path.as_ptr() as u64, u64::from(mode), 0)
}

pub fn getcwd(buf: &mut [u8]) -> i64 {
    call3(79, buf.as_mut_ptr() as u64, buf.len() as u64, 0)
}

pub fn chdir(path: &CStr) -> i64 {
    call3(80, path.as_ptr() as u64, 0, 0)
}

pub fn fchdir(fd: i32) -> i64 {
    call3(81, fd as u64, 0, 0)
}

pub fn rename(old: &CStr, new: &CStr) -> i64 {
    call3(82, old.as_ptr() as u64, new.as_ptr() as u64, 0)
}

pub fn mkdir(path: &CStr, mode: u32) -> i64 {
    call3(83, path.as_ptr() as u64, u64::from(mode), 0)
}

pub fn rmdir(path: &CStr) -> i64 {
    call3(84, path.as_ptr() as u64, 0, 0)
}

pub fn link(old: &CStr, new: &CStr) -> i64 {
    call3(86, old.as_ptr() as u64, new.as_ptr() as u64, 0)
}

pub fn symlink(target: &CStr, path: &CStr) -> i64 {
    call3(88, target.as_ptr() as u64, path.as_ptr() as u64, 0)
}

pub fn readlink(path: &CStr, buf: &mut [u8]) -> i64 {
    call3(
        89,
        path.as_ptr() as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )
}

pub fn chmod(path: &CStr, mode: u32) -> i64 {
    call3(90, path.as_ptr() as u64, u64::from(mode), 0)
}

pub fn fchmod(fd: i32, mode: u32) -> i64 {
    call3(91, fd as u64, u64::from(mode), 0)
}

pub fn umask(mask: u32) -> i64 {
    call3(95, u64::from(mask), 0, 0)
}

pub fn getdents64(fd: i32, buf: &mut [u8]) -> i64 {
    call3(217, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
}

pub fn unlinkat(dirfd: i32, path: &CStr, flags: u32) -> i64 {
    call3(263, dirfd as u64, path.as_ptr() as u64, u64::from(flags))
}

/// renameat2(2) relative to the working directory.
pub fn rename2(old: &CStr, new: &CStr, flags: u32) -> i64 {
    call6(
        316,
        [
            AT_FDCWD as u64,
            old.as_ptr() as u64,
            AT_FDCWD as u64,
            new.as_ptr() as u64,
            u64::from(flags),
            0,
        ],
    )
}

/// prctl(2) with a pointer argument (PR_SET_NAME, PR_GET_NAME).
pub fn prctl_name(option: u64, name: &mut [u8; 16]) -> i64 {
    call6(157, [option, name.as_mut_ptr() as u64, 0, 0, 0, 0])
}

pub fn dup(fd: i32) -> i64 {
    call3(32, fd as u64, 0, 0)
}

pub fn dup2(fd: i32, newfd: i32) -> i64 {
    call3(33, fd as u64, newfd as u64, 0)
}

pub fn dup3(fd: i32, newfd: i32, flags: u64) -> i64 {
    call3(292, fd as u64, newfd as u64, flags)
}

/// fcntl(2) with a `struct flock` (F_GETLK, F_SETLK, F_SETLKW).
pub fn fcntl_lock(fd: i32, cmd: u32, flock: &mut [u8; 32]) -> i64 {
    call3(
        nr::FCNTL,
        fd as u64,
        u64::from(cmd),
        flock.as_mut_ptr() as u64,
    )
}

pub fn pwrite(fd: i32, data: &[u8], offset: i64) -> i64 {
    call6(
        18,
        [
            fd as u64,
            data.as_ptr() as u64,
            data.len() as u64,
            offset as u64,
            0,
            0,
        ],
    )
}

/// pwritev2(2) of one buffer.
pub fn pwritev2(fd: i32, data: &[u8], offset: i64, flags: u32) -> i64 {
    let iov = [data.as_ptr() as u64, data.len() as u64];
    call6(
        328,
        [
            fd as u64,
            iov.as_ptr() as u64,
            1,
            offset as u64,
            0,
            u64::from(flags),
        ],
    )
}

/// readv(2) (offset None) or preadv(2) into two buffers.
pub fn readv2(fd: i32, a: &mut [u8], b: &mut [u8], offset: Option<i64>) -> i64 {
    let iov = [
        a.as_mut_ptr() as u64,
        a.len() as u64,
        b.as_mut_ptr() as u64,
        b.len() as u64,
    ];
    match offset {
        None => call3(19, fd as u64, iov.as_ptr() as u64, 2),
        Some(at) => call6(295, [fd as u64, iov.as_ptr() as u64, 2, at as u64, 0, 0]),
    }
}

/// statfs(2) and fstatfs(2) into a 120-byte `struct statfs`.
pub fn statfs(path: &CStr, buf: &mut [u8; 120]) -> i64 {
    call3(137, path.as_ptr() as u64, buf.as_mut_ptr() as u64, 0)
}

pub fn fstatfs(fd: i32, buf: &mut [u8; 120]) -> i64 {
    call3(138, fd as u64, buf.as_mut_ptr() as u64, 0)
}

pub fn getxattr(path: &CStr, name: &CStr, buf: &mut [u8]) -> i64 {
    call6(
        191,
        [
            path.as_ptr() as u64,
            name.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
        ],
    )
}

pub fn fgetxattr(fd: i32, name: &CStr, buf: &mut [u8]) -> i64 {
    call6(
        193,
        [
            fd as u64,
            name.as_ptr() as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
        ],
    )
}

pub fn listxattr(path: &CStr, buf: &mut [u8]) -> i64 {
    call3(
        194,
        path.as_ptr() as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )
}

pub fn setxattr(path: &CStr, name: &CStr, value: &[u8], flags: u64) -> i64 {
    call6(
        188,
        [
            path.as_ptr() as u64,
            name.as_ptr() as u64,
            value.as_ptr() as u64,
            value.len() as u64,
            flags,
            0,
        ],
    )
}

/// utimensat(2) with two `struct timespec`s (or None: both now). `path`
/// None passes NULL (the file open on `dirfd`).
pub fn utimensat(
    dirfd: i32,
    path: Option<&CStr>,
    times: Option<&[[i64; 2]; 2]>,
    flags: u32,
) -> i64 {
    call6(
        280,
        [
            dirfd as u64,
            path.map_or(0, |p| p.as_ptr() as u64),
            times.map_or(0, |t| t.as_ptr() as u64),
            u64::from(flags),
            0,
            0,
        ],
    )
}

pub fn fstat_into(fd: i32, target: Hostile) -> i64 {
    call3(nr::FSTAT, fd as u64, target.0, 0)
}

pub fn ioctl(fd: i32, request: u64, buf: &mut [u8; 64]) -> i64 {
    call3(nr::IOCTL, fd as u64, request, buf.as_mut_ptr() as u64)
}

/// ioctl(2) whose argument is a value, not a pointer (TCFLSH, TCXONC,
/// TIOCSIG, TIOCGPTPEER).
pub fn ioctl_value(fd: i32, request: u64, arg: u64) -> i64 {
    call3(nr::IOCTL, fd as u64, request, arg)
}

pub fn clock_gettime(clock: u64, buf: &mut [u8; 16]) -> i64 {
    call3(nr::CLOCK_GETTIME, clock, buf.as_mut_ptr() as u64, 0)
}

pub fn clock_gettime_into(clock: u64, target: Hostile) -> i64 {
    call3(nr::CLOCK_GETTIME, clock, target.0, 0)
}

/// nanosleep(2) with raw 16-byte `struct __kernel_timespec`s; `rem`, if
/// given, gets the time left when a signal cuts the sleep short.
pub fn nanosleep(req: &[u8; 16], rem: Option<&mut [u8; 16]>) -> i64 {
    let rem = rem.map_or(0, |r| r.as_mut_ptr() as u64);
    call3(35, req.as_ptr() as u64, rem, 0)
}

/// nanosleep(2) with a request the kernel cannot read.
pub fn nanosleep_from(req: Hostile) -> i64 {
    call3(35, req.0, 0, 0)
}

/// clock_nanosleep(2), as [`nanosleep`] with a clock and flags
/// (TIMER_ABSTIME 1).
pub fn clock_nanosleep(clock: i32, flags: u32, req: &[u8; 16], rem: Option<&mut [u8; 16]>) -> i64 {
    let rem = rem.map_or(0, |r| r.as_mut_ptr() as u64);
    call6(
        230,
        [
            clock as u32 as u64,
            u64::from(flags),
            req.as_ptr() as u64,
            rem,
            0,
            0,
        ],
    )
}

/// rt_sigsuspend(2): waits with `mask` blocked until a signal it does not
/// block is pending.
pub fn rt_sigsuspend(mask: Arg<'_, u64>, size: u64) -> i64 {
    call3(130, arg(&mask), size, 0)
}

/// restart_syscall(2): resumes an interrupted sleep, else EINTR. It takes
/// no arguments and touches only what the interrupted call had.
pub fn restart_syscall() -> i64 {
    call3(219, 0, 0, 0)
}

pub fn getrandom(buf: &mut [u8], flags: u64) -> i64 {
    call3(
        nr::GETRANDOM,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
        flags,
    )
}

pub fn getrandom_into(target: Hostile, len: u64) -> i64 {
    call3(nr::GETRANDOM, target.0, len, 0)
}

/// getpid(2): the PID inside the caller's compartment.
pub fn getpid() -> i64 {
    call3(nr::GETPID, 0, 0, 0)
}

pub fn set_tid_address(slot: &mut u32) -> i64 {
    call3(nr::SET_TID_ADDRESS, slot as *mut u32 as u64, 0, 0)
}

pub fn arch_prctl_get_into(code: u64, target: Hostile) -> i64 {
    call3(nr::ARCH_PRCTL, code, target.0, 0)
}

/// poll(2) on `fds`, each a raw `struct pollfd` (fd, events, revents).
pub fn poll(fds: &mut [[u8; 8]], timeout_ms: i32) -> i64 {
    call3(
        nr::POLL,
        fds.as_mut_ptr() as u64,
        fds.len() as u64,
        timeout_ms as u64,
    )
}

/// poll(2) with the array at a hostile address.
pub fn poll_from(fds: Hostile, nfds: u64) -> i64 {
    call3(nr::POLL, fds.0, nfds, 0)
}

/// Where a signal call reads its input or writes its output: nothing
/// (NULL), this program's own buffer, or a hostile address.
pub enum Arg<'a, T> {
    Null,
    Buf(&'a T),
    Hostile(Hostile),
}

pub enum Out<'a, T> {
    Null,
    Buf(&'a mut T),
    Hostile(Hostile),
}

fn arg<T>(a: &Arg<'_, T>) -> u64 {
    match a {
        Arg::Null => 0,
        Arg::Buf(b) => *b as *const T as u64,
        Arg::Hostile(h) => h.0,
    }
}

fn out<T>(o: &mut Out<'_, T>) -> u64 {
    match o {
        Out::Null => 0,
        Out::Buf(b) => *b as *mut T as u64,
        Out::Hostile(h) => h.0,
    }
}

/// rt_sigaction(2) with raw 32-byte kernel `struct sigaction`s. Setting a
/// handler is sound only for a signal this program never receives; the
/// tests use SIG_IGN or handlers for signals nothing sends.
pub fn rt_sigaction(
    sig: i32,
    act: Arg<'_, [u8; 32]>,
    mut old: Out<'_, [u8; 32]>,
    size: u64,
) -> i64 {
    call6(
        nr::RT_SIGACTION,
        [sig as u64, arg(&act), out(&mut old), size, 0, 0],
    )
}

pub fn rt_sigprocmask(how: i32, set: Arg<'_, u64>, mut old: Out<'_, u64>, size: u64) -> i64 {
    call6(
        nr::RT_SIGPROCMASK,
        [how as u64, arg(&set), out(&mut old), size, 0, 0],
    )
}

/// sigaltstack(2) with raw 24-byte `stack_t`s. The kernel only records
/// the stack; it is used only if a signal handler runs on it.
pub fn sigaltstack(ss: Arg<'_, [u8; 24]>, mut old: Out<'_, [u8; 24]>) -> i64 {
    call3(nr::SIGALTSTACK, arg(&ss), out(&mut old), 0)
}

/// Sets the FS base to `value`'s address, reads the 8 bytes at FS:0, and
/// puts the old base back. Returns `(set result, value read)`. This
/// runtime keeps no thread-local data, so FS is free to change.
pub fn fs_base_round_trip(value: &u64) -> (i64, u64) {
    let mut old = 0u64;
    let get = call3(nr::ARCH_PRCTL, ARCH_GET_FS, &raw mut old as u64, 0);
    let set = call3(nr::ARCH_PRCTL, ARCH_SET_FS, value as *const u64 as u64, 0);
    if set != 0 || get != 0 {
        return (if set != 0 { set } else { get }, 0);
    }
    let read: u64;
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: the FS base is the address of `value`, an 8-byte
    //   aligned u64 that lives for this call.
    // Instruction: `mov {r}, qword ptr fs:[0]` loads 8 bytes from FS.base
    //   + 0 (SDM Vol. 1 section 3.4.2.1: in 64-bit mode FS and GS bases
    //   still apply).
    // Exit state: {r} = *value. No stack use, flags unchanged.
    // SAFETY: FS.base points at `value`, which is borrowed for this call.
    unsafe {
        core::arch::asm!(
            "mov {r}, qword ptr fs:[0]",
            r = out(reg) read,
            options(nostack, readonly, preserves_flags),
        );
    }
    call3(nr::ARCH_PRCTL, ARCH_SET_FS, old, 0);
    (0, read)
}

/// Sets the GS base (`arch_prctl(ARCH_SET_GS)`). Nothing in this runtime
/// or in Rust code generated for this target reads through GS, so any
/// value is harmless to the program's own objects; `peldr` points it at a
/// fake Windows TEB.
pub fn set_gs_base(address: u64) -> i64 {
    call3(nr::ARCH_PRCTL, ARCH_SET_GS, address, 0)
}

pub fn arch_prctl_set_fs(address: Hostile) -> i64 {
    call3(nr::ARCH_PRCTL, ARCH_SET_FS, address.0, 0)
}

/// mmap(2) without MAP_FIXED, so it can never replace this program's own
/// memory. Returns the raw result.
pub fn mmap_raw(length: u64, prot: u64, flags: u64, fd: i32) -> i64 {
    if flags & 0x10 != 0 || flags & 0x10_0000 != 0 {
        return -22; // MAP_FIXED / MAP_FIXED_NOREPLACE: not offered here
    }
    let result = call6(nr::MMAP, [0, length, prot, flags, fd as u64, 0]);
    if result >= 0 {
        // Not an owned region: give it straight back.
        call3(nr::MUNMAP, result as u64, length, 0);
    }
    result
}

/// mmap(hint, length, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0), kept
/// until the program exits. `hint` is only a hint (never MAP_FIXED), so
/// the kernel never places this over memory the program already has.
/// Returns the raw result. For tests that fill the address space.
pub fn mmap_keep(hint: u64, length: u64, prot: u64) -> i64 {
    call6(
        nr::MMAP,
        [hint, length, prot, MAP_PRIVATE | MAP_ANONYMOUS, u64::MAX, 0],
    )
}

/// Writes `prefix`, `value` in decimal and `suffix` as one line to fd 1.
pub fn write_number(prefix: &[u8], value: u64, suffix: &[u8]) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    let mut rest = value;
    loop {
        at -= 1;
        digits[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    writev(1, &[prefix, &digits[at..], suffix]);
}

/// An anonymous private mapping this program owns. No Rust reference
/// into it ever exists, so lending its address to the kernel is sound.
pub struct Region {
    address: u64,
    length: u64,
}

impl Region {
    /// mmap(NULL, length, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0).
    pub fn map(length: u64, prot: u64) -> Result<Region, i64> {
        Self::map_with(length, prot, 0)
    }

    /// As [`Region::map`], with extra flags such as MAP_NORESERVE. MAP_FIXED
    /// and MAP_FIXED_NOREPLACE are refused (-EINVAL): they could replace
    /// this program's own memory.
    pub fn map_with(length: u64, prot: u64, extra_flags: u64) -> Result<Region, i64> {
        if extra_flags & (0x10 | 0x10_0000) != 0 {
            return Err(-22);
        }
        let result = call6(
            nr::MMAP,
            [
                0,
                length,
                prot,
                MAP_PRIVATE | MAP_ANONYMOUS | extra_flags,
                u64::MAX,
                0,
            ],
        );
        if result < 0 {
            Err(result)
        } else {
            Ok(Region {
                address: result as u64,
                length,
            })
        }
    }

    /// A private mapping of `fd` from file offset `offset` (mmap with
    /// MAP_PRIVATE), placed by the kernel. Writes to it stay in this
    /// process; the file is not changed.
    pub fn map_file_private(length: u64, prot: u64, fd: i32, offset: u64) -> Result<Region, i64> {
        let result = call6(
            nr::MMAP,
            [0, length, prot, MAP_PRIVATE, fd as u32 as u64, offset],
        );
        if result < 0 {
            Err(result)
        } else {
            Ok(Region {
                address: result as u64,
                length,
            })
        }
    }

    /// A shared mapping of `fd` from file offset `offset` (mmap with
    /// MAP_SHARED), placed by the kernel. Stores reach the file and every
    /// other mapping of it, in this process or another; no Rust object
    /// lives in it, so another process's stores change nothing Rust relies
    /// on.
    pub fn map_file_shared(length: u64, prot: u64, fd: i32, offset: u64) -> Result<Region, i64> {
        const MAP_SHARED: u64 = 0x01;
        let result = call6(
            nr::MMAP,
            [0, length, prot, MAP_SHARED, fd as u32 as u64, offset],
        );
        if result < 0 {
            Err(result)
        } else {
            Ok(Region {
                address: result as u64,
                length,
            })
        }
    }

    /// mmap at `address` exactly, with MAP_FIXED_NOREPLACE: fails (EEXIST)
    /// rather than replace anything already mapped, so it can never land
    /// on this program's own memory.
    pub fn map_at(address: u64, length: u64, prot: u64) -> Result<Region, i64> {
        const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
        let result = call6(
            nr::MMAP,
            [
                address,
                length,
                prot,
                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                u64::MAX,
                0,
            ],
        );
        if result < 0 {
            Err(result)
        } else if result as u64 != address {
            // Kernels before Linux 4.17 treat the flag as a hint.
            call3(nr::MUNMAP, result as u64, length, 0);
            Err(-17)
        } else {
            Ok(Region { address, length })
        }
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn length(&self) -> u64 {
        self.length
    }

    fn range(&self, offset: u64, len: usize) -> Option<u64> {
        let end = offset.checked_add(len as u64)?;
        (end <= self.length).then_some(self.address + offset)
    }

    /// Copies `bytes` into the region at `offset`. Fails (`None`) if the
    /// range does not fit. The region must be writable there; if it is not,
    /// the write faults and the kernel ends the program (nothing in Rust's
    /// memory model is affected: no Rust object lives in a region).
    pub fn write(&self, offset: u64, bytes: &[u8]) -> Option<()> {
        let at = self.range(offset, bytes.len())?;
        // SAFETY: `[at, at + len)` lies inside this mapping (checked
        // above), which this value owns and in which no Rust object or
        // reference exists (module rule), so it cannot overlap `bytes`.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), at as *mut u8, bytes.len()) };
        Some(())
    }

    /// The 8 bytes at `offset` as a little-endian u64 (any alignment).
    pub fn read_u64(&self, offset: u64) -> Option<u64> {
        let at = self.range(offset, 8)?;
        // SAFETY: inside the mapping (checked); read_unaligned allows any
        // alignment; any 8 bytes are a valid u64.
        Some(unsafe { (at as *const u64).read_unaligned() })
    }

    /// Copies `buf.len()` bytes at `offset` into `buf`. Fails (`None`) if
    /// the range does not fit. The region must be readable there; if it
    /// is not, the read faults and the kernel ends the program.
    pub fn read(&self, offset: u64, buf: &mut [u8]) -> Option<()> {
        let at = self.range(offset, buf.len())?;
        // SAFETY: `[at, at + len)` lies inside this mapping (checked), in
        // which no Rust object or reference exists (module rule), so it
        // cannot overlap `buf`; any bytes are valid `u8`s.
        unsafe { core::ptr::copy_nonoverlapping(at as *const u8, buf.as_mut_ptr(), buf.len()) };
        Some(())
    }

    /// Writes `value` at `offset` (any alignment).
    pub fn write_u64(&self, offset: u64, value: u64) -> Option<()> {
        self.write(offset, &value.to_le_bytes())
    }

    /// mprotect(2) on `[offset, offset + len)` of the region; both must be
    /// page-aligned (else -EINVAL from the kernel) and inside it.
    pub fn protect_range(&self, offset: u64, len: u64, prot: u64) -> i64 {
        match offset.checked_add(len) {
            Some(end) if end <= self.length => {
                call3(nr::MPROTECT, self.address + offset, len, prot)
            }
            _ => -22,
        }
    }

    /// read(2) from `fd` into the region at `offset`.
    pub fn read_from(&self, fd: i32, offset: u64, len: u64) -> i64 {
        call3(nr::READ, fd as u64, self.address + offset, len)
    }

    /// write(2) from the region at `offset` to `fd`.
    pub fn write_to(&self, fd: i32, offset: u64, len: u64) -> i64 {
        call3(nr::WRITE, fd as u64, self.address + offset, len)
    }

    pub fn protect(&self, prot: u64) -> i64 {
        call3(nr::MPROTECT, self.address, self.length, prot)
    }

    /// getrandom(2) of `len` bytes into the region (one call).
    pub fn getrandom(&self, len: u64) -> i64 {
        call3(nr::GETRANDOM, self.address, len.min(self.length), 0)
    }

    /// poll(2) on `nfds` `struct pollfd`s at the start of the region, with
    /// timeout 0.
    pub fn poll(&self, nfds: u64) -> i64 {
        call3(nr::POLL, self.address, nfds, 0)
    }

    /// munmap(2). The address stays useful as a pointer to nothing.
    pub fn unmap(self) -> (i64, Unmapped) {
        let result = call3(nr::MUNMAP, self.address, self.length, 0);
        (result, Unmapped(self.address))
    }
}

/// A whole file read into memory and then made read-only, so it can be
/// borrowed as `&[u8]`: after `map_file` returns nothing ever writes to it.
pub struct MappedFile {
    region: Region,
    len: usize,
}

/// Largest file `map_file` reads.
pub const MAP_FILE_LIMIT: u64 = 64 << 20;

/// Opens `path` and reads all of it into a fresh read-only mapping.
/// Errors are `-errno`; a file over `MAP_FILE_LIMIT` is -EFBIG.
pub fn map_file(path: &CStr) -> Result<MappedFile, i64> {
    let fd = openat(AT_FDCWD, path, O_RDONLY, 0);
    if fd < 0 {
        return Err(fd);
    }
    let fd = fd as i32;
    let result = read_all(fd);
    close(fd);
    result
}

fn read_all(fd: i32) -> Result<MappedFile, i64> {
    let mut stat = [0u8; 144];
    let r = fstat(fd, &mut stat);
    if r < 0 {
        return Err(r);
    }
    // st_size: offset 48 of x86-64 `struct stat`
    // (arch/x86/include/uapi/asm/stat.h, v6.12).
    let size = u64::from_le_bytes(stat[48..56].try_into().unwrap_or([0; 8]));
    if size > MAP_FILE_LIMIT {
        return Err(-27); // EFBIG
    }
    let region = Region::map(size.max(1).next_multiple_of(4096), PROT_READ | PROT_WRITE)?;
    let mut done = 0;
    while done < size {
        let n = region.read_from(fd, done, size - done);
        if n < 0 {
            return Err(n);
        }
        if n == 0 {
            break; // shorter than fstat said: use what was read
        }
        done += n as u64;
    }
    let r = region.protect(PROT_READ);
    if r < 0 {
        return Err(r);
    }
    Ok(MappedFile {
        region,
        len: done as usize,
    })
}

impl MappedFile {
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: `len` bytes from the start of the mapping were filled by
        // read(2) and the whole mapping was then made PROT_READ; this value
        // owns it and never unmaps or writes it, so the slice is valid,
        // initialized and unchanging for as long as `self` is borrowed.
        unsafe { core::slice::from_raw_parts(self.region.address as *const u8, self.len) }
    }
}

/// The address of a region after munmap. This program has no allocator
/// that could put anything there, so it is as good as a hostile address.
#[derive(Clone, Copy, Debug)]
pub struct Unmapped(u64);

impl Unmapped {
    pub fn read_into(self, fd: i32, len: u64) -> i64 {
        call3(nr::READ, fd as u64, self.0, len)
    }
}

/// brk(2). Moving the break never touches existing Rust objects: the heap
/// it manages is not used by this runtime.
pub fn brk(address: u64) -> u64 {
    call3(nr::BRK, address, 0, 0) as u64
}

/// read(2) into the break area between `start` and `end`, which this
/// runtime never uses for anything else.
pub fn read_into_heap(fd: i32, start: u64, end: u64) -> i64 {
    call3(nr::READ, fd as u64, start, end.saturating_sub(start))
}

/// A system call number no Linux kernel assigns, for unknown-number
/// tests: 500 to 511 lie between the newest native calls (462 at v6.12,
/// a few more since) and the x32 range that starts at 512. Any other
/// number is refused here, because even all-zero arguments are not
/// harmless for every call (vfork would share this stack).
pub fn unassigned_syscall(number: u64) -> i64 {
    // 0x1000 is above Linux's NR_syscalls and below the x32 bit, so Linux
    // v6.12 sends it to sys_ni_syscall (arch/x86/entry/common.c,
    // do_syscall_64); on Keel it was the Phase 1 test call, now removed.
    if !(500..512).contains(&number) && number != 0x1000 {
        return -22;
    }
    call3(number, 0, 0, 0)
}

/// pipe2(2) (pipe(2) when `flags` is None): the read end, then the write
/// end, in `fds`.
pub fn pipe2(fds: &mut [i32; 2], flags: Option<u64>) -> i64 {
    let at = fds.as_mut_ptr() as u64;
    match flags {
        None => call3(22, at, 0, 0),
        Some(f) => call3(293, at, f, 0),
    }
}

/// pipe2(2) writing its descriptors to an address the kernel may refuse.
pub fn pipe2_into(target: Hostile) -> i64 {
    call3(293, target.0, 0, 0)
}

/// eventfd2(2) (eventfd(2) when `flags` is None).
pub fn eventfd2(initval: u32, flags: Option<u64>) -> i64 {
    match flags {
        None => call3(284, u64::from(initval), 0, 0),
        Some(f) => call3(290, u64::from(initval), f, 0),
    }
}

/// memfd_create(2).
pub fn memfd_create(name: &CStr, flags: u64) -> i64 {
    call3(319, name.as_ptr() as u64, flags, 0)
}

/// ppoll(2): `ts` a raw `struct timespec` (written back), `mask` a signal
/// set of `size` bytes (the kernel reads 8).
pub fn ppoll(fds: &mut [[u8; 8]], ts: Option<&mut [u8; 16]>, mask: Option<&u64>, size: u64) -> i64 {
    let ts = ts.map_or(0, |t| t.as_mut_ptr() as u64);
    let mask = mask.map_or(0, |m| m as *const u64 as u64);
    call6(
        271,
        [fds.as_mut_ptr() as u64, fds.len() as u64, ts, mask, size, 0],
    )
}

/// The three descriptor sets of select(2) and pselect6(2), 128 bytes each
/// (FD_SETSIZE 1024 bits); None is a NULL set.
pub struct FdSets<'a> {
    pub read: Option<&'a mut [u8; 128]>,
    pub write: Option<&'a mut [u8; 128]>,
    pub except: Option<&'a mut [u8; 128]>,
}

impl FdSets<'_> {
    fn addresses(&mut self) -> [u64; 3] {
        let at = |s: &mut Option<&mut [u8; 128]>| s.as_mut().map_or(0, |b| b.as_mut_ptr() as u64);
        [
            at(&mut self.read),
            at(&mut self.write),
            at(&mut self.except),
        ]
    }
}

/// select(2): `tv` a raw `struct timeval` (written back).
pub fn select(n: i32, mut sets: FdSets<'_>, tv: Option<&mut [u8; 16]>) -> i64 {
    let [r, w, e] = sets.addresses();
    let tv = tv.map_or(0, |t| t.as_mut_ptr() as u64);
    call6(23, [n as u64, r, w, e, tv, 0])
}

/// pselect6(2): `ts` a raw `struct timespec` (written back); the mask and
/// its size go in the argument pack the sixth argument points to.
pub fn pselect6(
    n: i32,
    mut sets: FdSets<'_>,
    ts: Option<&mut [u8; 16]>,
    mask: Option<&u64>,
    size: u64,
) -> i64 {
    let [r, w, e] = sets.addresses();
    let ts = ts.map_or(0, |t| t.as_mut_ptr() as u64);
    let pack = [mask.map_or(0, |m| m as *const u64 as u64), size];
    call6(270, [n as u64, r, w, e, ts, pack.as_ptr() as u64])
}

/// epoll_create1(2) (epoll_create(2) with `size` when `flags` is None).
pub fn epoll_create1(flags: Option<u64>, size: i32) -> i64 {
    match flags {
        None => call3(213, size as u32 as u64, 0, 0),
        Some(f) => call3(291, f, 0, 0),
    }
}

/// epoll_ctl(2) with a raw 12-byte `struct epoll_event` (None: NULL).
pub fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: Option<&[u8; 12]>) -> i64 {
    let at = event.map_or(0, |e| e.as_ptr() as u64);
    call6(233, [epfd as u64, op as u64, fd as u64, at, 0, 0])
}

/// epoll_ctl(2) reading the event from an address the kernel may refuse.
pub fn epoll_ctl_from(epfd: i32, op: i32, fd: i32, event: Hostile) -> i64 {
    call6(233, [epfd as u64, op as u64, fd as u64, event.0, 0, 0])
}

/// epoll_wait(2) into `events`, raw 12-byte `struct epoll_event`s.
pub fn epoll_wait(epfd: i32, events: &mut [[u8; 12]], timeout_ms: i32) -> i64 {
    call6(
        232,
        [
            epfd as u64,
            events.as_mut_ptr() as u64,
            events.len() as u64,
            timeout_ms as u64,
            0,
            0,
        ],
    )
}

/// epoll_wait(2) writing to an address no Rust object occupies.
pub fn epoll_wait_into(epfd: i32, target: Hostile, maxevents: i32, timeout_ms: i32) -> i64 {
    call6(
        232,
        [
            epfd as u64,
            target.0,
            maxevents as u32 as u64,
            timeout_ms as u64,
            0,
            0,
        ],
    )
}

/// epoll_pwait(2): a mask of `size` bytes (the kernel reads 8).
pub fn epoll_pwait(
    epfd: i32,
    events: &mut [[u8; 12]],
    timeout_ms: i32,
    mask: Option<&u64>,
    size: u64,
) -> i64 {
    let mask = mask.map_or(0, |m| m as *const u64 as u64);
    call6(
        281,
        [
            epfd as u64,
            events.as_mut_ptr() as u64,
            events.len() as u64,
            timeout_ms as u64,
            mask,
            size,
        ],
    )
}

/// epoll_pwait2(2): `ts` a raw `struct timespec` (None: no limit).
pub fn epoll_pwait2(
    epfd: i32,
    events: &mut [[u8; 12]],
    ts: Option<&[u8; 16]>,
    mask: Option<&u64>,
    size: u64,
) -> i64 {
    let ts = ts.map_or(0, |t| t.as_ptr() as u64);
    let mask = mask.map_or(0, |m| m as *const u64 as u64);
    call6(
        441,
        [
            epfd as u64,
            events.as_mut_ptr() as u64,
            events.len() as u64,
            ts,
            mask,
            size,
        ],
    )
}

/// socket(2).
pub fn socket(family: i32, ty: u32, protocol: i32) -> i64 {
    call3(
        41,
        family as u32 as u64,
        u64::from(ty),
        protocol as u32 as u64,
    )
}

/// socketpair(2) into `sv`.
pub fn socketpair(family: i32, ty: u32, protocol: i32, sv: &mut [i32; 2]) -> i64 {
    call6(
        53,
        [
            family as u32 as u64,
            u64::from(ty),
            protocol as u32 as u64,
            sv.as_mut_ptr() as u64,
            0,
            0,
        ],
    )
}

/// socketpair(2) writing to an address the kernel may refuse.
pub fn socketpair_into(family: i32, ty: u32, target: Hostile) -> i64 {
    call6(53, [family as u32 as u64, u64::from(ty), 0, target.0, 0, 0])
}

/// bind(2) with the address bytes `addr` (its length is theirs).
pub fn bind(fd: i32, addr: &[u8]) -> i64 {
    call3(49, fd as u64, addr.as_ptr() as u64, addr.len() as u64)
}

/// connect(2) with the address bytes `addr`.
pub fn connect(fd: i32, addr: &[u8]) -> i64 {
    call3(42, fd as u64, addr.as_ptr() as u64, addr.len() as u64)
}

pub fn listen(fd: i32, backlog: i32) -> i64 {
    call3(50, fd as u64, backlog as u32 as u64, 0)
}

/// accept4(2); `peer` the address buffer and its length (in and out).
pub fn accept4(fd: i32, peer: Option<(&mut [u8], &mut i32)>, flags: u32) -> i64 {
    let (a, l) = peer.map_or((0, 0), |(b, l)| {
        (b.as_mut_ptr() as u64, l as *mut i32 as u64)
    });
    call6(288, [fd as u64, a, l, u64::from(flags), 0, 0])
}

/// getsockname(2) (`peer` false) or getpeername(2).
pub fn getname(fd: i32, addr: &mut [u8], len: &mut i32, peer: bool) -> i64 {
    call3(
        if peer { 52 } else { 51 },
        fd as u64,
        addr.as_mut_ptr() as u64,
        len as *mut i32 as u64,
    )
}

pub fn shutdown(fd: i32, how: i32) -> i64 {
    call3(48, fd as u64, how as u32 as u64, 0)
}

/// sendto(2); `to` an address, or none.
pub fn sendto(fd: i32, data: &[u8], flags: u32, to: Option<&[u8]>) -> i64 {
    let (a, l) = to.map_or((0, 0), |t| (t.as_ptr() as u64, t.len() as u64));
    call6(
        44,
        [
            fd as u64,
            data.as_ptr() as u64,
            data.len() as u64,
            u64::from(flags),
            a,
            l,
        ],
    )
}

/// recvfrom(2); `from` the address buffer and its length (in and out).
pub fn recvfrom(fd: i32, buf: &mut [u8], flags: u32, from: Option<(&mut [u8], &mut i32)>) -> i64 {
    let (a, l) = from.map_or((0, 0), |(b, l)| {
        (b.as_mut_ptr() as u64, l as *mut i32 as u64)
    });
    call6(
        45,
        [
            fd as u64,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            u64::from(flags),
            a,
            l,
        ],
    )
}

/// sendmsg(2) of `parts` as its iovec, with no name and no control data.
pub fn sendmsg(fd: i32, parts: &[&[u8]], flags: u32) -> i64 {
    let mut iov = [0u64; 16];
    let n = parts.len().min(8);
    for (i, p) in parts[..n].iter().enumerate() {
        iov[2 * i] = p.as_ptr() as u64;
        iov[2 * i + 1] = p.len() as u64;
    }
    let mut hdr = [0u64; 7];
    hdr[2] = iov.as_ptr() as u64;
    hdr[3] = n as u64;
    call3(46, fd as u64, hdr.as_ptr() as u64, u64::from(flags))
}

/// recvmsg(2) into two buffers; `name` an address buffer. Returns the
/// result and the msghdr's name length and flags as written back.
pub fn recvmsg2(
    fd: i32,
    a: &mut [u8],
    b: &mut [u8],
    name: Option<&mut [u8]>,
    flags: u32,
) -> (i64, i32, i32) {
    let iov = [
        a.as_mut_ptr() as u64,
        a.len() as u64,
        b.as_mut_ptr() as u64,
        b.len() as u64,
    ];
    let mut hdr = [0u64; 7];
    if let Some(n) = name {
        hdr[0] = n.as_mut_ptr() as u64;
        hdr[1] = n.len() as u64;
    }
    hdr[2] = iov.as_ptr() as u64;
    hdr[3] = 2;
    let r = call3(47, fd as u64, hdr.as_mut_ptr() as u64, u64::from(flags));
    (r, hdr[1] as u32 as i32, hdr[6] as u32 as i32)
}

pub fn setsockopt(fd: i32, level: i32, name: i32, val: &[u8]) -> i64 {
    call6(
        54,
        [
            fd as u64,
            level as u32 as u64,
            name as u32 as u64,
            val.as_ptr() as u64,
            val.len() as u64,
            0,
        ],
    )
}

pub fn getsockopt(fd: i32, level: i32, name: i32, val: &mut [u8], len: &mut i32) -> i64 {
    call6(
        55,
        [
            fd as u64,
            level as u32 as u64,
            name as u32 as u64,
            val.as_mut_ptr() as u64,
            len as *mut i32 as u64,
            0,
        ],
    )
}

/// sendmsg(2) with a name, the vectors `parts` (up to 8) and control
/// data, each optional.
pub fn sendmsg_full(
    fd: i32,
    name: Option<&[u8]>,
    parts: &[&[u8]],
    control: Option<&[u8]>,
    flags: u32,
) -> i64 {
    let mut iov = [0u64; 16];
    let n = parts.len().min(8);
    for (i, p) in parts[..n].iter().enumerate() {
        iov[2 * i] = p.as_ptr() as u64;
        iov[2 * i + 1] = p.len() as u64;
    }
    let mut hdr = [0u64; 7];
    if let Some(nm) = name {
        hdr[0] = nm.as_ptr() as u64;
        hdr[1] = nm.len() as u64;
    }
    hdr[2] = iov.as_ptr() as u64;
    hdr[3] = n as u64;
    if let Some(c) = control {
        hdr[4] = c.as_ptr() as u64;
        hdr[5] = c.len() as u64;
    }
    call3(46, fd as u64, hdr.as_ptr() as u64, u64::from(flags))
}

/// What recvmsg wrote back: the result, msg_namelen, msg_controllen and
/// msg_flags.
pub struct Received {
    pub result: i64,
    pub namelen: i32,
    pub controllen: u64,
    pub flags: i32,
}

/// recvmsg(2) into `buf`, with an optional name buffer and control
/// buffer (None: NULL).
pub fn recvmsg_full(
    fd: i32,
    buf: &mut [u8],
    name: Option<&mut [u8]>,
    control: Option<&mut [u8]>,
    flags: u32,
) -> Received {
    let iov = [buf.as_mut_ptr() as u64, buf.len() as u64];
    let mut hdr = [0u64; 7];
    if let Some(n) = name {
        hdr[0] = n.as_mut_ptr() as u64;
        hdr[1] = n.len() as u64;
    }
    hdr[2] = iov.as_ptr() as u64;
    hdr[3] = 1;
    if let Some(c) = control {
        hdr[4] = c.as_mut_ptr() as u64;
        hdr[5] = c.len() as u64;
    }
    let result = call3(47, fd as u64, hdr.as_mut_ptr() as u64, u64::from(flags));
    Received {
        result,
        namelen: hdr[1] as u32 as i32,
        controllen: hdr[5],
        flags: hdr[6] as u32 as i32,
    }
}
