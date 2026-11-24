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
    pub const CLONE: u64 = 56;
    pub const FORK: u64 = 57;
    pub const KILL: u64 = 62;
    pub const RT_SIGRETURN: u64 = 15;
    pub const TKILL: u64 = 200;
    pub const TGKILL: u64 = 234;
    pub const GETTID: u64 = 186;
    pub const FUTEX: u64 = 202;
    pub const EXECVE: u64 = 59;
    pub const WAIT4: u64 = 61;
    pub const GETPPID: u64 = 110;
    pub const EXIT: u64 = 60;
    pub const FCNTL: u64 = 72;
    pub const SIGALTSTACK: u64 = 131;
    pub const ARCH_PRCTL: u64 = 158;
    pub const SET_TID_ADDRESS: u64 = 218;
    pub const CLOCK_GETTIME: u64 = 228;
    pub const EXIT_GROUP: u64 = 231;
    pub const OPENAT: u64 = 257;
    pub const FTRUNCATE: u64 = 77;
    pub const GETRANDOM: u64 = 318;
}

/// Size of the kernel buffer user data passes through.
const CHUNK: usize = 4096;

type SysResult = Result<u64, Errno>;

/// Registers the handler and the exit hook. Call once at boot.
pub fn init() {
    keel_hal::syscall::set_handler(handle);
    keel_hal::vm::set_file_reader(read_mapped_page);
    keel_hal::vm::set_object_hook(crate::fs::object_mapped);
    sched::set_exit_hook(process::on_thread_exit);
    crate::signal::init();
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
    t[nr::POLL as usize] =
        Some(|p, a| crate::ready::poll(p, a[0], a[1] as u32, a[2] as u32 as i32));
    {
        // P3-T10: pipes, eventfds, memfd and the other waits (ADR 0025).
        use crate::ready as r;
        t[22] = Some(|p, a| r::pipe2(p, a[0], 0));
        t[293] = Some(|p, a| r::pipe2(p, a[0], a[1] as u32 as u64));
        t[284] = Some(|p, a| r::eventfd2(p, a[0] as u32, 0));
        t[290] = Some(|p, a| r::eventfd2(p, a[0] as u32, a[1] as u32 as u64));
        t[319] = Some(|p, a| r::memfd_create(p, a[0], a[1] as u32 as u64));
        t[23] = Some(|p, a| r::select(p, a[0] as u32 as i32, [a[1], a[2], a[3]], a[4]));
        t[270] = Some(|p, a| r::pselect6(p, a[0] as u32 as i32, [a[1], a[2], a[3]], a[4], a[5]));
        t[271] = Some(|p, a| r::ppoll(p, a[0], a[1] as u32, a[2], a[3], a[4]));
        // P3-T10 part 2: epoll (ADR 0026).
        use crate::epoll as e;
        t[213] = Some(|p, a| e::epoll_create(p, a[0] as u32 as i32));
        t[291] = Some(|p, a| e::epoll_create1(p, a[0] as u32 as u64));
        t[233] = Some(|p, a| {
            e::epoll_ctl(
                p,
                a[0] as u32 as i32,
                a[1] as u32 as i32,
                a[2] as u32 as i32,
                a[3],
            )
        });
        t[232] = Some(|p, a| {
            e::epoll_wait(
                p,
                a[0] as u32 as i32,
                a[1],
                a[2] as u32 as i32,
                a[3] as u32 as i32,
            )
        });
        t[281] = Some(|p, a| {
            let (epfd, max, ms) = (a[0] as u32 as i32, a[2] as u32 as i32, a[3] as u32 as i32);
            e::epoll_pwait(p, epfd, a[1], max, ms, a[4], a[5])
        });
        // P3-T11: Unix domain sockets (ADR 0027).
        use crate::socket as k;
        t[41] = Some(|p, a| k::socket(p, a[0] as u32 as i32, a[1] as u32, a[2] as u32 as i32));
        t[53] = Some(|p, a| {
            k::socketpair(p, a[0] as u32 as i32, a[1] as u32, a[2] as u32 as i32, a[3])
        });
        t[49] = Some(|p, a| k::bind(p, a[0] as u32 as i32, a[1], a[2] as u32 as i32));
        t[50] = Some(|p, a| k::listen(p, a[0] as u32 as i32, a[1] as u32 as i32));
        t[42] = Some(|p, a| k::connect(p, a[0] as u32 as i32, a[1], a[2] as u32 as i32));
        t[43] = Some(|p, a| k::accept4(p, a[0] as u32 as i32, a[1], a[2], 0));
        t[288] = Some(|p, a| k::accept4(p, a[0] as u32 as i32, a[1], a[2], a[3] as u32));
        t[51] = Some(|p, a| k::getname(p, a[0] as u32 as i32, a[1], a[2], false));
        t[52] = Some(|p, a| k::getname(p, a[0] as u32 as i32, a[1], a[2], true));
        t[48] = Some(|p, a| k::shutdown(p, a[0] as u32 as i32, a[1] as u32 as i32));
        t[44] = Some(|p, a| {
            k::sendto(
                p,
                a[0] as u32 as i32,
                a[1],
                a[2],
                a[3] as u32,
                a[4],
                a[5] as u32 as i32,
            )
        });
        t[45] =
            Some(|p, a| k::recvfrom(p, a[0] as u32 as i32, a[1], a[2], a[3] as u32, a[4], a[5]));
        t[46] = Some(|p, a| k::sendmsg(p, a[0] as u32 as i32, a[1], a[2] as u32));
        t[47] = Some(|p, a| k::recvmsg(p, a[0] as u32 as i32, a[1], a[2] as u32));
        t[54] = Some(|p, a| {
            let (fd, level, name) = (a[0] as u32 as i32, a[1] as u32 as i32, a[2] as u32 as i32);
            k::setsockopt(p, fd, level, name, a[3], a[4] as u32 as i32)
        });
        t[55] = Some(|p, a| {
            let (fd, level, name) = (a[0] as u32 as i32, a[1] as u32 as i32, a[2] as u32 as i32);
            k::getsockopt(p, fd, level, name, a[3], a[4])
        });
        t[441] = Some(|p, a| {
            let (epfd, max) = (a[0] as u32 as i32, a[2] as u32 as i32);
            e::epoll_pwait2(p, epfd, a[1], max, a[3], a[4], a[5])
        });
    }
    t[nr::OPENAT as usize] = Some(|p, a| openat(p, a[0] as u32 as i32, a[1], a[2], a[3]));
    // open(2) is openat(AT_FDCWD, ...), as Linux's sys_open (`fs/open.c`),
    // which also sets O_LARGEFILE on 64-bit (no effect here).
    t[nr::OPEN as usize] = Some(|p, a| openat(p, AT_FDCWD, a[0], a[1] | O_LARGEFILE, a[2]));
    t[nr::PREAD64 as usize] = Some(|p, a| pread64(p, a[0] as u32 as i32, a[1], a[2], a[3]));
    t[nr::FCNTL as usize] = Some(|p, a| fcntl(p, a[0] as u32 as i32, a[1] as u32, a[2]));
    t[nr::FTRUNCATE as usize] = Some(|p, a| ftruncate(p, a[0] as u32 as i32, a[1] as i64));
    // Filesystem calls (P3-T8, ADR 0022), numbers from syscall_64.tbl.
    // The plain forms are the *at forms with AT_FDCWD and flags 0, as
    // Linux defines them.
    {
        use crate::fscalls as f;
        t[4] = Some(|p, a| f::stat(p, a[0], a[1]));
        t[6] = Some(|p, a| f::lstat(p, a[0], a[1]));
        t[8] = Some(|p, a| f::lseek(p, a[0] as u32 as i32, a[1] as i64, a[2] as u32));
        t[21] = Some(|p, a| f::faccessat2(p, AT_FDCWD, a[0], a[1] as u32, 0));
        t[79] = Some(|p, a| f::getcwd(p, a[0], a[1]));
        t[80] = Some(|p, a| f::chdir(p, a[0]));
        t[81] = Some(|p, a| f::fchdir(p, a[0] as u32 as i32));
        t[82] = Some(|p, a| f::renameat2(p, AT_FDCWD, a[0], AT_FDCWD, a[1], 0));
        t[83] = Some(|p, a| f::mkdirat(p, AT_FDCWD, a[0], a[1] as u32));
        t[84] = Some(|p, a| f::unlinkat(p, AT_FDCWD, a[0], f::AT_REMOVEDIR));
        t[86] = Some(|p, a| f::linkat(p, AT_FDCWD, a[0], AT_FDCWD, a[1], 0));
        t[87] = Some(|p, a| f::unlinkat(p, AT_FDCWD, a[0], 0));
        t[88] = Some(|p, a| f::symlinkat(p, a[0], AT_FDCWD, a[1]));
        t[89] = Some(|p, a| f::readlinkat(p, AT_FDCWD, a[0], a[1], a[2] as u32 as i32));
        t[90] = Some(|p, a| f::fchmodat(p, AT_FDCWD, a[0], a[1] as u32));
        t[91] = Some(|p, a| f::fchmod(p, a[0] as u32 as i32, a[1] as u32));
        t[95] = Some(|p, a| f::umask(p, a[0] as u32));
        t[217] = Some(|p, a| f::getdents64(p, a[0] as u32 as i32, a[1], a[2] as u32));
        t[258] = Some(|p, a| f::mkdirat(p, a[0] as u32 as i32, a[1], a[2] as u32));
        t[262] = Some(|p, a| f::newfstatat(p, a[0] as u32 as i32, a[1], a[2], a[3] as u32));
        t[263] = Some(|p, a| f::unlinkat(p, a[0] as u32 as i32, a[1], a[2] as u32));
        t[264] =
            Some(|p, a| f::renameat2(p, a[0] as u32 as i32, a[1], a[2] as u32 as i32, a[3], 0));
        t[265] = Some(|p, a| {
            f::linkat(
                p,
                a[0] as u32 as i32,
                a[1],
                a[2] as u32 as i32,
                a[3],
                a[4] as u32,
            )
        });
        t[266] = Some(|p, a| f::symlinkat(p, a[0], a[1] as u32 as i32, a[2]));
        t[267] = Some(|p, a| f::readlinkat(p, a[0] as u32 as i32, a[1], a[2], a[3] as u32 as i32));
        t[268] = Some(|p, a| f::fchmodat(p, a[0] as u32 as i32, a[1], a[2] as u32));
        t[269] = Some(|p, a| f::faccessat2(p, a[0] as u32 as i32, a[1], a[2] as u32, 0));
        t[280] = Some(|p, a| f::utimensat(p, a[0] as u32 as i32, a[1], a[2], a[3] as u32));
        t[316] = Some(|p, a| {
            f::renameat2(
                p,
                a[0] as u32 as i32,
                a[1],
                a[2] as u32 as i32,
                a[3],
                a[4] as u32,
            )
        });
        t[439] = Some(|p, a| f::faccessat2(p, a[0] as u32 as i32, a[1], a[2] as u32, a[3] as u32));
        // Descriptor-level calls (P3-T8 second part, ADR 0023).
        t[32] = Some(|p, a| f::dup(p, a[0] as u32 as i32));
        t[33] = Some(|p, a| f::dup3(p, a[0] as u32 as i32, a[1] as u32 as i32, 0, true));
        t[292] = Some(|p, a| {
            f::dup3(
                p,
                a[0] as u32 as i32,
                a[1] as u32 as i32,
                a[2] as u32 as u64,
                false,
            )
        });
        t[19] = Some(|p, a| f::readv(p, a[0] as u32 as i32, a[1], a[2], None, 0));
        t[295] = Some(|p, a| f::readv(p, a[0] as u32 as i32, a[1], a[2], Some(a[3] as i64), 0));
        t[327] = Some(|p, a| {
            let at = (a[3] as i64 != -1).then_some(a[3] as i64);
            f::readv(p, a[0] as u32 as i32, a[1], a[2], at, a[5] as u32)
        });
        t[18] = Some(|p, a| {
            if (a[3] as i64) < 0 {
                return Err(Errno::EINVAL);
            }
            f::pwritev(p, a[0] as u32 as i32, &[(a[1], a[2])], Some(a[3] as i64), 0)
        });
        t[296] =
            Some(|p, a| f::pwritev_user(p, a[0] as u32 as i32, a[1], a[2], Some(a[3] as i64), 0));
        t[328] = Some(|p, a| {
            let at = (a[3] as i64 != -1).then_some(a[3] as i64);
            f::pwritev_user(p, a[0] as u32 as i32, a[1], a[2], at, a[5] as u32)
        });
        t[137] = Some(|p, a| f::statfs(p, a[0], a[1]));
        // prctl (157): thread names (ADR 0024).
        t[157] = Some(|p, a| crate::procfs::prctl(p, a[0], a[1]));
        t[138] = Some(|p, a| f::fstatfs(p, a[0] as u32 as i32, a[1]));
        {
            use f::{XattrCall as C, XattrTarget as T};
            t[188] = Some(|p, a| {
                f::xattr(
                    p,
                    T::Path(a[0], true),
                    C::Set {
                        name: a[1],
                        size: a[3],
                        flags: a[4],
                    },
                )
            });
            t[189] = Some(|p, a| {
                f::xattr(
                    p,
                    T::Path(a[0], false),
                    C::Set {
                        name: a[1],
                        size: a[3],
                        flags: a[4],
                    },
                )
            });
            t[190] = Some(|p, a| {
                f::xattr(
                    p,
                    T::Fd(a[0] as u32 as i32),
                    C::Set {
                        name: a[1],
                        size: a[3],
                        flags: a[4],
                    },
                )
            });
            t[191] = Some(|p, a| f::xattr(p, T::Path(a[0], true), C::Get(a[1])));
            t[192] = Some(|p, a| f::xattr(p, T::Path(a[0], false), C::Get(a[1])));
            t[193] = Some(|p, a| f::xattr(p, T::Fd(a[0] as u32 as i32), C::Get(a[1])));
            t[194] = Some(|p, a| f::xattr(p, T::Path(a[0], true), C::List));
            t[195] = Some(|p, a| f::xattr(p, T::Path(a[0], false), C::List));
            t[196] = Some(|p, a| f::xattr(p, T::Fd(a[0] as u32 as i32), C::List));
            t[197] = Some(|p, a| f::xattr(p, T::Path(a[0], true), C::Remove(a[1])));
            t[198] = Some(|p, a| f::xattr(p, T::Path(a[0], false), C::Remove(a[1])));
            t[199] = Some(|p, a| f::xattr(p, T::Fd(a[0] as u32 as i32), C::Remove(a[1])));
        }
    }
    t[nr::EXECVE as usize] = Some(|p, a| execve(p, a[0], a[1], a[2]));
    t[nr::WAIT4 as usize] = Some(|p, a| wait4(p, a[0] as u32 as i32, a[1], a[2] as u32, a[3]));
    t[nr::GETPPID as usize] = Some(|p, _| Ok(u64::from(p.lock().parent_pid())));
    t[nr::GETTID as usize] =
        Some(|p, _| process::with_current_thread(p, |t| u64::from(t.tid)).ok_or(Errno::ESRCH));
    t[nr::KILL as usize] = Some(|p, a| kill(p, a[0] as u32 as i32, a[1] as u32 as i32));
    t[nr::TKILL as usize] = Some(|p, a| tgkill(p, None, a[0] as u32 as i32, a[1] as u32 as i32));
    t[nr::TGKILL as usize] = Some(|p, a| {
        tgkill(
            p,
            Some(a[0] as u32 as i32),
            a[1] as u32 as i32,
            a[2] as u32 as i32,
        )
    });
    t[nr::FUTEX as usize] = Some(|p, a| {
        let space = p.lock().space()?.id();
        crate::futex::futex(
            space,
            a[0],
            a[1] as u32,
            a[2] as u32,
            a[3],
            a[4],
            a[5] as u32,
        )
    });
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
        // exit ends the calling thread; exit_group the whole process.
        nr::EXIT => sched::exit_with((a[0] & 0xff) as i64),
        nr::EXIT_GROUP => match process::current() {
            Some(p) => process::exit_group(p, (a[0] & 0xff) as i64),
            None => sched::exit_with((a[0] & 0xff) as i64),
        },
        nr::CLONE => match process::current() {
            Some(p) => clone(&p, &call.frame, a),
            None => unimplemented(number, &a),
        },
        // Outside the table: it also needs the caller's stack pointer.
        // fork needs the caller's registers, which the table's handlers
        // do not get.
        nr::FORK => match process::current() {
            Some(p) => process::fork(&p, &call.frame),
            None => unimplemented(number, &a),
        },
        // rt_sigreturn replaces every register, so it needs the caller's
        // frame; its result is the restored RAX, not an errno.
        nr::RT_SIGRETURN => match process::current() {
            Some(p) => return crate::signal::rt_sigreturn(&p, &call.frame),
            None => unimplemented(number, &a),
        },
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

pub(crate) fn fault<T>(_: T) -> Errno {
    Errno::EFAULT
}

fn vm_error(error: AsError) -> Errno {
    match error {
        AsError::Vm(VmError::Invalid) => Errno::EINVAL,
        AsError::Vm(VmError::NoMemory) | AsError::OutOfMemory => Errno::ENOMEM,
        AsError::Vm(VmError::Exists) => Errno::EEXIST,
        AsError::Vm(VmError::WriteExec | VmError::NotExecutable | VmError::NotWritable) => {
            Errno::EACCES
        }
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
/// A pipe or eventfd is EINVAL here (as Linux's calls that need an inode
/// operation pipefs lacks); callers that answer otherwise use [`file_or`].
pub(crate) fn file(
    p: &Arc<IrqMutex<Process>>,
    fd: i32,
    required: Rights,
) -> Result<Arc<IrqMutex<OpenFile>>, Errno> {
    file_or(p, fd, required, Errno::EINVAL)
}

/// As [`file`], with `not_file` for a descriptor that holds no file (a
/// pipe or eventfd): ENOTDIR where a directory is wanted, ESPIPE for a
/// seek, ENODEV for a mapping.
pub(crate) fn file_or(
    p: &Arc<IrqMutex<Process>>,
    fd: i32,
    required: Rights,
    not_file: Errno,
) -> Result<Arc<IrqMutex<OpenFile>>, Errno> {
    match object(p, fd, required)? {
        Object::File(file) => Ok(file),
        _ => Err(not_file),
    }
}

/// The object behind `fd`, if the handle has `required`.
pub(crate) fn object(
    p: &Arc<IrqMutex<Process>>,
    fd: i32,
    required: Rights,
) -> Result<Object, Errno> {
    match p.lock().handles.check(fd, required) {
        Ok(object) => Ok(object.clone()),
        Err(Refusal::MissingRights { .. }) => {
            RIGHTS_REFUSALS.fetch_add(1, Ordering::Relaxed);
            Err(Errno::EBADF)
        }
        Err(Refusal::NoHandle) => Err(Errno::EBADF),
    }
}

/// Copies a NUL-terminated path from user memory, one page at a time so a
/// string ending just before an unmapped page is still read.
pub(crate) fn user_path(address: u64) -> Result<Vec<u8>, Errno> {
    user_string(address, PATH_MAX, Errno::ENAMETOOLONG)
}

/// A NUL-terminated string from user memory, read a page at a time. With
/// its NUL it must fit in `max` bytes, else `too_long`.
/// A NUL-terminated string of at most `max` bytes with its NUL
/// (ENAMETOOLONG past that).
pub(crate) fn user_string_max(address: u64, max: usize) -> Result<Vec<u8>, Errno> {
    user_string(address, max, Errno::ENAMETOOLONG)
}

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

/// wait4(2) (P3-T3). As Linux's kernel_wait4 (`kernel/exit.c` at v6.12):
/// options other than WNOHANG, WUNTRACED, WCONTINUED, __WNOTHREAD,
/// __WCLONE and __WALL are EINVAL; INT_MIN is ESRCH. -1 waits for any
/// child. Keel has no process groups yet and every process of a
/// compartment would be in one, so 0 (the caller's group) is any child,
/// and another negative pgid finds none (ECHILD). No child matching:
/// ECHILD. WNOHANG with none exited returns 0. Stopped and continued
/// children do not exist until signals do, so WUNTRACED and WCONTINUED
/// change nothing. The status is written if `status` is not NULL; a
/// `rusage` is written as all zero (no accounting yet).
fn wait4(
    p: &Arc<IrqMutex<Process>>,
    pid: i32,
    status: u64,
    options: u32,
    rusage: u64,
) -> SysResult {
    const WNOHANG: u32 = 1;
    const KNOWN: u32 = 1 | 2 | 8 | 0x2000_0000 | 0x4000_0000 | 0x8000_0000;
    /// sizeof(struct rusage) on x86-64.
    const RUSAGE_SIZE: usize = 144;
    if options & !KNOWN != 0 {
        return Err(Errno::EINVAL);
    }
    let which = match pid {
        i32::MIN => return Err(Errno::ESRCH),
        -1 | 0 => process::WaitFor::Any,
        pid if pid > 0 => process::WaitFor::Pid(pid as u32),
        _ => return Err(Errno::ECHILD),
    };
    let Some((child, wait_status)) = process::wait(p, which, options & WNOHANG == 0)? else {
        return Ok(0);
    };
    // Like Linux, the child is already reaped when a copy-out fails.
    if status != 0 {
        copy_to_user(status, &wait_status.to_le_bytes()).map_err(fault)?;
    }
    if rusage != 0 {
        copy_to_user(rusage, &[0u8; RUSAGE_SIZE]).map_err(fault)?;
    }
    Ok(u64::from(child))
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
    // /proc/<pid>/exe: the program's path from the root. A relative path
    // is taken from the working directory; symbolic links in it are not
    // resolved, where Linux reports the file's own path (ADR 0024).
    let exe_path = if path.first() == Some(&b'/') {
        path.clone()
    } else {
        let mut full = fs::with(|fs| fs.path_of(root, cwd)).unwrap_or_else(|_| b"/".to_vec());
        if full.last() != Some(&b'/') {
            full.push(b'/');
        }
        full.extend_from_slice(&path);
        full
    };
    loaded
        .space
        .attach_budget(compartment.memory().clone())
        .map_err(|_| Errno::ENOMEM)?;

    // No failure past this point: the old program is gone. Its other
    // threads end (Linux's de_thread); they leave as they exit.
    process::end_other_threads(p);
    let (old_space, closed) = {
        let mut process = p.lock();
        let old = process.space.replace(loaded.space.clone());
        process.brk_start = loaded.brk_start;
        process.brk = loaded.brk_start;
        if let Some(t) = process.threads.get_mut(&sched::current().0) {
            t.clear_child_tid = 0;
            // begin_new_exec: the thread is named after the file, as
            // given (`kbasename(bprm->filename)`).
            t.comm = process::comm_of(&path);
        }
        process.exe = exe_path.clone();
        process.signals.reset_for_exec();
        if let Some(t) = process.threads.get_mut(&sched::current().0) {
            t.signals.reset_for_exec();
        }
        (old, process.handles.take_close_on_exec())
    };
    // Closed outside the process lock, as close(2) does, with their
    // record locks (ADR 0023).
    for handle in closed {
        crate::fscalls::closed(p, handle);
    }
    // The thread switches to the new space here; only then may the old
    // one (still the CPU's until now) be dropped.
    let switched = sched::exec_current(loaded.space, loaded.entry, loaded.rsp);
    drop(old_space);
    if switched.is_err() {
        // Past the point of no return there is nothing to return to: as
        // Linux's bprm_execve (force_fatal_sig(SIGSEGV), `fs/exec.c`), the
        // process ends as if by SIGSEGV. Asked, not done here: the return
        // path ends the thread after this call's references are dropped.
        p.lock().killed_by.get_or_insert(11);
        sched::request_exit(sched::current(), 128 + 11);
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
            drop(process);
            crate::fscalls::fcntl_more(p, fd, cmd, arg)
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
/// read(2), pread64 and readv: `count` bytes into user memory at `buf`.
pub(crate) fn read_into(
    p: &Arc<IrqMutex<Process>>,
    fd: i32,
    buf: u64,
    count: u64,
    at: Option<u64>,
) -> SysResult {
    read_at(p, fd, buf, count, at)
}

fn read_at(
    p: &Arc<IrqMutex<Process>>,
    fd: i32,
    buf: u64,
    count: u64,
    at: Option<u64>,
) -> SysResult {
    let file = match object(p, fd, Rights::READ)? {
        Object::File(file) => file,
        // Pipes and eventfds have no position (`stream_open`, and no
        // FMODE_PREAD for an anonymous inode): pread ESPIPE.
        _ if at.is_some() => return Err(Errno::ESPIPE),
        other => return crate::ready::read(&other, &[(buf, count)]).unwrap_or(Err(Errno::EINVAL)),
    };
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
                let n = fs::with(|fs| {
                    let n = fs.read(f.node, from, &mut chunk[..want])?;
                    // file_accessed (relatime).
                    fs.touch_atime(f.node);
                    Ok(n)
                })?;
                // Stores through shared mappings are the newest data.
                keel_hal::vm::shared_read(f.node, from, &mut chunk[..n]);
                if at.is_none() {
                    f.offset += n as u64;
                }
                n
            }
            Kind::Directory => return Err(Errno::EISDIR),
            // A descriptor never names a symbolic link itself (open
            // follows it, O_NOFOLLOW refuses it).
            Kind::Symlink | Kind::Socket => return Err(Errno::EINVAL),
            // No lock held: a console read can wait for the keyboard.
            Kind::Device(device) => fs::device_read(device, &mut chunk[..want])?,
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
pub(crate) fn quota_of(p: &Arc<IrqMutex<Process>>) -> Option<Arc<keel_core::compartment::Quota>> {
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
    write_at(file, buf, count, quota, None, None)
}

/// write(2), and with `at` the positional writes (pwrite64, pwritev): at
/// the file position (moving it) or at `at` (leaving it). `append`
/// overrides the description's O_APPEND (pwritev2's RWF_APPEND and
/// RWF_NOAPPEND); with O_APPEND or RWF_APPEND a file is written at its
/// end, even by a positional write, as Linux does.
pub(crate) fn write_at(
    file: &Arc<IrqMutex<OpenFile>>,
    buf: u64,
    count: u64,
    quota: Option<&Arc<keel_core::compartment::Quota>>,
    at: Option<u64>,
    append: Option<bool>,
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
            if let Some(target) = &f.comm {
                // /proc/.../comm renames a thread (ADR 0024).
                // comm_write takes the first bytes and reports the whole
                // count as written.
                return crate::procfs::write_comm(target, &chunk[..want]).map(|_| count as u64);
            }
            match f.kind {
                Kind::File => {
                    let append = append.unwrap_or(f.append);
                    let offset = match at {
                        Some(at) => at.saturating_add(done as u64),
                        None => f.offset,
                    };
                    let node = f.node;
                    let result = fs::with(|fs| {
                        let at = if append { fs.stat(node)?.size } else { offset };
                        let n = fs.write_as(node, at, &chunk[..want], quota)?;
                        Ok((n, at + n as u64))
                    });
                    match result {
                        Ok((n, end)) => {
                            // Shared mappings of the file see the write.
                            keel_hal::vm::shared_write(node, end - n as u64, &chunk[..n]);
                            if at.is_none() {
                                f.offset = end;
                            }
                            n
                        }
                        // ENOSPC and the like: report what was written.
                        Err(error) if done == 0 => return Err(error),
                        Err(_) => break,
                    }
                }
                Kind::Symlink | Kind::Socket => return Err(Errno::EINVAL),
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
    let file = match object(p, fd, Rights::WRITE)? {
        Object::File(file) => file,
        other => {
            return crate::ready::write(p, &other, &[(buf, count)]).unwrap_or(Err(Errno::EINVAL));
        }
    };
    write_to(&file, buf, count, quota_of(p).as_ref())
}

fn writev(p: &Arc<IrqMutex<Process>>, fd: i32, iov: u64, count: u64) -> SysResult {
    let target = object(p, fd, Rights::WRITE)?;
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
    let file = match target {
        Object::File(file) => file,
        // A pipe takes the vectors as one write (atomic up to PIPE_BUF).
        other => return crate::ready::write(p, &other, &vectors).unwrap_or(Err(Errno::EINVAL)),
    };
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
    // Closing needs no right: the handle is the caller's own. Its record
    // locks on the file go too (ADR 0023); the handle is dropped outside
    // the process lock.
    let handle = p.lock().handles.close(fd)?;
    crate::fscalls::closed(p, handle);
    Ok(0)
}

fn fstat(p: &Arc<IrqMutex<Process>>, fd: i32, buf: u64) -> SysResult {
    let node = match object(p, fd, Rights::STAT)? {
        Object::File(file) => file.lock().node,
        other => {
            let b = crate::ready::stat_bytes(&other).ok_or(Errno::EINVAL)?;
            copy_to_user(buf, &b).map_err(fault)?;
            return Ok(0);
        }
    };
    let stat = fs::with(|fs| fs.stat(node))?;
    copy_to_user(buf, &stat_bytes(&stat)).map_err(fault)?;
    Ok(0)
}

fn openat(p: &Arc<IrqMutex<Process>>, dirfd: i32, path: u64, flags: u64, mode: u64) -> SysResult {
    if flags & !O_KNOWN != 0 || flags & O_ACCMODE == O_ACCMODE {
        return Err(Errno::EINVAL);
    }
    let path = user_path(path)?;
    if let Some(hit) = crate::procfs::open(p, &path, flags) {
        return open_proc(p, hit?, flags);
    }
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
        // A pipe or eventfd is not a directory, whatever its rights.
        file_or(p, dirfd, Rights::NONE, Errno::ENOTDIR)?;
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
    let umask = crate::fscalls::umask_of(p);
    // O_EXCL with O_CREAT, and O_NOFOLLOW, do not follow a symbolic link
    // as the last component (open(2); `open_last_lookups`).
    let follow = flags & O_NOFOLLOW == 0 && !(flags & O_CREAT != 0 && flags & O_EXCL != 0);
    let node = fs::with(|fs| {
        let node = match fs.resolve(root, base, &path, follow) {
            Ok(_) if flags & O_CREAT != 0 && flags & O_EXCL != 0 => return Err(Errno::EEXIST),
            Ok(node) => node,
            Err(Errno::ENOENT) if flags & O_CREAT != 0 => {
                // "name/" cannot be created as a file (EISDIR, as
                // `open_last_lookups` for O_CREAT with a trailing slash).
                if keel_core::vfs::has_trailing_slash(&path) {
                    return Err(Errno::EISDIR);
                }
                let (dir, name) = fs.lookup_parent(root, base, &path)?;
                fs.create_file_as(dir, name, (mode as u32) & 0o7777 & !umask, quota.as_ref())?
            }
            Err(error) => return Err(error),
        };
        let kind = fs.kind(node)?;
        // O_NOFOLLOW on a symbolic link: ELOOP (open(2)).
        if kind == Kind::Symlink {
            return Err(Errno::ELOOP);
        }
        if kind == Kind::Directory && (write || flags & O_CREAT != 0) {
            return Err(Errno::EISDIR);
        }
        if kind != Kind::Directory && flags & O_DIRECTORY != 0 {
            return Err(Errno::ENOTDIR);
        }
        // A socket's name cannot be opened (`bad_sock_fops`: ENXIO).
        if kind == Kind::Socket {
            return Err(Errno::ENXIO);
        }
        if kind == Kind::File && write && flags & O_TRUNC != 0 {
            fs.set_len_as(node, 0, quota.as_ref())?;
            keel_hal::vm::shared_truncate(node, 0);
        }
        // The open file description holds the node (ADR 0022); pinned
        // here, under the same lock as the lookup, so it cannot go between.
        fs.pin(node);
        Ok((node, kind))
    })?;
    let (node, kind) = node;
    let open = OpenFile {
        node,
        kind,
        offset: 0,
        append: flags & O_APPEND != 0,
        // f_flags: O_LARGEFILE added on 64-bit (`force_o_largefile`),
        // O_CLOEXEC not kept (`build_open_flags`), and O_CREAT, O_EXCL,
        // O_NOCTTY, O_TRUNC cleared after the open (`do_dentry_open`).
        status: (flags | O_LARGEFILE) & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_CLOEXEC),
        comm: None,
    };
    let handle = Handle {
        object: Object::File(Arc::new(IrqMutex::new(open))),
        rights: file_rights(read, write, kind),
        close_on_exec: flags & O_CLOEXEC != 0,
    };
    let fd = p.lock().handles.insert(handle)?;
    Ok(fd as u64)
}

/// openat of a `/proc` path (ADR 0024): a procfs file as a snapshot in a
/// detached, pinned tmpfs node; a followed `exe` link as the program
/// itself, read only (a running program is not opened for writing:
/// ETXTBSY, as Linux's `deny_write_access`).
fn open_proc(p: &Arc<IrqMutex<Process>>, hit: crate::procfs::Hit, flags: u64) -> SysResult {
    let access = flags & O_ACCMODE;
    let (read, write) = (access != O_WRONLY, access != O_RDONLY);
    let (node, comm) = match hit {
        crate::procfs::Hit::Node(node) => {
            let (data, comm) = crate::procfs::contents(p, node)?;
            let perms = node.permissions();
            (fs::with(|fs| fs.create_detached(data, perms))?, comm)
        }
        crate::procfs::Hit::Real(ino) => {
            if write {
                return Err(Errno::ETXTBSY);
            }
            fs::with(|fs| {
                fs.pin(ino);
                Ok(())
            })?;
            (ino, None)
        }
    };
    let open = OpenFile {
        node,
        kind: Kind::File,
        offset: 0,
        append: false,
        status: (flags | O_LARGEFILE) & !(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_CLOEXEC),
        comm,
    };
    let handle = Handle {
        object: Object::File(Arc::new(IrqMutex::new(open))),
        rights: file_rights(read, write, Kind::File),
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
    // MAP_SHARED and MAP_SHARED_VALIDATE (which differ only in refusing
    // unknown flags, which Keel refuses for both: SR-10) map a file's own
    // pages (ADR 0021). Shared anonymous memory (and shared /dev/zero,
    // which Linux makes the same) is not supported yet: EINVAL.
    let shared = match flags & MAP_TYPE {
        MAP_PRIVATE => false,
        MAP_SHARED | MAP_SHARED_VALIDATE if flags & MAP_ANONYMOUS == 0 => true,
        _ => return Err(Errno::EINVAL),
    };
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
        // A pipe or eventfd has no mmap operation: do_mmap ENODEV.
        let open = file_or(p, fd, Rights::NONE, Errno::ENODEV)?;
        let (may_read, may_exec, may_write) = {
            let process = p.lock();
            (
                process.handles.check(fd, Rights::READ).is_ok(),
                process.handles.check(fd, Rights::MAP_EXEC).is_ok(),
                process.handles.check(fd, Rights::WRITE).is_ok(),
            )
        };
        // mmap(2): "EACCES ... MAP_SHARED was requested and PROT_WRITE is
        // set, but fd is not open in read/write (O_RDWR) mode".
        if shared && prot.write && !may_write {
            RIGHTS_REFUSALS.fetch_add(1, Ordering::Relaxed);
            return Err(Errno::EACCES);
        }
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
                    object: node,
                    offset,
                    may_exec,
                    shared,
                    may_write,
                });
            }
            Kind::Device(Device::Zero) if !shared => {}
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
    let space = p.lock().space()?;
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
    let n = fs::with(|fs| {
        if offset >= fs.stat(ino)?.size {
            return Ok(None);
        }
        fs.read(ino, offset, page).map(Some)
    })
    .ok()
    .flatten()?;
    // A private page first touched after a shared mapping wrote the file
    // gets those stores, as read(2) would (ADR 0021).
    keel_hal::vm::shared_read(object, offset, &mut page[..n]);
    Some(n)
}

/// ftruncate(2): sets the length of the regular file open on `fd`,
/// charged to the caller's compartment quota as a write is (ENOSPC), and
/// shared mappings of it follow (`shared_truncate`). As Linux's
/// do_sys_ftruncate and do_ftruncate (`fs/open.c`): a negative length
/// EINVAL, no handle EBADF, not a regular file or not open for writing
/// EINVAL.
fn ftruncate(p: &Arc<IrqMutex<Process>>, fd: i32, length: i64) -> SysResult {
    if length < 0 {
        return Err(Errno::EINVAL);
    }
    let open = file(p, fd, Rights::NONE)?;
    if p.lock().handles.check(fd, Rights::WRITE).is_err() {
        return Err(Errno::EINVAL);
    }
    let (kind, node) = {
        let f = open.lock();
        (f.kind, f.node)
    };
    if kind != Kind::File {
        return Err(Errno::EINVAL);
    }
    let quota = quota_of(p);
    fs::with(|fs| fs.set_len_as(node, length as u64, quota.as_ref()))?;
    keel_hal::vm::shared_truncate(node, length as u64);
    Ok(0)
}

fn munmap(p: &Arc<IrqMutex<Process>>, address: u64, length: u64) -> SysResult {
    if !address.is_multiple_of(PAGE) {
        return Err(Errno::EINVAL);
    }
    let length = page_length(length).map_err(|_| Errno::EINVAL)?;
    let space = p.lock().space()?;
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
    let space = p.lock().space()?;
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
        (process.space(), process.brk_start, process.brk)
    };
    let Ok(space) = space else {
        return current;
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
    /// FIONREAD (`include/uapi/asm-generic/ioctls.h`): an int, the bytes
    /// waiting in a pipe (`pipe_ioctl`).
    const FIONREAD: u32 = 0x541B;
    /// SIOCOUTQ (TIOCOUTQ): a socket's bytes sent and not yet read.
    const SIOCOUTQ: u32 = 0x5411;
    let file = match object(p, fd, Rights::STAT)? {
        Object::File(file) => file,
        // `unix_ioctl`: SIOCINQ (FIONREAD) and SIOCOUTQ; others ENOTTY.
        Object::Socket(sock) => {
            let n = match request {
                FIONREAD => sock.inq()?,
                SIOCOUTQ => sock.outq(),
                _ => return Err(Errno::ENOTTY),
            };
            let n = i32::try_from(n).unwrap_or(i32::MAX);
            copy_to_user(argument, &n.to_le_bytes()).map_err(fault)?;
            return Ok(0);
        }
        other => {
            let waiting = crate::ready::bytes_waiting(&other);
            return match (request, waiting) {
                (FIONREAD, Some(n)) => {
                    let n = i32::try_from(n).unwrap_or(i32::MAX);
                    copy_to_user(argument, &n.to_le_bytes()).map_err(fault)?;
                    Ok(0)
                }
                // pipe_ioctl's default and eventfd's absent ioctl.
                _ => Err(Errno::ENOTTY),
            };
        }
    };
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

/// set_tid_address(2): the calling thread's clear_child_tid; returns its
/// TID (Linux's task_pid_vnr, `kernel/fork.c`).
fn set_tid_address(p: &Arc<IrqMutex<Process>>, address: u64) -> u64 {
    process::with_current_thread(p, |t| {
        t.clear_child_tid = address;
        u64::from(t.tid)
    })
    .unwrap_or(0)
}

/// clone(2), x86-64 argument order (flags, stack, parent_tid, child_tid,
/// tls: `kernel/fork.c`, no CLONE_BACKWARDS on x86-64). As copy_process:
/// CLONE_THREAD needs CLONE_SIGHAND and CLONE_SIGHAND needs CLONE_VM
/// (EINVAL). Without CLONE_VM it is fork (the exit signal in the low byte
/// is ignored: nothing is delivered yet), with the child on `stack` if
/// given. With CLONE_VM: a thread, if the flags are within the set
/// `process::clone_thread` supports; anything else (vfork's CLONE_VFORK,
/// CLONE_VM without CLONE_THREAD, namespaces, ...) is EINVAL for now.
fn clone(
    p: &Arc<IrqMutex<Process>>,
    frame: &keel_hal::arch::x86_64::idt::TrapFrame,
    a: [u64; 6],
) -> SysResult {
    use process::clone_flags::*;
    let (flags, stack, parent_tid, child_tid, tls) = (a[0] & 0xffff_ffff, a[1], a[2], a[3], a[4]);
    let flags = flags & !CSIGNAL;
    if (flags & CLONE_THREAD != 0 && flags & CLONE_SIGHAND == 0)
        || (flags & CLONE_SIGHAND != 0 && flags & CLONE_VM == 0)
    {
        return Err(Errno::EINVAL);
    }
    if flags & CLONE_VM == 0 {
        if flags & !CLONE_DETACHED != 0 {
            return Err(Errno::EINVAL);
        }
        let mut registers = *frame;
        if stack != 0 {
            registers.rsp = stack;
        }
        return process::fork(p, &registers);
    }
    const THREAD: u64 = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
    const OPTIONAL: u64 = CLONE_SYSVSEM
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_CHILD_SETTID
        | CLONE_DETACHED;
    if flags & THREAD != THREAD || flags & !(THREAD | OPTIONAL) != 0 {
        return Err(Errno::EINVAL);
    }
    process::clone_thread(p, frame, flags, stack, parent_tid, child_tid, tls)
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
    let old = {
        let mut process = p.lock();
        let old = process.signals.sigaction(sig, new)?;
        // do_sigaction: a signal set to be ignored is dropped wherever it
        // is pending ("POSIX 3.3.1.3: Setting a signal action to SIG_IGN
        // for a signal that is pending shall cause the pending signal to
        // be discarded, whether or not it is blocked"), SIGCHLD,
        // SIGWINCH and SIGURG with SIG_DFL too.
        if let Some(action) = new
            && (action.handler == keel_core::signal::SIG_IGN
                || (action.handler == keel_core::signal::SIG_DFL
                    && keel_core::signal::default_action(sig)
                        == keel_core::signal::DefaultAction::Ignore))
        {
            let bit = keel_core::signal::sigmask(sig);
            process.pending.discard(bit);
            for t in process.threads.values_mut() {
                t.signals.pending.discard(bit);
            }
        }
        old
    };
    if oldact != 0 {
        copy_to_user(oldact, &old.to_bytes()).map_err(fault)?;
    }
    Ok(0)
}

/// rt_sigprocmask(2): the calling thread's blocked mask. A signal it
/// unblocks that is pending is delivered as the call returns.
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
    let old = process::with_current_thread(p, |t| t.signals.sigprocmask(how, new))
        .ok_or(Errno::ESRCH)??;
    if oldset != 0 {
        copy_to_user(oldset, &old.to_le_bytes()).map_err(fault)?;
    }
    Ok(0)
}

/// sigaltstack(2): the calling thread's alternate signal stack. `user_rsp` decides
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
    let old = process::with_current_thread(p, |t| t.signals.sigaltstack(new, user_rsp))
        .ok_or(Errno::ESRCH)??;
    if old_ss != 0 {
        copy_to_user(old_ss, &old.to_bytes()).map_err(fault)?;
    }
    Ok(0)
}

/// kill(2) (P3-T6): sends `signal` to the process `pid` of the caller's
/// compartment (ESRCH if there is none: a PID names a process only in its
/// own compartment, ADR 0014), with `si_code` SI_USER and the caller's PID
/// as `si_pid`. Signal 0 only checks that the process exists. EINVAL
/// outside 0 to 64. Process groups (PID 0 or negative) are ESRCH for now:
/// they arrive with P3-T7.
fn kill(p: &Arc<IrqMutex<Process>>, pid: i32, signal: i32) -> SysResult {
    use keel_core::signal::{NSIG, SI_USER, SigInfo};
    if !(0..=NSIG as i32).contains(&signal) {
        return Err(Errno::EINVAL);
    }
    if pid <= 0 {
        return Err(Errno::ESRCH);
    }
    let (compartment, me) = {
        let process = p.lock();
        (process.member.compartment().clone(), process.pid())
    };
    let target = process::find_in(&compartment, pid as u32).ok_or(Errno::ESRCH)?;
    if signal != 0 {
        crate::signal::send_to_process(&target, SigInfo::from_process(signal, SI_USER, me, 0));
    }
    Ok(0)
}

/// tgkill(2) and, with `tgid` None, tkill(2): sends `signal` to the thread
/// `tid` (of the process `tgid`) in the caller's compartment, with
/// `si_code` SI_TKILL. EINVAL for a TID or TGID not above 0 or a signal
/// outside 0 to 64; ESRCH if no such thread.
fn tgkill(p: &Arc<IrqMutex<Process>>, tgid: Option<i32>, tid: i32, signal: i32) -> SysResult {
    use keel_core::signal::{NSIG, SI_TKILL, SigInfo};
    if !(0..=NSIG as i32).contains(&signal) || tid <= 0 || tgid.is_some_and(|g| g <= 0) {
        return Err(Errno::EINVAL);
    }
    let (compartment, me) = {
        let process = p.lock();
        (process.member.compartment().clone(), process.pid())
    };
    let (target, thread) = process::find_thread(&compartment, tid as u32).ok_or(Errno::ESRCH)?;
    if tgid.is_some_and(|g| target.lock().pid() != g as u32) {
        return Err(Errno::ESRCH);
    }
    if signal != 0 {
        crate::signal::send_to_thread(
            &target,
            thread,
            SigInfo::from_process(signal, SI_TKILL, me, 0),
        );
    }
    Ok(0)
}
