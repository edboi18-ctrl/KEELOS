//! Escape suite: what the kernel never does and memory it must not leak
//! (ADR 0047).
//!
//! - 1-9: every never-implemented call (spec section 7): ENOSYS.
//! - 10-19: forbidden `clone` flags: each namespace flag, alone and all
//!   together, EINVAL; and the flag combinations clone(2) itself refuses.
//! - 20-29: forbidden `prctl` options (each would change what the
//!   process may do, or what may be done to it) and unknown `arch_prctl`
//!   codes: EINVAL.
//! - 30-39: the 32-bit entries, `int 0x80` and `sysenter`, in children:
//!   each ends by a signal, never as a system call.
//! - 40-59: writable-and-executable memory (SR-12): EACCES from mmap and
//!   mprotect, anonymous and file mappings, private and shared.
//! - 60-79: memory it is given is zero: fresh anonymous mappings, a
//!   mapping in place of one it filled, memory a child filled before it
//!   exited, a memfd grown by truncation, and the tail of a file's last
//!   page.
//!
//! Exit 0, or the number of the check that failed.
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, NEVER_IMPLEMENTED, PROT_EXEC, PROT_READ, PROT_WRITE, Region};
use keel_sectests::{EACCES, EINVAL, ENOSYS, fail, in_child};

const ME: &[u8] = b"esccalls";
const MAP_SHARED: u64 = 0x01;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const RWX: u64 = PROT_READ | PROT_WRITE | PROT_EXEC;
const SIGILL: i32 = 4;
const SIGSEGV: i32 = 11;

/// clone(2)'s namespace flags, Linux v6.12 `include/uapi/linux/sched.h`.
const CLONE_NEW: [u64; 7] = [
    0x0002_0000, // CLONE_NEWNS
    0x0200_0000, // CLONE_NEWCGROUP
    0x0400_0000, // CLONE_NEWUTS
    0x0800_0000, // CLONE_NEWIPC
    0x1000_0000, // CLONE_NEWUSER
    0x2000_0000, // CLONE_NEWPID
    0x4000_0000, // CLONE_NEWNET
];

/// prctl options Keel does not have, Linux v6.12
/// `include/uapi/linux/prctl.h`: each changes the process's privileges,
/// its handling by other processes, or kernel behaviour for it.
const PRCTL: [u64; 18] = [
    1,           // PR_SET_PDEATHSIG
    4,           // PR_SET_DUMPABLE
    8,           // PR_SET_KEEPCAPS
    22,          // PR_SET_SECCOMP
    24,          // PR_CAPBSET_DROP
    26,          // PR_SET_TSC
    28,          // PR_SET_SECUREBITS
    29,          // PR_SET_TIMERSLACK
    35,          // PR_SET_MM
    36,          // PR_SET_CHILD_SUBREAPER
    38,          // PR_SET_NO_NEW_PRIVS
    41,          // PR_SET_THP_DISABLE
    45,          // PR_SET_FP_MODE
    47,          // PR_CAP_AMBIENT
    53,          // PR_SET_SPECULATION_CTRL
    57,          // PR_SET_IO_FLUSHER
    59,          // PR_SET_SYSCALL_USER_DISPATCH
    0x5961_6d61, // PR_SET_PTRACER
];

/// arch_prctl codes other than the FS and GS ones, Linux v6.12
/// `arch/x86/include/uapi/asm/prctl.h`, and 0.
const ARCH_PRCTL: [u64; 12] = [
    0, 0x1011, 0x1012, 0x1021, 0x1022, 0x1023, 0x2001, 0x2002, 0x2003, 0x4002, 0x5001, 0x5003,
];

/// Whether every byte of `region` reads as zero.
fn all_zero(region: &Region) -> bool {
    (0..region.length() / 8).all(|i| region.read_u64(i * 8) == Some(0))
}

fn fill(region: &Region, byte: u8) {
    let word = u64::from_le_bytes([byte; 8]);
    for i in 0..region.length() / 8 {
        region.write_u64(i * 8, word);
    }
}

fn main(_: &Startup) -> i32 {
    // 1-9: never implemented.
    for &nr in NEVER_IMPLEMENTED {
        let r = sys::never_implemented(nr);
        if r != ENOSYS {
            return fail(ME, 1, (nr as i64) << 16 | -r);
        }
    }

    // 10-19: clone.
    for (i, &flag) in CLONE_NEW.iter().enumerate() {
        let r = sys::clone_namespace(flag);
        if r != EINVAL {
            return fail(ME, 10 + i as i32, r);
        }
    }
    let r = sys::clone_namespace(CLONE_NEW.iter().fold(0, |a, f| a | f));
    if r != EINVAL {
        return fail(ME, 17, r);
    }
    // CLONE_THREAD without CLONE_SIGHAND, CLONE_SIGHAND without CLONE_VM.
    for flags in [0x1_0000u64 | 0x100, 0x800] {
        let r = sys::clone_refused(flags);
        if r != EINVAL {
            return fail(ME, 18, r);
        }
    }

    // 20-29: prctl and arch_prctl.
    for &option in &PRCTL {
        let r = sys::prctl_option(option);
        if r != EINVAL {
            return fail(ME, 20, (option as i64) << 16 | -r);
        }
    }
    for &code in &ARCH_PRCTL {
        let r = sys::arch_prctl_option(code);
        if r != EINVAL {
            return fail(ME, 21, (code as i64) << 16 | -r);
        }
    }

    // 30-39: the 32-bit entries.
    let int80 = in_child(|| {
        sys::int80();
        0
    });
    if int80.map(|s| s & 0x7f) != Ok(SIGSEGV) {
        return fail(ME, 30, keel_sectests::outcome(int80));
    }
    let sysenter = in_child(|| {
        sys::sysenter();
        0
    });
    if !matches!(sysenter.map(|s| s & 0x7f), Ok(SIGSEGV | SIGILL)) {
        return fail(ME, 31, keel_sectests::outcome(sysenter));
    }

    // 40-59: writable and executable.
    let r = Region::map(4096, RWX).err().unwrap_or(0);
    if r != EACCES {
        return fail(ME, 40, r);
    }
    for (i, prot) in [RWX, PROT_WRITE | PROT_EXEC].into_iter().enumerate() {
        let r = sys::mmap_raw(4096, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1);
        if r != EACCES {
            return fail(ME, 41 + i as i32, r);
        }
        // Shared anonymous memory is not implemented (ADR 0021): EINVAL,
        // whatever the protection.
        let r = sys::mmap_raw(4096, prot, MAP_SHARED | MAP_ANONYMOUS, -1);
        if r != EINVAL {
            return fail(ME, 43 + i as i32, r);
        }
    }
    let Ok(rw) = Region::map(8192, PROT_READ | PROT_WRITE) else {
        return fail(ME, 45, -1);
    };
    rw.write(0, b"\xc3");
    for (i, prot) in [RWX, PROT_WRITE | PROT_EXEC].into_iter().enumerate() {
        let r = rw.protect(prot);
        if r != EACCES {
            return fail(ME, 46 + i as i32, r);
        }
        let r = rw.protect_range(4096, 4096, prot);
        if r != EACCES {
            return fail(ME, 48 + i as i32, r);
        }
    }
    // Executable, then writable as well: refused the other way round too.
    if rw.protect(PROT_READ | PROT_EXEC) != 0 {
        return fail(ME, 50, -1);
    }
    let r = rw.protect(RWX);
    if r != EACCES {
        return fail(ME, 51, r);
    }
    // A file: a memfd with a page of data, mapped private and shared.
    let memfd = sys::memfd_create(c"esc", 0);
    if memfd < 0 || sys::pwrite(memfd as i32, &[0xc3; 4096], 0) != 4096 {
        return fail(ME, 52, memfd);
    }
    let memfd = memfd as i32;
    let r = Region::map_file_private(4096, RWX, memfd, 0)
        .err()
        .unwrap_or(0);
    if r != EACCES {
        return fail(ME, 53, r);
    }
    let r = Region::map_file_shared(4096, RWX, memfd, 0)
        .err()
        .unwrap_or(0);
    if r != EACCES {
        return fail(ME, 54, r);
    }
    for (i, map) in [Region::map_file_private, Region::map_file_shared]
        .into_iter()
        .enumerate()
    {
        let Ok(m) = map(4096, PROT_READ | PROT_WRITE, memfd, 0) else {
            return fail(ME, 55 + i as i32, -1);
        };
        let r = m.protect(RWX);
        if r != EACCES {
            return fail(ME, 57 + i as i32, r);
        }
        m.unmap();
    }

    // 60-79: fresh memory is zero.
    const MIB: u64 = 1 << 20;
    let Ok(fresh) = Region::map(MIB, PROT_READ | PROT_WRITE) else {
        return fail(ME, 60, -1);
    };
    if !all_zero(&fresh) {
        return fail(ME, 61, -1);
    }
    fill(&fresh, 0xa5);
    let (_, _) = fresh.unmap();
    let Ok(again) = Region::map(MIB, PROT_READ | PROT_WRITE) else {
        return fail(ME, 62, -1);
    };
    if !all_zero(&again) {
        return fail(ME, 63, -1);
    }
    again.unmap();
    // A child fills 4 MiB and exits; its frames are free again, and what
    // this process is given next is zero.
    let filled = in_child(|| match Region::map(4 * MIB, PROT_READ | PROT_WRITE) {
        Ok(r) => {
            fill(&r, 0x5a);
            0
        }
        Err(_) => 1,
    });
    if filled != Ok(0) {
        return fail(ME, 64, keel_sectests::outcome(filled));
    }
    let Ok(after) = Region::map(4 * MIB, PROT_READ | PROT_WRITE) else {
        return fail(ME, 65, -1);
    };
    if !all_zero(&after) {
        return fail(ME, 66, -1);
    }
    after.unmap();
    // A memfd: filled, cut to nothing, grown again: zero.
    let f = sys::memfd_create(c"fresh", 0);
    if f < 0 {
        return fail(ME, 67, f);
    }
    let f = f as i32;
    if sys::pwrite(f, &[0xee; 8192], 0) != 8192 || sys::ftruncate(f, 0) != 0 {
        return fail(ME, 68, -1);
    }
    if sys::ftruncate(f, 8192) != 0 {
        return fail(ME, 69, -1);
    }
    let mut buf = [0xffu8; 8192];
    if sys::pread(f, &mut buf, 0) != 8192 || buf.iter().any(|&b| b != 0) {
        return fail(ME, 70, -1);
    }
    // The tail of a file's last page, past its end, maps as zero.
    if sys::ftruncate(f, 0) != 0
        || sys::pwrite(f, &[0xee; 8192], 0) != 8192
        || sys::ftruncate(f, 100) != 0
    {
        return fail(ME, 71, -1);
    }
    let Ok(tail) = Region::map_file_private(4096, PROT_READ, f, 0) else {
        return fail(ME, 72, -1);
    };
    let mut page = [0u8; 4096];
    tail.read(0, &mut page);
    if page[..100].iter().any(|&b| b != 0xee) || page[100..].iter().any(|&b| b != 0) {
        return fail(ME, 73, -1);
    }
    0
}

keel_rt::main!(main);
