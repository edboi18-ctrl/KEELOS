//! Random system calls, for the in-guest kernel fuzzer (Phase 1 security
//! acceptance item 6: one hour of random-syscall fuzzing, no kernel
//! panic), since P3-S8 inside a compartment (ADR 0047).
//!
//! The kernel is what is under test. This program's only job is to keep
//! making calls the kernel must survive: mostly the calls Keel
//! implements, with arguments drawn from values that reach their checks
//! (descriptors, sizes, flags, pointers into a scratch region it owns,
//! hostile addresses, page-aligned addresses in an arena), plus fully
//! random numbers and arguments.
//!
//! **Keel only.** Random system calls on a real Linux host could reboot
//! it, kill processes or delete files, so [`run`] refuses to start unless
//! `/etc/keel-release` exists (Keel's initramfs has it; Linux has no such
//! file).

use crate::sys::{self, AT_FDCWD, O_RDONLY, Region};
use crate::syscall6;

/// SplitMix64 (Sebastiano Vigna, https://prng.di.unimi.it/splitmix64.c,
/// public domain): constants 0x9e3779b97f4a7c15, 0xbf58476d1ce4e5b9,
/// 0x94d049bb133111eb, shifts 30, 27, 31. Not for secrets; it makes a run
/// reproducible from its seed.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[(self.next_u64() % items.len() as u64) as usize]
    }
}

/// Linux x86-64 numbers of the calls Keel implements (docs/syscalls.md),
/// chosen most of the time so the fuzzer gets past the ENOSYS check.
const IMPLEMENTED: [u64; 26] = [
    0, 1, 2, 3, 5, 7, 9, 10, 11, 12, 13, 14, 16, 17, 20, 39, 61, 72, 110, 131, 158, 186, 218, 228,
    257, 318,
];
const NR_POLL: u64 = 7;
const NR_OPENAT: u64 = 257;
/// exit and exit_group end the run early; they are made once, at the end.
/// execve would too, if a random path ever named a program: it is never
/// made here (hostile executables have their own test). Nor are clone
/// and vfork: a child sharing this program's memory would run on its
/// stack and change what the parent's Rust code relies on (fork has its
/// own tests). fork (57) is made: since P3-S8 the fuzzer runs inside a
/// compartment whose process limit bounds the children, and each child,
/// a copy, goes on fuzzing with a seed of its own; the kernel's harness
/// kills what is left when the first process ends. Nor kill (a random
/// SIGKILL could end the fuzzer itself, a SIGSTOP stop it for good) or
/// futex (a FUTEX_WAIT whose value happens to match would block for ever,
/// which the harness counts as a hung run); both have their own tests.
/// Nor rt_sigreturn (it would load registers from whatever lies on the
/// stack and jump there) or tkill and tgkill (a random fatal signal, as
/// kill); signals have their own test (exec.signals).
const NR_EXIT: u64 = 60;
const NR_EXIT_GROUP: u64 = 231;
const NR_EXECVE: u64 = 59;
const NR_FORK: u64 = 57;
const NR_RT_SIGRETURN: u64 = 15;
const NR_TKILL: u64 = 200;
const NR_TGKILL: u64 = 234;
const NEVER: [u64; 10] = [
    56,
    58,
    NR_EXECVE,
    62,
    NR_EXIT,
    202,
    NR_EXIT_GROUP,
    NR_RT_SIGRETURN,
    NR_TKILL,
    NR_TGKILL,
];

/// Size of the scratch region whose address the fuzzer hands out.
const SCRATCH: u64 = 64 * 1024;
/// Where page-aligned "address" arguments point: a 1 GiB window far from
/// this program, for mmap(MAP_FIXED), munmap and mprotect to play in.
const ARENA: u64 = 0x2000_0000_0000;

const HOSTILE: [u64; 7] = [
    0,
    0x1000,
    0xffff_8000_0000_0000,
    0xffff_ffff_ffff_f000,
    0x8000_0000_0000_0000,
    0x0000_7fff_ffff_f000,
    u64::MAX,
];

/// Paths for openat: devices (never `/dev/console`, whose reads wait for
/// a line), directories, files the fuzzer may create, odd forms.
const PATHS: [&[u8]; 13] = [
    b"/dev/null\0",
    b"/dev/zero\0",
    b"/dev/urandom\0",
    b"/\0",
    b"/dev\0",
    b"/test\0",
    b"/test/startup\0",
    b"/etc/keel-release\0",
    b"/fuzz-a\0",
    b"/fuzz-dir/b\0",
    b"../../..\0",
    b"\0",
    b"/dev/null/x\0",
];

/// The memory this program itself uses: its image (around `code`) and its
/// stack (below `stack`). No argument may name it, so the kernel can never
/// write over a Rust object of this program.
struct Avoid {
    code: u64,
    stack: u64,
}

impl Avoid {
    /// 16 MiB either side of the code covers any test program's image;
    /// 64 MiB below the initial stack pointer covers the stack, and 1 MiB
    /// above it the arguments and environment.
    fn contains(&self, value: u64) -> bool {
        let near_code = value.wrapping_sub(self.code.saturating_sub(16 << 20)) < (32 << 20);
        let near_stack = value.wrapping_sub(self.stack.saturating_sub(64 << 20)) < (65 << 20);
        near_code || near_stack
    }

    fn guard(&self, value: u64) -> u64 {
        if self.contains(value) {
            0xffff_8000_0000_0000
        } else {
            value
        }
    }
}

struct State {
    rng: Rng,
    scratch: u64,
    /// The last non-negative result: often an fd or a mapping.
    last: u64,
}

impl State {
    /// One argument. About 80% are small or structured values that reach
    /// the kernel's checks; the rest are huge (random, negative, an earlier
    /// result). Huge sizes are kept rare because a call that is allowed to
    /// move 2 GiB (MAX_RW_COUNT) takes over a minute without hardware
    /// acceleration, which would leave little time for anything else.
    fn argument(&mut self) -> u64 {
        let r = self.rng.next_u64();
        match r % 20 {
            0..=3 => (r >> 8) & 7,
            4..=6 => self
                .rng
                .pick(&[0, 1, 2, 3, 4, 5, 6, 7, 900, u64::MAX, AT_FDCWD as u64]),
            7..=9 => {
                if self.rng.next_u64().is_multiple_of(16) {
                    self.rng.pick(&[1 << 20, 64 << 30, u64::MAX])
                } else {
                    self.rng
                        .pick(&[0, 1, 8, 24, 32, 144, 4095, 4096, 4097, SCRATCH, r >> 52])
                }
            }
            10..=11 => self.scratch + (r >> 16) % SCRATCH,
            12 => self.rng.pick(&HOSTILE),
            13 => (r >> 32) & self.rng.next_u64() & 0xffff_ffff,
            14 => ARENA + ((r >> 12) % (1 << 18)) * 4096,
            15 => self.rng.next_u64(),
            16 => (r >> 56).wrapping_neg(),
            _ => self.last,
        }
    }

    fn number(&mut self) -> u64 {
        let r = self.rng.next_u64();
        let number = match r % 10 {
            0..=6 => self.rng.pick(&IMPLEMENTED),
            7 | 8 => (r >> 8) % 600,
            _ => self.rng.next_u64(),
        };
        if NEVER.contains(&number) { 1 } else { number }
    }
}

/// Makes `calls` random system calls, then returns how many it made.
/// Returns `None` (having made none) when not on Keel.
pub fn run(seed: u64, calls: u64, initial_sp: u64) -> Option<u64> {
    let marker = sys::openat(AT_FDCWD, c"/etc/keel-release", O_RDONLY, 0);
    if marker < 0 {
        return None;
    }
    sys::close(marker as i32);
    // No console: reads of it wait for a line, and random writes would
    // flood the serial line the test results travel on.
    for fd in 0..3 {
        sys::close(fd);
    }
    let scratch = Region::map(SCRATCH, sys::PROT_READ | sys::PROT_WRITE).ok()?;
    let avoid = Avoid {
        code: run as *const () as u64,
        stack: initial_sp,
    };
    let mut state = State {
        rng: Rng::new(seed),
        scratch: scratch.address(),
        last: 0,
    };
    for _ in 0..calls {
        let number = state.number();
        let mut a = [0u64; 6];
        for slot in &mut a {
            *slot = avoid.guard(state.argument());
        }
        if number == NR_POLL {
            // A random timeout could sleep for days with nothing to wait
            // for; keep it at 0-2 ms.
            a[2] = state.rng.next_u64() % 3;
        }
        if number == NR_OPENAT && !state.rng.next_u64().is_multiple_of(4) {
            // openat only reads its path, so a read-only string in this
            // program's image is safe to hand out here.
            a[1] = state.rng.pick(&PATHS).as_ptr() as u64;
        }
        // SAFETY: no argument names this program's memory: every value
        // passed `Avoid::guard`, which keeps out its image and stack,
        // except openat's path, which the kernel only reads. What the
        // arguments may name is the scratch region and the arena, which
        // hold no Rust object, hostile addresses, or random values. A call
        // can still end this program (munmap over its code, say); the
        // kernel then ends it with a fault, which is an ordinary end of a
        // fuzz run. The one residual case, a write that starts in a
        // mapping the fuzzer made and runs on into the stack, needs a
        // random MAP_FIXED mapping placed directly below the stack, and
        // would only corrupt this program, never the kernel. fork gives the
        // child its own copy of this memory, as `sys::fork` does; clone and
        // vfork, which could share it, are never made (`NEVER`).
        let result = unsafe { syscall6(number, a) };
        if number == NR_FORK && result == 0 {
            // The child: the same seed would repeat the parent's calls.
            state.rng = Rng::new(state.rng.next_u64() ^ (sys::getpid() as u64).rotate_left(32));
        }
        if result >= 0 {
            state.last = result as u64;
        }
    }
    Some(calls)
}
