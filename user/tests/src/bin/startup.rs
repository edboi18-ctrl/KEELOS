//! Checks the process state a loader creates (P1-T11): the initial stack,
//! argv, envp, the auxiliary vector, registers at entry, and the loaded
//! segments. Runs on Linux and on Keel.
//!
//! Run as `startup alpha` with `KEEL_TEST=1` in the environment. Exits 0
//! when every check passes, otherwise with the number of the first failed
//! check (and a line on stderr).
#![no_std]
#![no_main]

use core::hint::black_box;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use keel_rt::{AT_ENTRY, AT_PAGESZ, Startup};

/// `PT_LOAD` and `PF_X` (Linux `include/uapi/linux/elf.h`).
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
/// RFLAGS.DF (SDM Vol. 1 section 3.4.3.1); the psABI requires it clear.
const RFLAGS_DF: u64 = 1 << 10;

/// Initialised data: must arrive with this value (`.data`).
static DATA: AtomicU64 = AtomicU64::new(0x5EED_CAFE_F00D_1234);
/// Zero-initialised data spanning two pages (`.bss`).
static BSS: [AtomicU8; 8192] = [const { AtomicU8::new(0) }; 8192];

fn checks(s: &Startup) -> [(&'static str, bool); 15] {
    let mut args = s.args();
    let argv0 = args.next();
    let argv1 = args.next();
    let entry = keel_rt::entry_address();
    let entry_in_code = s.program_headers().is_some_and(|headers| {
        headers.iter().any(|h| {
            h.p_type == PT_LOAD
                && h.p_flags & PF_X != 0
                && entry >= h.p_vaddr
                && entry - h.p_vaddr < h.p_memsz
        })
    });
    let bss_zero = BSS.iter().all(|b| b.load(Ordering::Relaxed) == 0);
    [
        (
            "stack 16-byte aligned at entry",
            s.initial_sp.is_multiple_of(16),
        ),
        ("rdx is 0 at entry", s.initial_rdx == 0),
        (
            "direction flag clear at entry",
            s.initial_rflags & RFLAGS_DF == 0,
        ),
        (
            "argc is 2, argv NULL-terminated",
            s.argc() == 2 && s.argv_terminated(),
        ),
        ("argv[1] is \"alpha\"", argv1 == Some(b"alpha")),
        ("KEEL_TEST=1 in envp", s.env().any(|e| e == b"KEEL_TEST=1")),
        ("AT_PAGESZ is 4096", s.aux(AT_PAGESZ) == Some(4096)),
        ("AT_ENTRY is _start", s.aux(AT_ENTRY) == Some(entry)),
        (
            "AT_PHDR lists an executable PT_LOAD holding _start",
            entry_in_code,
        ),
        (
            "AT_RANDOM gives 16 bytes, not all zero",
            s.random().is_some_and(|r| r != [0; 16]),
        ),
        (
            "AT_EXECFN is argv[0]",
            s.execfn().is_some() && s.execfn() == argv0,
        ),
        (
            "initialised data",
            DATA.load(Ordering::Relaxed) == 0x5EED_CAFE_F00D_1234,
        ),
        ("bss is zero", bss_zero),
        ("data and bss are writable", write_data()),
        ("256 KiB of stack usable", deep_stack(64)),
    ]
}

fn write_data() -> bool {
    DATA.store(7, Ordering::Relaxed);
    BSS[8191].store(9, Ordering::Relaxed);
    DATA.load(Ordering::Relaxed) == 7 && BSS[8191].load(Ordering::Relaxed) == 9
}

/// Recurses with a 4 KiB frame `depth` times, touching each frame.
#[inline(never)]
fn deep_stack(depth: u32) -> bool {
    let mut frame = [0u8; 4096];
    frame[0] = depth as u8;
    frame[4095] = depth as u8;
    let frame = black_box(frame);
    let deeper = depth == 0 || deep_stack(depth - 1);
    deeper && frame[0] == depth as u8 && frame[4095] == depth as u8
}

fn main(s: &Startup) -> i32 {
    for (number, (name, passed)) in (1..).zip(checks(s)) {
        if !passed {
            keel_rt::write(2, b"startup: check failed: ");
            keel_rt::write(2, name.as_bytes());
            keel_rt::write(2, b"\n");
            return number;
        }
    }
    keel_rt::write(1, b"startup: all checks passed\n");
    0
}

keel_rt::main!(main);
