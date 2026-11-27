//! Debug tracing (spec section 15, "Debugging toolkit"; P3-S9, ADR 0043).
//! Compiled only into kernels built with the `debug-tracing` feature:
//! SR-21 allows tracing options in no other build, so a release kernel
//! has neither the options nor the code behind them.
//!
//! The kernel command line takes:
//! - `trace=WHAT[,WHAT...]`, WHAT being `syscalls` (every system call
//!   with its arguments and result), `faults` (user faults and the
//!   signal each becomes), `signals` (every signal sent to a process) or
//!   `sched` (threads created and ended);
//! - `trace.pid=N`, which limits `syscalls`, `faults` and `signals` to
//!   processes whose PID in their compartment is N.
//!
//! Each traced event is one line on the kernel log starting `trace:`.

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use keel_core::signal::SigInfo;
use keel_hal::kprintln;

type ProcessRef = alloc::sync::Arc<keel_hal::sync::IrqMutex<crate::process::Process>>;

use keel_core::trace::{FAULTS, SCHED, SIGNALS, SYSCALLS};

static FLAGS: AtomicU8 = AtomicU8::new(0);
/// 0 for every process.
static PID: AtomicU32 = AtomicU32::new(0);
/// Lines written, for tests.
static LINES: AtomicU64 = AtomicU64::new(0);

/// Turns on what `cmdline` asks for, and reports it.
pub fn configure(cmdline: &str) {
    let (flags, pid, unknown) = keel_core::trace::parse(cmdline);
    for what in unknown {
        kprintln!("trace: {what:?} not understood; ignored");
    }
    set(flags, pid);
    if flags != 0 {
        kprintln!(
            "trace: on ({}{}{}{}), {}",
            if flags & SYSCALLS != 0 {
                "syscalls "
            } else {
                ""
            },
            if flags & FAULTS != 0 { "faults " } else { "" },
            if flags & SIGNALS != 0 { "signals " } else { "" },
            if flags & SCHED != 0 { "sched " } else { "" },
            match pid {
                0 => alloc::string::String::from("every process"),
                n => alloc::format!("PID {n} only"),
            }
        );
    }
}

/// Sets the flags and the PID filter (0 for every process).
pub fn set(flags: u8, pid: u32) {
    PID.store(pid, Ordering::Relaxed);
    FLAGS.store(flags, Ordering::Relaxed);
    keel_hal::sched::set_trace(flags & SCHED != 0);
}

/// How many trace lines have been written.
pub fn lines() -> u64 {
    LINES.load(Ordering::Relaxed)
}

/// Whether `flag` is on for the process with PID `pid`.
fn wants(flag: u8, pid: u32) -> bool {
    FLAGS.load(Ordering::Relaxed) & flag != 0 && {
        let only = PID.load(Ordering::Relaxed);
        only == 0 || only == pid
    }
}

fn identity(p: &ProcessRef) -> (u32, u32) {
    let process = p.lock();
    (process.member.compartment().id(), process.pid())
}

/// A system call that has returned `result`, or (None) one that will not
/// return.
pub fn syscall(p: &ProcessRef, number: u64, a: &[u64; 6], result: Option<i64>) {
    if FLAGS.load(Ordering::Relaxed) & SYSCALLS == 0 {
        return;
    }
    let (compartment, pid) = identity(p);
    if !wants(SYSCALLS, pid) {
        return;
    }
    LINES.fetch_add(1, Ordering::Relaxed);
    kprintln!(
        "trace: c{compartment} pid {pid} tid {}: {}({number}) {:#x} {:#x} {:#x} {:#x} {:#x} {:#x} -> {}",
        keel_hal::sched::current().0,
        crate::names::name(number).unwrap_or("unknown"),
        a[0],
        a[1],
        a[2],
        a[3],
        a[4],
        a[5],
        match result {
            Some(r) => alloc::format!("{r:#x}"),
            None => alloc::string::String::from("(does not return)"),
        }
    );
}

/// A user fault, and the signal it becomes.
pub fn fault(p: &ProcessRef, vector: u64, rip: u64, info: &SigInfo) {
    if FLAGS.load(Ordering::Relaxed) & FAULTS == 0 {
        return;
    }
    let (compartment, pid) = identity(p);
    if !wants(FAULTS, pid) {
        return;
    }
    LINES.fetch_add(1, Ordering::Relaxed);
    kprintln!(
        "trace: c{compartment} pid {pid}: fault vector {vector} at {rip:#x} -> signal {} code {}",
        info.signo,
        info.code
    );
}

/// A signal sent to a process.
pub fn signal(target: &ProcessRef, info: &SigInfo) {
    if FLAGS.load(Ordering::Relaxed) & SIGNALS == 0 {
        return;
    }
    let (compartment, pid) = identity(target);
    if !wants(SIGNALS, pid) {
        return;
    }
    LINES.fetch_add(1, Ordering::Relaxed);
    kprintln!(
        "trace: c{compartment} pid {pid}: signal {} code {}",
        info.signo,
        info.code
    );
}
