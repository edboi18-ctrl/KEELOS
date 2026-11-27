//! The Linux x86-64 personality (spec section 5): system calls, processes,
//! the root filesystem and program loading, in safe Rust on top of
//! `keel-hal` and `keel-core`.
//!
//! `abi` and `names` are plain data and build (and are tested) on the
//! host; the rest needs the kernel half of `keel-hal` and builds only for
//! the kernel target, like `keel-hal` itself.
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

pub mod abi;
pub mod names;

#[cfg(target_os = "none")]
pub mod compartment;
#[cfg(target_os = "none")]
pub mod epoll;
#[cfg(target_os = "none")]
pub mod exec;
#[cfg(target_os = "none")]
pub mod fs;
#[cfg(target_os = "none")]
pub mod fscalls;

#[cfg(target_os = "none")]
pub mod futex;
/// Process groups and sessions (ADR 0030).
#[cfg(target_os = "none")]
pub mod jobs;
/// The native launch interface (P3-S2, ADR 0040).
#[cfg(target_os = "none")]
pub mod native;
#[cfg(target_os = "none")]
pub mod process;
#[cfg(target_os = "none")]
pub mod procfs;
#[cfg(target_os = "none")]
pub mod ready;
#[cfg(target_os = "none")]
pub mod signal;
/// nanosleep, clock_nanosleep and restart_syscall (ADR 0033).
#[cfg(target_os = "none")]
pub mod sleep;
#[cfg(target_os = "none")]
pub mod socket;
#[cfg(target_os = "none")]
pub mod syscall;
/// Debug tracing, only in `debug-tracing` builds (SR-21, ADR 0043).
#[cfg(all(target_os = "none", feature = "debug-tracing"))]
pub mod trace;
#[cfg(target_os = "none")]
pub mod tty;
