//! Keel hardware abstraction layer.
//!
//! This is the only kernel crate allowed to contain `unsafe` code and
//! assembly (spec section 7). Everything it exports is a safe interface;
//! each `unsafe` block inside carries a `// SAFETY:` comment naming the
//! invariant it relies on, and each assembly block carries the reasoning
//! block required by spec section 1, rule 4.
#![cfg_attr(not(test), no_std)]

extern crate alloc;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Keel supports x86-64 only (spec section 2, non-goals).");

#[cfg(target_os = "none")]
pub mod acpi;
pub mod arch;
pub mod boot;
pub mod console;
pub mod drivers;
pub mod heap;
#[cfg(target_os = "none")]
pub mod interrupts;
pub mod memory;
#[cfg(target_os = "none")]
pub mod mitigations;
pub mod random;
#[cfg(target_os = "none")]
pub mod sched;
pub mod sync;
#[cfg(target_os = "none")]
pub mod syscall;
#[cfg(target_os = "none")]
pub mod time;
#[cfg(target_os = "none")]
pub mod vm;
