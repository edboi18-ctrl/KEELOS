//! Keel core services, written in safe Rust (spec section 5: the
//! "framekernel" split). Hardware access goes through `keel-hal`; this
//! crate holds the logic, so it is unit-tested on the host.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod acpi;
pub mod cpio;
pub mod elf;
pub mod exec;

pub mod frame;
pub mod paging;
pub mod vm;
