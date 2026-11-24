//! Keel core services, written in safe Rust (spec section 5: the
//! "framekernel" split). Hardware access goes through `keel-hal`; this
//! crate holds the logic, so it is unit-tested on the host.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod acpi;
pub mod compartment;
pub mod cpio;
pub mod cpuvuln;
pub mod crypto;
pub mod elf;
pub mod epoll;
pub mod errno;
pub mod exec;

pub mod frame;
pub mod handle;
pub mod keyboard;
pub mod lock;
pub mod paging;
pub mod pipe;
pub mod poll;
pub mod procfs;
pub mod rng;
pub mod signal;
pub mod tty;
pub mod vfs;
pub mod vm;
