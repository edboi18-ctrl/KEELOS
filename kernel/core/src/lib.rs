//! Keel core services, written in safe Rust (spec section 5: the
//! "framekernel" split). Hardware access goes through `keel-hal`; this
//! crate holds the logic, so it is unit-tested on the host.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod frame;
pub mod paging;
