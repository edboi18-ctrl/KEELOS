# Keel OS

A from-scratch x86-64 operating system kernel, written in Rust, that aims to
run unmodified Windows executables by hosting Wine's user-space code on a
Linux-compatible system-call interface, with every program confined to a
compartment that starts with no authority.

**Status:** early development. Keel is hardened by design but unaudited; do
not describe it or rely on it as secure.

## License

The kernel and native user-space code are licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Code derived from Wine, kept under `wine/`, is licensed
LGPL-2.1-or-later.
