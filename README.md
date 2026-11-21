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

## Building and running

Requirements: [rustup](https://rustup.rs) (the pinned toolchain installs
itself from `rust-toolchain.toml`) and QEMU. Windows 10 1803 or later, or
Linux. Every command is the same in PowerShell and in a Unix shell.

```
cargo xtask build        # kernel + initramfs -> target/esp
cargo xtask run          # boot in QEMU, serial on the terminal
cargo xtask test         # headless acceptance tests for completed phases
cargo xtask audit        # format, lint, unsafe count, licenses, advisories
cargo xtask dist         # release zip and disk image -> target/dist
cargo xtask verify FILE  # check a downloaded release before using it
```

If QEMU or its UEFI firmware is not found, set `KEEL_QEMU` and
`KEEL_OVMF_CODE` to their full paths. Project status is in
[docs/STATUS.md](docs/STATUS.md).
