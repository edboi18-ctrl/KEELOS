# Dependencies

Every third-party input to the build: version, license, how it is pinned
and verified, and why it is here (SR-29, SR-32). Nothing enters the build
without a row in this file.

## Toolchain

| Input | Version | Pinned by | Verified by |
| --- | --- | --- | --- |
| Rust | 1.100.0 (stable), target `x86_64-unknown-none` | `rust-toolchain.toml` | rustup checks each component against the hashes in the signed channel manifest |

## Bootloader

| Input | Version | License | Pinned by | Verified by |
| --- | --- | --- | --- | --- |
| Limine `limine-binary.tar.gz` (uses `BOOTX64.EFI`, `LICENSE`) | 12.9.6 | BSD-2-Clause | URL and SHA-256 in `xtask/src/limine.rs` | SHA-256 of the archive and of each extracted file on every build |

Pin record for Limine 12.9.6, made 2026-11-17:

- Archive SHA-256:
  `b38aabb042b0c0f9f562b7741be3c1204838d7bbacfa78bb411c674bd5b984ee`
- `BOOTX64.EFI` SHA-256:
  `e486ae7abd7d5b88f98f43cfd6e8f9057ff975ecd667dfb33f1581de36e00982`
- The upstream detached signature `limine-binary.tar.gz.sig` verified as a
  good signature from the Limine release key
  `05D2 9860 D0A0 668A AEFB 9D69 1F3C 021B ECA2 3821` (Mintsuki), fetched
  from keyserver.ubuntu.com. The key itself was not independently
  certified (trust on first use); the fingerprint matches the one that
  upstream's release workflow publishes in its release notes.
- 12.9.6 (2026-10-28) was chosen over 12.10.0 because the latter was
  three days old when the pin was made.

To move to a new Limine release: download the archive and its `.sig`,
verify the signature against the fingerprint above, then update the
version, URL, and the three SHA-256 values in `xtask/src/limine.rs` and
this section.

## Crates

All crates are vendored in `vendor/` and resolved from there
(`.cargo/config.toml`); `Cargo.lock` is committed. Cargo verifies every
vendored file against the crate's `.cargo-checksum.json`.

Kernel (linked into the image):

| Crate | Version | License | Why |
| --- | --- | --- | --- |
| `spin` | 0.12.3 | MIT | Spinlock for the console sinks |
| `font8x8` | 0.3.1 | MIT (font data is public domain) | 8x8 bitmap font for the framebuffer console |

Host tool `xtask` only (never linked into the image):

| Crate | Version | License | Why |
| --- | --- | --- | --- |
| `sha2` | 0.11.1 | MIT OR Apache-2.0 | SHA-256 of downloads and release artifacts |
| `blake2` | 0.11.0 | MIT OR Apache-2.0 | BLAKE2B hashes written into `limine.conf` (SR-27) |
| `digest`, `crypto-common`, `block-buffer`, `hybrid-array`, `typenum`, `const-oid`, `cpufeatures`, `cmov`, `ctutils`, `cfg-if`, `libc` | see `Cargo.lock` | MIT OR Apache-2.0 | Transitive dependencies of the two RustCrypto crates above (`libc` only on non-x86 hosts) |

## Host tools (not build inputs)

These run on the developer's machine or the CI runner. They do not
contribute bytes to the image, so they are named here but not hash-pinned.

| Tool | Used for |
| --- | --- |
| `curl`, `tar` | Downloading and unpacking the Limine archive (ADR 0001); the result is SHA-256 verified |
| QEMU (`qemu-system-x86_64`) and OVMF/edk2 firmware | `cargo xtask run` and `cargo xtask test` |

## GitHub Actions

None yet. Each action will be listed here with its full commit SHA when
the workflows are added (SR-32).
