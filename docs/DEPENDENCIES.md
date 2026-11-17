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
| `fatfs` | 0.3.6 | MIT | Writes the FAT32 system partition of the release disk image (built without the `chrono` feature, so no timestamps) |
| `bitflags` 1.3.2, `byteorder` 1.5.0, `log` 0.4.35 | see `Cargo.lock` | MIT OR Apache-2.0; Unlicense OR MIT (`byteorder`) | Dependencies of `fatfs` |
| `digest`, `crypto-common`, `block-buffer`, `hybrid-array`, `typenum`, `const-oid`, `cpufeatures`, `cmov`, `ctutils`, `cfg-if`, `libc` | see `Cargo.lock` | MIT OR Apache-2.0 | Transitive dependencies of the two RustCrypto crates above (`libc` only on non-x86 hosts) |

## Host tools (not build inputs)

These run on the developer's machine or the CI runner. They do not
contribute bytes to the image, so they are named here but not hash-pinned.

| Tool | Used for |
| --- | --- |
| `curl`, `tar` | Downloading and unpacking the Limine archive (ADR 0001); the result is SHA-256 verified |
| QEMU (`qemu-system-x86_64`) and OVMF/edk2 firmware | `cargo xtask run`, `test`, `boot-check`. CI installs the runner distribution's packages (`qemu-system-x86`, `ovmf` on Ubuntu 24.04). |
| `cargo-deny` 0.21.0 (MIT OR Apache-2.0) | `cargo xtask audit` advisory check. Upstream release binary, pinned by SHA-256 in `xtask/src/audit.rs` and verified on every run: Linux `a2170b85...b4585a903`, Windows `8c445ef9...bfcef4824`; both equal the `.sha256` files upstream publishes beside the assets (checked 2026-11-17). It downloads the RustSec advisory database at run time, which is by nature unpinned. |
| GitHub CLI (`gh`) | `cargo xtask verify` (attestation check) on the owner's PC; `gh release create` in the release workflow (preinstalled on hosted runners) |
| `git` | `cargo xtask dist` clean-tree check |

## GitHub Actions

Every action is first-party (owned by GitHub) and pinned by full commit
SHA (SR-32). The SHAs were read from the upstream tags with
`git ls-remote --tags` on 2026-11-17. No third-party action is used; the
release is created with the `gh` CLI in a plain shell step.

| Action | Version | Commit SHA | Used in |
| --- | --- | --- | --- |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` | `ci.yml`, `release.yml` |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | `release.yml` |
| `actions/download-artifact` | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` | `release.yml` |
| `actions/attest-build-provenance` | v4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` | `release.yml` |

Runner image: `ubuntu-24.04` (GitHub-hosted). Its preinstalled `rustup`
installs the toolchain named in `rust-toolchain.toml`.
