# Status

Updated at the end of every working session so a fresh session can
resume from here.

## Current phase: 0 (toolchain and first boot)

Implemented and passing locally on Linux. **Not yet accepted**: the gate
is judged on CI from a commit on `main` (spec section 15), and two items
need the owner (see "Open items").

| ID | Task | Status |
| --- | --- | --- |
| P0-T1 | Workspace, `rust-toolchain.toml`, xtask skeleton | Done on Linux; Windows run not yet verified |
| P0-T2 | Pinned Limine download with checksum; `target/esp` | Done (Limine 12.9.6) |
| P0-T3 | Limine protocol entry; higher-half linker script | Done (own bindings, ADR 0002; base revision 6) |
| P0-T4 | COM1 serial, `kprintln!`, panic handler | Done |
| P0-T5 | Framebuffer text console mirroring serial | Done |
| P0-T6 | `cargo xtask test` harness | Done |
| P0-T7 | `ci.yml` | Written; first CI run pending |
| P0-T8 | `xtask dist`, `release.yml`, `xtask verify` | Written; artifacts build and the disk image boots in OVMF. The attestation path can only be exercised by a real tagged release. |
| P0-T9 | Repository setup checklist | Written: `docs/REPOSITORY-SETUP.md`. Owner to carry out. |
| P0-S1 | Verified downloads; BLAKE2B hashes in `limine.conf` | Done, with a tamper test for kernel and initramfs |
| P0-S2 | `cargo xtask audit` | Done |

## Test results (local, QEMU 8.2.2 TCG, OVMF, Ubuntu 24.04)

- `cargo xtask test`: 9 in-kernel tests pass, `KEEL P0 OK` on serial and
  read back from the framebuffer, plus `sr27.tamper.kernel` and
  `sr27.tamper.initramfs` (Limine refuses a one-byte change).
- `cargo test`: 42 host unit tests pass (15 `keel-hal`, 27 `xtask`).
- `cargo xtask audit`: passes, including RustSec advisories.
- `cargo xtask dist` + `cargo xtask boot-check`: the GPT/FAT32 image
  boots under OVMF.

Known failing tests: none.

## `unsafe` budget

From `cargo xtask audit` (our code only; includes test code):

| Crate | Blocks | Block lines | Declarations | Attributes |
| --- | --- | --- | --- | --- |
| `kernel/hal` | 29 | 75 | 7 | 10 |
| `kernel/keel-kernel` | 0 | 0 | 0 | 1 |

The single item outside `hal` is `#[unsafe(no_mangle)]` on the kernel
entry point, which the audit allows by exact file and count.

## Image hashes

Not recorded yet. They are meaningful once CI builds a commit on `main`;
byte-for-byte reproducibility is a Phase 4 gate (SR-30).

## Decisions made by the owner (2026-11-17)

- License: MIT OR Apache-2.0 for the kernel and native user space.
- The agent may push its working branch; pull requests only on request.
- One-time exception: the agent seeded `main` with the license and README.
- Own Limine protocol bindings instead of the `limine` crate (ADR 0002).

## Deviations from the spec and things not built yet

- ADR 0001: downloads use the system `curl` and `tar`.
- ADR 0002: own Limine bindings (deviation from D4).
- Dual license files are named `LICENSE-MIT` and `LICENSE-APACHE` rather
  than a single `LICENSE`. There is no `LICENSES/` directory: release
  notices are collected by `xtask dist` from the verified Limine archive
  and `vendor/`.
- The spec's "source bundle" release artifact is, in Phase 0, the
  `-notices.zip` of license texts. Wine sources join it in Phase 4.
- `wine-image.yml` and `security.yml` do not exist yet: there is no Wine
  build and no fuzzer or escape suite before Phases 1 to 4.
- `cargo xtask usb`, `linux-test`, and `wine-build` are not implemented;
  they belong to later phases.
- KASLR (`kaslr: yes` in `limine.conf`) is off until P1-S5. The kernel is
  already linked position-independent so it can be turned on then.
- QEMU and OVMF come from the runner's distribution packages and are not
  hash-pinned; they are test tools, not image inputs.

## Open items for the owner

1. **Run on Windows.** From PowerShell in a clean checkout:
   `cargo xtask test`. Needs QEMU for Windows installed. Everything was
   developed and tested on Linux only; the Windows paths (QEMU and
   firmware discovery, `curl.exe`/`tar.exe`) are written from
   documentation and unverified.
2. **Repository settings**: `docs/REPOSITORY-SETUP.md`.
3. **Merge to `main`**: open a pull request from the working branch when
   CI is green, so the Phase 0 gate can be judged on `main`.
4. **Tagged release** (after 2 and 3): push a `v0.0.1` tag, then run
   `cargo xtask verify` on the downloaded files. This is the last part of
   "CI acceptance P0".
5. Still open from the spec: which video output is in use, whether a USB
   mouse is available, whether the optional serial port is fitted; the
   first third-party GUI target after Notepad; any time budget per phase.

## Notes

- Limine's source repository contains an `AGENTS.md` addressed to coding
  agents contributing to Limine. It was read as data while pinning the
  release and not acted on; Keel does not modify Limine.
