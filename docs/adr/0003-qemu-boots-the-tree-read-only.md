# ADR 0003: QEMU boots the boot tree from a read-only virtio disk

Status: accepted (Phase 1)

## Context

Spec section 4 gives the baseline QEMU invocation
`-drive format=raw,file=fat:rw:target/esp`: QEMU's virtual FAT driver
exposes the `target/esp` directory as a writable disk. Found while
testing P1-T2 on 2026-11-21:

- OVMF writes an `NvVars` file into the ESP on every boot, and QEMU writes
  that back into the host directory.
- When QEMU is killed (the test harness kills it on timeout and once a
  tamper test has seen Limine's refusal), write-back can be cut short. One
  manual run left `target/esp` unbootable ("Load Error" from the firmware).

A test harness must not modify what it tests.

## Options

1. Keep `fat:rw:`. Simple, but the build output can change under a test.
2. `fat:rw:` with `snapshot=on`. Refused by QEMU: "Unable to set VVFAT to
   'rw' when drive is read-only".
3. Read-only `fat:` on the default (SATA) interface. Refused by QEMU: the
   emulated AHCI disk does not accept read-only media ("Block node is
   read-only").
4. Read-only `fat:` on a virtio disk: `if=virtio,readonly=on`. OVMF ships
   a virtio-blk driver and boots from it.

## Decision

Option 4 for `cargo xtask run`, `test` and the tamper tests. Release disk
images keep using `snapshot=on` (`cargo xtask boot-check`), which works for
plain image files.

## Consequences

- Nothing is ever written into `target/esp` by a test run.
- The full test suite runs in about 10 seconds instead of about 17
  locally (no NvVars writes).
- The emulated boot device is virtio rather than SATA. Neither matches the
  real machine (USB mass storage, Phase 6), and Limine reads the boot
  files through UEFI either way, so nothing tested by Phases 0 to 5
  depends on the controller type.
