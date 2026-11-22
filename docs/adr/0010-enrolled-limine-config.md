# ADR 0010: Enrol the `limine.conf` hash into the shipped `BOOTX64.EFI`

Status: accepted (audit finding 2, `docs/PHASE1-AUDIT.md`). Signing and
Secure Boot remain the owner's steps (SR-34).

## Context

`xtask` writes BLAKE2B hashes of the kernel and initramfs into
`boot/limine.conf` (SR-27). That file is plain text on a writable FAT
partition, next to an unsigned Limine executable. Anyone who can write
the USB stick can replace the kernel together with its hash, or add a
`cmdline:` that selects a self-test scenario. The tamper tests showed
that accidental corruption is caught, not that an attacker is stopped.

Limine v12.9.6 can carry the config's BLAKE2B inside its EFI executable:

- `common/lib/config.c`: the string `++CONFIG_B2SUM_SIGNATURE++` is
  followed by 128 hex digits, all `0` when nothing is enrolled.
  `init_config` hashes the config file's bytes
  (`config_size - 2` = the file size), compares, and panics with
  `!!! CHECKSUM MISMATCH FOR CONFIG FILE !!!` on a mismatch. When a
  checksum is enrolled it also disables the config editor. This check
  does not depend on Secure Boot.
- `USAGE.md`, "Secure Boot": with Secure Boot active *and* a checksum
  enrolled, Limine also requires a hash on every loaded path, forces
  `hash_mismatch_panic`, and removes the UEFI shell key. "If no config
  checksum is enrolled, Limine treats Secure Boot as inactive and none of
  the above hardening is applied."
- `host/limine.c`, `enroll_config`: the `limine enroll-config` command
  finds the marker and overwrites the 128 bytes after it with the hex
  digest given.

## Decision

1. **`xtask` enrols the hash itself** (`build::enroll_config`). That
   avoids an extra host tool, which would need its own pin and a Windows
   build, and the format is these few lines. The function refuses an
   executable with no marker, with more than one, or without 128 hex
   digits after it, so a different Limine build cannot be patched in the
   wrong place. The pinned `BOOTX64.EFI` (12.9.6) has exactly one marker
   followed by 128 `0` digits.
2. **Every boot tree is enrolled**, release images and test boots alike,
   so every test boot exercises the shipped arrangement.
3. **The pinned SHA-256 covers the downloaded file.** The shipped copy
   differs from it only in those 128 bytes (`docs/DEPENDENCIES.md`).
4. **New tamper test `sr27.tamper.config`**: after enrolment, flip one
   byte of the config and require Limine's config-mismatch panic, with
   no kernel output. The panic comes before the config is read, so it
   reaches serial through the firmware console (OVMF copies it there).
   With enrolment disabled the test fails.

## What this does and does not give

- It does detect an edited `limine.conf` (a new kernel hash, a test
  `cmdline:`, a turned-on editor) with no other change.
- It does not stop an attacker who can write the stick. Without Secure
  Boot, they can enrol a new hash into the unsigned `BOOTX64.EFI`, or
  replace it. Verified boot needs the executable signed with a key the
  firmware trusts, and Secure Boot turned on. Both are the owner's steps
  (SR-34); until then, Keel's boot chain detects corruption but is not a
  verified boot.
- Self-test scenarios remain in release kernels. They are selected only
  by the command line, which is now exactly as trustworthy as the
  executable that checks the config.
