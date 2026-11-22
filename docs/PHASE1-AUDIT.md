# Phase 1 security audit

Audit date: 2026-11-22. Commit audited: `1502eb9` (identical on `main` and
the working branch at the time).

This file is a work list. Each finding says what is wrong, where, why it
matters, what to change, and how to tell the change is done. Findings are
ordered by priority. Line numbers refer to commit `1502eb9`; re-locate the
code by the quoted text if the file has moved on.

## Status on the working branch

The audit read `1502eb9`; the working branch was about 40 commits ahead
when the fixes started (P1-T4 to P1-T14 and P1-S1 to P1-S7 done). Each
finding was re-checked there before it was fixed.

| # | Status |
| --- | --- |
| 1 | Open |
| 2 | Open |
| 3 | Fixed. `cargo xtask verify` derives `refs/tags/v<version>` from the artifact name (`verify::release_ref`: only `keel-<version>.img`, `-esp.zip`, `-notices.zip`, with `N.N.N` or `N.N.N-suffix` versions, as `release.yml`'s tag filters) and passes it as `--source-ref`; other names are refused before anything else. Unit tests for accepted and rejected names. Checked against `gh attestation verify --help` (gh 2.89.0). Still depends on the tag ruleset (finding 4). |
| 4 | Open (settings: owner) |
| 5 | Fixed. `workflow_problems` reads the block-YAML subset the workflows use, with each key's path, and checks allow-lists: triggers `push`, `pull_request`, `schedule`, `workflow_dispatch` (the last two for `security.yml`); `permissions` at any level only as a block of `read`/`none`, with `write` only for `contents`, `id-token`, `attestations` in `release.yml`'s `publish` job; runner exactly `ubuntu-24.04`; step `uses:` pinned to a SHA with a version comment, no `./`, `docker://` or job-level reusable workflows; the word `secrets` nowhere, scripts included. YAML it does not interpret (anchors, aliases, merge keys, flow mappings, tags, tabs, extra documents) is refused. One test case per table row plus those forms, each checked to fail for its intended reason; a test runs the three real workflows. |
| 6 | Fixed. The same check over all 20 `asm!` blocks on the working branch that claim `preserves_flags` found two more: `xrstor64` and `fxrstor64` in `fpu.rs` load the x87 status word and MXCSR, which that option also covers (the Rust Reference, asm.rules.preserved-registers). All three no longer claim it. |
| 7 | Fixed. Guard pages were done in P1-T4. Recursion: `idt::fatal` and the panic handler each set a flag on first entry; a nested entry prints one fixed line to COM1 (no formatting, no framebuffer) and halts, or exits QEMU in test mode. Scenario `fault_in_panic` panics, then faults inside the panic handler; it hangs (180 s timeout) with the panic handler's guard disabled. |
| 8 | Fixed. `memory::init` refuses an HHDM offset that is not page-aligned and in the higher half (`MemoryInitError::BadHhdm`) and uses only usable entries that are page-aligned, non-empty, non-wrapping and overlap no other entry of any kind (`keel_core::frame::sound_usable_regions`, host tests); skipped entries are counted in the boot log. A normal boot no longer prints the kernel base or HHDM offset (checked: a release-image boot's serial log has no `0xffff` address); test boots still do, for `kaslr.layout_varies`. Fatal dumps still print addresses, which is expected for a crash report. |

## Scope and limits

- Read in full: everything outside `vendor/` (kernel crates, `xtask`,
  workflows, linker script, docs).
- Phase status: at this commit `docs/STATUS.md` lists only P1-T1, P1-T2
  and P1-T3 as done. P1-T4 to P1-T14 and P1-S1 to P1-S7 are not started.
  This audit covers the code that exists, not a complete Phase 1.
- No finding is exploitable today: there is no user mode and no untrusted
  input after the bootloader. Findings 1 to 3 should be fixed before more
  work builds on them.
- Not done: `cargo xtask test` (QEMU) and `cargo xtask audit` were not
  run. The Limine and `cargo-deny` archives were not re-downloaded. The
  GitHub repository settings could not be read.
- Finding 5 was established by reading the code, not by running a test.

## Summary

| # | Severity | Area | Finding |
| --- | --- | --- | --- |
| 1 | Medium | Kernel | Frame handles can be forged; safe code can write or free any allocated frame |
| 2 | Medium | Boot chain | `limine.conf` is not authenticated, so the pinned hashes have no root of trust |
| 3 | Medium | Release | `cargo xtask verify` does not pin the git ref of the attestation |
| 4 | Medium | Repository | Branch and tag protections appear not to be applied (owner action) |
| 5 | Low to medium | Tooling | The workflow policy check in `xtask audit` can be bypassed |
| 6 | Low | Kernel | `preserves_flags` on an `asm!` block that modifies flags (undefined behaviour) |
| 7 | Low | Kernel | Double-fault stack sits directly above live data; no panic recursion guard |
| 8 | Low | Kernel | Boot values used without validation; kernel addresses printed at boot |

---

## 1. Frame handles can be forged

**Where**

- `kernel/core/src/frame.rs:15-22`: `Frame` derives `Clone, Copy` and
  `Frame::containing(address)` is public.
- `kernel/hal/src/memory.rs:141` `release`, `:132` `retain`, `:156`
  `with_frame_bytes`: all public, all accept any `Frame`.

**Problem**

Any safe code, in any crate, can build a `Frame` for any physical address
and then:

- write to it with `with_frame_bytes(Frame::containing(x), ...)` whenever
  that frame is allocated to anyone;
- free it with `release(Frame::containing(x))` while its real owner still
  uses it;
- keep a copy of a handle after releasing it and release it again after
  the frame has been handed to a new owner.

Nothing is stored in frames yet, so this is harmless today. Once frames
hold page tables (P1-T4), kernel stacks or heap memory, it is memory
corruption reachable from a `#![forbid(unsafe_code)]` crate, which defeats
the split between `keel-hal` and the safe crates. The `SAFETY` comment at
`memory.rs:165` ("Frames are never mapped as Rust objects elsewhere")
stops being true at that point.

Also: `with_frame_bytes` runs the caller's closure while the `FRAMES` lock
is held (`memory.rs:160`). A closure that allocates or releases a frame
deadlocks, because `spin::Mutex` is not re-entrant.

**Change**

- Make a frame handle unforgeable and owned. Suggested shape: an owned
  type that is not `Copy` or `Clone`, created only by the allocator, and
  consumed by `release`. A plain address-to-frame conversion, if still
  needed for page-table walking, must not grant access to contents or
  the right to free.
- `retain` should return a second owned handle rather than leaving one
  handle standing for two references.
- Make raw access to frame contents either `unsafe` with a stated
  contract, or take a mutable borrow of the owned handle. Do not hold the
  allocator lock while the caller's closure runs.
- Update the `SAFETY` comments in `memory.rs` to match.

**Done when**

- Code in `kernel/core` or `kernel/keel-kernel` cannot, without `unsafe`,
  obtain access to or free a frame it was not given by the allocator.
- The self-test `frames.release` in
  `kernel/keel-kernel/src/selftest.rs` still proves that a freed frame
  can be neither freed again nor read, using the new API.
- Host unit tests and `cargo xtask test` pass.

---

## 2. `limine.conf` is not authenticated

**Where**

- `xtask/src/build.rs:81-107` (`limine_conf`): writes BLAKE2B hashes for
  the kernel and initramfs into `boot/limine.conf`.
- `xtask/src/dist.rs`: ships that file on the FAT32 partition next to an
  unsigned `EFI/BOOT/BOOTX64.EFI`.

**Problem**

The hashes protect the kernel and initramfs only if the config that holds
them is itself trusted. It is a plain file on a writable FAT partition,
and the bootloader binary is unsigned. Anyone who can write the USB stick
can replace the kernel and its hash together, or add
`cmdline: test=1 scenario=double_fault` to make the shipped kernel crash
itself. The tamper test (`sr27.tamper.*` in `xtask/src/qemu.rs`) shows
that accidental corruption is caught; it does not show resistance to an
attacker.

The self-tests and the `double_fault` scenario are compiled into the
release kernel and selected only by the command line, which comes from
this unauthenticated file.

**Source**

Limine v12.9.6 `USAGE.md`, section "Secure Boot": Limine enforces the
config checksum, mandatory file hashes and the disabled editor only when
UEFI Secure Boot is active and a config BLAKE2B checksum is enrolled in
the EFI executable. "If no config checksum is enrolled, Limine treats
Secure Boot as inactive and none of the above hardening is applied." The
tool is `limine enroll-config`.

**Change**

- In `xtask dist`, enrol the BLAKE2B hash of the generated `limine.conf`
  into the copy of `BOOTX64.EFI` that is shipped. This changes the
  bootloader's bytes, so the pinned SHA-256 in `xtask/src/limine.rs` then
  applies to the input file, not the shipped one; record that in
  `docs/DEPENDENCIES.md`. Decide how enrolment is done without adding an
  unpinned host tool (the `limine` host utility is in the same upstream
  archive; pin and verify it the same way, or implement the enrolment in
  `xtask` from Limine's documented format). Write an ADR for the choice.
- Signing and turning Secure Boot on remain the owner's steps (SR-34).
  Until both are in place, `README.md` and `docs/STATUS.md` should say
  that the boot chain detects corruption but is not a verified boot.
- Consider whether release images should be able to run self-test
  scenarios at all. If they stay, state in `selftest.rs` that the command
  line is trusted only once the config is enrolled.

**Done when**

- A release image whose `limine.conf` has been edited is refused by
  Limine under Secure Boot, covered by a test or a documented manual
  check.
- The docs describe the boot chain's guarantees accurately.

---

## 3. `cargo xtask verify` does not pin the git ref

**Where**

`xtask/src/verify.rs:58-63`:

```
gh attestation verify <file> --repo edboi18-ctrl/KEELOS
  --signer-workflow edboi18-ctrl/KEELOS/.github/workflows/release.yml
  --deny-self-hosted-runners
```

**Problem**

The check names the workflow file but not the ref it ran from. Anyone
with push access to any branch can change `release.yml` on that branch to
run on a branch push, build anything, and attest it. The attestation's
signer is still `.github/workflows/release.yml` in this repository, so
`cargo xtask verify` reports the file as verified. Fork pull requests
cannot do this (no `id-token`), so the exposure is accounts and
automation with write access.

**Source**

GitHub CLI manual, `gh attestation verify`: `--source-ref <string>`
"Enforce that the git ref associated with the source repository matches
the provided value". `--source-digest` and `--signer-digest` are also
available.

**Change**

- Derive the version from the artifact's file name (`keel-<version>.img`,
  `keel-<version>-esp.zip`, `keel-<version>-notices.zip`), validate it
  with the same rule as `dist::validate_version`, and pass
  `--source-ref refs/tags/v<version>`.
- Fail with a clear message if the file name does not match that
  pattern.
- Add unit tests for the name-to-ref mapping, including names that must
  be rejected.

**Done when**

- An attestation produced from a branch ref no longer verifies.
- This depends on finding 4: the tag ruleset is what stops someone
  pushing a `v*` tag that carries a modified workflow.

---

## 4. Repository protections appear not to be applied (owner action)

**Where**

`docs/REPOSITORY-SETUP.md`: every checkbox except the license line is
unticked.

**Problem**

Without the branch ruleset, `.github/CODEOWNERS` has no effect and `main`
can be pushed to directly. Without the tag ruleset, anyone with write
access can start a release. Findings 3 and 5 rely on these settings as
the enforcement layer. The actual settings could not be read during the
audit; this finding rests on the checklist.

**Change**

- Owner: carry out sections 2, 3 and 4 of `docs/REPOSITORY-SETUP.md` and
  tick the boxes. An agent session must not change repository settings.
- Agent: extend `.github/CODEOWNERS` to cover `/xtask/`, because
  `xtask/src/audit.rs` and `xtask/src/verify.rs` are the code that
  enforces workflow policy and release verification. A pull request can
  currently weaken them without owner review.

**Done when**

- The checklist is ticked and `CODEOWNERS` covers `/xtask/`.

---

## 5. The workflow policy check can be bypassed

**Where**

`xtask/src/audit.rs:401-469` (`workflow_problems`) and `:471-498`
(`check_workflows`).

**Problem**

The check is line-based and misses these:

| Input | Why it passes |
| --- | --- |
| Job-level `permissions: write-all` | Line 441 only matches lines ending in `: write`. The inline check at line 449 applies to the top level only. |
| Job-level `permissions: { contents: write }` | Ends in `}`, not `: write`. |
| `${{ secrets['NAME'] }}`, `toJSON(secrets)`, `secrets: inherit` | Line 438 looks for the text `secrets.` only. |
| `runs-on: [linux, x64]` or `runs-on: { group: ... }` | Line 435 looks for the text `self-hosted` only. |
| `uses: ./.github/actions/x` | Local actions are exempt from pinning (line 422) and files outside `.github/workflows` are never read, so a local composite action can call unpinned third-party actions. |
| Triggers `workflow_run`, `issue_comment` | Only `pull_request_target` is rejected. |

**Change**

- Permissions: reject any `permissions:` value that is not a block of
  `<scope>: read` or `<scope>: none` lines, at any indentation, except
  the named write scopes in the `publish` job of `release.yml`. Reject
  `write-all` and flow mappings everywhere.
- Secrets: reject the word `secrets` in any expression or key, not just
  `secrets.`.
- Runners: allow only an explicit list of GitHub-hosted labels
  (currently `ubuntu-24.04`) and reject everything else.
- Actions: reject `uses: ./...` unless the audit also checks the files
  under `.github/actions/` with the same rules.
- Triggers: allow only an explicit list (`push`, `pull_request`) and
  reject everything else.
- Prefer allow-lists to deny-lists throughout: the present approach of
  searching for forbidden text is what makes these gaps possible.
- Add one case per row above to `rejects_each_policy_violation`.

**Done when**

- Every row in the table is rejected by a unit test, and the two real
  workflow files still pass.

---

## 6. `preserves_flags` on an `asm!` block that modifies flags

**Where**

`kernel/hal/src/arch/x86_64/gdt.rs:275-296`. The block contains
`"xor eax, eax"` (line 285) and declares `options(preserves_flags)`
(line 294). The reasoning comment at lines 263-266 says the flags are
unchanged.

**Reasoning**

1. `xor eax, eax` writes the status flags. Intel SDM Vol. 2, "XOR -
   Logical Exclusive OR", Flags Affected: "The OF and CF flags are
   cleared; the SF, ZF, and PF flags are set according to the result. The
   state of the AF flag is undefined."
2. The Rust Reference, "Inline assembly", rules for options: with
   `preserves_flags`, on x86 the status flags in `EFLAGS` (CF, PF, AF,
   ZF, SF, OF) "must be restored upon exiting the assembly code". The
   option "allows the compiler to avoid recomputing the condition flags
   after execution of the assembly code".
3. The block exits with ZF and PF set and CF, OF and SF cleared, whatever
   they were on entry. That breaks the contract, which is undefined
   behaviour: the compiler may keep a comparison result in the flags
   across the block.
4. Checked in the built kernel: the disassembly of
   `init_descriptor_tables` shows `xor eax, eax` at `0xffffffff80006953`,
   followed by code that does not read flags before setting them. There
   is no miscompile in this build. A later compiler or a change to the
   surrounding code could produce one.

The other instructions in the block (`lgdt`, `push`, `lea`, `retfq`,
`mov` to a segment register, `ltr`) do not modify the status flags, so
`xor` is the only offender.

**Change**

- Remove `preserves_flags` from this block. This is the smallest correct
  change and costs nothing at this call site.
- Correct the exit-state comment at lines 263-266 to say that `xor`
  modifies the status flags and that `preserves_flags` is therefore not
  claimed.
- Do not replace the `xor` with `mov eax, 0` just to keep the option;
  there is nothing to gain.

**Done when**

- The block no longer declares `preserves_flags`, the comment matches,
  and `gdt.selectors` still passes in `cargo xtask test`.

The other `asm!` blocks were checked and their options are correct:
`cpu.rs` (`cli`/`hlt`, `mov` from `cr2`, segment reads, `pushfq`/`pop`),
`port.rs` (`in`, `out`), `idt.rs` (`lidt`) and `selftest.rs` (`int3`,
the double-fault trigger).

---

## 7. Double-fault stack sits directly above live data

**Where**

- `kernel/hal/src/arch/x86_64/gdt.rs:71-83`: three 16 KiB IST stacks in
  `.bss.keel_entry`.
- `kernel/hal/src/arch/x86_64/idt.rs:363-377` (`fatal`) and
  `kernel/keel-kernel/src/main.rs:143-155` (panic handler).

**Problem**

In the built kernel the IST array starts at `0xffffffff80010000`, so the
double-fault stack (IST1, the lowest) grows down into the page at
`0xffffffff8000f000`. That page holds `.got`, `.dynamic`, the Limine
request block with its response pointers, and the `SERIAL` lock. Below it
are the GDT, TSS and IDT. The NMI stack overflows into the double-fault
stack, and the machine-check stack into the NMI stack.

The fatal path formats a register dump and draws text to the framebuffer
while running on that 16 KiB stack. An overflow would silently corrupt
the data above rather than fault.

Separately, there is no recursion guard: `fatal` panics, the panic
handler prints, and a fault during printing enters `fatal` again. With a
double fault this restarts at the top of IST1 each time and can loop
forever instead of halting.

The missing guard pages are already recorded in `gdt.rs:78-80` and
`docs/STATUS.md` as P1-T4 work. This finding adds the concrete layout and
the recursion problem.

**Change**

- P1-T4: unmapped guard pages below each IST stack and below the boot
  stack, as already planned. Until then, order the linker sections so
  that an overflow of IST1 runs into something that is not live data, or
  put a padding page there.
- Add a "fatal path entered" flag. On re-entry, skip formatting and the
  framebuffer and go straight to `halt_forever` (after `exit_qemu` in
  test mode).
- Consider a larger double-fault stack, or a fatal path that does not
  draw to the framebuffer when running on an IST stack.

**Done when**

- A fault inside the panic path halts instead of looping.
- Guard pages exist (P1-T4) and a self-test scenario shows an IST stack
  overflow faulting rather than corrupting memory.

---

## 8. Boot values used without validation; addresses printed at boot

**Where**

- `kernel/hal/src/memory.rs:58` and `:92-97`: `init` takes the HHDM
  offset and a region base and builds `&mut [u64]` and `&mut [u16]`
  slices at `hhdm + base`.
- `kernel/hal/src/boot/mod.rs:5-7`: the module documentation says counts
  and sizes are capped and combined with checked arithmetic.
- `kernel/keel-kernel/src/main.rs:102-113`: prints the HHDM offset and
  the kernel's virtual and physical base.

**Problem**

- `init` does not check that the HHDM offset is page-aligned and in the
  higher half, or that the chosen usable region's base is page-aligned.
  A misaligned value makes the slice construction undefined behaviour.
  The protocol guarantees these properties, and the self-test
  `boot.hhdm` and `boot.memmap` check them, but only in test mode. SR-19
  and SR-20 ask for the check in the normal path.
- The memory map is not checked for overlapping `Usable` entries before
  they are added to the allocator.
- Printing the kernel base and HHDM offset at every boot gives away the
  layout that KASLR (P1-S5) is meant to hide. Exception dumps also print
  kernel addresses; that is normal for a fatal dump but should not reach
  an unprivileged reader later.

**Change**

- In `memory::init`, return a new `MemoryInitError` variant unless the
  HHDM offset is at least `0xffff_8000_0000_0000` and a multiple of 4096,
  and skip any usable region whose base or length is not a multiple of
  4096 or which overlaps the previous one.
- Print the address lines only in test mode or behind a debug option,
  decided before P1-S5 enables KASLR. Record the decision in
  `docs/STATUS.md`.

**Done when**

- Host unit tests cover the rejected cases, and a normal boot no longer
  prints the kernel base once KASLR is on.

---

## Checked and found correct

Recorded so that a later audit does not repeat the work.

- **Vendored crates.** All 19 registry crates in `Cargo.lock` were
  downloaded from `static.crates.io`. Each tarball's SHA-256 equals the
  `checksum` in `Cargo.lock` and the `package` value in the crate's
  `.cargo-checksum.json`, and every vendored file is byte-identical to
  the file in the tarball. The only differences are `.gitignore` and
  `.gitattributes` files that `cargo vendor` leaves out.
- **Pinned actions.** `git ls-remote --tags` on the four upstream
  repositories returned exactly the SHAs in the workflows for
  `actions/checkout` v7.0.1, `actions/upload-artifact` v7.0.2,
  `actions/download-artifact` v8.0.2 and
  `actions/attest-build-provenance` v4.2.2.
- **Secrets and injected instructions.** No credentials in tracked files
  outside `vendor/`. No text addressed to AI agents (for example "ignore
  previous instructions") anywhere in the tree, `vendor/` included.
- **Host tests.** `cargo test --locked --offline`: 55 pass (6
  `keel-core`, 21 `keel-hal`, 28 `xtask`).
- **W^X.** The built kernel has three load segments with flags `R E`,
  `R` and `RW`; none is both writable and executable.
- **Exception entry.** The error-code vector list (8, 10 to 14, 17, 21,
  29, 30) is correct. The frame is 176 bytes, so the stack is 16-byte
  aligned at the `call`. The saved-CS offset used for the `swapgs` test
  is correct before and after the register pushes.
- **GDT and TSS.** Descriptor encodings, the SYSCALL/SYSRET selector
  arithmetic, the 104-byte TSS layout, and an I/O map base at the segment
  limit (no I/O bitmap) are correct.
- **Release workflow.** The build job has a read-only token and the job
  with write permissions runs no repository code. Shell variables are
  quoted, and `validate_version` keeps tag-derived text out of paths.
- **Downloads.** Limine and `cargo-deny` are accepted only on a pinned
  SHA-256, and `cargo-deny` is re-extracted from the verified archive on
  every run.

## Sources

- Intel 64 and IA-32 Architectures Software Developer's Manual, Vol. 2,
  "XOR - Logical Exclusive OR", Flags Affected (as rendered at
  https://www.felixcloutier.com/x86/xor).
- The Rust Reference, "Inline assembly", options and rules for inline
  assembly:
  https://doc.rust-lang.org/reference/inline-assembly.html
- Limine v12.9.6, `USAGE.md` ("Secure Boot") and `CONFIG.md`
  (`hash_mismatch_panic`, `editor_enabled`, "Paths"):
  https://github.com/limine-bootloader/limine/tree/v12.9.6
- GitHub CLI manual, `gh attestation verify`:
  https://cli.github.com/manual/gh_attestation_verify
- Built kernel inspected with `readelf`, `llvm-objdump` and `llvm-nm`
  from the pinned toolchain (Rust 1.100.0), release profile, target
  `x86_64-unknown-none`.
