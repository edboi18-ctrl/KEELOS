# Phase 2 security audit

Audit date: 2026-11-22. Commit audited: `437981a` (`main` after pull
request #7). Compared with `5f23a97`, the commit of the third Phase 1
audit.

**Verdict: clear to start Phase 3.** Phase 2 changed the kernel only to
fix the three items from the last audit. Everything else it added runs
in user mode. No finding blocks. One low-severity item (D1) is new. The
last section lists what Phase 3 has to settle early, because Phase 3 is
where hostile code first runs.

## Status on the working branch

| # | Status |
| --- | --- |
| D1 | Fixed. A name is found with one section lookup (binary search, since `parse` checked the sections are in RVA order) and one scan of at most `MAX_NAME` bytes, instead of a full section-table scan per byte; and a total cap, `MAX_IMPORTS` (16,384), bounds the walk. Test `shared_import_tables_are_walked_quickly` builds the audit's file: the walk ends with `TooManyImports` after 16,384 imports in 7 ms (test build, parser optimized), 9 ms in a release build, against about 226 s before; without the total cap it walks 1,044,225 imports and fails. The file is in the corpus as `TooManyImports-shared-tables.exe`. `Image::section` now checks its index. The module comment is corrected. The parser and fuzz engine build optimized in the dev profile (overflow checks stay on), so `fuzz-pe` keeps its throughput with the slower template. |
| Phase 3 item 3 (test results on the serial line) | Done at the start of Phase 3: results travel on COM2, which only the kernel writes, and `cargo xtask test` reads verdicts only from there; `results.channel_isolated` checks a program's forged lines stay on COM1. |
| Phase 3 item 4 (fork from user mode) | Done. `fork` reaches `AddressSpace::duplicate` from user mode (ADR 0018). `forkprobe` checks copy-on-write, shared offsets, wait statuses and zombies under Linux and on Keel. `vm.shared_frame_limit` fills a frame's reference count from user mode (the limit lowered to 12 for the test; 65,534 is host-tested): the 12th fork is `ENOMEM`, nothing leaks, and the program keeps running. The system-call fuzzer does not fork yet (it would fork without limit in the system compartment); that comes with the in-compartment fuzzer (P3-S8). |
| Phase 3 item 5 (program loading from user input) | Done for ELF. `execve` (ADR 0017) runs the parser and loader on files a program wrote. `user/tests/badexec` writes randomly damaged copies of a small valid executable: header bytes, boundary values in header fields, any byte, truncation. Each copy is run by a forked child, in a compartment with limits (`exec.hostile_executables`, 400 per boot): no kernel panic, every process slot and frame back. Longer runs found and fixed a scheduler bug in how exit statuses were kept (`sched.exit_status_order`). A damaged program can loop in user mode; such a child is now killed after 3 s with `kill(SIGKILL)` (ADR 0019). Two 3,000-file runs killed 10 and 4. |

## What was run (QEMU 8.2.2, TCG, no KVM, Ubuntu 24.04)

- `cargo test --locked --offline`: passed.
- `cargo xtask audit --offline`: passed (advisory check skipped). The
  census shows `unsafe` only where ADR 0013 allows it: 3 blocks in
  `user/peldr`, all in `src/foreign.rs`, and `winetest/hello-console`.
- `cargo xtask test`: passed, 136 PASS lines, phases 0, 1 and 2,
  including `acceptance.peldr_hello`, `peldr.relocated` and
  `peldr.refuses_non_pe`.
- `cargo xtask fuzz-pe --minutes 5 --seed 99173`: passed, 45,340,000
  inputs, 3,191,172 accepted as images, no panic.
- `winetest/hello-console/build.sh` in a scratch copy: the rebuilt
  executable has SHA-256 `f603ceac...65e4`, identical to the checked-in
  `hello.exe` and to `hello.sha256`. The binary in the repository is what
  its source builds.
- CI run 45073751195 on `main` at `437981a` succeeded.

Not run: the kernel system-call fuzzer (the kernel changes are the three
fixes below), anything under KVM or on real hardware, `cargo xtask dist`.

## What was read

In full: `user/pe/src/lib.rs`, `user/peldr/src/main.rs` and
`foreign.rs`, the additions to `user/keel-rt/src/sys.rs`,
`xtask/src/fuzzpe.rs`, the diffs to `xtask` (`audit.rs`, `build.rs`,
`main.rs`, `qemu.rs`), every kernel diff (`core/elf.rs`, `paging.rs`,
`vfs.rs`; `hal/heap.rs`, `vm.rs`; `linux-abi/exec.rs`, `fs.rs`), and
ADR 0013. Also, from the list of files earlier audits skipped:
`hal/mitigations.rs` and the dispatch part of `hal/interrupts.rs`.

Not read: `user/pe/src/tests.rs`, `fuzz/pe-fuzz/src/lib.rs`,
`winetest/hello-console/src/main.rs`, and the Phase 2 additions to
`keel-kernel/src/selftest.rs`. Still unread from earlier audits:
`core/acpi.rs`, `cpuvuln.rs`, `crypto.rs`, `keyboard.rs`;
`hal/arch/x86_64/apic.rs`, `hal/time.rs`, `drivers/ps2.rs`; the rest of
`selftest.rs`; the test programs under `user/tests`.

## Third-audit findings, re-checked

| # | Result |
| --- | --- |
| C1 | Fixed. `Image::bias_for_base` uses `checked_sub` and then `check_bias`; `exec::load` calls it. A host test covers an image above the load base, and the random-input test calls it with four bases. |
| C2 | Fixed. `clear_user_half` hands each leaf and table to a callback as the walk reaches it and allocates nothing. A table is reported only after everything below it, so freeing it at once is safe: the walk never reads it again. |
| C3 | Fixed. `grow_file` asks `may_allocate` with the full size before every buffer allocation, and falls back from doubling to the exact size. The kernel's answer leaves the reserve untouched. |

## Phase 2 code

**PE parser (`user/pe`).** `#![forbid(unsafe_code)]`, no allocation.
Every file offset goes through `slice::get`; every RVA sum is a checked
add or is bounded by an earlier check. I found no path to a panic by
reading, and 45 million fuzz inputs here found none. It refuses
writable-and-executable sections, sections that overlap, are misaligned
or leave the image, an entry point outside executable code, and an image
that does not fit the user half.

Two things the parser does not check, both harmless today:

- An import slot or a relocation target only has to lie inside the image,
  not inside a writable section. `peldr` writes them before it applies
  section protections, so an image can have its own headers or code
  patched. It can only affect itself.
- `Image::section(index)` is public and does not check `index` against
  the section count. `peldr` never passes a larger one.

**Loader (`user/peldr`).** Maps with `MAP_FIXED_NOREPLACE`, so an image
cannot land on the loader's own memory. All copies go through
bounds-checked `Region` methods. The three `unsafe` blocks are the
`write` system call on the program's buffer, the store of the byte count
through the program's pointer, and the call to the entry point. Each is
unavoidable for what `peldr` does and none reaches the kernel except
through ordinary system calls.

**The boundary that matters.** A hostile `.exe` controls the `peldr`
process completely. That is by design (ADR 0013). What contains it is the
kernel, which Phase 2 did not weaken: no new system call, no new kernel
`unsafe`, no change to the entry path or to user-memory handling.

## New finding

### D1. A small crafted file keeps the PE parser busy for minutes

**Where**: `user/pe/src/lib.rs`: `Imports::step`, `Image::name_at`,
`Image::bytes_at`.

**Problem**: the module comment says a crafted file "cannot make the
parser loop for long". The caps allow 256 DLLs of 4096 imports each.
Import descriptors may share one lookup table and one name, so the file
stays small. For every import the parser reads two names one byte at a
time, and every byte read rescans the section table (up to 96 sections).

**Measured**: a 44,544-byte file with 96 sections and 255 descriptors
sharing a 4095-entry table. The first 20,000 imports took 4.34 s on this
host, in a release build, while other tests were running. The file holds
1,044,225 imports, so the whole walk is about 226 s by extrapolation. The
program that builds the file is appended to this document.

**Impact**: low. The work is in a user process, which the kernel
preempts, and the process harms only itself. It matters if something
ever waits on `peldr` with a deadline, and it makes the comment wrong.

**Change**: find the section once per name instead of once per byte
(look up the section containing the start, then scan its slice for the
NUL). Consider a cap on total imports. Correct the comment either way.
Add the file to `fuzz/pe-corpus/` with a time bound in the test.

**Done when**: the appended program reports a full walk in well under a
second.

## Before hostile code runs: what Phase 3 must settle

None of these is new and none is a defect in Phase 2. They are the open
assumptions that stop being safe once Phase 3 runs code that is trying to
get out.

1. **Limits are global, not per compartment.** The 65530-mapping cap is
   per address space, but the tmpfs node and byte caps and the frame
   reserve are shared by everything. One program can use up the tmpfs or
   push free memory down to the reserve, after which every other
   program's system calls return `ENOMEM`. ADR 0011 already assigns this
   to P3-S4.
2. **Ambient authority.** `AT_FDCWD` and absolute paths still resolve
   from the process root, which is the filesystem root for every process
   (ADR 0012).
3. **Test results share the serial line with user output.** A hostile
   program can print a forged `TEST ... PASS` line. `docs/STATUS.md`
   already says this must change before the escape suite.
4. **Fork is untested from user mode.** `AddressSpace::duplicate`
   (copy-on-write sharing) is exercised only by kernel self-tests. The
   first system call that reaches it needs the same hostile-pointer and
   fuzz treatment the Phase 1 calls had, and reference-count overflow
   (65534 sharers of one frame) needs a test from user mode.
5. **Program loading from user input.** C1 was a kernel panic reachable
   only because nothing lets a program pick a file to load. `execve`
   makes `core::elf` and `linux-abi::exec::load` attack surface. The
   parser has a random-input test; the loader path (mapping, copying,
   stack building) has none with hostile files.
6. **Signals.** Delivery builds a frame on the user stack and
   `rt_sigreturn` restores registers from user memory. Every restored
   value must pass through the same sanitising as
   `entry::prepare_user_return` (selectors, RFLAGS mask, canonical RIP
   and RSP).
7. **Boot chain.** Still detects corruption only. Signing and Secure
   Boot are the owner's steps (ADR 0010).
8. **Unread code.** The files listed above under "Not read" have had no
   audit. `core/acpi.rs` and the APIC and PS/2 drivers take firmware and
   device input rather than program input, so they rank below the items
   above.

## Program for D1

A standalone crate depending on `user/pe` by path. Build with
`cargo build --release` and run.

```rust
use std::time::Instant;
fn p16(v: &mut [u8], at: usize, x: u16) { v[at..at + 2].copy_from_slice(&x.to_le_bytes()); }
fn p32(v: &mut [u8], at: usize, x: u32) { v[at..at + 4].copy_from_slice(&x.to_le_bytes()); }
fn p64(v: &mut [u8], at: usize, x: u64) { v[at..at + 8].copy_from_slice(&x.to_le_bytes()); }
fn main() {
    const NSEC: usize = 96;
    const DLLS: usize = 255;
    const FUNCS: usize = 4095;
    let hdr = 0x1400usize; // headers incl. 96 section headers, file aligned
    let data_len = (DLLS + 1) * 20 + (FUNCS + 1) * 8 + 2 + 256 + 256;
    let raw_len = data_len.next_multiple_of(512);
    let mut f = vec![0u8; hdr + 512 + raw_len];
    f[0] = b'M'; f[1] = b'Z';
    p32(&mut f, 0x3c, 0x40);
    f[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    p16(&mut f, coff, 0x8664);
    p16(&mut f, coff + 2, NSEC as u16);
    p16(&mut f, coff + 16, 240);
    p16(&mut f, coff + 18, 0x0002);
    let opt = coff + 20;
    p16(&mut f, opt, 0x20b);
    p32(&mut f, opt + 16, 0x2000); // entry in section 0
    p64(&mut f, opt + 24, 0x1_4000_0000);
    p32(&mut f, opt + 32, 0x1000);
    p32(&mut f, opt + 36, 512);
    let last_rva = 0x2000 + (NSEC as u32 - 1) * 0x10000;
    let size_of_image = (last_rva + raw_len as u32).next_multiple_of(0x1000) ;
    p32(&mut f, opt + 56, size_of_image);
    p32(&mut f, opt + 60, hdr as u32);
    p32(&mut f, opt + 108, 16);
    p32(&mut f, opt + 112 + 8, last_rva);            // import dir rva
    p32(&mut f, opt + 112 + 12, ((DLLS + 1) * 20) as u32);
    let table = opt + 240;
    for i in 0..NSEC {
        let s = table + i * 40;
        let rva = 0x2000 + i as u32 * 0x10000;
        if i == NSEC - 1 {
            p32(&mut f, s + 8, raw_len as u32);
            p32(&mut f, s + 12, rva);
            p32(&mut f, s + 16, raw_len as u32);
            p32(&mut f, s + 20, (hdr + 512) as u32);
            p32(&mut f, s + 36, 0xC000_0000);
        } else {
            p32(&mut f, s + 8, 0x1000);
            p32(&mut f, s + 12, rva);
            p32(&mut f, s + 16, if i == 0 { 512 } else { 0 });
            p32(&mut f, s + 20, hdr as u32);
            p32(&mut f, s + 36, if i == 0 { 0x6000_0000 } else { 0x4000_0000 });
        }
    }
    let base = hdr + 512;
    let lookup_off = (DLLS + 1) * 20;
    let hint_off = lookup_off + (FUNCS + 1) * 8;
    let dll_off = hint_off + 2 + 256;
    for d in 0..DLLS {
        let at = base + d * 20;
        p32(&mut f, at, last_rva + lookup_off as u32);
        p32(&mut f, at + 12, last_rva + dll_off as u32);
        p32(&mut f, at + 16, last_rva + lookup_off as u32);
    }
    for e in 0..FUNCS { p64(&mut f, base + lookup_off + e * 8, (last_rva + hint_off as u32) as u64); }
    for b in 0..255 { f[base + hint_off + 2 + b] = b'a'; f[base + dll_off + b] = b'k'; }
    println!("file size {} bytes", f.len());
    let image = pe::parse(&f).expect("parses");
    let start = Instant::now();
    let mut n = 0u64;
    for imp in image.imports() {
        imp.expect("import ok");
        n += 1;
        if n == 20_000 { break; }
    }
    let t = start.elapsed();
    let total = (DLLS * FUNCS) as f64;
    println!("{n} imports in {:.2?}; {} imports in the file -> about {:.0} s for all",
        t, DLLS * FUNCS, t.as_secs_f64() * total / n as f64);
}
```
