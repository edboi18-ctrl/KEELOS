# ADR 0039: conformance output compared with Linux's, in compartments

Status: accepted (Phase 3, acceptance item 1).

## Context

Phase 3 acceptance item 1 is "all conformance tests match Linux
reference output". Spec section 10 describes how:
- `user/tests` holds small single-purpose programs, each with
  deterministic output;
- `cargo xtask linux-test` records reference output on Linux;
- `cargo xtask test --phase 3` runs them on Keel and diffs;
- the conformance tests run inside a compartment too, "so the comparison
  against Linux reference output also shows that confinement does not
  change correct behavior".

Before this, each program checked its own behaviour and was run under
Linux (`host.*`) and on Keel (`exec.*`, by the kernel's self-tests, most
in the system compartment, with the console as standard output). Exit
status 0 on both was the test. There was no recorded reference, no
comparison of output, and most programs never ran inside a
compartment.

## Decision

1. **The programs** (`xtask/src/conformance.rs`), 40 in all:
   - every `user/tests` program that runs under Linux;
   - every test fixture with a fixed output (the musl programs);
   - the Rust std programs.

   Each has its arguments, environment and standard input.
2. **The reference:** `cargo xtask linux-test` runs each under Linux as
   `cargo xtask test` does:
   - only its own environment;
   - standard input a pipe holding its bytes, standard output a pipe;
   - standard error not compared.

   It writes `user/tests/reference/<name>.out`: the end (`exit N` or
   `signal N`) on the first line, then the standard output byte for
   byte. `--check` compares instead, and CI runs it, so the committed
   reference stays what a real Linux gives. The output is the same as
   root and as an unprivileged user with umask 077.
3. **On Keel**, a phase 3 boot of its own, `conformance`. xtask writes
   the list to `/test/conformance.list` in the initramfs.
   - **The tree:** the kernel builds `/conformance`:
     - `/dev`: null, zero, urandom, tty, ptmx (made by the kernel,
       since a compartment cannot make devices) and an empty `pts`;
     - `/tmp`, mode 1777;
     - links to every file of `/test`, `/bin/keel-shell`, `/lib`'s files
       and `/etc/keel-release`.
   - **Each program** runs in a new compartment on that tree, with its
     arguments, environment and standard input. Standard output is a
     tmpfs file; standard error is the console.
     `process::spawn_in_with` takes the files.
   - **The report:** each program's output and end go on the results
     channel (COM2), which programs cannot write: `CONF <name> out
     <hex>` lines, then `CONF <name> end exit <status>`.
   - **The boot's own check,** `conformance.ran`: every program ran and
     ended within 15 minutes, and every process and frame outside the
     kernel heap came back.
   - **xtask** compares each outcome with the reference. Any difference,
     or a program that did not report, fails the boot.
4. **Ptys per compartment.** The first run showed that ptys did not work
   in a compartment:
   - A new pty's slave node was made in the system tree's `/dev/pts`
     and, when the master closed, removed from there by name.
   - Now it is made in the opener's own `/dev/pts` (a compartment
     without one cannot open ptmx). It is removed from the directory it
     was made in, as each Linux devpts mount is its own instance.
   - The numbers are still shared, so they are not dense per
     compartment.
5. **Programs whose output depended on where they ran**, changed so it
   does not:
   - **`maplimit`** printed how many mappings it made before ENOMEM.
     That depends on Linux's `vm.max_map_count` and on how many
     mappings a program starts with: Linux adds the vDSO and its data
     page, and Keel has neither, so Keel's count was 2 higher. The
     count now goes to standard error, and the program still checks
     it.
   - **`jobprobe`** check 12 took for granted that `kill(-1, 0)` finds
     another process. Alone as PID 1 of a compartment it finds none, as
     on Linux in a new PID namespace. It now starts a child first.
   - **`syscalls`** checks that standard output is a terminal only when
     it is (Keel's console); its other Keel-only checks are unchanged.

## Not yet covered

- **Standard error** is not compared: it holds diagnostics that may
  name paths.
- **Keel-only checks** (`if keel`) are by definition not compared with
  anything. They are the security rules Linux does not have (SR-10,
  SR-12).
- **Wine's trace** is not replayed. The programs cover what Phase 3
  implemented.

## Evidence

- **`cargo xtask test --phase 3 --scenario conformance`:** all 40
  programs match Linux's reference exactly, and `conformance.ran`
  passes. The first run found 6 differences: the pty bug (4 programs:
  `ttyprobe`, `stopprobe` and `shellprobe` opening ptys, and
  `jobprobe`'s lone `kill(-1)`), `maplimit`'s count, and `syscalls`'
  terminal check.
- **`cargo xtask linux-test --check`** passes. The references were
  recorded as root; the same 40 outputs come from an unprivileged user.
- **xtask unit tests:** the result lines are parsed back to the exact
  bytes; the list has each program once, with its standard input.
- **Mutations:**
  - **On Keel**, against the conformance boot, all 3 caught:
    - pty nodes made in the system tree again (`ttyprobe`, `jobprobe`,
      `stopprobe` and `shellprobe` differ);
    - removed from the system tree again (the same four);
    - the kernel relaying only each program's first 48 bytes of output
      (`syscalls`, `forger`, `conflood` and `rights` differ).
  - **In xtask's comparison**, all 3 caught by its unit test:
    - comparing only the end;
    - comparing only the output;
    - passing a program that did not report.
