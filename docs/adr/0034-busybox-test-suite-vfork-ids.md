# ADR 0034: BusyBox's test suite, vfork, and the ID calls

Status: accepted (Phase 3, P3-T13 part 2).

## Context

P3-T13 names BusyBox "a large free test suite". The owner's build
(`fixtures/busybox`) ships the source's `testsuite/` directory as
`testsuite.tar`. It holds about 940 tests of BusyBox's applets and
shell, which exercise files, pipes, processes, signals and terminals
through real programs.

A first run on Keel found two gaps that affected almost every test:
- **vfork.** BusyBox starts other programs through `spawn()`, which uses
  `vfork()`, and Keel had none (ADR 0019 left it out). Every applet that
  runs another program got ENOSYS: `xargs`, `find -exec`, `env`, and
  `runtest`'s own list of applets, so the suite ran only its 9
  self-tests.
- **The ID calls.** getuid, getgid, geteuid and getegid were ENOSYS too.
  BusyBox read `-ENOSYS` as uid 4294967258, so it decided it was not
  root: `cp` and `cpio` tests expecting root's behaviour failed.

The rules are Linux v6.12's:
- `kernel/fork.c`: `SYSCALL_DEFINE0(vfork)` (CLONE_VFORK | CLONE_VM,
  SIGCHLD), `kernel_clone`, `wait_for_vfork_done` (TASK_KILLABLE),
  `complete_vfork_done` from `mm_release` at execve (`exec_mmap`) and
  exit;
- `kernel/sys.c`: getuid, geteuid, getgid, getegid, getresuid,
  getresgid.

## Decision

1. **vfork (58)**, as `kernel_clone` with CLONE_VFORK | CLONE_VM:
   - **The child** is a new process, as fork makes, but it uses the
     parent's own address space (shared, not copied; charged to the
     compartment once) and the caller's stack.
   - **The calling thread** waits until the child execs or exits. Only a
     kill ends the wait (TASK_KILLABLE). Other signals sent meanwhile are
     taken after. The parent's other threads go on.
   - **The release:** execve, once the new image is in place, and the
     exit of the child's last thread set its `vfork_done` and wake the
     parent, as `mm_release` does.
2. **clone (56) with CLONE_VFORK:**
   - **CLONE_VM | CLONE_VFORK** (musl's posix_spawn, with a stack of its
     own) is vfork.
   - **CLONE_VFORK alone** is a fork whose caller waits in the same way.
   - CLONE_VM without CLONE_THREAD otherwise is still EINVAL.
3. **The IDs.** Every Keel process is root in its compartment (ADR
   0030):
   - **getuid, getgid, geteuid and getegid** return 0;
   - **getresuid and getresgid** write three zeros, in Linux's order,
     ending with EFAULT at the first that cannot be written.
4. **BusyBox's test suite**, a phase 3 boot of its own (the
   `busybox_testsuite` scenario):
   - **The tree:** xtask unpacks `testsuite.tar` into that boot's
     initramfs, with each member's mode, as `/test/bb/testsuite`, beside
     `/test/bb/busybox` and `/test/bb/.config`, the layout `runtest`
     expects. A small reader (`xtask/src/tar.rs`) accepts only regular
     files and directories with plain relative names and a correct
     checksum.
   - **The run:** the kernel starts BusyBox's shell, which installs the
     applets in `/bin` (the Linux reference's layout) and runs
     `./runtest` with its output in `/tmp/bbts.log`.
   - **The verdict:** every `PASS:` line of
     `fixtures/busybox/keel-expected.txt` must appear in the log. Tests
     that pass but are not listed are reported, so the list can grow.
     Scripts start with `#!/bin/sh`, which Keel's execve does not handle
     yet: ash runs them itself when execve gives ENOEXEC, as POSIX asks
     (`shell/ash.c` `tryexec`).
   - **The time:** about 27 minutes under QEMU's emulator, minutes with
     KVM. The boot gets an hour, and `cargo xtask test --phase 3
     --scenario busybox_testsuite` runs it alone.
5. **The reference.** `fixtures/busybox/linux-results.txt` is the same
   suite under Linux 6.18, run as root with the same layout, BusyBox's
   shell as `/bin/sh` included. It ran in a chroot inside private mount
   and PID namespaces, so the tests could not reach the host. The
   results: 909 pass, 12 skipped, 1 untested, and 14 fail. Of the
   failures, 4 need the network (wget), 1 a domain name (hostname) and 1
   time zone data (date). The other 8 (awk, two of cpio, dd, three of
   sed, unzip) were not looked into; they fail on Keel too.

   `keel-expected.txt` is every one of those passes, except 18 that
   needed what Keel lacked (15 since ADR 0035 added FIFOs):
   - **chroot(2)**, which 13 mdev tests run in;
   - **FIFOs** (mkfifo is mknod with S_IFIFO), for 3 diff tests (done
     in ADR 0035);
   - **the PID directories of /proc**, which pidof lists (2 tests).

## Not yet covered

- The 18 tests above, and what they need: chroot, mknod and FIFOs, and
  /proc's process directories. Also chown, lchown and fchown, which
  `cpio` and `tar` call (ENOSYS; no test depends on the result), and
  sysinfo.
- `#!` in execve (binfmt_script): only shells run scripts today.
- CLONE_VM without CLONE_VFORK or CLONE_THREAD (a process sharing its
  parent's memory without the wait).
- IDs other than 0: setuid, setgid and the rest.

## Evidence

- **`busybox.testsuite` (phase 3, scenario `busybox_testsuite`).** 891
  tests pass on Keel, exactly the expected list: Linux's 909 less the 18
  above. 32 fail (Linux's 14 and those 18), 12 are skipped and 1 is
  untested, as under Linux.
- **`exec.spawn` (phase 3) and `host.spawnprobe`.** `user/tests/spawnprobe`
  makes 10 checks, which pass under Linux (as root, and as an
  unprivileged user with umask 077) and on Keel, where it runs with
  `root` and must find every ID 0. Keel runs it twice and measures the
  second run: every node, frame and process is back. The vfork children
  run only assembly (keel-rt's `vfork_then_exit` and `vfork_exec`), so
  no Rust code runs on the parent's stack. The checks:
  - **vfork:** the parent waiting until the child exits, and the child's
    write in the parent's memory;
  - **CLONE_VFORK alone:** the parent waiting, and the child's write its
    own;
  - **CLONE_VM | CLONE_VFORK:** as vfork;
  - **execve:** a child that executes a program letting the parent go on
    at once, while the program runs on; a failed execve letting the
    child exit;
  - **the IDs:** agreeing with each other, getresuid and getresgid
    giving them, EFAULT for a bad pointer.
- **Mutations** on Keel, 10, all caught (the spawnprobe check that
  failed in brackets):
  - **vfork:** the address space copied instead of shared (1); the
    caller not waiting (1); no release at execve (4, the parent waiting
    for the program to end) or at exit (the parent never coming back:
    `exec.spawn` times out); CLONE_VFORK alone sharing the memory (2);
    CLONE_VM | CLONE_VFORK refused (3).
  - **The IDs:** geteuid 1 (7); getresuid writing nothing (8), or
    without EFAULT (9).
  - **Through the suite:** getuid and geteuid 1, run in the
    `busybox_testsuite` boot. `busybox.testsuite` fails, naming its four
    regressions: `cp-does-not-copy-unreadable-file`, `cpio uses by
    default uid/gid` and the two `cpio extracts zero-sized hardlinks`.

## Consequences

- BusyBox's applets that run other programs work, and so does any
  program using vfork or posix_spawn.
- About 900 tests of real programs now guard Keel's Linux personality
  in every `cargo xtask test`. A change that breaks one of them fails
  CI, and one that makes a listed gap pass is reported.
