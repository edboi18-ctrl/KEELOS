# ADR 0014: Compartments

Status: accepted (Phase 3, P3-S1 and the first part of P3-S4). Extends
ADR 0012 (path authority) and ADR 0011 (resource limits).

## Context

Phase 3 runs code that may try to get out. The spec makes the compartment
the unit of confinement (SR-2 to SR-4, SR-8) and requires compartments to
exist before any Wine binary runs on Keel. The Phase 2 audit lists what
stops being safe once hostile code runs, and two of its items are about
this:

- **Ambient authority (item 2).** Absolute paths and `AT_FDCWD` resolve
  from the process root, which was `/` for every process.
- **Global limits (item 1).** Every limit except the mapping cap is
  shared by all processes.

What existed already: each process has a `root` inode that no lookup
leaves (`vfs::Fs::lookup`; `..` stops at it), and ADR 0012 planned for a
compartment to set that root.

## Decision

1. **A compartment is a kernel object** (`keel_core::compartment`), in
   safe Rust and tested on the host. It holds an ID, a root inode, its
   limits and counters for what its processes use. Every process belongs
   to exactly one: `Process::member` holds the compartment and the
   process's PID there, and dropping the process gives its slot back.
2. **The compartment fixes the root.** A process's root and initial
   working directory are its compartment's root. Absolute paths and
   `AT_FDCWD` start there and `..` stops there, so a process can name
   nothing outside its root. No new lookup rule is needed (ADR 0012,
   consequence 2). Resolution walks inodes under the filesystem lock from
   start to end, so a concurrent change cannot slip a step outside the
   root.
3. **Each compartment has its own PID space.** Its first process is PID 1
   and `getpid` returns the compartment-local PID, as in a Linux PID
   namespace (pid_namespaces(7)). PIDs stay below 2^22, Linux's
   `PID_MAX_LIMIT` (proc_sys_kernel(5)). They are not reused yet: a
   compartment can start at most 2^22 − 1 processes in its lifetime, until
   `wait4` and reaping arrive (P3-T3).
4. **Limits are per compartment.** The first is the number of live
   processes. At the limit a new process is refused with `EAGAIN`, as
   fork(2) is at `RLIMIT_NPROC`. The counter goes up before the process is
   created and only from a value below the limit, so concurrent creations
   cannot pass it. Memory, tmpfs bytes and nodes, and handles move to
   per-compartment accounting in the next steps of P3-S4.
5. **The system compartment** (ID 0, root `/`, no limits beyond the
   kernel's own) holds the programs the kernel itself starts at boot and
   in tests. `process::spawn` puts a program there, and
   `process::spawn_in` into a given compartment. Only the kernel creates
   compartments today. Programs will ask for them through `keel-launch`
   and a manifest (P3-S2).

## Not yet covered

These parts of P3-S1 arrive with the features they confine, each built
per compartment from the start:

- Unix-socket names (P3-T11).
- IPC names: futex keys for shared memory (P3-T5), `memfd`.
- The procfs view (P3-T9).
- Signals and `kill` (P3-T6). A PID names a process only inside its own
  compartment.
- `rename` (P3-T8). It must keep every working directory beneath its
  root, or a moved directory would let relative lookups escape. A process
  can only name directories under its own root, so only the system
  compartment could move one out.

## Evidence

- Host tests (`keel_core::compartment`):
  - PIDs start at 1 in each compartment.
  - The process limit refuses with `EAGAIN` and frees a slot on drop.
  - An exhausted PID space refuses without leaking a slot.
  - 32 concurrent admissions against a limit of 8 admit exactly 8.
- `compartment.files_confined` (phase 3): `user/tests/compprobe` runs in
  compartment A (root `/comp/a`), then B, then A again.
  - Each run checks it cannot open the system's `/test/compprobe`.
  - It also cannot reach the other compartment's marker file by any of
    four routes (`/marker-b`, `/comp/b/marker-b`, `/../b/marker-b`,
    `../b/marker-b`).
  - Its own `/` works, and so does `..` clamped at it.
  - The kernel then checks from `/` that each marker is in its own
    compartment's directory and nowhere else.
  - With the system root given to every process again, all three runs
    fail at their first check (exit 2).
- `compartment.pid_space`: the PIDs compprobe checks (1, 1, then 2), and
  both counts back at 0 after the processes exit.
- `compartment.process_limit`: in a one-process compartment, a second
  `nap` is refused with `EAGAIN` while the first lives, and admitted after
  it exits. With the limit check removed, the second is admitted and the
  test fails.

## Consequences

- Programs started by the kernel are unchanged (system compartment), so
  phases 0 to 2 behave as before. The musl program still runs as PID 1.
- A confined program sees an empty tree unless the kernel puts files
  under its root. Read-only base images shared between compartments
  arrive with P3-S5.
