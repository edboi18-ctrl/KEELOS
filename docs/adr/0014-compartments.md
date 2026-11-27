# ADR 0014: Compartments

Status: accepted (Phase 3, P3-S1 and the first part of P3-S4; P3-S1
complete). Extends
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
4. **Limits are per compartment.**
   - **Processes.** The number alive at once. At the limit a new process
     is refused with `EAGAIN`, as fork(2) is at `RLIMIT_NPROC`. The
     counter goes up before the process is created and only from a value
     below the limit, so concurrent creations cannot pass it.
   - **Memory, in 4 KiB frames.** Each address space counts the user
     frames it holds: present pages, pages parked by `PROT_NONE`, and its
     user page tables. That covers every place user memory is allocated
     (`hal::vm`: demand-zero faults, page tables, `duplicate`, parked
     pages). A page shared copy-on-write counts in every space that maps
     it, so sharing overcounts, never undercounts. Replacing a shared page
     with a private copy keeps the space's count the same.
   - **Charging.** It happens under the space's lock, against the
     compartment's `Budget`, in one atomic check-and-add.
   - **Attaching.** At spawn the space is attached to the budget, which
     charges what the loader already populated. If that does not fit,
     the process is refused with `ENOMEM` before it runs.
   - **At the limit.** A page fault that cannot be charged is treated
     like one that cannot be resolved for lack of memory. A user access
     ends the thread; a kernel copy returns `EFAULT`. That is how
     "killed cleanly at its limit" (security acceptance P3, item 3) works
     for memory. Linux would OOM-kill instead, inside the cgroup.
   - **Teardown** gives every frame back.
   - **Not counted:** the two top-level tables of each space, kernel
     stacks, and handles. Each is bounded per process, and processes are
     bounded per compartment.
   - **tmpfs bytes and nodes**, the rest of Phase 2 audit item 1. A
     compartment's `Quota` caps the file data its files hold and the
     nodes it creates.
     - Every node records an owner: the quota of the compartment that
       created it. A node the kernel made has none.
     - A file's growth is charged to its owner. A kernel-made file gets
       as its owner the first compartment that grows it, so a
       compartment cannot grow a file the kernel put in its tree at
       nobody's expense.
     - Each file records how many of its bytes are charged. Those are its
       last bytes, so truncating gives them back first.
     - Overwriting costs nothing.
     - Past the limit: `ENOSPC`, as write(2) and open(2) report when "the
       device ... has no room". The quota is the compartment's device
       size.
     - The global tmpfs caps still apply on top.
     - The system compartment has no quota: limits that are all unlimited
       create none.
     - Nodes are never given back yet, because nothing can be deleted.
       `unlink` and `rmdir` (P3-T8) must uncharge the owner.
5. **The system compartment** (ID 0, root `/`, no limits beyond the
   kernel's own) holds the programs the kernel itself starts at boot and
   in tests. `process::spawn` puts a program there, and
   `process::spawn_in` into a given compartment. Only the kernel creates
   compartments today. Programs will ask for them through `keel-launch`
   and a manifest (P3-S2).

## Covered since, with the features they confine

The rest of P3-S1 arrived with the features it confines, each built per
compartment from the start (closed in the P3-S1 closing pass):

- **Unix-socket names** (ADRs 0027 and 0028). Abstract names live in a
  table keyed by compartment, type and name, so two compartments can bind
  the same abstract name and neither can reach the other's. Path names
  are nodes in the tree, so they resolve beneath the root like any path.
- **IPC names.** Futex waiters are keyed by (address space, address)
  (ADR 0019), and no address space is shared across compartments.
  `memfd` names are labels only, never looked up. Keel has no System V
  IPC and no POSIX message queues: those calls are ENOSYS.
- **The procfs view** (ADRs 0024 and 0037). `/proc` lists only the
  caller's compartment's PIDs, and `/proc/<pid>` exists only for them.
- **Signals and `kill`** (ADRs 0019, 0020 and 0030). A PID, a process
  group and `kill(-1)` name processes only inside the caller's
  compartment (ESRCH otherwise).
- **`rename`** (ADR 0022, decision 6). A relative lookup from a working
  directory that has been moved out of the root names nothing.

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
- `compartment.side_by_side` (phase 3; security acceptance P3 item 2):
  `user/tests/sidebyside` runs in compartments A and B at the same time,
  twice: first A holds 3 children and B 1, then the other way round, so
  each direction is checked while the other compartment holds what is
  looked for. The kernel lets both start, sets them going together, and
  lets them finish only when both have checked. Each run checks:
  - **Processes:** `/proc` lists exactly its own PIDs; `kill` (signal 0
    and SIGKILL) of each PID only the other has is ESRCH; at the end its
    own children are all still alive.
  - **Files:** the other's marker cannot be named by any of four routes.
  - **Sockets:** both bind the same abstract name; connecting to the
    other's abstract stream name and sending to its abstract datagram
    name are ECONNREFUSED, and its socket path is ENOENT, while its own
    names work; at the end no connection or datagram has arrived from
    the other.
  - Both process counts return to 0.
  - Mutations, each caught by this test:
    - abstract names in one table for all compartments;
    - the compartment check dropped from the process list (`/proc`);
    - the compartment check dropped from the PID lookup (`kill`);
    - every compartment rooted at `/`.
- `compartment.pid_space`: the PIDs compprobe checks (1, 1, then 2), and
  both counts back at 0 after the processes exit.
- `compartment.process_limit`: in a one-process compartment, a second
  `nap` is refused with `EAGAIN` while the first lives, and admitted after
  it exits. With the limit check removed, the second is admitted and the
  test fails.
- `compartment.memory_limit`: `user/tests/hog` touches 64 MiB, page by
  page from a fixed address, in a compartment limited to 4,352 frames
  (17 MiB).
  - It is ended by a page fault, and the fault address shows it touched
    at most the limit and within 64 pages of it.
  - Afterwards the budget is back at 0 and the free frame count back at
    its value before.
  - 8 MiB in the same compartment runs to exit 0, and a program in
    another compartment runs normally.
  - Mutations:
    - A fault that ignores a refused charge runs to page 4,608, the next
      page-table boundary, and fails the test. The limit is chosen off a
      512-page boundary for that reason: at 4,096 the refused page table
      would have stopped it exactly at the limit anyway.
    - Teardown that keeps the charge leaves 4,352 used and fails.
- `compartment.memory_limit_at_spawn`: a limit of 2 frames refuses the
  loaded `hog` (10 frames already populated) at spawn with `ENOMEM`,
  charging nothing. With attaching that charges nothing, it is admitted
  and the test fails.
- Host tests for `Budget`: exact limit, no overflow, no underflow, and
  16 threads making 3,200 charges against a limit of 1,000 get exactly
  1,000.
- `compartment.tmpfs_quota`: two compartments, each with 64 KiB and 8
  nodes and an empty kernel-made `/given`, each run `user/tests/tmpquota`.
  - Growing `/given` stops with `ENOSPC` at exactly 65,536 bytes.
  - Creating files stops with `ENOSPC` at exactly 8.
  - After `O_TRUNC`, a 4 KiB write fits again.
  - Both compartments reach their own limits, so neither is charged for
    the other. Each ends with 4,096 bytes and 8 nodes charged.
  - Mutations:
    - Writes charged to no quota run past the limit (exit 2).
    - Creations charged to no quota run past 8 nodes (exit 4).
    - Truncation that gives nothing back cannot write again (exit 7).
- Host tests in `vfs`:
  - the byte limit, with overwrite free and truncate giving back;
  - the node limit, where a refused creation costs nothing;
  - a kernel-made file's first grower paying, a later grower paying the
    owner and not itself, and truncation below the kernel's bytes giving
    back only what was charged.

## Consequences

- Programs started by the kernel are unchanged (system compartment), so
  phases 0 to 2 behave as before. The musl program still runs as PID 1.
- A confined program sees an empty tree unless the kernel puts files
  under its root. Read-only base images shared between compartments
  arrive with P3-S5.
