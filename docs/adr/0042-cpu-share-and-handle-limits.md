# ADR 0042: CPU share and handle limits per compartment

Status: accepted (Phase 3, P3-S4 complete). Extends ADR 0014 (limits)
and ADR 0040 (the limits structure).

## Context

- **SR-8:** each compartment has caps on memory, processes and threads,
  handles, tmpfs bytes and CPU share. A fork bomb or memory hog in one
  compartment leaves the others responsive.
- **Security acceptance P3, item 3:** a fork bomb and a memory hog in
  compartment A leave a shell in compartment B responsive, and A is
  killed cleanly at its limit.

Already in place (ADR 0014):
- processes, with threads taking slots (ADR 0019);
- memory;
- tmpfs bytes and nodes.

Missing:
- **CPU share.** The scheduler kept one round-robin queue of ready
  threads, so a compartment got CPU time in proportion to its runnable
  threads. Sixteen spinning children in A would give B's one thread a
  turn about every 160 ms.
- **Handles.** Every process had the kernel's fixed table of 1024. The
  manifest's `[limits] handles` was checked but not enforced (ADR 0040).

## Decision

### CPU share: fair between compartments

- **Groups.** The ready queue (`keel_core::fairq::FairQueue`,
  host-tested) keeps ready threads per group:
  - a user thread's group is its compartment's ID;
  - kernel threads and the system compartment are group 0.
- **Turns.** Groups take turns. Each pick runs the first thread of the
  group at the front, and that group goes to the back if it has more
  ready threads. Within a group, threads keep the order in which they
  became ready, as the single queue did.
- **Result.** When every group is busy, each gets an equal share of the
  CPU, however many threads it has. A group with nothing ready takes no
  turn, so an idle compartment costs nothing. The time slice is
  unchanged at 10 ms.
- **Assignment.**
  - A process spawned into a compartment (`process::spawn_in`, the
    native `compartment_spawn`) starts in its compartment's group.
  - A thread made by `fork`, `vfork` or `clone` inherits its parent's.
  - A process never leaves its compartment (SR-2), so nothing changes
    a group afterwards.
- **Shares are equal; there is no weight to set.** SR-8 asks for a cap,
  and an equal share is one: with *n* busy compartments, none can take
  more than 1/*n*. A manifest weight can come later if a workload needs
  one.

### Handles: a limit per process, set by the compartment

- **What the limit counts.** `Limits::handles` is the number of
  descriptors each process of the compartment may hold, as
  RLIMIT_NOFILE is per process on Linux. The kernel's table size, 1024,
  caps it. Every process is bounded and so is the number of processes,
  so the compartment's total is bounded too.
- **Where it is applied.**
  - **At spawn:** the new process's table is lowered to the limit. EMFILE
    refuses the spawn if a given descriptor already lies beyond it.
  - **fork** copies the table, limit and all.
  - **Beyond the limit**, a new descriptor is EMFILE. `dup2` and
    `dup3` to an index beyond it are EBADF (`HandleTable::place`), as
    Linux answers past RLIMIT_NOFILE.
- **In the native interface,** bytes 32 to 35 of ADR 0040's limits
  structure (reserved until now) carry the limit; 0 means the kernel's
  own. A factory's ceiling bounds it like any other limit.
- **In manifests,** `[limits] handles` (3 to 1024; 1024 when left out)
  now reaches the kernel through keel-launch. keel-init's ceiling for
  keel-launch is 1024.

## Not yet covered

- **Weights:** CPU shares are equal (see above).
- **SMP:** Keel runs on one CPU (decision D8). Each CPU will need its own
  fair queue, and balancing between them, when SMP arrives in Phase 6.
- **Time spent in the kernel on a compartment's behalf** (page faults,
  copies) counts against whichever thread is running, as before. Every
  such operation is bounded, and the thread that caused it is the one
  running, so it falls on the compartment that caused it.

## Evidence

- **Host tests:**
  - `keel_core::fairq` (5):
    - 64 hogs in one group and 1 in another get 500 slices each out of
      1,000;
    - three groups take turns in order;
    - order within a group is kept;
    - a group that empties leaves the turns and rejoins at the back;
    - 5,000 random pushes and pops against a model keep the invariant:
      a group is in the turns exactly when it has a ready thread, and
      exactly once.
  - `keel_core::handle`: a limit only goes down, never past a held
    handle (EMFILE, nothing changed), and a copy keeps it.
  - `keel_core::compartment`: a handle limit above the ceiling does not
    fit.
- **`compartment.under_load` (phase 3; security acceptance P3 item 3).**
  The setup:
  - Compartment A (17 processes, 8 MiB) runs `loadprobe bomb`, which
    forks until EAGAIN, every child spinning in user mode, then touches
    memory until its memory limit ends it with a fault.
  - With A's 16 children spinning, compartment B runs `loadprobe
    respond 100`: 50 sleeps of 5 ms and 10 forks with waits, each of
    which must finish within 100 ms. The system compartment runs the
    same, and then B runs `keel-shell -c "echo b: responsive"`, which
    must finish within a second.
  - Then A is killed. Its process count and memory budget return to 0,
    and every frame outside the kernel heap comes back.

  Measured in QEMU (TCG), over two runs:

  | | Sleep lateness | Fork and wait |
  | --- | --- | --- |
  | B alone | 1.4 to 1.7 ms | 2.2 to 2.3 ms |
  | B, A loaded | 20.3 to 25.9 ms | 11.9 to 12.0 ms |
  | System compartment, A loaded | up to 37.5 ms | up to 49.5 ms |

  That is about two time slices, as fair turns predict: each wait is
  for A's turn. The bound of 100 ms leaves a factor of 2 on both sides
  of the measurements. With one queue for all threads (the first
  mutation below), the same runs took 177 to 264 ms and 331 ms.
- **`launch.manifest`:** the manifest with `handles = 16` runs its
  program with descriptors up to 15 and EMFILE beyond.
- **Mutations,** each caught:

  | Mutation | Caught by |
  | --- | --- |
  | every thread in one group (the old single queue) | `compartment.under_load`: B and the system compartment 177 to 264 ms late, forks 331 ms |
  | `fork` and `clone` not inheriting the group (children in group 0) | `compartment.under_load`: the system compartment 163 ms late, forks 333 ms; B passes, which is why the system compartment is measured too |
  | a spawned process put in group 0 | `compartment.under_load`: both slow (182 to 193 ms, 358 to 365 ms) |
  | the handle limit not applied at spawn | `launch.manifest`: the 16-handle program exits 65 |
  | the native limit's handle field ignored | `launch.manifest`: exit 65 |

## Consequences

- A compartment's CPU-bound threads compete only with each other. Every
  other compartment, and the system compartment with keel-init and its
  shell, keeps its share.
- Two busy compartments each get half, where before one with more threads
  got more. Tests that time things in the system compartment while
  another compartment is busy now see less delay.
