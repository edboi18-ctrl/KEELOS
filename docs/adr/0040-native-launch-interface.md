# ADR 0040: the native launch interface, keel-launch and manifests

Status: accepted (Phase 3, P3-S2).

## Context

SR-2 and SR-3 (spec section 3) put every user process in exactly one
compartment, and make a new compartment empty. Its root directory,
device nodes and compositor connection are grants listed in its
manifest. Spec section 3, "Compartments in practice":
- `keel-init` starts with the only handle that can create compartments;
- it passes a restricted copy to `keel-launch`, the one program that
  reads manifests and starts applications;
- nothing inside an application compartment can create another
  compartment or obtain that handle;
- the native interface (create compartment, add grant, spawn first
  process, kill, query usage) is in a system-call range separate from
  the Linux ABI, works only for a caller holding the factory handle, and
  stays under ten calls.

Until now, compartments could be made only by the kernel itself
(`keel_linux_abi::compartment::create`, used by the self-tests).

## Decision

### Two new kinds of handle

- **A factory** (`Object::Factory`) can create compartments.
  - **Ceiling:** it carries one, a `Limits`, and every compartment it
    creates, or factory derived from it, must fit beneath it.
  - **Rights:** `CREATE` to create compartments or derive factories;
    `DUPLICATE` to be copied by dup, fork or SCM_RIGHTS; `STAT` for
    fstat.
- **A compartment handle** (`Object::Compartment`) is held by whoever
  created that compartment. Its rights:
  - `GRANT` (new, bit 14) to add device grants;
  - `CREATE` to spawn a process in it;
  - `SIGNAL` to kill;
  - `STAT` to read usage;
  - `WAIT` to wait for it to empty;
  - `DUPLICATE` as usual.

Neither is a file. read, write, mmap, poll and the like are EBADF or
EINVAL on them, as on an epoll handle. fstat gives an anonymous inode,
as Linux gives for anon_inode files.

### The calls

Seven calls, numbered from `0x1000_0000`. That is far above Linux's
x86-64 numbers (below 512) and below the x32 bit (`0x4000_0000`), which
Keel refuses. The arguments are registers, as for Linux calls. Errors
are -errno. Structures are little-endian, `repr(C)`, and every reserved
field must be 0 (EINVAL otherwise, SR-10).

| Nr | Call | Does |
| --- | --- | --- |
| +0 | `restrict(fd, rights)` | A new descriptor for the same object with `rights & mask`. SR-1: duplicating may remove rights, never add. Any handle with DUPLICATE. |
| +1 | `factory_derive(factory, limits*)` | A new factory whose ceiling is `limits`, which must fit beneath the old one's (EPERM). Needs CREATE. |
| +2 | `compartment_create(factory, rootfd, limits*)` | A new, empty compartment whose root is the directory `rootfd` names, with `limits` (EPERM above the factory's ceiling, EINVAL for a zero process limit). Needs CREATE on the factory, and ENUMERATE on `rootfd`, a directory (ENOTDIR). |
| +3 | `compartment_grant_device(c, device)` | Makes `/dev/<name>` in the compartment's tree. The devices: null 1, zero 2, urandom 3, tty 4, ptmx 5 (with `/dev/pts`). `/dev` must exist (ENOENT). An existing name is EEXIST, an unknown device EINVAL. Needs GRANT. |
| +4 | `compartment_spawn(c, path*, argv**, envp**, stdio*)` | Starts the program at `path`, looked up beneath the compartment's root, as a process in it, the first one PID 1. It gets fds 0 to 2 from `stdio` (three of the caller's descriptors, each needing DUPLICATE; -1 leaves it closed) and nothing else. A factory or compartment handle may not be given (EPERM). Returns the PID. Needs CREATE. |
| +5 | `compartment_kill(c, signal)` | Sends `signal` to every process in the compartment. Needs SIGNAL. |
| +6 | `compartment_wait(c, usage*, flags)` | Fills `usage`: processes, memory bytes, tmpfs bytes and nodes, and PID 1's wait status (-1 while it runs). Without WNOHANG (1), it first waits until the compartment has no process left; a signal interrupts it (ERESTARTSYS). WNOHANG needs STAT, waiting needs WAIT. |

`limits` is 40 bytes: processes (u32) and 4 reserved bytes, then memory
bytes, tmpfs bytes and tmpfs nodes (u64 each), then 8 reserved bytes.
`u64::MAX` (and `u32::MAX`) is no limit. Memory is rounded down to 4 KiB
frames.

`usage` is 40 bytes: processes (u32) and PID 1's wait status (i32),
then memory bytes, tmpfs bytes and tmpfs nodes (u64 each), then 8
reserved bytes, written as 0.

### Who holds what

- **keel-init:** the kernel starts `/sbin/keel-init` with the factory at
  fd 3, close-on-exec, its ceiling the kernel's (no limit). It is the
  only process the kernel gives one.
- **keel-launch:** keel-init gives it a factory derived with a fixed
  ceiling (1 GiB, 256 processes, 256 MiB and 65,536 nodes of tmpfs),
  restricted to CREATE and STAT, so it cannot be copied on. It is given
  as fd 3 of `keel-launch` alone: what keel-init runs otherwise (the
  shell) inherits nothing, since the original is close-on-exec.
- **Compartments:** a compartment's processes get only the three stdio
  descriptors they were spawned with. Nothing in a compartment can name
  a factory: fork copies only what the process has, SCM_RIGHTS needs
  DUPLICATE, and spawn refuses factory and compartment handles.

### Manifests and keel-launch

`keel-launch MANIFEST` reads the manifest, checks it, creates the
compartment with the factory on fd 3, grants its devices, spawns `exec`
with the manifest's arguments and environment and keel-launch's own fds
0 to 2, and waits. It exits with PID 1's exit code, or 128 plus the
signal that ended it.

The format is the spec's: a TOML subset. Comments (`#`), `key = value`,
tables (`[root]`), and array tables (`[[grant]]`). Values are strings
(`"..."` with `\\`, `\"` and `\n`), decimal integers, `true`/`false` and
arrays of strings.

| Key | Meaning | Now |
| --- | --- | --- |
| `name` | the application's name (1 to 64 bytes: letters, digits, `-`, `_`, `.`) | required |
| `exec` | the program, a path in the compartment | required, absolute |
| `args` | arguments after argv[0] | optional |
| `env` | `KEY=VALUE` strings | optional |
| `devices` | device grants, by name | optional; the five above |
| `profile` | syscall and ioctl allowlist | only `"default"` until P3-S3 |
| `[root] base` | the directory that becomes `/`, a path in keel-launch's tree | required |
| `[root] prefix`, `writable` | layered image | refused until P3-S5 |
| `[[grant]]` | a directory mounted inside | refused until P3-S5 (needs mounts) |
| `[display] allowed` | compositor connection | only `false` until Phase 5 |
| `[network] allowed` | network | only `false` |
| `[limits] memory_mb`, `processes`, `tmpfs_mb`, `tmpfs_nodes` | the compartment's limits | optional; default 256 MiB, 64, 64 MiB, 4096 |
| `[limits] handles` | descriptors per process | at most 1024, Keel's fixed table size |

Fail closed (SR-10): an unknown key or table, a value of the wrong type,
a key given twice, a string over 4096 bytes, or a manifest over 64 KiB
is an error naming the line. Nothing is created unless the whole
manifest is good. The parser is a `no_std` crate without allocation,
`user/manifest`. It is fuzzed on the host (`cargo xtask fuzz-manifest`,
spec section 3, "Parser fuzzing on the host").

## Not yet covered

- **Layered roots and mounted grants** (`prefix`, `writable`,
  `[[grant]]`): P3-S5.
- **Allowlist profiles:** P3-S3.
- **Audit records** of creation and grants: P3-S6. The calls are the
  points where they will go.
- **How a user at the shell asks for a launch.** keel-launch can be run
  only by keel-init now (`keel-init --launch MANIFEST`), since only
  keel-init has a factory to give. A launch service the shell could ask
  is left open.
- **CPU share** (SR-8): no limit yet.
- **A per-compartment handle cap:** each process has Keel's fixed table
  of 1024. `[limits] handles` is checked (3 to 1024) but not yet
  enforced below that.

## Evidence

- **`exec.launch` (phase 3):** `user/tests/launchprobe`, Keel only (Linux
  has no such calls), is run by the kernel with a factory on fd 3. It
  makes 10 checks, runs twice, and the second run must give back every
  node, frame and process. The checks:
  1. a call past the last ENOSYS, a handle that is no factory EBADF;
  2. restrict keeps only the rights asked for, unknown bits EINVAL, and
     a handle without DUPLICATE cannot be copied on;
  3. a derived factory's ceiling: above it EPERM, reserved bytes or no
     processes EINVAL;
  4. compartment_create: above the ceiling EPERM, a file as root
     ENOTDIR (before the right is checked), a root without ENUMERATE
     EBADF;
  5. grant_device: the node appears, twice EEXIST, unknown EINVAL, and
     no `/dev` ENOENT;
  6. spawn: a missing program ENOENT, a factory as stdio EPERM, the
     first process PID 1;
  7. inside, PID 1 has only the stdio it was given, no factory, sees
     nothing outside its tree, and cannot use the calls; wait returns
     its status (42) and no process;
  8. a STAT-only handle can look (WNOHANG: one process running, memory
     charged) but not wait, spawn or kill; kill with SIGKILL ends the
     compartment, and wait reports signal 9;
  9. a compartment's limits hold: with one process, its fork is EAGAIN;
  10. the handles are not files: read EBADF, lseek ESPIPE, fstat an
      anonymous inode.
- **Mutations** on Keel, 12, all caught (the launchprobe check that
  failed in brackets):
  - **ceilings:** ignored at create (4) or at derive (3);
  - **rights:** restrict keeping every right (2); a STAT-only handle
    allowed to wait (the probe never ends);
  - **spawn:** a factory given as stdio (6);
  - **create:** the system root instead of the given directory (5); the
    limits ignored (9);
  - **ending:** PID 1's status not kept (7); kill doing nothing (the
    probe never ends); wait not waiting (7);
  - **checks:** reserved bytes not checked (3).
