# ADR 0045: the audit log

Status: accepted (Phase 3, P3-S6). Extends ADR 0040 (one native call)
and ADR 0041 (where refusals go).

## Context

**SR-11:** "Compartment creation, every grant, and denied operations
(rate-limited) are recorded in a kernel log readable only through a
handle held by `keel-init`."

Until now:
- nothing recorded creations or grants;
- profile refusals (ADR 0041) went to the kernel's console log, the
  first 8 of each compartment, where anyone at the console could read
  them;
- native calls above a factory's ceiling were EPERM and recorded
  nowhere.

## Decision

### The log

- **The data structure:** one log in the kernel
  (`keel_core::audit::AuditLog`, host-tested, behind an interrupt-safe
  lock in `keel_linux_abi::audit`) holds the last 1,024 records, each
  numbered in order. When full, the oldest goes.
- **What is recorded:**

  | Record | When | Fields |
  | --- | --- | --- |
  | `create` | every compartment created, by the native call or by the kernel for its tests | compartment, profile, process limit, who (a process by compartment and PID, or `kernel`) |
  | `grant` | every successful device grant (`compartment_grant_device`) | compartment, device, who |
  | `deny` | a system call, operation or ioctl request outside the caller's profile (ADR 0041); a native call above its factory's ceiling (`factory_derive`, `compartment_create`: EPERM) | compartment, PID, the call and its number, the operation, the errno, and how many denials were suppressed before this one |

  The call's name comes from Keel's table; the native calls are
  `factory_derive` and `compartment_create` with their own numbers
  (`0x1000_0000` and up).
- **Rate limit:**
  - **What is limited:** denials, per compartment, by a token bucket
    (`keel_core::audit::Limiter`, lock-free): 32 at once, then 1 a
    second. Creations and grants are never limited: only a factory
    holder makes them, and its ceiling bounds them.
  - **What is not lost:** a denial past the limit is counted, not
    recorded, and the next one recorded carries
    `suppressed=N`. So every denial is accounted for, either recorded or
    counted, and one program cannot flush other records out of the log.
  - **The console:** denials no longer go to the console log at all.

### Reading it

- **Opening:** a new native call, `audit_open(factory)` (`+7`; ADR
  0040's interface now has eight of its ten), gives an audit handle. It
  needs a new right on the factory, AUDIT (bit 15).
- **Who can open it:**
  - **The root factory has AUDIT.** The kernel gives that factory to
    keel-init alone, close-on-exec.
  - **Derived factories don't:** `factory_derive` gives a new factory
    the usual factory rights, and `restrict` can only remove rights.
  - So only keel-init, or a program keel-init hands its own factory, can
    open the log. keel-launch gets a factory restricted to CREATE and
    STAT.
  - **The handle cannot reach a compartment:** `compartment_spawn`
    refuses it as standard input, output or error, as it refuses factory
    and compartment handles (EPERM).
- **Reading:** `read(2)` on the handle gives whole lines of text, as
  many as fit, from where that handle last stopped.
  - **It starts** at the oldest record kept, so keel-init sees what
    happened since boot as far as the log reaches.
  - **Buffers:** a buffer too small for the next line is EINVAL, as for
    Linux's `/dev/kmsg`.
  - **Nothing new:** 0.
  - **A reader that fell behind** first gets a `lost=N before seq=S`
    line.
  - **Other operations:** writing is EBADF; the handle has READ, STAT
    and DUPLICATE.

  A line looks like:

  ```
  audit: seq=41 time=12.345 create c=7 profile=default processes=64 by=c0:1
  audit: seq=42 time=12.346 grant c=7 device=null by=c0:1
  audit: seq=43 time=12.400 deny c=7 pid=1 getppid(110) errno=38
  audit: seq=44 time=12.401 deny c=7 pid=1 fcntl(72) op=0x1 errno=22 suppressed=5
  ```

## Evidence

- **Host tests** (`keel_core::audit`, 5):
  - lines in order and read once;
  - a small buffer gets whole lines or EINVAL;
  - a full log drops the oldest, and a late reader is told how many it
    lost;
  - the limiter allows a burst, then its rate, refilling to the burst
    and no further;
  - over 10,000 simulated milliseconds the limiter admits at most its
    budget, and every denial is admitted, reported as suppressed, or
    pending.
- **`exec.launch`** (launchprobe check 12):
  - a restricted copy of the root factory and a derived factory cannot
    open the log (EBADF); the root factory can;
  - an 8-byte read is EINVAL, and a write EBADF;
  - the log holds this program's own `create` and `grant` of
    `/dev/null` (by its compartment and PID), and its
    `compartment_create` above a ceiling, denied with EPERM;
  - check 1's "no such native call" moved to the ninth number.
- **`audit.log`** (phase 3), after `compartment.profiles`: for both the
  default-profile and full-profile compartments:
  - the log has their creation, by the kernel;
  - at least 32 denials are recorded;
  - recorded + reported as suppressed + still pending equals the
    compartment's count of refusals, and some were suppressed (each
    makes 50 or more in well under a second).

- **Measured:** the default-profile compartment made 57 refusals:
  32 recorded and 25 pending. The full-profile one made 50: 32 recorded
  and 18 pending.
- **`exec.launch`** also checks that `compartment_spawn` refuses the
  audit handle as a new process's standard output (EPERM).
- **Mutations,** each caught:

  | Mutation | Caught by |
  | --- | --- |
  | the root factory without AUDIT | `exec.launch`: check 12 |
  | a derived factory with AUDIT | `exec.launch`: check 12 |
  | creations not recorded | `audit.log` and `exec.launch` |
  | grants not recorded | `exec.launch`: check 12 |
  | native refusals not recorded | `exec.launch`: check 12 |
  | no rate limit | `audit.log`: all 57 and 50 recorded, none suppressed |
  | profile refusals not recorded | `audit.log`: 0 recorded |
  | spawn giving the audit handle to a compartment | `exec.launch`: check 12 |

## Not yet covered

- **What keel-init does with the log.** It holds the handle's factory;
  showing or keeping the records (for instance a command at the shell
  that keel-init answers) comes with the shell's administration
  commands.
- **Other refusals:** a handle without the right a call needs (EBADF,
  SR-1) is not recorded. Every system call checks rights, so these are
  far more frequent, and mostly ordinary program errors.
- **Persistence:** the log is in memory, gone at reboot.
