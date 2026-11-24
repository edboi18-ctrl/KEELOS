# ADR 0026: epoll

Status: accepted (Phase 3, P3-T10 part 2).

## Context

epoll is the call Wine uses most after `read` and `rt_sigprocmask`
(`docs/syscall-inventory.md`):

| Call | Calls | How |
| --- | --- | --- |
| `epoll_pwait` | 21615 | 128 events, a 16 ms timeout, no mask |
| `epoll_ctl` | 155 | ADD with EPOLLIN 174 times, MOD once, ADD with EPOLLOUT once |
| `epoll_create1` | 1 | |

ADR 0025 built one readiness queue and the poll masks of pipes,
eventfds and the console. Linux's epoll (`fs/eventpoll.c`) hooks each
item onto its file's wait queues. A wake whose key (the events it
announces) matches the item's interest puts it on the ready list
(`ep_poll_callback`), and `ep_send_events` reports from that list. For
edge-triggered items, which wakes happen decides what is reported.

## Decision

1. **Wake counts in place of callbacks.** Each object counts the wakes of
   its wait queues by key (`keel_core::epoll::Wakes`), where Linux calls
   `wake_up_poll`:
   - **A pipe's readers' queue** is woken with EPOLLIN | EPOLLRDNORM by
     every write. Linux's `pipe_write` wakes on every write once the pipe
     has been polled ("Epoll nonsensically wants a wakeup whether the pipe
     was already empty or not").
   - **A pipe's writers' queue** is woken with EPOLLOUT | EPOLLWRNORM by a
     read of a full pipe (`was_full`).
   - **Both pipe queues** are woken for everything when the last reader or
     the last writer goes, but not both (`pipe_release`).
   - **An eventfd** has one queue: EPOLLOUT after a read, EPOLLIN after a
     write.
   - **The console** wakes with EPOLLIN | EPOLLRDNORM at each finished line
     (`n_tty_receive_handle_newline`).

   An item hears the queue its file would wait on: a pipe's read end the
   readers', its write end the writers' (`pipe_poll`). It keeps the counts
   it saw last. When a count has moved, for a key of 0 or one sharing a
   bit with its interest, it joins the ready list as the callback would
   have put it. Items look at the counts whenever the set is used: at
   every wait and every check while waiting, under the readiness queue's
   lock, so no wake is lost.
2. **The set** (`keel_core::epoll::Set`, host-tested) follows
   `fs/eventpoll.c`:
   - **ADD** (`ep_insert`): EEXIST if the item is there; the interest
     gains EPOLLERR and EPOLLHUP; an item ready now goes on the ready list.
   - **MOD** (`ep_modify`): ENOENT if absent; EINVAL for an item added with
     EPOLLEXCLUSIVE; the new interest, and on the list if ready now.
   - **DEL:** ENOENT if absent.
   - **Sending** (`ep_send_events`), up to `maxevents`, takes the ready
     list. An item ready for nothing it wants leaves it. A reported item
     shows its mask & interest, and its data:
     - with EPOLLONESHOT it is disabled (interest = private bits) until
       MOD;
     - with EPOLLET it leaves the list until its next matching wake;
     - otherwise it goes back on the end, so level-triggered items take
       turns when `maxevents` is short.

     Items not reached stay first. An event that cannot be copied out
     puts its item back, and the call is EFAULT if none was copied.
3. **Items and lifetime.** An item is keyed by its target's identity and
   the descriptor number, as Linux's (file, fd). It holds the target
   weakly and goes when the target is released, not when one of its
   descriptors closes (`eventpoll_release`). A duplicate keeps it alive,
   and it reports the data it was given. It also keeps the handle's
   rights at ADD and MOD, and reports readiness only for what they allow,
   as poll does (SR-1, ADR 0008).
4. **epoll_create and epoll_create1** (`do_epoll_create`):
   - **Arguments:** flags other than EPOLL_CLOEXEC are EINVAL; a size of 0
     or less is EINVAL.
   - **The descriptor** is an anonymous inode: mode 0600, the eventfds'
     inode, ANON_INODE_FS_MAGIC. lseek is 0 (`noop_llseek`); read and write
     are EINVAL. F_GETFL is O_RDWR.
   - **poll and select** on it report POLLIN while a listed item is ready
     (`ep_eventpoll_poll`).
5. **epoll_ctl** checks in Linux's order (`do_epoll_ctl`):
   1. the event is read unless the op is DEL (EFAULT);
   2. `epfd`, then `fd`, must be open (EBADF);
   3. the target must have a poll method (EPERM): pipes, eventfds, epoll
      instances and the console do; regular files, directories,
      `/dev/null`, `/dev/zero` and `/dev/urandom` do not (checked on Linux:
      all five EPERM);
   4. `epfd` must be an epoll instance, not the target itself (EINVAL);
   5. EPOLLEXCLUSIVE is EINVAL with MOD, and with ADD of an epoll target
      or of bits beyond EPOLLEXCLUSIVE_OK_BITS;
   6. an unknown op is EINVAL.

   EPOLLEXCLUSIVE is otherwise accepted: it changes which of several
   waiters wakes, and Keel wakes them all.
6. **epoll_wait, epoll_pwait and epoll_pwait2** (`do_epoll_wait`,
   `ep_poll`):
   - **Arguments:** `maxevents` at or below 0, or above EP_MAX_EVENTS
     (178956970), is EINVAL. The array must pass Linux's `access_ok`: up
     to a page, any user address will do (NULL is one, and EFAULT comes
     only if an event is written there); longer, it must end in the user
     half. `epfd` not open is EBADF; not an epoll instance, EINVAL.
   - **The wait:**
     1. ready items are sent; if any were, the call returns their count;
     2. with a zero timeout, or past the deadline, it returns 0;
     3. a signal pending that the thread does not block is EINTR. This
        comes after the timeout, so a zero-timeout call is never
        interrupted. Linux returns EINTR as such, never restarting.
     4. otherwise it waits for a change, a signal or the deadline.
   - **epoll_wait and epoll_pwait** take milliseconds (negative: none).
     **epoll_pwait2** takes a timespec, read before the mask (EINVAL for
     a negative or out-of-range one), and does not write the time back.
   - **Masks:** epoll_pwait and epoll_pwait2 take a temporary mask as
     ppoll (ADR 0025). A call that was not interrupted puts it back at
     once, before any signal is delivered, so a signal only its mask let
     in stays pending. This rule (`restore_saved_sigmask_unless`) was
     missing from part 1; it now holds for ppoll and pselect6 too.

## Not yet covered

- **Nested epoll.** Adding an epoll instance to another is EINVAL; Linux
  allows it, with loop and depth checks (ELOOP).
- **Wakes Keel does not model:**
  - `pipe_read`'s `wake_next_reader` and `pipe_write`'s
    `wake_next_writer`, after a blocked reader or writer, which give an
    edge-triggered item an extra edge;
  - the console's writers' queue, so an edge-triggered EPOLLOUT item on
    the console reports once, at ADD.
- **"Full" in bytes.** A pipe counts as full at 65536 bytes (ADR 0025), so
  a read wakes writers only then; Linux counts 16 page buffers.
- **EPOLLWAKEUP** is kept and does nothing (it needs CAP_BLOCK_SUSPEND
  and the suspend machinery). EPOLLRDHUP, EPOLLPRI and EPOLLMSG are never
  reported: no Keel object has them.
- **Busy polling** (`EPIOCSPARAMS`) and the epoll ioctls are ENOTTY.

## Evidence

- **Host tests** (`keel_core::epoll`):
  - ctl errors and the implicit EPOLLERR | EPOLLHUP;
  - level-triggered rotation and items leaving the list;
  - edge-triggered items needing a matching wake;
  - EPOLLONESHOT until MOD;
  - a fault putting the item back;
  - poll on the set;
  - wake counting by key, and the event layout.

  `keel_core::pipe`: which operations wake which queue.
- **`exec.epoll` (phase 3) and `host.epollprobe`:** `user/tests/
  epollprobe` makes 64 checks, which pass under Linux and on Keel:
  - **creation:** flags, close-on-exec, F_GETFL, epoll_create's size;
    stat, fstatfs, lseek, read and write;
  - **epoll_ctl's checks in their order:** EPERM for a memfd, `/dev/null`
    and a directory (before the op); EINVAL for itself and a non-epoll
    epfd; EBADF; EFAULT for ADD only; EEXIST, ENOENT; the EPOLLEXCLUSIVE
    rules;
  - **epoll_wait's checks:** maxevents, EINVAL, EBADF, EFAULT for a kernel
    address; a NULL array fine with nothing ready and EFAULT with
    something; the faulting item still ready after;
  - **level-triggered:** reported while ready, with its data and only the
    asked-for events; EPOLLHUP unasked;
  - **edge-triggered:** an edge per write, none from a read for readers;
    for writers an edge from a read of a full pipe and none otherwise;
    an eventfd's read (EPOLLOUT) no edge for a reader, its write one;
  - **EPOLLONESHOT** until MOD; two level-triggered items taking turns;
  - **lifetime:** an item living on through a duplicate and going with
    the last close;
  - **poll on the epoll descriptor;**
  - **timeouts** (epoll_wait, epoll_pwait2), EINVALs;
  - **a wait woken by a child's write** while the child still runs;
  - **masks:** a handler interrupting epoll_pwait and epoll_pwait2 (EINTR,
    the mask back after); a zero-timeout epoll_pwait returning 0, its
    pending signal kept pending and its handler not run.
- **`pipeprobe`** gains the ppoll case: a descriptor ready and a pending
  signal the mask lets in: 1, the signal still pending.
- **Mutations** on Keel, 24, each caught (the check that failed in
  brackets):
  - **The set:**
    - edge-triggered as level (37); level-triggered not requeued (32);
    - EPOLLONESHOT ignored (44); no implicit EPOLLHUP (35);
    - no rotation (48); any wake key firing (51);
    - a faulting item dropped (27);
    - ADD or MOD not linking a ready item (34, 46).
  - **The wakes:**
    - one queue for both pipe ends (41); no wake from a full pipe's
      read (41);
    - no wake at the last close (35); none from a write (26);
    - an eventfd read waking with EPOLLIN (51).
  - **epoll_ctl:** files pollable (11); no EPERM check (11); MOD with
    EPOLLEXCLUSIVE allowed (28); the event's fault ignored (17).
  - **epoll_wait:**
    - a strict `access_ok` (25); maxevents unchecked (23);
    - the signal checked before the timeout (77);
    - poll on the epoll descriptor never ready (67);
    - a wait that ignores readiness (the probe never finishes).
  - **The mask** kept after a call that was not interrupted: epollprobe
    77 and pipeprobe 101.

## Consequences

- Wine's server and threads wait in epoll_pwait as on Linux, woken by the
  pipe writes and closes they wait for.
- An epoll wait checks its whole set on every readiness change, which
  costs as the set grows; per-object queues can replace the counts
  without changing the set.
