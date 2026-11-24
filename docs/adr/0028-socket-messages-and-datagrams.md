# ADR 0028: Descriptor and credential passing, and datagram sockets

Status: accepted (Phase 3, P3-T11 part 2).

## Context

ADR 0027 built Unix stream sockets without ancillary data. Wine needs
it: of its ~830 `sendmsg` and `recvmsg` calls, almost every one carries
one SCM_RIGHTS descriptor. A few carry SCM_CREDENTIALS too (with
SO_PASSCRED set around them), and the receives use MSG_CMSG_CLOEXEC. The
spec's P3-T11 also asks for datagram sockets.

Linux v6.12 keeps a socket's receive queue as sk_buffs, each with its
bytes, its descriptors (`UNIXCB(skb).fp`), the sender's credentials, and
the sender (whose name a datagram's receiver reports). Reads are shaped
by those parts.

## Decision

1. **A queue of parts** (`keel_core::unix::Queue`, host-tested) replaces
   the byte stream. Each part holds its bytes (and how many are read),
   the descriptors sent with it, the sender's credentials if any, the
   sender's name (datagrams), and a token dropped with the part (a
   datagram's charge to its sender's send buffer).
   - **A stream read** (`unix_stream_read_generic`):
     - takes bytes across parts;
     - stops after a part with descriptors, or in the middle of a part;
     - for a reader with SO_PASSCRED, stops before a part whose
       credentials differ from the first part read's (`unix_skb_scm_eq`);
     - detaches the descriptors of every part it takes bytes from.

     It is planned before anything is taken, so bytes that fault on the
     way out stay queued with their descriptors.
   - **MSG_PEEK** copies the descriptors (`unix_peek_fds`): the peek and
     the read after it each get new descriptors.
2. **Sending ancillary data** (`__scm_send`, `cmsg_nxthdr`), walked in
   Linux's order:
   - a header shorter than 16 bytes, or longer than the control data
     left, is EINVAL; other levels are skipped;
   - SCM_RIGHTS: an empty one sends nothing; more than SCM_MAX_FD (253)
     in all is EINVAL; each descriptor must be open (EBADF);
   - SCM_CREDENTIALS: exactly CMSG_LEN(12) (else EINVAL); uid or gid -1
     EINVAL; the pid must be a process of the sender's compartment
     (ESRCH). Keel's processes are root, which may claim any pid, uid and
     gid (`scm_check_creds`);
   - any other SOL_SOCKET type is EINVAL.

   Passing a descriptor needs the handle's DUPLICATE right (EBADF
   without, as any missing right: SR-1). The receiver's new handle gets
   the sender's rights, so passing never adds a right.
3. **Descriptors in flight.**
   - **Stream:** they go with the first part of a send. A stream send of
     no bytes sends no part, so its descriptors are dropped (Linux's
     `while (sent < len)` loop).
   - **Lifetime:** a descriptor in flight keeps its object alive after
     the sender closes it.
   - **Limit:** each compartment may have at most 1024 in flight
     (ETOOMANYREFS when past it, as `too_many_unix_fds`). Linux exempts
     root, which all Keel processes are; Keel holds every compartment to
     the limit, so the memory they hold stays bounded.
4. **Credentials** (`maybe_add_creds`, `__scm_recv_common`). A part with
   none given gets the sender's (its compartment, pid, uid 0, gid 0) if
   the sender or the receiver has SO_PASSCRED, or the receiver is not
   yet accepted. A reader with SO_PASSCRED gets SCM_CREDENTIALS:
   - the part's pid if of its compartment, else 0;
   - for a part with none, pid 0 and the overflow uid and gid (65534);
   - if nothing was read, all 0 (Linux's zeroed cookie).
5. **Receiving ancillary data** (`scm_recv_unix`, `put_cmsg`,
   `scm_detach_fds`):
   - **Order:** SCM_CREDENTIALS first, then SCM_RIGHTS.
   - **Truncation:** less room than a header gives MSG_CTRUNC and nothing;
     less than the whole message, as much as fits (its cmsg_len the room)
     and MSG_CTRUNC. Each message advances the buffer by CMSG_SPACE, at
     most to its end.
   - **Descriptors:** as many as fit, each a new handle with the sender's
     rights, close-on-exec with MSG_CMSG_CLOEXEC. The rest are closed,
     and MSG_CTRUNC is set if any were left out (or none could fit). A
     full handle table (EMFILE) stops the installing.
   - **No buffer:** with no control buffer, MSG_CTRUNC if either kind was
     due, and the descriptors are closed. read and recv close them too.
   - **Write-back:** msg_controllen gives the bytes used; msg_flags gets
     MSG_CTRUNC and MSG_TRUNC.
6. **Datagram sockets** (`unix_dgram_ops`): SOCK_DGRAM, and SOCK_RAW
   (which is SOCK_DGRAM, as SO_TYPE reports). SOCK_SEQPACKET stays
   ESOCKTNOSUPPORT.
   - **Sending** (`unix_dgram_sendmsg`), in Linux's order:
     1. an address, or else the connected peer (ENOTCONN);
     2. autobind with SO_PASSCRED;
     3. a datagram longer than the send buffer less 32 bytes is EMSGSIZE;
     4. room in the sender's send buffer (its datagrams not yet read; its
        own SEND_SHUTDOWN is EPIPE);
     5. the target ([`find`]):
        - a connected peer that has gone disconnects the sender, dropping
          what it had received, and is ECONNREFUSED;
        - one connected to another socket is EPERM (`unix_may_send`);
        - one shut for reading is EPIPE, with no SIGPIPE;
        - its queue full (more than 10, `max_dgram_qlen`'s default) waits
          or is EAGAIN, unless it is the sender or connected back to it.

     The datagram is queued whole with the sender's name, and the call
     returns its length.
   - **Receiving** (`__unix_dgram_recvmsg`): one datagram. A short buffer
     truncates it and sets MSG_TRUNC; MSG_TRUNC in the flags returns the
     whole length. The sender's name is reported if it had one. A
     pending error comes first, then reading shut down (0), then EAGAIN
     or a wait. A fault copying it out loses the datagram (it was
     taken): EFAULT.
   - **connect** (`unix_dgram_connect`):
     - AF_UNSPEC disconnects; anything shorter than a family is EINVAL;
     - otherwise it is checked as send's target (EPERM included);
     - connecting elsewhere or disconnecting drops what the socket had
       received; if anything was dropped and the old peer was connected
       back, the old peer gets ECONNRESET (`unix_dgram_disconnected`).
   - **Release:** releasing a datagram socket does not shut its peer down.
   - **Readiness** (`unix_dgram_poll`):
     - no EPOLLHUP for an unconnected socket;
     - not writable while its peer's queue is full and the peer is not
       connected back to it;
     - FIONREAD gives the first datagram's length.
   - **Wakes:** reading a datagram releases its sender's charge, which
     wakes the sender (EPOLLOUT, `sock_wfree`).
7. **Abstract names are per type.** Linux mixes the socket's type into an
   abstract name's hash bucket (`unix_abstract_hash`). So a stream socket
   and a datagram socket can hold the same abstract name, and a lookup
   finds only its own type's: ECONNREFUSED, never EPROTOTYPE, which only
   path names give. ADR 0027 had one table for all types; the table is
   now keyed by compartment, type and name.

## Not yet covered

- **A garbage collector for in-flight cycles.** A socket passed into its
  own queue, or a loop of sockets passed into each other's, stays alive
  with what it holds (`unix_gc` collects these on Linux). The in-flight
  limit bounds them per compartment, but a leaked cycle keeps its share
  of the limit.
- **SOCK_SEQPACKET**, MSG_OOB, SO_PASSPIDFD and SCM_PIDFD, SO_PASSSEC
  and SCM_SECURITY, and timestamps.
- **Buffer accounting by bytes, not truesize** (as ADR 0027). A datagram
  socket's send buffer therefore holds many more small datagrams than on
  Linux, where each costs an sk_buff. The queue length limit (10), not
  the buffer, is what a receiver's sender meets first.
- **`max_dgram_qlen`** is fixed at its default; Linux's is a sysctl.

## Evidence

- **Host tests** (`keel_core::unix`):
  - a stream read crossing parts and stopping after descriptors;
  - consume detaching only touched parts' descriptors;
  - credential boundaries with and without SO_PASSCRED;
  - partial reads;
  - control parsing (several messages, skipped levels, the EINVALs, 254
    descriptors);
  - truncation on the way out (credentials into a header-sized buffer,
    descriptors into room for two of three).
- **`exec.socket_messages` (phase 3) and `host.scmprobe`:**
  `user/tests/scmprobe` makes 70 checks, which pass under Linux (as root
  and as an unprivileged user with umask 077) and on Keel. Keel runs it
  twice and measures the second run: every node, frame and process is
  back.
  - **SCM_RIGHTS:**
    - the message's layout and msg_controllen;
    - one open file description shared; MSG_CMSG_CLOEXEC;
    - EBADF, the EINVALs, a skipped level, 254 descriptors;
    - room for one of three (MSG_CTRUNC), no buffer;
    - read boundaries before and after a part with descriptors;
    - MSG_PEEK's copies;
    - descriptors with no bytes dropped;
    - lifetime past the sender's close; a socket passed and used; a
      read-only file staying read-only; a child passing to its parent.
  - **SCM_CREDENTIALS:**
    - none without SO_PASSCRED; the sender's pid, uid and gid with it,
      before SCM_RIGHTS;
    - a child's pid, and the read boundary between it and the parent's;
    - explicit credentials; ESRCH (EPERM for Linux's unprivileged user),
      EINVAL for uid -1 and for a length too short or too long;
    - a header-sized buffer.
  - **Datagrams:**
    - boundaries, SO_TYPE (and SOCK_RAW), truncation and MSG_TRUNC both
      ways, an empty datagram, MSG_PEEK, FIONREAD, poll;
    - sendto and recvfrom names, ECONNREFUSED, ENOTCONN;
    - abstract names per type, EPROTOTYPE through a path;
    - connect, EPERM, descriptors over a datagram, AF_UNSPEC;
    - a gone peer (ECONNREFUSED, then ENOTCONN); EMSGSIZE; a full queue
      (EAGAIN); EPIPE for a receiver shut for reading, with no SIGPIPE.
- **`exec.sockets`** still passes its 102 checks with abstract names per
  type.
- **Mutations** on Keel, 29, all caught (the scmprobe check that failed
  in brackets; 101 is the probe panicking on the control data it got):
  - **SCM_RIGHTS:**
    - descriptors dropped on datagrams (67) or streams (3);
    - consume keeping them (3); the sender's rights ignored (25);
    - the read boundary after descriptors ignored (17);
    - MSG_PEEK's copies missing (19);
    - no MSG_CTRUNC without a buffer (16); twice the room for descriptors
      (101); MSG_CMSG_CLOEXEC ignored (7);
    - SCM_MAX_FD unchecked (13); an unknown type accepted (9).
  - **Credentials:**
    - not added for a SO_PASSCRED reader (33);
    - the credential boundary ignored (35);
    - SCM_RIGHTS before SCM_CREDENTIALS (101);
    - ESRCH unchecked (39); a long SCM_CREDENTIALS accepted (43).
  - **Datagrams:**
    - not truncated (53); MSG_TRUNC's length ignored (55);
    - `unix_may_send` always true (66);
    - a gone peer left connected (69);
    - EMSGSIZE unchecked (70); the queue length unchecked (72);
    - a receiver shut for reading accepting (74);
    - no sender name (61);
    - EPOLLHUP when unconnected (58); FIONREAD the whole queue (57);
    - AF_UNSPEC ignored (68);
    - MSG_PEEK consuming (the probe never finishes).
  - **Abstract names not per type:** scmprobe 60, and sockprobe 96.

## Consequences

- Wine's server can pass handles to its clients, and its clients
  credentials to it, as on Linux.
- A descriptor sent through a socket keeps exactly the rights its handle
  had: the capability model holds across processes.
