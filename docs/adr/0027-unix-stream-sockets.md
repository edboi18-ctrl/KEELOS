# ADR 0027: Unix domain stream sockets

Status: accepted (Phase 3, P3-T11 part 1; descriptor passing,
credentials and datagram sockets are part 2).

## Context

The spec's P3-T11 asks for "Unix domain sockets: stream and datagram,
filesystem and abstract names, `SCM_RIGHTS`". The Wine traces
(`docs/syscall-inventory.md`) show how Wine uses them:

| Use | Calls |
| --- | --- |
| wineserver's socket: `socket(AF_UNIX, SOCK_STREAM)`, `bind` to the relative path `socket` after `fchdir` into the server directory, `listen(5)` | 1 each |
| a client: `socket`, `SO_PASSCRED`, `connect` to `socket`; the server `accept`s it (the client then has an autobind name, `@a21bd`) | 1 each |
| `socketpair(AF_UNIX, SOCK_STREAM)` | 11 |
| `sendmsg` / `recvmsg` with one SCM_RIGHTS descriptor, MSG_CMSG_CLOEXEC, and SCM_CREDENTIALS | ~830 each (part 2) |
| `setsockopt(SO_PASSCRED)` on and off | 22 |
| `shutdown(SHUT_WR)` | 1 |

The other socket calls in the traces are netlink (`AF_NETLINK`,
`NETLINK_ROUTE`: the network interfaces) and `AF_INET` datagram
sockets. Neither is P3-T11's.

## Decision

1. **Sockets are objects.** `Object::Socket` holds the socket's state:
   - **The connection:** unconnected, listening, or connected.
   - **The name** it is bound to.
   - **Its receive queue**, as one byte stream (Linux's
     `sk_receive_queue`).
   - **Flags:** shutdown bits, a pending error (`sk_err`), options, the
     peer's credentials, and wake counts for epoll (ADR 0026).

   A connected pair points at each other weakly, so either side's last
   close is seen by the other. The handle has READ, WRITE, STAT and
   DUPLICATE; socket calls need only the handle, and the data calls READ
   or WRITE as read and write do.
2. **Creation** (`__sys_socket`, `__sock_create`, `unix_create`),
   checked in Linux's order:
   1. flags other than SOCK_CLOEXEC and SOCK_NONBLOCK are EINVAL;
   2. a family outside 0..AF_MAX is EAFNOSUPPORT;
   3. a type at or past SOCK_MAX is EINVAL;
   4. any family but AF_UNIX is EAFNOSUPPORT: Keel has no other, where
      Linux has AF_INET, AF_NETLINK and the rest;
   5. a protocol other than 0 or PF_UNIX is EPROTONOSUPPORT;
   6. only SOCK_STREAM is supported. SOCK_DGRAM (and SOCK_RAW, which is
      SOCK_DGRAM) arrives in part 2; SOCK_SEQPACKET is not planned.
      Until then, and for any other type, ESOCKTNOSUPPORT.

   The socket's own inode is S_IFSOCK | 0777 on sockfs (`sock_alloc`,
   SOCKFS_MAGIC). lseek is ESPIPE, mmap ENODEV. F_GETFL is O_RDWR with
   O_NONBLOCK.

   **socketpair** connects two sockets, each with the caller's
   credentials as its peer's; EFAULT closes both again.
3. **Names** (`unix_bind`, `unix_validate_addr`, `unix_mkname_bsd`,
   host-tested in `keel_core::unix`). An address of 2 bytes or less, or
   more than 110, or of another family, is EINVAL. bind with the family
   alone autobinds.
   - **A path** is cut at its first NUL. bind makes a socket node first
     (`vfs_mknod` S_IFSOCK; tmpfs's new `Kind::Socket`), mode 0777 less
     the umask:
     - a taken name is EADDRINUSE, and lookup errors are as mknod's;
     - a socket already named is then EINVAL, and the node is removed;
     - the node is pinned while the socket is bound;
     - opening it is ENXIO (`bad_sock_fops`); stat shows S_IFSOCK;
       getdents gives DT_SOCK;
     - when the socket goes, the node stays and names nothing: a connect
       to it is ECONNREFUSED, as on Linux.
   - **An abstract name** (first byte NUL) is the bytes as given. It lives
     in a table of the socket's compartment, as Linux's names are per
     network namespace. EADDRINUSE if taken, EINVAL if the socket is
     already named; it is freed when the socket goes.
   - **Autobind** (`unix_autobind`) gives an abstract name of a NUL and
     five hex digits (8 bytes with the family), searching from a random
     start. bind of the family alone does it, as does connect with
     SO_PASSCRED set (which is how Wine's clients get `@a21bd`).
   - **getsockname** gives the name as bound: a path with its NUL, an
     abstract name as given, an unnamed socket the family alone.
4. **listen** (`unix_listen`): the backlog is capped at SOMAXCONN (4096,
   taken as unsigned, so a negative one too). Not a stream socket is
   EOPNOTSUPP; unnamed EINVAL; connected EINVAL. Listening takes the
   caller's credentials as the socket's (`update_peercred`).
5. **connect** (`unix_stream_connect`), in Linux's order:
   1. the address (EINVAL);
   2. autobind if SO_PASSCRED is set and the socket is unnamed;
   3. the listener (`unix_find_other`): a missing path is ENOENT (lookup
      errors as lookup's); a node that is not a socket, or a name no one
      holds, ECONNREFUSED; another type EPROTOTYPE; not listening, or
      shut for reading, ECONNREFUSED;
   4. a full backlog (more waiting than the backlog): EAGAIN if
      non-blocking, else a wait (up to SO_SNDTIMEO);
   5. this socket connected EISCONN, listening EINVAL (checked only after
      the listener is found, as Linux);
   6. the connection itself: a new socket (Linux's embryo), connected to
      this one, named as the listener, with the caller's credentials,
      queued on the listener. This socket gets the listener's
      credentials.

   It is connected at once: the client can write before `accept`.
6. **accept and accept4** (`__sys_accept4_file`, `unix_accept`):
   - **Checks:** flags other than SOCK_CLOEXEC and SOCK_NONBLOCK are EINVAL
     (after EBADF, before ENOTSOCK); not a stream socket EOPNOTSUPP; not
     listening EINVAL.
   - **No connection waiting:** EAGAIN if the listener is non-blocking,
     else a wait (up to SO_RCVTIMEO).
   - **The new socket** inherits SO_PASSCRED. The peer's address (the
     client's name, or the family alone) is written if asked; a fault
     there closes the new socket again, as `do_accept`'s `fput`.
7. **Data** on a connected stream socket:
   - **Sending** (`unix_stream_sendmsg`), in this order:
     1. MSG_OOB is EOPNOTSUPP;
     2. an address is EISCONN if connected, else EOPNOTSUPP;
     3. no peer is ENOTCONN;
     4. sending shut down is EPIPE, with SIGPIPE unless MSG_NOSIGNAL;
     5. the bytes go to the peer's queue while what this side has sent
        unread is below its send buffer (SO_SNDBUF). Without room it
        waits, or gives EAGAIN or the count so far.
     6. a peer gone or shut for reading is EPIPE, with SIGPIPE if nothing
        was sent.
   - **Receiving** (`unix_stream_read_generic`):
     - not connected is EINVAL;
     - it returns what is waiting, up to the request: all of it with
       MSG_WAITALL, else at least a byte; MSG_PEEK leaves the bytes;
     - with nothing waiting: a pending error first (ECONNRESET, reported
       once), then end of file if shut for reading, then EAGAIN or a wait
       (up to SO_RCVTIMEO);
     - a zero-length recv waits for data as Linux's does, but read of
       nothing is 0 at once (`sock_read_iter`);
     - bytes that fault on the way out stay queued.
   - **Calls:** read, write, readv and writev, sendto, recvfrom, sendmsg
     and recvmsg all reach these.
     - recvfrom and recvmsg report the sender's name if it has one, else
       a length of 0 (`unix_copy_addr`).
     - recvmsg writes back the name length, msg_flags (MSG_CMSG_CLOEXEC
       kept) and a control length of 0.
     - Ancillary data on sendmsg is EINVAL until part 2.
8. **shutdown** (`unix_shutdown`): `how` outside 0..2 is EINVAL. The
   socket's shutdown gains how + 1, and a peer gains the mirror (reading
   shut here is writing shut there). An unconnected socket is fine.
9. **Release** (`unix_release_sock`), when the last reference goes:
   - its names go and its node is unpinned;
   - a connected peer is shut down both ways, with ECONNRESET if this side
     had unread data or was never accepted;
   - a listener's waiting connections are released, so their clients read
     ECONNRESET, then end of file.
10. **Readiness** (`unix_poll`):
    - **Bits:**
      - EPOLLERR with an error pending;
      - EPOLLHUP shut both ways, or unconnected (TCP_CLOSE);
      - readable with data or a connection to accept, or shut for
        reading (with EPOLLRDHUP);
      - writable unless listening, while what it sent unread is at most a
        quarter of its send buffer (`unix_writable`).
    - **Wakes**, as epoll hears them (ADR 0026): EPOLLIN | EPOLLPRI |
      EPOLLRDNORM | EPOLLRDBAND when data or a connection arrives
      (`sock_def_readable`); EPOLLOUT | EPOLLWRNORM | EPOLLWRBAND when the
      peer reads (`unix_write_space`); everything at shutdown and close.
    - **Rights:** poll's rights filter now passes POLLRDBAND and POLLRDHUP
      with READ, and POLLWRBAND with WRITE (it had dropped them).
    - **ioctl:** FIONREAD (SIOCINQ) gives the bytes waiting, EINVAL for a
      listener; SIOCOUTQ what was sent unread; other ioctls ENOTTY.
11. **Options** (`sk_setsockopt`, `sk_getsockopt`):
    - **setsockopt:** a negative length is EINVAL; levels other than
      SOL_SOCKET EOPNOTSUPP; a value shorter than an int EINVAL. It
      takes:
      - SO_PASSCRED;
      - SO_SNDBUF and SO_RCVBUF: capped at 212992, doubled, at least 4608
        or 2304, as checked on Linux;
      - SO_RCVTIMEO and SO_SNDTIMEO: a timeval; microseconds out of
        range are EDOM; negative means no waiting, zero no limit;
      - the flags SO_DEBUG, SO_REUSEADDR, SO_DONTROUTE, SO_BROADCAST,
        SO_KEEPALIVE and SO_OOBINLINE, kept and reported.

      SO_TYPE, SO_PROTOCOL, SO_DOMAIN and SO_ERROR are ENOPROTOOPT, as is
      everything else (listed below).
    - **getsockopt** checks the level before reading the length (EFAULT;
      negative EINVAL); the length caps the copy and is written back. It
      reports:
      - the options above;
      - SO_TYPE, SO_DOMAIN, SO_PROTOCOL (0) and SO_ACCEPTCONN;
      - SO_ERROR, which takes the pending error;
      - SO_PEERCRED: pid, uid 0, gid 0. The pid is 0 for a process of
        another compartment; with no peer it is pid 0, uid and gid -1, as
        `cred_to_ucred`.

## Not yet covered

- **Part 2:** SCM_RIGHTS and SCM_CREDENTIALS on sendmsg and recvmsg,
  MSG_CMSG_CLOEXEC, SO_PASSCRED's credentials on receipt, and datagram
  sockets.
- **Other families** (AF_INET, AF_INET6, AF_NETLINK, AF_PACKET) are
  EAFNOSUPPORT. Wine's network-interface and DNS code falls back without
  them.
- **SOCK_SEQPACKET** and **MSG_OOB**. Linux supports both (MSG_OOB with
  CONFIG_AF_UNIX_OOB).
- **Buffer accounting.** Linux counts each sk_buff's truesize against
  SO_SNDBUF and admits a send while below it, so a socket holds less
  payload than its buffer size, and SIOCOUTQ reports memory. Keel counts
  payload bytes, for both.
- **Restarting.** Interrupted waits return EINTR and are not restarted
  (ADR 0020); Linux restarts blocking socket calls with SA_RESTART.
- **Permissions on connect:** the node's write permission is not
  checked. Keel's processes are all root, which passes it on Linux.
- **The other options:** SO_LINGER, SO_PRIORITY, SO_RCVLOWAT, SO_PEEK_OFF,
  SO_PASSPIDFD, SO_PEERPIDFD, SO_PEERSEC, SO_BINDTODEVICE and the
  timestamping options are ENOPROTOOPT, where Linux takes most of them.
  The timeouts are kept in nanoseconds, where Linux rounds them to
  jiffies.

## Evidence

- **Host tests** (`keel_core::unix`): address parsing (autobind, a path
  cut at NUL, abstract names, the length limits, a wrong family), names
  as reported, autobind's format, the stream queue (peek, put back), the
  buffer sizes, timeouts and `struct ucred`.
- **`exec.sockets` (phase 3) and `host.sockprobe`:** `user/tests/
  sockprobe` makes 102 checks, which pass under Linux and on Keel. Keel
  runs it twice and measures the second run: the probe queues about 200
  KiB in one socket, and the heap's first growth to that mark keeps its
  page-table frames. After the second run every node, frame and process
  is back.
  - **Creation and options:**
    - the flag and family errors;
    - stat, fstatfs, ESPIPE, ENOTSOCK, EBADF;
    - SO_TYPE, SO_DOMAIN, SO_PROTOCOL, SO_ACCEPTCONN, SO_ERROR, the
      buffers (present: their defaults are the host's sysctls) and SO_SNDBUF
      doubled, the ENOPROTOOPT/EOPNOTSUPP/EINVAL
      rules, a short getsockopt buffer, SO_RCVTIMEO and EDOM,
      SO_PEERCRED with no peer.
  - **Unconnected:** poll, read EINVAL, write ENOTCONN, getpeername,
    getsockname, shutdown, listen and accept.
  - **socketpair:**
    - data both ways, credentials, FIONREAD;
    - MSG_PEEK, MSG_DONTWAIT, a zero read, sendmsg and recvmsg vectors;
    - MSG_WAITALL across a child's two writes; a blocking read woken by a
      child;
    - filling until EAGAIN and draining;
    - shutdown and EPIPE, MSG_NOSIGNAL (with SIGPIPE's default action
      too); death by SIGPIPE;
    - ECONNRESET for unread data.
  - **Paths:**
    - the node's mode and ENXIO; EADDRINUSE; a second bind EINVAL with no
      node left;
    - address errors; ECONNREFUSED before listen;
    - connect and write before accept; EISCONN;
    - accept4's flags checked first (EINVAL on a listener), its address
      and close-on-exec; names on both sides;
      credentials; recvfrom's sender, named and unnamed;
    - ENOENT, ECONNREFUSED for a file; the backlog's EAGAIN;
    - ECONNRESET for connections never accepted; the stale node.
  - **Abstract names:** as bound; EADDRINUSE; autobind's form; SO_PASSCRED
    autobinding a client, seen by getpeername and recvfrom; the name
    freed with its socket.
  - **A blocking accept** woken by a child's connect.
  - **epoll:**
    - a listener readable with a connection waiting;
    - edge-triggered reads, an edge per write;
    - an edge-triggered writer woken when its peer drains;
    - EPOLLHUP at the peer's close.
- **Mutations** on Keel, 36, of which 35 were caught (the check that
  failed in brackets):
  - **Creation and options:**
    - socket's flags unchecked (2); the protocol unchecked (3);
    - SO_SNDBUF not doubled (9); EDOM unchecked (15); getsockopt's
      length uncapped (13).
  - **Unconnected sockets:**
    - listen on an unnamed socket (21); read allowed (18); write EPIPE
      instead of ENOTCONN (18);
    - getpeername allowed (19); no EPOLLHUP (17).
  - **Data:**
    - no SIGPIPE (55); MSG_NOSIGNAL ignored (58);
    - MSG_PEEK consuming (38); MSG_WAITALL ignored (42);
    - FIONREAD wrong (36); always writable (45);
    - an unnamed sender reported with a name (41).
  - **Release and errors:**
    - no ECONNRESET for unread data (57) or for an embryo (83);
    - the pending error never reported (57);
    - shutdown not mirrored to the peer (the probe never finishes).
  - **Names:**
    - EEXIST for a taken path (64); the node left after a second bind
      (65);
    - a path without its NUL (63); the umask ignored (61);
    - a socket node that opens (62).
  - **Connections:**
    - connecting to a non-listener (67); the backlog unchecked (82);
    - the accepted socket unnamed (74); accept4's flags unchecked (87);
    - no autobind with SO_PASSCRED (97).
  - **Wakes:** none for the writer (130), the reader (125), the listener
    (122), or at close (127).
  - **The one not caught,** an abstract name left in the table after its
    socket goes, is equivalent: bind treats a name whose socket is gone as
    free, so only memory is kept (a key per name).

## Consequences

- Wine's server socket, its clients' connections and its socketpairs run
  as on Linux, except for the descriptor passing part 2 adds.
- Bound path names are tmpfs nodes like any other: unlink removes them,
  and quotas charge them.
