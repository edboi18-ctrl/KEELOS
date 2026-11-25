# ADR 0029: Terminals: the N_TTY line discipline, the console and ptys

Status: accepted (Phase 3, P3-T12 part 1).

## Context

P3-T12 asks for a TTY layer good enough for a shell on the serial
console: canonical mode, echo, and Ctrl-C to SIGINT. Phase 1 had a small
canonical-mode reader for the keyboard (P1-T14), with fixed settings and
TCGETS reporting `tty_std_termios`. A shell, BusyBox and Wine's console
code need the rest: settings that can change (raw mode for line editing,
VMIN and VTIME), the termios ioctls, input from the serial line, and
ptys, which are also the only way to check Keel's terminals against
Linux's from a test program.

The rules are Linux v6.12's, read from its source: `drivers/tty/n_tty.c`
(the line discipline), `tty_io.c`, `tty_ioctl.c`, `tty_buffer.c`,
`tty_baudrate.c`, `pty.c`, `fs/devpts/inode.c`, `lib/ctype.c`, and the
uapi termbits headers.

This is part 1. Sessions, process groups, the controlling terminal and
the signals ISIG raises are part 2 (ADR 0030).

## Decision

1. **The line discipline** (`keel_core::tty::Tty`, host-tested) follows
   `n_tty.c`, function by function:
   - **Input** (`n_tty_receive_char_special` and its callees), in Linux's
     order: IXON's START and STOP; ISIG's VINTR, VQUIT and VSUSP (the
     signal, the input and echo discarded unless NOFLSH, the character
     echoed with no newline); IXANY; IGNCR, ICRNL, INLCR; then in
     canonical mode VERASE, VKILL, VWERASE (BSD's ALTWERASE: back over
     the word and the non-word characters after it), VLNEXT, VREPRINT,
     NL, VEOF, VEOL, VEOL2. ISTRIP and IUCLC come first, EXTPROC skips
     it all, and a mode with none of these flags takes bytes as they are.
     The special characters are worked out when the settings change
     (`char_map`), so a disabled (0) character is never special.
   - **Echo** is a queue of operations (n_tty's echo buffer, decoded):
     bytes through output processing, `^X` for a control character with
     ECHOCTL, going back over a tab by the columns it took, and the
     column bookkeeping. It is sent when 256 bytes are pending or at the
     end of an input batch, and what was not sent yet goes with the
     input when ISIG flushes: `ab^C` typed in one write echoes `^C`. The
     erase rules (`eraser`): ECHOE's `\b \b`, two of them for a `^X`,
     ECHOPRT's `\...\` and `/`, ECHOK and ECHOKE for a kill, and IUTF8
     erasing a whole character.
   - **The read buffer** holds 4096 bytes (`N_TTY_BUF_SIZE`). In
     canonical mode with no line complete, input still comes in when it
     is full, each byte replacing the last, so erase and newline work: a
     line is at most 4095 bytes and its newline. Otherwise input waits
     in the flip buffer (`tty_buffer.c`) until a read makes room, and the
     bytes waiting there are still scanned for START and STOP
     (`lookahead_bufs`).
   - **Reads** (`n_tty_read`): canonical, to the end of the first line
     (an end-of-file mark not copied, and skipped when the buffer fills
     just before it); otherwise VMIN and VTIME (0.1 s units) as termios(3)
     describes, MIN 0 TIME 0 returning 0 at once even blocking. Turning
     ICANON on with input waiting makes it one line.
   - **Output** (`do_output_char`): OPOST with ONLCR, OCRNL, ONOCR,
     ONLRET, OLCUC, XTABS, and the column count the tab and erase echo
     use.
   - **Flow control:** STOP (or TCXONC's TCOOFF) stops output: writes
     wait, or EAGAIN; echo waits too. START, IXANY or TCOON restart it.
   - **FIONREAD** in canonical mode counts complete lines without their
     end-of-file marks (`inq_canon`).
   - **Character classes** are the kernel's (`lib/ctype.c`): Latin-1
     letters count for word erase, and OLCUC turns 223 into 191 as
     Linux's `toupper` does.
2. **Settings** (`tty_set_termios`, `set_termios`):
   - TCGETS, TCSETS, TCSETSW, TCSETSF; TCGETS2 and its setters (the
     speeds); TCGETA and its setters (struct termio: the low halves of
     the flags, the first eight control characters).
   - The speeds come from the CBAUD and CIBAUD codes, BOTHER from
     c_ospeed and c_ispeed (`tty_termios_baud_rate`).
   - TCSETSW and TCSETSF wait for the terminal's own output to drain
     (EINTR on a signal); TCSETSF also empties the read buffer.
   - Locked settings (TIOCGLCKTRMIOS, TIOCSLCKTRMIOS) keep their bits;
     ADDRB cannot be set this way; a pty is always CS8 and CREAD
     (`pty_set_termios`).
   - A master's settings and window-size requests act on its slave
     (`tty_pair_get_tty`).
3. **The other ioctls:** TIOCGWINSZ and TIOCSWINSZ; TCFLSH (TCIFLUSH,
   TCOFLUSH, TCIOFLUSH; else EINVAL); TCXONC (TCOOFF, TCOON, TCIOFF,
   TCION; else EINVAL); FIONREAD and TIOCOUTQ; TCSBRK and TCSBRKP (they
   wait for output; neither driver sends a break, as neither has
   `break_ctl`); TIOCEXCL, TIOCNXCL, TIOCGEXCL; TIOCGETD and TIOCSETD
   (N_TTY, 0, only: another number EINVAL); TIOCGDEV; TIOCGSOFTCAR and
   TIOCSSOFTCAR. A master also has TIOCGPTN, TIOCSPTLCK, TIOCGPTLCK,
   TIOCGPTPEER, TIOCSIG (SIGINT, SIGQUIT or SIGTSTP, else EINVAL) and
   TIOCGPKT. Anything else on a terminal, and every request on a file
   that is not one, is ENOTTY.
4. **Ptys** (`pty.c`, devpts):
   - Opening `/dev/ptmx` (5:2) makes a pair at the lowest free index and
     its slave node `/dev/pts/N` (136+N/256 : N%256, mode 0600, devpts's
     default). The slave starts locked (TIOCSPTLCK unlocks it); opening
     it while locked, or after the master closed, is EIO.
   - The master's writes are the slave's input; the slave's output, its
     echo included, is the master's input. Each end's driver buffers 8192
     bytes (`tty_buffer_set_limit`). The master's settings are raw and
     cannot be changed.
   - **Closing:** when the slave's last description closes, the master's
     reads are EIO once its input is read, and its poll has POLLHUP
     (TTY_OTHER_CLOSED); the master can still write, and the slave's
     line discipline still takes it. Opening the slave again ends that.
     When the master closes, the slave's descriptions are hung up (reads
     0, writes and requests EIO, poll everything: `hung_up_tty_fops`),
     its node goes, and the index is free once the last end is gone.
   - **A failed slave open** (locked) makes its open descriptions' reads
     and writes EIO until an open succeeds, as `pty_open` sets
     TTY_IO_ERROR on that path.
   - At most 64 ptys at once (ENOSPC), until compartments have a pty
     quota.
5. **The console** is a `Tty` too:
   - **Input:** the keyboard (as before) and COM1, both by interrupt.
     COM1's received-data interrupt is IRQ 4 with IER bit 0 and MCR OUT2
     (PC16550D datasheet; Linux's `serial8250_do_startup` sets OUT2 for
     the same reason). Its settings are a serial console's: B115200 CS8
     CREAD HUPCL CLOCAL with the standard flags.
   - **Echo** is printed by the echo thread from a 4096-byte queue
     (UART_XMIT_SIZE), since interrupt context cannot take the console's
     output locks; TIOCOUTQ counts it, and TCSETSW and tcdrain wait for
     it. A program's writes are processed under the terminal's lock and
     printed by the writer, after any echo still queued.
   - **What reaches the screen:** the line discipline does ONLCR, so
     COM1 now gets terminal output without the serial driver's own
     newline translation. Output is still filtered to text as before
     (SR-10's console rule), now letting backspace through for erase echo
     and line editing.
   - **The emergency output paths** (a panic, and a user fault's
     message) took a fresh COM1 handle and programmed the UART again,
     which cleared its interrupt enable register and FIFOs: after the
     first user fault, serial input stopped. Once COM1 is set up they now
     use it as it is.
6. **A terminal is an open file.** Its description carries the terminal
   end it opened (`OpenFile::tty`): read, write, readv, writev, ioctl,
   poll and epoll come to the terminal; stat, fcntl and `/proc` treat it
   as the node it was opened through. A terminal is not seekable
   (ESPIPE), and readv and writev are one read or write, as Linux's
   `tty_read` takes an iov_iter.

## Not yet covered

- **Job control:** sessions, process groups, the controlling terminal
  (TIOCSCTTY, TIOCNOTTY, TIOCGPGRP, TIOCSPGRP, TIOCGSID), the signals
  ISIG and TIOCSIG raise, SIGWINCH, SIGTTIN and SIGTTOU: part 2.
- **Packet mode** (TIOCPKT: only turning it off works; ENOTTY
  otherwise), TIOCSTI, TIOCCONS, TIOCVHANGUP, the modem lines (TIOCMGET
  and its setters) and TIOCGSERIAL.
- **`/dev/tty`** and `/dev/pts/ptmx`; devpts mount options.
- **Restarting** a read or write a handled signal interrupted: EINTR
  only (ADR 0020).
- **Parity and framing errors, breaks** (PARMRK only doubles 0xff): no
  driver reports them.
- **Line disciplines** other than N_TTY.
- Linux keeps a stale flow-control lookahead count across a flip-buffer
  flush; Keel resets it with the buffer.

## Evidence

- **Host tests** (`keel_core::tty`, 22): Linux's defaults and
  `INIT_C_CC`; speeds; termios, termios2 and termio round trips; lines,
  echo, ICRNL and ONLCR; reads at line ends and buffer sizes; end of
  file and the skipped mark; erase, kill (with and without ECHOKE),
  werase, ECHOPRT, tab erase; ^C's flush and echo, and a batch's pending
  echo lost with it; NOFLSH; LNEXT and REPRINT; non-canonical reads and
  poll's VMIN; switching to canonical; output processing (ONLCR, XTABS,
  OLCUC with Latin-1, OCRNL, ONOCR); input mapping (INLCR, ISTRIP, IUCLC,
  IGNCR); NL as a control character without ICANON; flow control (STOP,
  START, IXANY, TCOOFF); canonical overflow; the flip buffer filling;
  locked settings and ADDRB.
- **`exec.terminals` (phase 3) and `host.ttyprobe`:**
  `user/tests/ttyprobe` makes 117 checks, which pass under Linux (as root
  and as an unprivileged user with umask 077) and on Keel. Keel runs it
  twice and measures the second run: every node (the /dev/pts nodes
  included), frame and process is back. The checks cover /dev/ptmx and
  the slave nodes and numbers; locking, TIOCGPTPEER and the failed
  open's EIO; ESPIPE and ENOTTY; the default settings; settings through
  the master; speeds and BOTHER; TCSETA's high halves; the window size;
  the small requests; canonical lines, erase, kill, werase, ^C, ^\, ^D,
  FIONREAD, ^V, ^R, readv, ISIG off and NOFLSH, and the 4096-byte line;
  VMIN and VTIME (timed); switching to canonical; non-canonical echo;
  EAGAIN; output and input processing; VEOL and VEOL2; STOP and START,
  IXANY, TCXONC; TCFLSH and TCSETSF; input waiting when the buffers are
  full; EINTR; a closed slave, reopening it, and a hung-up slave.
- **`console.serial_line` (phase 1):** a program blocked reading
  `/dev/console` gets a line typed on COM1 through the UART's loopback
  mode (received by interrupt, a DEL erasing a character, CR made NL),
  then end of file. **`console.keyboard_line`** still passes.
- **Mutations** on Keel, 35 (the ttyprobe check that failed in
  brackets; "hung" is the probe never finishing):
  - **Input:** canonical overflow refused (67); ISIG not flushing (56);
    ISTRIP (87), INLCR (86) and IXANY (94) ignored; STOP ignored (92);
    TCOOFF not stopping (96); VLNEXT (62) and VREPRINT (63) ignored;
    switching to ICANON not making a line (75).
  - **Echo and erase:** ECHOCTL off (54); a control character erased as
    one cell (54); word erase without `_` (53); ECHOKE ignored (52).
  - **Reads:** the end-of-file mark copied (58) or not skipped at a full
    buffer (59, a check added for it); FIONREAD counting the partial line
    (60); poll ignoring VMIN (72); VTIME ignored (71); no inter-byte timer
    (hung); no EIO after the slave closed (110); poll without POLLHUP
    (111).
  - **Output:** ONLCR (45), XTABS (82) and ONOCR (83) off.
  - **Settings:** a pty's cflag not forced (28); termio's high halves
    lost (34); the input speed 0 with CIBAUD B0 (30); a master's settings
    its own (23); TCSETSF (103) and TCIFLUSH (100) keeping input.
  - **Ptys:** the lock ignored (5); no TTY_IO_ERROR after a failed open
    (17); the slave's node left behind (20, its index taken).
  - **Equivalent:** dropping the hung-up check at the start of write (the
    write loop makes it before writing anything).

## Consequences

- Line editors that draw with escape sequences (BusyBox's, readline's)
  are held back by the console's text filter; P3-T13 decides how a shell
  on the console gets them (a pty-backed terminal, or a narrower filter).

- A shell can run on the serial console, with line editing in raw mode.
- Wine and other programs can use ptys and the termios calls as on Linux.
- What the console shows stays text: no escape sequences reach the
  screen or COM1 from a program.
