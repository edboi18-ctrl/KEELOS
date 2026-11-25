//! P3-T12 part 1: terminals, checked against Linux through ptys. Runs
//! under Linux (`host.ttyprobe`) and on Keel (`exec.terminals`) and must
//! pass on both.
//!
//! Semantics from termios(3), pty(7), ioctl_tty(2) (TIOCGPTN, TIOCSPTLCK,
//! TIOCGPTPEER, TCFLSH, TCXONC, TIOCINQ) and Linux v6.12's
//! `drivers/tty/n_tty.c`, `pty.c`, `tty_ioctl.c` and `tty_io.c`. The ptys
//! are opened with O_NOCTTY, so none becomes a controlling terminal and
//! ISIG raises no signal (nothing is in the foreground). Linux moves pty
//! input in a work item, so output is read after poll says it is there,
//! and "nothing came" is checked with a short wait.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, O_RDWR};

const EIO: i64 = -5;
const EAGAIN: i64 = -11;
const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const EINVAL: i64 = -22;
const ENOTTY: i64 = -25;
const ESPIPE: i64 = -29;

const O_NOCTTY: u64 = 0o400;
const O_NONBLOCK: u64 = 0o4000;
const F_SETFL: u32 = 4;

const TCGETS: u64 = 0x5401;
const TCSETS: u64 = 0x5402;
const TCSETSF: u64 = 0x5404;
const TCGETA: u64 = 0x5405;
const TCSETA: u64 = 0x5406;
const TCXONC: u64 = 0x540A;
const TCFLSH: u64 = 0x540B;
const TIOCEXCL: u64 = 0x540C;
const TIOCNXCL: u64 = 0x540D;
const TIOCOUTQ: u64 = 0x5411;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TIOCGSOFTCAR: u64 = 0x5419;
const TIOCSSOFTCAR: u64 = 0x541A;
const FIONREAD: u64 = 0x541B;
const TIOCSETD: u64 = 0x5423;
const TIOCGETD: u64 = 0x5424;
const TCGETS2: u64 = 0x802C_542A;
const TCSETS2: u64 = 0x402C_542B;
const TIOCGPTN: u64 = 0x8004_5430;
const TIOCSPTLCK: u64 = 0x4004_5431;
const TIOCGDEV: u64 = 0x8004_5432;
const TIOCSIG: u64 = 0x4004_5436;
const TIOCGPKT: u64 = 0x8004_5438;
const TIOCGPTLCK: u64 = 0x8004_5439;
const TIOCGEXCL: u64 = 0x8004_5440;
const TIOCGPTPEER: u64 = 0x5441;
const TIOCGLCKTRMIOS: u64 = 0x5456;

// termios flags (asm-generic termbits).
const ICRNL: u32 = 0x100;
const IXON: u32 = 0x400;
const IXANY: u32 = 0x800;
const ISTRIP: u32 = 0x20;
const INLCR: u32 = 0x40;
const IGNCR: u32 = 0x80;
const IUCLC: u32 = 0x200;
const OPOST: u32 = 0x1;
const OLCUC: u32 = 0x2;
const ONLCR: u32 = 0x4;
const OCRNL: u32 = 0x8;
const ONOCR: u32 = 0x10;
const XTABS: u32 = 0x1800;
const CBAUD: u32 = 0x100f;
const B9600: u32 = 0xd;
const B38400: u32 = 0xf;
const BOTHER: u32 = 0x1000;
const CS7: u32 = 0x20;
const CS8: u32 = 0x30;
const CREAD: u32 = 0x80;
const PARENB: u32 = 0x100;
const CLOCAL: u32 = 0x800;
const ISIG: u32 = 0x1;
const ICANON: u32 = 0x2;
const ECHO: u32 = 0x8;
const NOFLSH: u32 = 0x80;
const IEXTEN: u32 = 0x8000;
const VTIME: usize = 5;
const VMIN: usize = 6;
const VEOL: usize = 11;
const VEOL2: usize = 16;

const TCIFLUSH: u64 = 0;
const TCOOFF: u64 = 0;
const TCOON: u64 = 1;
const TCIOFF: u64 = 2;
const TCION: u64 = 3;

const POLLIN: u16 = 1;
const POLLOUT: u16 = 4;
const POLLERR: u16 = 8;
const POLLHUP: u16 = 0x10;

const SIGUSR1: i32 = 10;
const S_IFMT: u32 = 0o170000;
const S_IFCHR: u32 = 0o020000;

fn nap(ms: i32) {
    sys::poll(&mut [], ms);
}

fn ready(fd: i32, events: u16, ms: i32) -> u16 {
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&fd.to_le_bytes());
    e[4..6].copy_from_slice(&events.to_le_bytes());
    let mut fds = [e];
    sys::poll(&mut fds, ms);
    u16::from_le_bytes([fds[0][6], fds[0][7]])
}

/// Whether `fd` becomes readable within `ms`.
fn readable(fd: i32, ms: i32) -> bool {
    ready(fd, POLLIN, ms) & POLLIN != 0
}

/// Everything that arrives on `fd` until 200 ms pass with nothing more.
fn drain(fd: i32, out: &mut [u8]) -> usize {
    let mut len = 0;
    while len < out.len() && readable(fd, 200) {
        let n = sys::read(fd, &mut out[len..]);
        if n <= 0 {
            break;
        }
        len += n as usize;
    }
    len
}

/// Whether the output arriving on `fd` is exactly `want`.
fn output_is(fd: i32, want: &[u8]) -> bool {
    let mut buf = [0u8; 256];
    let n = drain(fd, &mut buf);
    &buf[..n] == want
}

/// Reads one read's worth after `fd` is readable.
fn read_now(fd: i32, buf: &mut [u8]) -> i64 {
    if !readable(fd, 2000) {
        return -1000;
    }
    sys::read(fd, buf)
}

fn int_ioctl(fd: i32, request: u64) -> Option<i32> {
    let mut b = [0u8; 64];
    (sys::ioctl(fd, request, &mut b) == 0).then(|| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn set_int(fd: i32, request: u64, v: i32) -> i64 {
    let mut b = [0u8; 64];
    b[..4].copy_from_slice(&v.to_le_bytes());
    sys::ioctl(fd, request, &mut b)
}

#[derive(Clone, Copy)]
struct Termios {
    iflag: u32,
    oflag: u32,
    cflag: u32,
    lflag: u32,
    line: u8,
    cc: [u8; 19],
}

fn word(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn get(fd: i32) -> Option<Termios> {
    let mut b = [0u8; 64];
    if sys::ioctl(fd, TCGETS, &mut b) != 0 {
        return None;
    }
    let mut cc = [0u8; 19];
    cc.copy_from_slice(&b[17..36]);
    Some(Termios {
        iflag: word(&b, 0),
        oflag: word(&b, 4),
        cflag: word(&b, 8),
        lflag: word(&b, 12),
        line: b[16],
        cc,
    })
}

fn put_bytes(t: &Termios, b: &mut [u8; 64]) {
    b[0..4].copy_from_slice(&t.iflag.to_le_bytes());
    b[4..8].copy_from_slice(&t.oflag.to_le_bytes());
    b[8..12].copy_from_slice(&t.cflag.to_le_bytes());
    b[12..16].copy_from_slice(&t.lflag.to_le_bytes());
    b[16] = t.line;
    b[17..36].copy_from_slice(&t.cc);
}

fn set_with(fd: i32, request: u64, t: &Termios) -> i64 {
    let mut b = [0u8; 64];
    put_bytes(t, &mut b);
    sys::ioctl(fd, request, &mut b)
}

/// Changes `fd`'s settings with `f` (TCSETS).
fn modify(fd: i32, f: impl FnOnce(&mut Termios)) -> bool {
    let Some(mut t) = get(fd) else {
        return false;
    };
    f(&mut t);
    set_with(fd, TCSETS, &t) == 0
}

/// "/dev/pts/N" with its NUL.
fn pts_path(n: i32, out: &mut [u8; 32]) -> &CStr {
    let prefix = b"/dev/pts/";
    out[..prefix.len()].copy_from_slice(prefix);
    let mut digits = [0u8; 10];
    let mut len = 0;
    let mut v = n as u32;
    loop {
        digits[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for i in 0..len {
        out[prefix.len() + i] = digits[len - 1 - i];
    }
    out[prefix.len() + len] = 0;
    CStr::from_bytes_until_nul(&out[..]).unwrap_or(c"/dev/pts/")
}

/// A pty pair: the master, the slave and its number. The master is
/// non-blocking, so draining it never waits.
fn openpty() -> Option<(i32, i32, i32)> {
    let m = sys::open(c"/dev/ptmx", O_RDWR | O_NOCTTY, 0);
    if m < 0 {
        return None;
    }
    let m = m as i32;
    let n = int_ioctl(m, TIOCGPTN)?;
    if set_int(m, TIOCSPTLCK, 0) != 0 {
        return None;
    }
    let mut path = [0u8; 32];
    let s = sys::open(pts_path(n, &mut path), O_RDWR | O_NOCTTY, 0);
    if s < 0 {
        return None;
    }
    sys::fcntl(m, F_SETFL, O_NONBLOCK);
    Some((m, s as i32, n))
}

fn close2(a: i32, b: i32) {
    sys::close(a);
    sys::close(b);
}

fn rdev(st: &[u8; 144]) -> u64 {
    u64::from_le_bytes(st[40..48].try_into().unwrap_or([0; 8]))
}

fn mode(st: &[u8; 144]) -> u32 {
    word(st, 24)
}

/// Linux's `new_encode_dev` (and the stat st_rdev of glibc's makedev for
/// small numbers).
fn dev(major: u64, minor: u64) -> u64 {
    (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
}

fn now_ms() -> u64 {
    let mut b = [0u8; 16];
    sys::clock_gettime(1, &mut b);
    let sec = u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]));
    let nsec = u64::from_le_bytes(b[8..].try_into().unwrap_or([0; 8]));
    sec * 1000 + nsec / 1_000_000
}

fn ptys() -> i32 {
    // 1. /dev/ptmx is the character device 5:2; a new pty is locked, its
    //    slave cannot be opened (EIO) until TIOCSPTLCK unlocks it.
    let m = sys::open(c"/dev/ptmx", O_RDWR | O_NOCTTY, 0);
    if m < 0 {
        return 1;
    }
    let m = m as i32;
    let mut st = [0u8; 144];
    if sys::fstat(m, &mut st) != 0 || mode(&st) & S_IFMT != S_IFCHR || rdev(&st) != dev(5, 2) {
        return 2;
    }
    let Some(n) = int_ioctl(m, TIOCGPTN) else {
        return 3;
    };
    if n < 0 || int_ioctl(m, TIOCGPTLCK) != Some(1) {
        return 4;
    }
    let mut path = [0u8; 32];
    let p = pts_path(n, &mut path);
    if sys::open(p, O_RDWR | O_NOCTTY, 0) != EIO {
        return 5;
    }
    if set_int(m, TIOCSPTLCK, 0) != 0 || int_ioctl(m, TIOCGPTLCK) != Some(0) {
        return 6;
    }
    let s = sys::open(p, O_RDWR | O_NOCTTY, 0);
    if s < 0 {
        return 7;
    }
    let s = s as i32;
    // 2. The slave is 136+N/256 : N%256, as its node; TIOCGDEV gives that
    //    number on both ends. The slave has no TIOCGPTN or TIOCSPTLCK.
    let want = dev(136 + n as u64 / 256, n as u64 % 256);
    if sys::fstat(s, &mut st) != 0 || mode(&st) & S_IFMT != S_IFCHR || rdev(&st) != want {
        return 8;
    }
    if sys::stat(p, &mut st) != 0 || rdev(&st) != want {
        return 9;
    }
    let devnum = |fd| int_ioctl(fd, TIOCGDEV).map(|v| v as u32 as u64);
    if devnum(m) != Some(want) || devnum(s) != Some(want) {
        return 10;
    }
    let mut b = [0u8; 64];
    if sys::ioctl(s, TIOCGPTN, &mut b) != ENOTTY || set_int(s, TIOCSPTLCK, 0) != ENOTTY {
        return 11;
    }
    // 3. A terminal is not seekable; a file that is not one answers no
    //    terminal request.
    if sys::lseek(m, 0, 0) != ESPIPE || sys::lseek(s, 0, 0) != ESPIPE {
        return 12;
    }
    if sys::pread(s, &mut b[..4], 0) != ESPIPE {
        return 13;
    }
    let null = sys::open(c"/dev/null", O_RDWR, 0) as i32;
    if sys::ioctl(null, TCGETS, &mut b) != ENOTTY {
        return 14;
    }
    sys::close(null);
    // 4. TIOCGPTPEER opens the slave too (EIO on a slave, or while
    //    locked). The failed open makes the slave's reads EIO until an
    //    open succeeds (`pty_open` sets TTY_IO_ERROR).
    let peer = sys::ioctl_value(m, TIOCGPTPEER, O_RDWR | O_NOCTTY);
    if peer < 0 || sys::ioctl_value(s, TIOCGPTPEER, O_RDWR) != EIO {
        return 15;
    }
    set_int(m, TIOCSPTLCK, 1);
    if sys::ioctl_value(m, TIOCGPTPEER, O_RDWR) != EIO {
        return 16;
    }
    set_int(m, TIOCSPTLCK, 0);
    sys::write(m, b"p\n");
    if read_now(peer as i32, &mut b) != EIO {
        return 17;
    }
    let again = sys::ioctl_value(m, TIOCGPTPEER, O_RDWR | O_NOCTTY);
    if again < 0 || read_now(peer as i32, &mut b) != 2 {
        return 17;
    }
    sys::close(again as i32);
    sys::close(peer as i32);
    // 5. The master's other requests: TIOCSIG takes SIGINT, SIGQUIT and
    //    SIGTSTP (nothing is in the foreground here); packet mode is off.
    if sys::ioctl_value(m, TIOCSIG, 2) != 0 || sys::ioctl_value(m, TIOCSIG, 9) != EINVAL {
        return 18;
    }
    if int_ioctl(m, TIOCGPKT) != Some(0) || sys::ioctl_value(s, TIOCSIG, 2) != ENOTTY {
        return 19;
    }
    close2(m, s);
    0
}

fn settings() -> i32 {
    let Some((m, s, _)) = openpty() else {
        return 20;
    };
    // 6. A slave starts as tty_std_termios with B38400 CS8 CREAD: ICRNL
    //    IXON; OPOST ONLCR; ISIG ICANON ECHO ECHOE ECHOK ECHOCTL ECHOKE
    //    IEXTEN; INIT_C_CC. The master reports the slave's.
    let Some(t) = get(s) else {
        return 21;
    };
    let cc = *b"\x03\x1c\x7f\x15\x04\x00\x01\x00\x11\x13\x1a\x00\x12\x0f\x17\x16\x00\x00\x00";
    if t.iflag != ICRNL | IXON
        || t.oflag != OPOST | ONLCR
        || t.cflag != B38400 | CS8 | CREAD
        || t.lflag != 0x8a3b
        || t.line != 0
        || t.cc != cc
    {
        return 22;
    }
    if get(m).map(|x| (x.iflag, x.lflag, x.cc)) != Some((t.iflag, t.lflag, t.cc)) {
        return 23;
    }
    // 7. TCGETS2: the speeds, 38400. TCGETA: the low halves and the first
    //    eight control characters.
    let mut b = [0u8; 64];
    if sys::ioctl(s, TCGETS2, &mut b) != 0 || word(&b, 36) != 38400 || word(&b, 40) != 38400 {
        return 24;
    }
    if sys::ioctl(s, TCGETA, &mut b) != 0
        || u16::from_le_bytes([b[0], b[1]]) != (ICRNL | IXON) as u16
        || b[9..17] != cc[..8]
    {
        return 25;
    }
    // 8. Set through the master, seen on the slave. A pty's cflag is CS8
    //    and CREAD whatever is asked (`pty_set_termios`).
    if !modify(m, |t| {
        t.lflag &= !ECHO;
        t.cflag = (t.cflag & !(0x30)) | CS7 | PARENB;
    }) {
        return 26;
    }
    let Some(t2) = get(s) else {
        return 27;
    };
    if t2.lflag & ECHO != 0 || t2.cflag != B38400 | CS8 | CREAD {
        return 28;
    }
    // 9. Speeds: B9600 gives 9600 both ways; BOTHER takes c_ospeed.
    if !modify(s, |t| t.cflag = (t.cflag & !CBAUD) | B9600) {
        return 29;
    }
    sys::ioctl(s, TCGETS2, &mut b);
    if word(&b, 36) != 9600 || word(&b, 40) != 9600 {
        return 30;
    }
    let c = word(&b, 8);
    b[8..12].copy_from_slice(&((c & !CBAUD) | BOTHER).to_le_bytes());
    b[40..44].copy_from_slice(&12345u32.to_le_bytes());
    if sys::ioctl(s, TCSETS2, &mut b) != 0 {
        return 31;
    }
    sys::ioctl(s, TCGETS2, &mut b);
    if word(&b, 40) != 12345 || word(&b, 36) != 12345 || word(&b, 8) & CBAUD != BOTHER {
        return 32;
    }
    // 10. TCSETA keeps the flags' high halves.
    if !modify(s, |t| t.iflag = 0x10000 | ICRNL) {
        return 33;
    }
    sys::ioctl(s, TCGETA, &mut b);
    b[0..2].copy_from_slice(&(IXON as u16).to_le_bytes());
    if sys::ioctl(s, TCSETA, &mut b) != 0 || get(s).map(|t| t.iflag) != Some(0x10000 | IXON) {
        return 34;
    }
    // 11. The window size: zero at first; set on the master, seen on the
    //    slave.
    if sys::ioctl(s, TIOCGWINSZ, &mut b) != 0 || b[..8] != [0; 8] {
        return 35;
    }
    b[..8].copy_from_slice(&[24, 0, 80, 0, 1, 0, 2, 0]);
    if sys::ioctl(m, TIOCSWINSZ, &mut b) != 0 {
        return 36;
    }
    let mut w = [0u8; 64];
    if sys::ioctl(s, TIOCGWINSZ, &mut w) != 0 || w[..8] != [24, 0, 80, 0, 1, 0, 2, 0] {
        return 37;
    }
    // 12. Small requests: no locked settings; N_TTY only (0) as the line
    //    discipline here, an unknown number EINVAL; CLOCAL through
    //    TIOCSSOFTCAR; TIOCEXCL; nothing unsent on a pty.
    if sys::ioctl(s, TIOCGLCKTRMIOS, &mut b) != 0 || b[..36] != [0; 36] {
        return 38;
    }
    if int_ioctl(s, TIOCGETD) != Some(0)
        || set_int(s, TIOCSETD, 0) != 0
        || set_int(s, TIOCSETD, 99) != EINVAL
    {
        return 39;
    }
    if int_ioctl(s, TIOCGSOFTCAR) != Some(0)
        || set_int(s, TIOCSSOFTCAR, 1) != 0
        || int_ioctl(s, TIOCGSOFTCAR) != Some(1)
        || get(s).map(|t| t.cflag & CLOCAL) != Some(CLOCAL)
    {
        return 40;
    }
    let excl = |req| sys::ioctl(s, req, &mut [0u8; 64]);
    if excl(TIOCEXCL) != 0
        || int_ioctl(s, TIOCGEXCL) != Some(1)
        || excl(TIOCNXCL) != 0
        || int_ioctl(s, TIOCGEXCL) != Some(0)
    {
        return 41;
    }
    if int_ioctl(s, TIOCOUTQ) != Some(0) || int_ioctl(m, TIOCOUTQ) != Some(0) {
        return 42;
    }
    close2(m, s);
    0
}

fn canonical() -> i32 {
    let Some((m, s, _)) = openpty() else {
        return 43;
    };
    let mut buf = [0u8; 64];
    // 13. A line: Enter (CR) becomes NL (ICRNL), the echo's NL becomes
    //    CR NL (ONLCR). Nothing is readable before the line ends.
    sys::write(m, b"ab");
    if readable(s, 100) || !output_is(m, b"ab") {
        return 44;
    }
    sys::write(m, b"\r");
    if read_now(s, &mut buf) != 3 || &buf[..3] != b"ab\n" || !output_is(m, b"\r\n") {
        return 45;
    }
    // 14. A read takes one line, or what fits.
    sys::write(m, b"one\ntwo\n");
    output_is(m, b"one\r\ntwo\r\n");
    if read_now(s, &mut buf[..2]) != 2 || &buf[..2] != b"on" {
        return 46;
    }
    if sys::read(s, &mut buf) != 2 || &buf[..2] != b"e\n" {
        return 47;
    }
    if sys::read(s, &mut buf) != 4 || &buf[..4] != b"two\n" {
        return 48;
    }
    // 15. Erase (DEL) rubs out a character; kill (^U) the line, a
    //    character at a time (ECHOKE); word erase (^W) back to a space.
    sys::write(m, b"kex\x7fl\n");
    if read_now(s, &mut buf) != 4 || &buf[..4] != b"kel\n" {
        return 49;
    }
    if !output_is(m, b"kex\x08 \x08l\r\n") {
        return 50;
    }
    sys::write(m, b"abc\x15xy\n");
    if read_now(s, &mut buf) != 3 || &buf[..3] != b"xy\n" {
        return 51;
    }
    if !output_is(m, b"abc\x08 \x08\x08 \x08\x08 \x08xy\r\n") {
        return 52;
    }
    sys::write(m, b"foo bar_1\x17baz\n");
    if read_now(s, &mut buf) != 8 || &buf[..8] != b"foo baz\n" {
        return 53;
    }
    drain(m, &mut buf);
    // 16. A control character echoes as ^X and erases as two cells.
    sys::write(m, b"\x1b\x7f");
    if !output_is(m, b"^[\x08 \x08\x08 \x08") {
        return 54;
    }
    // 17. ^C with ISIG: the line is discarded and ^C echoed, with no
    //    newline; echo of the same batch not yet sent goes too.
    sys::write(m, b"lost");
    drain(m, &mut buf);
    sys::write(m, b"\x03");
    if !output_is(m, b"^C") || int_ioctl(s, FIONREAD) != Some(0) {
        return 55;
    }
    sys::write(m, b"\n");
    if read_now(s, &mut buf) != 1 || buf[0] != b'\n' {
        return 56;
    }
    drain(m, &mut buf);
    sys::write(m, b"xy\x1c");
    if !output_is(m, b"^\\") {
        return 57;
    }
    // 18. ^D: alone, an end of file (a read of 0, and FIONREAD counts
    //    nothing, but poll says readable); after text, the line without a
    //    newline. It is not echoed.
    sys::write(m, b"\x04");
    if !readable(s, 2000) || int_ioctl(s, FIONREAD) != Some(0) || sys::read(s, &mut buf) != 0 {
        return 58;
    }
    sys::write(m, b"ab\x04");
    if read_now(s, &mut buf) != 2 || &buf[..2] != b"ab" || !output_is(m, b"ab") {
        return 59;
    }
    // A read whose buffer fills just before the ^D takes the mark too
    // (`canon_skip_eof`): nothing is left to read.
    sys::write(m, b"abc\x04");
    if read_now(s, &mut buf[..3]) != 3 || readable(s, 100) {
        return 59;
    }
    drain(m, &mut buf);
    // 19. FIONREAD counts complete lines only.
    sys::write(m, b"abc\nxyz");
    drain(m, &mut buf);
    if int_ioctl(s, FIONREAD) != Some(4) {
        return 60;
    }
    sys::read(s, &mut buf);
    if int_ioctl(s, FIONREAD) != Some(0) || readable(s, 0) {
        return 61;
    }
    sys::write(m, b"\x15");
    drain(m, &mut buf);
    // 20. ^V takes the next character literally (echo "^", BS); ^R
    //    reprints the line.
    sys::write(m, b"\x16\x03\n");
    if read_now(s, &mut buf) != 2 || &buf[..2] != b"\x03\n" || !output_is(m, b"^\x08^C\r\n") {
        return 62;
    }
    sys::write(m, b"ab\x12");
    if !output_is(m, b"ab^R\r\nab") {
        return 63;
    }
    sys::write(m, b"\n");
    read_now(s, &mut buf);
    drain(m, &mut buf);
    // 21. readv: one line across both buffers.
    sys::write(m, b"abcdef\n");
    let (mut x, mut y) = ([0u8; 3], [0u8; 10]);
    if !readable(s, 2000) || sys::readv2(s, &mut x, &mut y, None) != 7 || &y[..4] != b"def\n" {
        return 64;
    }
    drain(m, &mut buf);
    // 22. Without ISIG ^C is data; with NOFLSH the line is kept.
    modify(s, |t| t.lflag &= !ISIG);
    sys::write(m, b"a\x03\n");
    if read_now(s, &mut buf) != 3 || &buf[..3] != b"a\x03\n" {
        return 65;
    }
    modify(s, |t| t.lflag |= ISIG | NOFLSH);
    sys::write(m, b"ab\x03cd\n");
    if read_now(s, &mut buf) != 5 || &buf[..5] != b"abcd\n" {
        return 66;
    }
    // 23. A full line takes no more, but erase and newline still work:
    //    4096 bytes at most, the newline included.
    modify(s, |t| t.lflag &= !ECHO);
    drain(m, &mut buf);
    let xs = [b'x'; 1000];
    for _ in 0..5 {
        sys::write(m, &xs);
    }
    sys::write(m, b"\n");
    let mut big = [0u8; 8192];
    if read_now(s, &mut big) != 4096 || big[4095] != b'\n' {
        return 67;
    }
    close2(m, s);
    0
}

fn non_canonical() -> i32 {
    let Some((m, s, _)) = openpty() else {
        return 68;
    };
    let mut buf = [0u8; 64];
    // 24. Without ICANON a read takes what is there (VMIN 1, VTIME 0).
    modify(s, |t| t.lflag &= !(ICANON | ECHO));
    sys::write(m, b"abc");
    if read_now(s, &mut buf) != 3 || &buf[..3] != b"abc" {
        return 69;
    }
    // 25. VMIN 0 VTIME 0: a read returns at once, with 0 if nothing.
    modify(s, |t| {
        t.cc[VMIN] = 0;
        t.cc[VTIME] = 0;
    });
    if sys::read(s, &mut buf) != 0 {
        return 70;
    }
    // 26. VMIN 0 VTIME 2: up to 0.2 s for a byte.
    modify(s, |t| t.cc[VTIME] = 2);
    let start = now_ms();
    let got = sys::read(s, &mut buf);
    let took = now_ms() - start;
    if got != 0 || !(150..3000).contains(&took) {
        return 71;
    }
    // 27. VMIN 3 VTIME 0: poll waits for three bytes; FIONREAD counts what
    //    is there.
    modify(s, |t| {
        t.cc[VMIN] = 3;
        t.cc[VTIME] = 0;
    });
    sys::write(m, b"xy");
    nap(100);
    if readable(s, 100) || int_ioctl(s, FIONREAD) != Some(2) {
        return 72;
    }
    sys::write(m, b"z");
    if read_now(s, &mut buf) != 3 {
        return 73;
    }
    // 28. VMIN 5 VTIME 1: two bytes, then 0.1 s with no more ends the read.
    modify(s, |t| {
        t.cc[VMIN] = 5;
        t.cc[VTIME] = 1;
    });
    sys::write(m, b"pq");
    nap(50);
    let start = now_ms();
    let got = sys::read(s, &mut buf);
    let took = now_ms() - start;
    if got != 2 || !(50..=3000).contains(&took) {
        return 74;
    }
    // 29. Turning ICANON on with input waiting makes it a line.
    modify(s, |t| {
        t.cc[VMIN] = 1;
        t.cc[VTIME] = 0;
    });
    sys::write(m, b"raw");
    nap(100);
    modify(s, |t| t.lflag |= ICANON);
    if int_ioctl(s, FIONREAD) != Some(3) || sys::read(s, &mut buf) != 3 {
        return 75;
    }
    // 30. Echo without ICANON: NL is an ordinary character (^J with
    //    ECHOCTL); CR is mapped to NL (ICRNL), which echoes as CR NL.
    modify(s, |t| t.lflag = (t.lflag | ECHO) & !ICANON);
    sys::write(m, b"\n");
    if !output_is(m, b"^J") {
        return 76;
    }
    sys::write(m, b"\r");
    if !output_is(m, b"\r\n") {
        return 77;
    }
    // 31. With nothing to read and O_NONBLOCK, EAGAIN.
    drain(s, &mut buf);
    sys::fcntl(s, F_SETFL, O_NONBLOCK | O_RDWR);
    if sys::read(s, &mut buf) != EAGAIN {
        return 78;
    }
    sys::fcntl(s, F_SETFL, O_RDWR);
    close2(m, s);
    0
}

fn processing() -> i32 {
    let Some((m, s, _)) = openpty() else {
        return 79;
    };
    let mut buf = [0u8; 64];
    // 32. Output: NL becomes CR NL (ONLCR); without OPOST nothing changes.
    sys::write(s, b"a\nb");
    if !output_is(m, b"a\r\nb") {
        return 80;
    }
    modify(s, |t| t.oflag = 0);
    sys::write(s, b"a\nb");
    if !output_is(m, b"a\nb") {
        return 81;
    }
    // 33. XTABS expands a tab to the next multiple of 8; OLCUC upper-cases.
    modify(s, |t| t.oflag = OPOST | ONLCR | XTABS | OLCUC);
    sys::write(s, b"\nab\tc\n");
    if !output_is(m, b"\r\nAB      C\r\n") {
        return 82;
    }
    // 34. OCRNL makes CR NL; ONOCR drops a CR at column 0.
    modify(s, |t| t.oflag = OPOST | OCRNL | ONOCR);
    sys::write(s, b"\rx\r");
    if !output_is(m, b"x\n") {
        return 83;
    }
    // 35. writev is one write.
    modify(s, |t| t.oflag = OPOST | ONLCR);
    sys::writev(s, &[b"1\n", b"2\n"]);
    if !output_is(m, b"1\r\n2\r\n") {
        return 84;
    }
    // 36. Input: IGNCR drops CR; INLCR makes NL a CR, so VEOL ends the
    //    line; ISTRIP clears bit 7; IUCLC (with IEXTEN) lower-cases.
    modify(s, |t| {
        t.lflag &= !ECHO;
        t.iflag = IGNCR;
    });
    sys::write(m, b"a\r\n");
    if read_now(s, &mut buf) != 2 || &buf[..2] != b"a\n" {
        return 85;
    }
    modify(s, |t| {
        t.iflag = INLCR;
        t.cc[VEOL] = b'z';
    });
    sys::write(m, b"a\nz");
    if read_now(s, &mut buf) != 3 || &buf[..3] != b"a\rz" {
        return 86;
    }
    modify(s, |t| t.iflag = ISTRIP | IUCLC);
    sys::write(m, b"\xc1B\n");
    if read_now(s, &mut buf) != 3 || &buf[..3] != b"ab\n" {
        return 87;
    }
    // 37. VEOL2 ends a line only with IEXTEN.
    modify(s, |t| {
        t.iflag = 0;
        t.cc[VEOL2] = b'!';
    });
    sys::write(m, b"hi!");
    if read_now(s, &mut buf) != 3 || &buf[..3] != b"hi!" {
        return 88;
    }
    modify(s, |t| t.lflag &= !IEXTEN);
    sys::write(m, b"no!");
    if readable(s, 100) {
        return 89;
    }
    sys::write(m, b"\n");
    if read_now(s, &mut buf) != 4 {
        return 90;
    }
    close2(m, s);
    0
}

fn flow_and_flush() -> i32 {
    let Some((m, s, _)) = openpty() else {
        return 91;
    };
    let mut buf = [0u8; 64];
    sys::fcntl(s, F_SETFL, O_NONBLOCK | O_RDWR);
    // 38. ^S (IXON) stops the slave's output: its writes are EAGAIN and
    //    poll has no POLLOUT; ^Q starts it again.
    sys::write(m, b"\x13");
    nap(100);
    if sys::write(s, b"x") != EAGAIN || ready(s, POLLOUT, 0) & POLLOUT != 0 {
        return 92;
    }
    sys::write(m, b"\x11");
    nap(100);
    if sys::write(s, b"x") != 1 || !output_is(m, b"x") {
        return 93;
    }
    // 39. With IXANY any character restarts it.
    modify(s, |t| t.iflag |= IXANY);
    sys::write(m, b"\x13");
    nap(100);
    sys::write(m, b"k");
    nap(100);
    if sys::write(s, b"y") != 1 {
        return 94;
    }
    drain(m, &mut buf);
    // 40. Without IXON ^S is data (after the "k" above).
    modify(s, |t| t.iflag &= !(IXON | IXANY));
    sys::write(m, b"\x13\n");
    nap(100);
    if sys::write(s, b"z") != 1 || read_now(s, &mut buf) != 3 || &buf[..3] != b"k\x13\n" {
        return 95;
    }
    drain(m, &mut buf);
    // 41. TCXONC: TCOOFF stops output, TCOON restarts it; TCIOFF and
    //    TCION send STOP and START; another action is EINVAL.
    if sys::ioctl_value(s, TCXONC, TCOOFF) != 0 || sys::write(s, b"w") != EAGAIN {
        return 96;
    }
    if sys::ioctl_value(s, TCXONC, TCOON) != 0 || sys::write(s, b"w") != 1 {
        return 97;
    }
    drain(m, &mut buf);
    sys::ioctl_value(s, TCXONC, TCIOFF);
    sys::ioctl_value(s, TCXONC, TCION);
    if !output_is(m, b"\x13\x11") || sys::ioctl_value(s, TCXONC, 9) != EINVAL {
        return 98;
    }
    // 42. TCFLSH discards unread input; an unknown queue is EINVAL.
    modify(s, |t| t.lflag &= !ECHO);
    sys::write(m, b"gone\n");
    if !readable(s, 2000) || sys::ioctl_value(s, TCFLSH, TCIFLUSH) != 0 {
        return 99;
    }
    if readable(s, 100) || int_ioctl(s, FIONREAD) != Some(0) {
        return 100;
    }
    if sys::ioctl_value(s, TCFLSH, 5) != EINVAL {
        return 101;
    }
    // 43. TCSETSF discards it too.
    sys::write(m, b"also\n");
    let Some(t) = get(s) else {
        return 102;
    };
    if !readable(s, 2000) || set_with(s, TCSETSF, &t) != 0 || readable(s, 100) {
        return 103;
    }
    // 44. Input waits in the driver when the read buffer is full: the
    //    master's writes take a few kilobytes, then EAGAIN; reading makes
    //    room again.
    modify(s, |t| t.lflag &= !ICANON);
    let block = [b'f'; 1024];
    let mut total = 0;
    loop {
        let n = sys::write(m, &block);
        if n <= 0 {
            if n != EAGAIN {
                return 104;
            }
            break;
        }
        total += n;
        if total > 1 << 20 {
            break;
        }
    }
    if !(4095..=65536).contains(&total) {
        return 105;
    }
    let mut big = [0u8; 4096];
    while sys::read(s, &mut big) > 0 {}
    if ready(m, POLLOUT, 2000) & POLLOUT == 0 {
        return 106;
    }
    close2(m, s);
    0
}

fn closing() -> i32 {
    let Some((m, s, n)) = openpty() else {
        return 107;
    };
    let mut buf = [0u8; 64];
    // 45. A blocking read is interrupted by a signal (EINTR).
    if keel_rt::signal::catch(SIGUSR1) != 0 {
        return 108;
    }
    let parent = sys::getpid() as i32;
    let child = sys::fork();
    if child == 0 {
        nap(100);
        sys::kill(parent, SIGUSR1);
        keel_rt::exit(0);
    }
    if sys::read(s, &mut buf) != EINTR {
        return 109;
    }
    let mut st = 0;
    sys::wait4(child as i32, &mut st, 0);
    // 46. The slave's output stays readable after it closes; then the
    //    master's reads are EIO and poll has POLLHUP.
    sys::write(s, b"bye");
    sys::close(s);
    if !output_is(m, b"bye") || sys::read(m, &mut buf) != EIO {
        return 110;
    }
    if ready(m, POLLIN, 0) & POLLHUP == 0 {
        return 111;
    }
    // 47. The master can still write, and the closed slave's line
    //    discipline still echoes. Opening the slave again ends EIO.
    // (Linux moves it in two work items; POLLHUP does not wait for them.)
    if sys::write(m, b"q") != 1 {
        return 112;
    }
    nap(100);
    if !output_is(m, b"q") {
        return 112;
    }
    let mut path = [0u8; 32];
    let p = pts_path(n, &mut path);
    let s = sys::open(p, O_RDWR | O_NOCTTY, 0);
    if s < 0 || sys::read(m, &mut buf) != EAGAIN || ready(m, POLLIN, 0) & POLLHUP != 0 {
        return 113;
    }
    let s = s as i32;
    // 48. Closing the master hangs the slave up: reads 0, writes EIO,
    //    poll everything, requests EIO; its node is gone.
    sys::close(m);
    if sys::read(s, &mut buf) != 0 || sys::write(s, b"x") != EIO {
        return 114;
    }
    let all = POLLIN | POLLOUT | POLLERR | POLLHUP;
    if ready(s, POLLIN | POLLOUT, 0) & all != all {
        return 115;
    }
    if sys::ioctl(s, TCGETS, &mut [0u8; 64]) != EIO {
        return 116;
    }
    let mut st = [0u8; 144];
    if sys::stat(p, &mut st) != ENOENT {
        return 117;
    }
    sys::close(s);
    0
}

fn main(_: &Startup) -> i32 {
    for part in [
        ptys,
        settings,
        canonical,
        non_canonical,
        processing,
        flow_and_flush,
        closing,
    ] {
        let failed = part();
        if failed != 0 {
            return failed;
        }
    }
    sys::write(1, b"ttyprobe: 117 checks passed\n");
    0
}

keel_rt::main!(main);
