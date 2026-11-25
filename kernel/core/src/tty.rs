//! Terminals (P1-T14, P3-T12; ADR 0029): termios and the N_TTY line
//! discipline, and the terminal a device or pty end is built from.
//!
//! The rules are Linux v6.12's, read from its source:
//! - `drivers/tty/n_tty.c`: input processing ([`Tty::receive`]), echo,
//!   erasing, canonical and non-canonical reads, output processing
//!   (OPOST), poll, TIOCINQ;
//! - `drivers/tty/tty_ioctl.c`: setting termios, flushing, flow control;
//! - `drivers/tty/tty_buffer.c`: the flip buffer between a driver and the
//!   line discipline, and the flow-control lookahead past a full one;
//! - `drivers/tty/tty_baudrate.c`: speeds; `lib/ctype.c`: the character
//!   classes the discipline uses (Latin-1, not just ASCII);
//! - `include/uapi/asm-generic/termbits*.h` and
//!   `include/linux/termios_internal.h`: the layouts and defaults.
//!
//! Nothing here locks or blocks: the caller holds the terminal's lock,
//! and output goes to a [`Sink`] (the other end of a pty, or the
//! console's output queue).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::epoll::Wakes;
use crate::errno::Errno;

// --- termios layout and flags (asm-generic termbits) -----------------

/// `NCCS`: the control characters in a struct termios.
pub const NCCS: usize = 19;
/// `NCC`: those in the old struct termio.
pub const NCC: usize = 8;
/// sizeof(struct termios): four flag words, c_line, c_cc[19].
pub const TERMIOS_SIZE: usize = 36;
/// sizeof(struct termios2): struct termios, then c_ispeed and c_ospeed.
pub const TERMIOS2_SIZE: usize = 44;
/// sizeof(struct termio): four unsigned shorts, c_line, c_cc[8], padded.
pub const TERMIO_SIZE: usize = 18;

pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSWTC: usize = 7;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VREPRINT: usize = 12;
pub const VDISCARD: usize = 13;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;
pub const VEOL2: usize = 16;

pub const IGNBRK: u32 = 0x001;
pub const BRKINT: u32 = 0x002;
pub const IGNPAR: u32 = 0x004;
pub const PARMRK: u32 = 0x008;
pub const INPCK: u32 = 0x010;
pub const ISTRIP: u32 = 0x020;
pub const INLCR: u32 = 0x040;
pub const IGNCR: u32 = 0x080;
pub const ICRNL: u32 = 0x100;
pub const IUCLC: u32 = 0x200;
pub const IXON: u32 = 0x400;
pub const IXANY: u32 = 0x800;
pub const IXOFF: u32 = 0x1000;
pub const IMAXBEL: u32 = 0x2000;
pub const IUTF8: u32 = 0x4000;

pub const OPOST: u32 = 0x01;
pub const OLCUC: u32 = 0x02;
pub const ONLCR: u32 = 0x04;
pub const OCRNL: u32 = 0x08;
pub const ONOCR: u32 = 0x10;
pub const ONLRET: u32 = 0x20;
pub const TABDLY: u32 = 0x1800;
pub const XTABS: u32 = 0x1800;

pub const CBAUD: u32 = 0x0000_100f;
pub const B0: u32 = 0;
pub const B9600: u32 = 0x0000_000d;
pub const B38400: u32 = 0x0000_000f;
pub const B115200: u32 = 0x0000_1002;
pub const BOTHER: u32 = 0x0000_1000;
pub const CBAUDEX: u32 = 0x0000_1000;
pub const CSIZE: u32 = 0x0000_0030;
pub const CS7: u32 = 0x0000_0020;
pub const CS8: u32 = 0x0000_0030;
pub const CREAD: u32 = 0x0000_0080;
pub const PARENB: u32 = 0x0000_0100;
pub const HUPCL: u32 = 0x0000_0400;
pub const CLOCAL: u32 = 0x0000_0800;
pub const ADDRB: u32 = 0x2000_0000;
pub const IBSHIFT: u32 = 16;

pub const ISIG: u32 = 0x00001;
pub const ICANON: u32 = 0x00002;
pub const ECHO: u32 = 0x00008;
pub const ECHOE: u32 = 0x00010;
pub const ECHOK: u32 = 0x00020;
pub const ECHONL: u32 = 0x00040;
pub const NOFLSH: u32 = 0x00080;
pub const TOSTOP: u32 = 0x00100;
pub const ECHOCTL: u32 = 0x00200;
pub const ECHOPRT: u32 = 0x00400;
pub const ECHOKE: u32 = 0x00800;
pub const IEXTEN: u32 = 0x08000;
pub const EXTPROC: u32 = 0x10000;

/// TCFLSH arguments.
pub const TCIFLUSH: u64 = 0;
pub const TCOFLUSH: u64 = 1;
pub const TCIOFLUSH: u64 = 2;
/// TCXONC arguments.
pub const TCOOFF: u64 = 0;
pub const TCOON: u64 = 1;
pub const TCIOFF: u64 = 2;
pub const TCION: u64 = 3;

/// The read buffer's size (`N_TTY_BUF_SIZE`); also the echo buffer's.
pub const N_TTY_BUF_SIZE: usize = 4096;
/// Below this many unsent bytes a terminal is writable (n_tty_poll).
const WAKEUP_CHARS: usize = 256;
/// Echo is sent once this much is pending, or at the end of a batch.
const ECHO_COMMIT_WATERMARK: usize = 256;
const ECHO_BLOCK: usize = 256;
/// Unsent echo past this is dropped, oldest first.
const ECHO_DISCARD_WATERMARK: usize = N_TTY_BUF_SIZE - (ECHO_BLOCK + 32);
/// `__DISABLED_CHAR`: a c_cc entry of 0 is disabled; it also marks an
/// end of file in the read buffer.
const DISABLED: u8 = 0;

/// The signals input can raise (ISIG).
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGTSTP: u8 = 20;

const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLRDNORM: u32 = 0x040;

// --- character classes (lib/ctype.c) ---------------------------------

/// `iscntrl`: 0-31 and 127 (the kernel's table leaves 128-159 unclassed).
fn iscntrl(c: u8) -> bool {
    c < 0x20 || c == 0x7f
}

/// `isupper`: A-Z and Latin-1 192-222 but 215 (the multiplication sign).
fn isupper(c: u8) -> bool {
    c.is_ascii_uppercase() || ((192..=222).contains(&c) && c != 215)
}

/// `islower`: a-z and Latin-1 223-255 but 247 (the division sign).
fn islower(c: u8) -> bool {
    c.is_ascii_lowercase() || (c >= 223 && c != 247)
}

fn isalnum(c: u8) -> bool {
    isupper(c) || islower(c) || c.is_ascii_digit()
}

/// `toupper` (`__toupper`): a lower-case letter less 32, so 223 (sharp
/// s) becomes 191 and 255 becomes 223, as the kernel computes it.
fn toupper(c: u8) -> u8 {
    if islower(c) { c - 32 } else { c }
}

fn tolower(c: u8) -> u8 {
    if isupper(c) { c + 32 } else { c }
}

// --- termios ----------------------------------------------------------

/// A terminal's settings (`struct ktermios`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; NCCS],
    pub ispeed: u32,
    pub ospeed: u32,
}

/// `INIT_C_CC`: ^C ^\ DEL ^U ^D, VTIME 0, VMIN 1, ^Q ^S ^Z, ^R ^O ^W ^V;
/// VSWTC, VEOL and VEOL2 disabled.
const INIT_C_CC: [u8; NCCS] = [
    0x03, 0x1c, 0x7f, 0x15, 0x04, 0, 1, 0, 0x11, 0x13, 0x1a, 0, 0x12, 0x0f, 0x17, 0x16, 0, 0, 0,
];

/// `baud_table` (x86): the speeds the CBAUD codes name, B0 to B4000000.
const BAUD_TABLE: [u32; 31] = [
    0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600,
    115200, 230400, 460800, 500000, 576000, 921600, 1000000, 1152000, 1500000, 2000000, 2500000,
    3000000, 3500000, 4000000,
];

/// The speed of a CBAUD code (`tty_termios_baud_rate`'s table lookup).
fn baud(code: u32) -> u32 {
    let mut index = code;
    if index & CBAUDEX != 0 {
        index = (index & !CBAUDEX) + 15;
    }
    BAUD_TABLE.get(index as usize).copied().unwrap_or(0)
}

impl Termios {
    /// `tty_std_termios`: ICRNL IXON; OPOST ONLCR; B38400 CS8 CREAD
    /// HUPCL; ISIG ICANON ECHO ECHOE ECHOK ECHOCTL ECHOKE IEXTEN.
    pub const fn standard() -> Self {
        Termios {
            iflag: ICRNL | IXON,
            oflag: OPOST | ONLCR,
            cflag: B38400 | CS8 | CREAD | HUPCL,
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
            line: 0,
            cc: INIT_C_CC,
            ispeed: 38400,
            ospeed: 38400,
        }
    }

    /// A pty slave's (`pts_driver->init_termios`): the standard settings
    /// with B38400 CS8 CREAD.
    pub const fn pty_slave() -> Self {
        let mut t = Termios::standard();
        t.cflag = B38400 | CS8 | CREAD;
        t
    }

    /// A pty master's (`ptm_driver->init_termios`): raw, B38400 CS8 CREAD.
    pub const fn pty_master() -> Self {
        let mut t = Termios::pty_slave();
        t.iflag = 0;
        t.oflag = 0;
        t.lflag = 0;
        t
    }

    fn i(&self, f: u32) -> bool {
        self.iflag & f != 0
    }
    fn o(&self, f: u32) -> bool {
        self.oflag & f != 0
    }
    fn l(&self, f: u32) -> bool {
        self.lflag & f != 0
    }

    /// `tty_termios_baud_rate`: BOTHER gives c_ospeed.
    pub fn output_speed(&self) -> u32 {
        let code = self.cflag & CBAUD;
        if code == BOTHER {
            self.ospeed
        } else {
            baud(code)
        }
    }

    /// `tty_termios_input_baud_rate`: CIBAUD, or the output speed if B0.
    pub fn input_speed(&self) -> u32 {
        let code = (self.cflag >> IBSHIFT) & CBAUD;
        match code {
            B0 => self.output_speed(),
            BOTHER => self.ispeed,
            _ => baud(code),
        }
    }

    /// struct termios (TCGETS).
    pub fn to_bytes(&self) -> [u8; TERMIOS_SIZE] {
        let mut b = [0u8; TERMIOS_SIZE];
        b[0..4].copy_from_slice(&self.iflag.to_le_bytes());
        b[4..8].copy_from_slice(&self.oflag.to_le_bytes());
        b[8..12].copy_from_slice(&self.cflag.to_le_bytes());
        b[12..16].copy_from_slice(&self.lflag.to_le_bytes());
        b[16] = self.line;
        b[17..36].copy_from_slice(&self.cc);
        b
    }

    /// struct termios2 (TCGETS2).
    pub fn to_bytes2(&self) -> [u8; TERMIOS2_SIZE] {
        let mut b = [0u8; TERMIOS2_SIZE];
        b[..TERMIOS_SIZE].copy_from_slice(&self.to_bytes());
        b[36..40].copy_from_slice(&self.ispeed.to_le_bytes());
        b[40..44].copy_from_slice(&self.ospeed.to_le_bytes());
        b
    }

    /// struct termio (TCGETA): the low halves of the flags, the first
    /// NCC control characters.
    pub fn to_termio(&self) -> [u8; TERMIO_SIZE] {
        let mut b = [0u8; TERMIO_SIZE];
        for (i, f) in [self.iflag, self.oflag, self.cflag, self.lflag]
            .iter()
            .enumerate()
        {
            b[i * 2..i * 2 + 2].copy_from_slice(&(*f as u16).to_le_bytes());
        }
        b[8] = self.line;
        b[9..17].copy_from_slice(&self.cc[..NCC]);
        b
    }

    /// These settings with a user's struct termios (TCSETS) or termios2
    /// (TCSETS2, 44 bytes) over them.
    pub fn with_bytes(&self, b: &[u8]) -> Termios {
        let word = |i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        let mut t = *self;
        if b.len() < TERMIOS_SIZE {
            return t;
        }
        t.iflag = word(0);
        t.oflag = word(4);
        t.cflag = word(8);
        t.lflag = word(12);
        t.line = b[16];
        t.cc.copy_from_slice(&b[17..36]);
        if b.len() >= TERMIOS2_SIZE {
            t.ispeed = word(36);
            t.ospeed = word(40);
        }
        t
    }

    /// These settings with a user's struct termio over them
    /// (`user_termio_to_kernel_termios`: the high halves of the flags
    /// kept, the first NCC control characters replaced).
    pub fn with_termio(&self, b: &[u8]) -> Termios {
        let half = |i: usize| u32::from(u16::from_le_bytes([b[i], b[i + 1]]));
        let mut t = *self;
        if b.len() < TERMIO_SIZE {
            return t;
        }
        t.iflag = (t.iflag & 0xffff_0000) | half(0);
        t.oflag = (t.oflag & 0xffff_0000) | half(2);
        t.cflag = (t.cflag & 0xffff_0000) | half(4);
        t.lflag = (t.lflag & 0xffff_0000) | half(6);
        t.line = b[8];
        t.cc[..NCC].copy_from_slice(&b[9..17]);
        t
    }
}

/// struct winsize: rows, columns, then pixels across and down.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Winsize {
    pub row: u16,
    pub col: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl Winsize {
    pub fn to_bytes(self) -> [u8; 8] {
        let mut b = [0u8; 8];
        for (i, v) in [self.row, self.col, self.xpixel, self.ypixel]
            .iter()
            .enumerate()
        {
            b[i * 2..i * 2 + 2].copy_from_slice(&v.to_le_bytes());
        }
        b
    }

    pub fn from_bytes(b: &[u8; 8]) -> Self {
        let half = |i: usize| u16::from_le_bytes([b[i], b[i + 1]]);
        Winsize {
            row: half(0),
            col: half(2),
            xpixel: half(4),
            ypixel: half(6),
        }
    }
}

// --- output -----------------------------------------------------------

/// Where a terminal's output goes: the other end's input (a pty) or a
/// device's output queue (the console).
pub trait Sink {
    /// How many bytes it can take now (`tty_write_room`).
    fn room(&self) -> usize;
    fn put(&mut self, bytes: &[u8]);
    /// Discards what was written but not yet taken
    /// (`tty_driver_flush_buffer`).
    fn flush(&mut self);
}

/// A sink of fixed room that collects what it is given.
pub struct Collect {
    pub bytes: Vec<u8>,
    pub limit: usize,
    /// Set when [`Sink::flush`] was called.
    pub flushed: bool,
}

impl Collect {
    pub fn new(limit: usize) -> Self {
        Collect {
            bytes: Vec::new(),
            limit,
            flushed: false,
        }
    }
}

impl Sink for Collect {
    fn room(&self) -> usize {
        self.limit - self.bytes.len()
    }
    fn put(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }
    fn flush(&mut self) {
        self.bytes.clear();
        self.flushed = true;
    }
}

/// An echo operation (n_tty's echo buffer codes, decoded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Echo {
    /// A byte, through output processing if OPOST (0xff, which n_tty
    /// escapes, is sent as it is).
    Byte(u8),
    /// A control character as `^X` (ECHOCTL).
    Ctrl(u8),
    /// Back over a tab: the columns since the line's start or the
    /// previous tab (bit 7 if after a tab), modulo 8.
    EraseTab(u8),
    SetCanonCol,
    MoveBackCol,
}

impl Echo {
    /// Its size in n_tty's echo buffer, for the watermarks.
    fn size(self) -> usize {
        match self {
            Echo::Byte(0xff) => 2,
            Echo::Byte(_) => 1,
            Echo::EraseTab(_) => 3,
            _ => 2,
        }
    }
}

/// Which characters are special (n_tty's `char_map`).
#[derive(Clone, Copy, Debug, Default)]
struct CharMap([u64; 4]);

impl CharMap {
    fn set(&mut self, c: u8) {
        self.0[usize::from(c >> 6)] |= 1 << (c & 63);
    }
    fn clear(&mut self, c: u8) {
        self.0[usize::from(c >> 6)] &= !(1 << (c & 63));
    }
    fn has(&self, c: u8) -> bool {
        self.0[usize::from(c >> 6)] & (1 << (c & 63)) != 0
    }
}

/// A byte of the read buffer with its line-end mark (`read_flags`).
const MARK: u16 = 0x100;

/// What [`Tty::receive`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Received {
    /// Signals for the terminal's foreground process group (ISIG).
    pub signals: Vec<u8>,
    /// Whether any input was taken from the flip buffer.
    pub progress: bool,
}

/// One terminal: its settings, the line discipline's state, and the flip
/// buffer its driver fills (`tty_struct`, `n_tty_data`, `tty_bufhead`).
#[derive(Debug)]
pub struct Tty {
    pub termios: Termios,
    /// TIOCSLCKTRMIOS: bits and characters set here cannot be changed.
    pub locked: Termios,
    pub winsize: Winsize,
    /// TIOCEXCL.
    pub exclusive: bool,
    /// A pty (`pty_set_termios` forces CS8 and CREAD).
    pty: bool,
    /// Input from the driver not yet taken by the line discipline.
    flip: VecDeque<u8>,
    flip_limit: usize,
    /// Flip bytes already scanned for flow control (`lookahead_count`).
    lookahead: usize,
    /// The read buffer (`read_buf`, `read_flags`), oldest first.
    buf: VecDeque<u16>,
    /// How many bytes at its front are complete lines (`canon_head`).
    canon: usize,
    icanon: bool,
    raw: bool,
    char_map: CharMap,
    erasing: bool,
    lnext: bool,
    column: u32,
    canon_column: u32,
    echo: VecDeque<Echo>,
    /// Echo ops up to here may be sent (`echo_mark`, `echo_commit`).
    echo_mark: usize,
    echo_commit: usize,
    /// `flow.stopped` (output stopped, by STOP or TCOOFF) and
    /// `flow.tco_stopped` (by TCOOFF).
    stopped: bool,
    tco_stopped: bool,
    /// Wakes of its read and write queues (for epoll's edges).
    pub wakes: Wakes,
}

impl Tty {
    /// A terminal with `termios`, whose driver buffers up to `flip_limit`
    /// bytes of input (a pty's is 8192: `tty_buffer_set_limit`).
    pub fn new(termios: Termios, flip_limit: usize, pty: bool) -> Self {
        let mut t = Tty {
            termios,
            locked: Termios {
                iflag: 0,
                oflag: 0,
                cflag: 0,
                lflag: 0,
                line: 0,
                cc: [0; NCCS],
                ispeed: 0,
                ospeed: 0,
            },
            winsize: Winsize::default(),
            exclusive: false,
            pty,
            flip: VecDeque::new(),
            flip_limit,
            lookahead: 0,
            buf: VecDeque::new(),
            canon: 0,
            icanon: false,
            raw: false,
            char_map: CharMap::default(),
            erasing: false,
            lnext: false,
            column: 0,
            canon_column: 0,
            echo: VecDeque::new(),
            echo_mark: 0,
            echo_commit: 0,
            stopped: false,
            tco_stopped: false,
            wakes: Wakes::new(),
        };
        t.ldisc_set_termios(None);
        t
    }

    fn cc(&self, i: usize) -> u8 {
        self.termios.cc[i]
    }

    // --- the driver side ---

    /// Room in the flip buffer (`tty_buffer_space_avail`).
    pub fn flip_room(&self) -> usize {
        self.flip_limit - self.flip.len()
    }

    /// Bytes from the driver (a pty's other end, a keyboard, a UART):
    /// as many as fit, which it returns
    /// (`tty_insert_flip_string_and_push_buffer`).
    pub fn push_input(&mut self, bytes: &[u8]) -> usize {
        let n = bytes.len().min(self.flip_room());
        self.flip.extend(&bytes[..n]);
        n
    }

    /// Discards input not yet taken (`tty_buffer_flush`).
    pub fn flush_flip(&mut self) {
        self.flip.clear();
        self.lookahead = 0;
    }

    /// Bytes waiting in the flip buffer.
    pub fn flip_len(&self) -> usize {
        self.flip.len()
    }

    /// Moves input from the flip buffer into the line discipline as far
    /// as it has room (`flush_to_ldisc`, `n_tty_receive_buf_common`),
    /// echoing to `out`. Input left over is scanned for START and STOP
    /// (`lookahead_bufs`).
    pub fn receive(&mut self, out: &mut dyn Sink) -> Received {
        let mut r = Received::default();
        while !self.flip.is_empty() {
            let n = self.flip.len().min(self.receive_room());
            if n == 0 {
                break;
            }
            let batch: Vec<u8> = self.flip.drain(..n).collect();
            self.receive_buf(&batch, out, &mut r.signals);
            r.progress = true;
        }
        if self.flip.len() > self.lookahead {
            let fresh: Vec<u8> = self.flip.iter().skip(self.lookahead).copied().collect();
            self.lookahead += fresh.len();
            if self.termios.i(IXON) {
                for c in fresh {
                    self.flow_ctrl(c, false, out);
                }
            }
        }
        r
    }

    /// Room for input (`n_tty_receive_buf_common`): the buffer less one,
    /// a third of that with PARMRK. In canonical mode with no line
    /// complete, input is let through one at a time even when full, the
    /// last byte giving way, so erase and newline still work.
    fn receive_room(&mut self) -> usize {
        let mut room = N_TTY_BUF_SIZE as isize - self.buf.len() as isize;
        if self.termios.i(PARMRK) {
            room = (room + 2).div_euclid(3);
        }
        room -= 1;
        if room <= 0 {
            let overflow = self.icanon && self.canon == 0;
            if overflow && room < 0 {
                self.buf.pop_back();
            }
            room = isize::from(overflow);
        }
        room as usize
    }

    /// `__receive_buf`.
    fn receive_buf(&mut self, cp: &[u8], out: &mut dyn Sink, signals: &mut Vec<u8>) {
        let t = self.termios;
        let preops = t.i(ISTRIP) || (t.i(IUCLC) && t.l(IEXTEN));
        let la = self.lookahead.min(cp.len());
        if self.raw || (t.l(EXTPROC) && !preops) {
            for &c in cp {
                self.put(c);
            }
        } else {
            for (i, &c) in cp.iter().enumerate() {
                self.receive_standard(c, i < la, out, signals);
            }
            self.flush_echoes(out);
        }
        self.lookahead = self.lookahead.saturating_sub(la);
        if self.icanon && !self.termios.l(EXTPROC) {
            return;
        }
        if !self.buf.is_empty() {
            self.wakes.wake(EPOLLIN | EPOLLRDNORM);
        }
    }

    /// `n_tty_receive_buf_standard`, for one character.
    fn receive_standard(
        &mut self,
        c: u8,
        lookahead_done: bool,
        out: &mut dyn Sink,
        signals: &mut Vec<u8>,
    ) {
        let t = self.termios;
        let mut c = c;
        if self.lnext {
            // n_tty_receive_char_lnext: taken literally.
            self.lnext = false;
            if t.i(ISTRIP) {
                c &= 0x7f;
            }
            if t.i(IUCLC) && t.l(IEXTEN) {
                c = tolower(c);
            }
            self.receive_char(c, out);
            return;
        }
        if t.i(ISTRIP) {
            c &= 0x7f;
        }
        if t.i(IUCLC) && t.l(IEXTEN) {
            c = tolower(c);
        }
        if t.l(EXTPROC) {
            self.put(c);
            return;
        }
        if self.char_map.has(c) {
            self.receive_special(c, lookahead_done, out, signals);
        } else {
            self.receive_char(c, out);
        }
    }

    /// `n_tty_receive_char`: an ordinary character.
    fn receive_char(&mut self, c: u8, out: &mut dyn Sink) {
        let t = self.termios;
        self.restart_on_any(out);
        if t.l(ECHO) {
            self.finish_erasing();
            if self.canon == self.buf.len() {
                self.add_echo(Echo::SetCanonCol);
            }
            self.echo_char(c);
            self.commit_echoes(out);
        }
        if c == 0xff && t.i(PARMRK) {
            self.put(c);
        }
        self.put(c);
    }

    /// IXANY: any input restarts stopped output.
    fn restart_on_any(&mut self, out: &mut dyn Sink) {
        let t = self.termios;
        if self.stopped && !self.tco_stopped && t.i(IXON) && t.i(IXANY) {
            self.start(out);
        }
    }

    /// `n_tty_receive_char_special`.
    fn receive_special(
        &mut self,
        c: u8,
        lookahead_done: bool,
        out: &mut dyn Sink,
        signals: &mut Vec<u8>,
    ) {
        let t = self.termios;
        if t.i(IXON) && self.flow_ctrl(c, lookahead_done, out) {
            return;
        }
        if t.l(ISIG) {
            let signal = if c == self.cc(VINTR) {
                Some(SIGINT)
            } else if c == self.cc(VQUIT) {
                Some(SIGQUIT)
            } else if c == self.cc(VSUSP) {
                Some(SIGTSTP)
            } else {
                None
            };
            if let Some(signal) = signal {
                self.signal_char(signal, c, out, signals);
                return;
            }
        }
        self.restart_on_any(out);
        let mut c = c;
        if c == b'\r' {
            if t.i(IGNCR) {
                return;
            }
            if t.i(ICRNL) {
                c = b'\n';
            }
        } else if c == b'\n' && t.i(INLCR) {
            c = b'\r';
        }
        if self.icanon && self.receive_canon(c, out) {
            return;
        }
        if t.l(ECHO) {
            self.finish_erasing();
            if c == b'\n' {
                self.add_echo(Echo::Byte(b'\n'));
            } else {
                if self.canon == self.buf.len() {
                    self.add_echo(Echo::SetCanonCol);
                }
                self.echo_char(c);
            }
            self.commit_echoes(out);
        }
        if c == 0xff && t.i(PARMRK) {
            self.put(c);
        }
        self.put(c);
    }

    /// `n_tty_receive_char_flow_ctrl`: START restarts output, STOP stops
    /// it; both are consumed. Already acted on if `lookahead_done`.
    fn flow_ctrl(&mut self, c: u8, lookahead_done: bool, out: &mut dyn Sink) -> bool {
        if c != self.cc(VSTART) && c != self.cc(VSTOP) {
            return false;
        }
        if lookahead_done {
            return true;
        }
        if c == self.cc(VSTART) {
            self.start(out);
        } else {
            self.stop();
        }
        true
    }

    /// `n_tty_receive_signal_char`: the signal (flushing unless NOFLSH),
    /// output restarted, and the character echoed.
    fn signal_char(&mut self, signal: u8, c: u8, out: &mut dyn Sink, signals: &mut Vec<u8>) {
        signals.push(signal);
        if !self.termios.l(NOFLSH) {
            // isig: the echo buffer, the driver's output and the read
            // buffer are discarded.
            self.echo.clear();
            self.echo_mark = 0;
            self.echo_commit = 0;
            out.flush();
            self.reset_buffer();
        }
        if self.termios.i(IXON) {
            self.start(out);
        }
        if self.termios.l(ECHO) {
            self.echo_char(c);
            self.commit_echoes(out);
        } else {
            self.process_echoes(out);
        }
    }

    /// `n_tty_receive_char_canon`: the canonical-mode characters.
    fn receive_canon(&mut self, c: u8, out: &mut dyn Sink) -> bool {
        let t = self.termios;
        if c == self.cc(VERASE) || c == self.cc(VKILL) || (c == self.cc(VWERASE) && t.l(IEXTEN)) {
            self.eraser(c);
            self.commit_echoes(out);
            return true;
        }
        if c == self.cc(VLNEXT) && t.l(IEXTEN) {
            self.lnext = true;
            if t.l(ECHO) {
                self.finish_erasing();
                if t.l(ECHOCTL) {
                    self.add_echo(Echo::Byte(b'^'));
                    self.add_echo(Echo::Byte(b'\x08'));
                    self.commit_echoes(out);
                }
            }
            return true;
        }
        if c == self.cc(VREPRINT) && t.l(ECHO) && t.l(IEXTEN) {
            self.finish_erasing();
            self.echo_char(c);
            self.add_echo(Echo::Byte(b'\n'));
            let line: Vec<u8> = self.buf.iter().skip(self.canon).map(|&b| b as u8).collect();
            for b in line {
                self.echo_char(b);
            }
            self.commit_echoes(out);
            return true;
        }
        if c == b'\n' {
            if t.l(ECHO) || t.l(ECHONL) {
                self.add_echo(Echo::Byte(b'\n'));
                self.commit_echoes(out);
            }
            self.newline(c);
            return true;
        }
        if c == self.cc(VEOF) {
            self.newline(DISABLED);
            return true;
        }
        if c == self.cc(VEOL) || (c == self.cc(VEOL2) && t.l(IEXTEN)) {
            if t.l(ECHO) {
                if self.canon == self.buf.len() {
                    self.add_echo(Echo::SetCanonCol);
                }
                self.echo_char(c);
                self.commit_echoes(out);
            }
            if c == 0xff && t.i(PARMRK) {
                self.put(c);
            }
            self.newline(c);
            return true;
        }
        false
    }

    /// `n_tty_receive_handle_newline`: ends the line.
    fn newline(&mut self, c: u8) {
        self.buf.push_back(u16::from(c) | MARK);
        self.canon = self.buf.len();
        self.wakes.wake(EPOLLIN | EPOLLRDNORM);
    }

    fn put(&mut self, c: u8) {
        self.buf.push_back(u16::from(c));
    }

    /// `reset_buffer_flags`: empties the read buffer.
    fn reset_buffer(&mut self) {
        self.buf.clear();
        self.canon = 0;
        self.erasing = false;
        self.lookahead = 0;
    }

    fn is_continuation(&self, c: u8) -> bool {
        self.termios.i(IUTF8) && c & 0xc0 == 0x80
    }

    /// `eraser`: VERASE, VWERASE and VKILL on the line being typed.
    fn eraser(&mut self, c: u8) {
        #[derive(PartialEq)]
        enum How {
            Erase,
            Werase,
            Kill,
        }
        let t = self.termios;
        if self.buf.len() == self.canon {
            return;
        }
        let kill_type = if c == self.cc(VERASE) {
            How::Erase
        } else if c == self.cc(VWERASE) {
            How::Werase
        } else {
            if !t.l(ECHO) {
                self.buf.truncate(self.canon);
                return;
            }
            if !t.l(ECHOK) || !t.l(ECHOKE) || !t.l(ECHOE) {
                self.buf.truncate(self.canon);
                self.finish_erasing();
                self.echo_char(self.cc(VKILL));
                // A newline if ECHOK is on and ECHOKE off.
                if t.l(ECHOK) {
                    self.add_echo(Echo::Byte(b'\n'));
                }
                return;
            }
            How::Kill
        };
        let mut seen_alnums = 0;
        while self.buf.len() != self.canon {
            // One character, all of a UTF-8 sequence with IUTF8.
            let mut head = self.buf.len();
            let mut c;
            loop {
                head -= 1;
                c = self.buf[head] as u8;
                if !(self.is_continuation(c) && head != self.canon) {
                    break;
                }
            }
            // Do not erase part of one.
            if self.is_continuation(c) {
                break;
            }
            if kill_type == How::Werase {
                // BSD's ALTWERASE.
                if isalnum(c) || c == b'_' {
                    seen_alnums += 1;
                } else if seen_alnums > 0 {
                    break;
                }
            }
            let erased: Vec<u8> = self.buf.iter().skip(head).map(|&b| b as u8).collect();
            self.buf.truncate(head);
            if t.l(ECHO) {
                if t.l(ECHOPRT) {
                    if !self.erasing {
                        self.add_echo(Echo::Byte(b'\\'));
                        self.erasing = true;
                    }
                    self.echo_char(c);
                    for &b in &erased[1..] {
                        self.add_echo(Echo::Byte(b));
                        self.add_echo(Echo::MoveBackCol);
                    }
                } else if kill_type == How::Erase && !t.l(ECHOE) {
                    self.echo_char(self.cc(VERASE));
                } else if c == b'\t' {
                    // The columns since the line's start or the last tab.
                    let mut num_chars: u32 = 0;
                    let mut after_tab = false;
                    for i in (self.canon..self.buf.len()).rev() {
                        let b = self.buf[i] as u8;
                        if b == b'\t' {
                            after_tab = true;
                            break;
                        } else if iscntrl(b) {
                            if t.l(ECHOCTL) {
                                num_chars += 2;
                            }
                        } else if !self.is_continuation(b) {
                            num_chars += 1;
                        }
                    }
                    let n = (num_chars & 7) as u8 | if after_tab { 0x80 } else { 0 };
                    self.add_echo(Echo::EraseTab(n));
                } else {
                    let rub = [Echo::Byte(b'\x08'), Echo::Byte(b' '), Echo::Byte(b'\x08')];
                    if iscntrl(c) && t.l(ECHOCTL) {
                        rub.iter().for_each(|&e| self.add_echo(e));
                    }
                    if !iscntrl(c) || t.l(ECHOCTL) {
                        rub.iter().for_each(|&e| self.add_echo(e));
                    }
                }
            }
            if kill_type == How::Erase {
                break;
            }
        }
        if self.buf.len() == self.canon && t.l(ECHO) {
            self.finish_erasing();
        }
    }

    fn finish_erasing(&mut self) {
        if self.erasing {
            self.add_echo(Echo::Byte(b'/'));
            self.erasing = false;
        }
    }

    /// `echo_char`: ECHOCTL shows a control character but tab as `^X`.
    fn echo_char(&mut self, c: u8) {
        if c != 0xff && self.termios.l(ECHOCTL) && iscntrl(c) && c != b'\t' {
            self.add_echo(Echo::Ctrl(c));
        } else {
            self.add_echo(Echo::Byte(c));
        }
    }

    fn add_echo(&mut self, e: Echo) {
        self.echo.push_back(e);
    }

    fn echo_bytes(&self, ops: usize) -> usize {
        self.echo.iter().take(ops).map(|e| e.size()).sum()
    }

    /// `commit_echoes`: sends the echo when enough is pending.
    fn commit_echoes(&mut self, out: &mut dyn Sink) {
        let head = self.echo.len();
        self.echo_mark = head;
        let old = self.echo_bytes(self.echo_commit);
        let nr = self.echo_bytes(head);
        if nr < ECHO_COMMIT_WATERMARK || nr % ECHO_BLOCK > old % ECHO_BLOCK {
            return;
        }
        self.echo_commit = head;
        self.send_echoes(out);
    }

    /// `process_echoes`: sends the echo committed so far.
    fn process_echoes(&mut self, out: &mut dyn Sink) {
        if self.echo_mark == 0 {
            return;
        }
        self.echo_commit = self.echo_mark;
        self.send_echoes(out);
    }

    /// `flush_echoes`: sends all of it (with ECHO or ECHONL).
    fn flush_echoes(&mut self, out: &mut dyn Sink) {
        let t = self.termios;
        if (!t.l(ECHO) && !t.l(ECHONL)) || self.echo_commit == self.echo.len() {
            return;
        }
        self.echo_commit = self.echo.len();
        self.send_echoes(out);
    }

    /// `__process_echoes`: as much committed echo as there is room for;
    /// then, if what is left is near the buffer's size, the oldest goes.
    fn send_echoes(&mut self, out: &mut dyn Sink) {
        let mut space = self.write_room(out);
        let mut bytes = Vec::new();
        let mut done = 0;
        while done < self.echo_commit {
            match self.echo[done] {
                Echo::Byte(0xff) => {
                    if space == 0 {
                        break;
                    }
                    bytes.push(0xff);
                    self.column += 1;
                    space -= 1;
                }
                Echo::Byte(c) => {
                    if self.termios.o(OPOST) {
                        match self.output_char(c, space, &mut bytes) {
                            Some(used) => space -= used,
                            None => break,
                        }
                    } else {
                        if space == 0 {
                            break;
                        }
                        bytes.push(c);
                        space -= 1;
                    }
                }
                Echo::Ctrl(c) => {
                    if space < 2 {
                        break;
                    }
                    bytes.extend_from_slice(&[b'^', c ^ 0o100]);
                    self.column += 2;
                    space -= 2;
                }
                Echo::EraseTab(n) => {
                    let mut num_chars = u32::from(n);
                    if n & 0x80 == 0 {
                        num_chars += self.canon_column;
                    }
                    let num_bs = 8 - (num_chars & 7) as usize;
                    if num_bs > space {
                        break;
                    }
                    space -= num_bs;
                    bytes.extend(core::iter::repeat_n(b'\x08', num_bs));
                    self.column = self.column.saturating_sub(num_bs as u32);
                }
                Echo::SetCanonCol => self.canon_column = self.column,
                Echo::MoveBackCol => self.column = self.column.saturating_sub(1),
            }
            done += 1;
        }
        self.drop_echoes(done);
        while self.echo_commit > 0 && self.echo_bytes(self.echo_commit) >= ECHO_DISCARD_WATERMARK {
            self.drop_echoes(1);
        }
        if !bytes.is_empty() {
            out.put(&bytes);
        }
    }

    fn drop_echoes(&mut self, n: usize) {
        self.echo.drain(..n);
        self.echo_commit -= n;
        self.echo_mark = self.echo_mark.saturating_sub(n);
    }

    /// `do_output_char`: one character with OPOST processing, into
    /// `bytes`; the bytes it took, or None if `space` is too small.
    fn output_char(&mut self, c: u8, space: usize, bytes: &mut Vec<u8>) -> Option<usize> {
        let t = self.termios;
        if space == 0 {
            return None;
        }
        let mut c = c;
        match c {
            b'\n' => {
                if t.o(ONLRET) {
                    self.column = 0;
                }
                if t.o(ONLCR) {
                    if space < 2 {
                        return None;
                    }
                    self.canon_column = 0;
                    self.column = 0;
                    bytes.extend_from_slice(b"\r\n");
                    return Some(2);
                }
                self.canon_column = self.column;
            }
            b'\r' => {
                if t.o(ONOCR) && self.column == 0 {
                    return Some(0);
                }
                if t.o(OCRNL) {
                    c = b'\n';
                    if t.o(ONLRET) {
                        self.canon_column = 0;
                        self.column = 0;
                    }
                } else {
                    self.canon_column = 0;
                    self.column = 0;
                }
            }
            b'\t' => {
                let spaces = 8 - (self.column & 7) as usize;
                if t.oflag & TABDLY == XTABS {
                    if space < spaces {
                        return None;
                    }
                    self.column += spaces as u32;
                    bytes.extend(core::iter::repeat_n(b' ', spaces));
                    return Some(spaces);
                }
                self.column += spaces as u32;
            }
            b'\x08' => self.column = self.column.saturating_sub(1),
            _ => {
                if !iscntrl(c) {
                    if t.o(OLCUC) {
                        c = toupper(c);
                    }
                    if !self.is_continuation(c) {
                        self.column += 1;
                    }
                }
            }
        }
        bytes.push(c);
        Some(1)
    }

    /// `pty_write_room`: nothing while output is stopped.
    fn write_room(&self, out: &dyn Sink) -> usize {
        if self.stopped { 0 } else { out.room() }
    }

    // --- flow control ---

    /// `__stop_tty`.
    fn stop(&mut self) {
        self.stopped = true;
    }

    /// `__start_tty`, and the echo held while stopped.
    fn start(&mut self, out: &mut dyn Sink) {
        if !self.stopped || self.tco_stopped {
            return;
        }
        self.stopped = false;
        self.wakes.wake(EPOLLOUT);
        self.process_echoes(out);
    }

    /// Whether output is stopped.
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    /// TCXONC's TCOOFF and TCOON; TCIOFF and TCION send STOP and START
    /// (`tty_send_xchar`, through the driver's write even if stopped).
    /// EINVAL for another action.
    pub fn tcxonc(&mut self, action: u64, out: &mut dyn Sink) -> Result<(), Errno> {
        match action {
            TCOOFF => {
                if !self.tco_stopped {
                    self.tco_stopped = true;
                    self.stop();
                }
            }
            TCOON => {
                if self.tco_stopped {
                    self.tco_stopped = false;
                    self.start(out);
                }
            }
            TCIOFF | TCION => {
                let c = self.cc(if action == TCIOFF { VSTOP } else { VSTART });
                if c != DISABLED {
                    let was = self.stopped;
                    if was {
                        self.start(out);
                    }
                    if !self.stopped && out.room() > 0 {
                        out.put(&[c]);
                    }
                    if was {
                        self.stop();
                    }
                }
            }
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    }

    // --- the reader's side ---

    /// `input_available_p`: a complete line in canonical mode; else at
    /// least a byte, or for poll with VTIME 0 at least VMIN.
    pub fn input_available(&self, poll: bool) -> bool {
        let t = self.termios;
        let amt = if poll && t.cc[VTIME] == 0 && t.cc[VMIN] != 0 {
            usize::from(t.cc[VMIN])
        } else {
            1
        };
        if self.icanon && !t.l(EXTPROC) {
            self.canon != 0
        } else {
            self.buf.len() >= amt
        }
    }

    /// Whether reads take lines (ICANON without EXTPROC).
    pub fn canonical(&self) -> bool {
        self.icanon && !self.termios.l(EXTPROC)
    }

    /// A canonical read (`canon_copy_from_read_buf`, with the retries
    /// `iterate_tty_read` makes): up to the end of the first line (its
    /// newline or EOL included, an end-of-file mark not) or `buf`'s size.
    /// If `buf` fills just before an end-of-file mark, the mark goes too
    /// (`canon_skip_eof`). 0 for an end of file.
    pub fn read_canon(&mut self, buf: &mut [u8]) -> usize {
        let mut done = 0;
        loop {
            let nr = buf.len() - done;
            if nr == 0 {
                if self.canon > 0 && self.buf[0] & MARK != 0 && self.buf[0] as u8 == DISABLED {
                    self.buf.pop_front();
                    self.canon -= 1;
                }
                break;
            }
            let n = nr.min(self.canon);
            let eol = (0..n).find(|&i| self.buf[i] & MARK != 0);
            let (copy, consume) = match eol {
                Some(e) if self.buf[e] as u8 == DISABLED => (e, e + 1),
                Some(e) => (e + 1, e + 1),
                None => (n, n),
            };
            for (slot, b) in buf[done..done + copy].iter_mut().zip(self.buf.iter()) {
                *slot = *b as u8;
            }
            done += copy;
            self.buf.drain(..consume);
            self.canon -= consume;
            if eol.is_some() || self.canon == 0 {
                break;
            }
        }
        done
    }

    /// A non-canonical read (`copy_from_read_buf`): what is there, up to
    /// `buf`'s size. With EXTPROC in canonical mode a lone VEOF is taken
    /// and read as nothing.
    pub fn read_raw(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.buf.len());
        for (slot, b) in buf[..n].iter_mut().zip(self.buf.iter()) {
            *slot = *b as u8;
        }
        let is_eof = n == 1 && buf[0] == self.cc(VEOF);
        self.buf.drain(..n);
        self.canon = self.canon.saturating_sub(n);
        if self.termios.l(EXTPROC) && self.icanon && is_eof && self.buf.is_empty() {
            return 0;
        }
        n
    }

    /// TIOCINQ (FIONREAD): in canonical mode the complete lines less their
    /// end-of-file marks (`inq_canon`), else all of the read buffer.
    pub fn inq(&self) -> usize {
        if self.termios.l(ICANON) && !self.termios.l(EXTPROC) {
            let eofs = self
                .buf
                .iter()
                .take(self.canon)
                .filter(|&&b| b & MARK != 0 && b as u8 == DISABLED)
                .count();
            self.canon - eofs
        } else {
            self.buf.len()
        }
    }

    /// Discards the read buffer (`n_tty_flush_buffer`; TCIFLUSH also
    /// empties the flip buffer, with [`Tty::flush_flip`]).
    pub fn flush_input(&mut self) {
        self.reset_buffer();
    }

    // --- the writer's side ---

    /// Writes what fits of `data` to `out` (`n_tty_write`'s loop): the
    /// pending echo first, then the bytes, with OPOST processing if set.
    /// Returns how many of `data` were taken.
    pub fn write(&mut self, data: &[u8], out: &mut dyn Sink) -> usize {
        self.process_echoes(out);
        let mut space = self.write_room(out);
        let mut bytes = Vec::new();
        let mut n = 0;
        if self.termios.o(OPOST) {
            for &c in data {
                match self.output_char(c, space, &mut bytes) {
                    Some(used) => {
                        space -= used;
                        n += 1;
                    }
                    None => break,
                }
            }
        } else {
            n = data.len().min(space);
            bytes.extend_from_slice(&data[..n]);
        }
        if !bytes.is_empty() {
            out.put(&bytes);
        }
        n
    }

    /// n_tty_poll's EPOLLOUT: little unsent (`chars`) and room to write.
    pub fn writable(&self, chars: usize, out: &dyn Sink) -> bool {
        chars < WAKEUP_CHARS && self.write_room(out) > 0
    }

    // --- settings ---

    /// `tty_set_termios` with the line discipline's `n_tty_set_termios`:
    /// locked bits and characters keep their old values, ADDRB is kept, a
    /// pty is CS8 and CREAD, and the discipline adapts.
    pub fn set_termios(&mut self, new: Termios, out: &mut dyn Sink) {
        let old = self.termios;
        let lk = self.locked;
        let keep = |new: u32, old: u32, locked: u32| (new & !locked) | (old & locked);
        let mut t = new;
        t.iflag = keep(t.iflag, old.iflag, lk.iflag);
        t.oflag = keep(t.oflag, old.oflag, lk.oflag);
        t.cflag = keep(t.cflag, old.cflag, lk.cflag);
        t.lflag = keep(t.lflag, old.lflag, lk.lflag);
        if lk.line != 0 {
            t.line = old.line;
        }
        for i in 0..NCCS {
            if lk.cc[i] != 0 {
                t.cc[i] = old.cc[i];
            }
        }
        t.cflag ^= (t.cflag ^ old.cflag) & ADDRB;
        if self.pty {
            // pty_set_termios.
            t.cflag &= !(CSIZE | PARENB);
            t.cflag |= CS8 | CREAD;
        }
        self.termios = t;
        self.ldisc_set_termios(Some(old));
        if !t.i(IXON) && old.i(IXON) && !self.tco_stopped {
            self.start(out);
        }
        // "The termios change make the tty ready for I/O".
        self.wakes.wake(0);
    }

    /// `n_tty_set_termios`.
    fn ldisc_set_termios(&mut self, old: Option<Termios>) {
        let t = self.termios;
        let switched = match old {
            None => true,
            Some(old) => (old.lflag ^ t.lflag) & (ICANON | EXTPROC) != 0,
        };
        if switched {
            for b in self.buf.iter_mut() {
                *b &= !MARK;
            }
            if !t.l(ICANON) || self.buf.is_empty() {
                self.canon = 0;
            } else {
                if let Some(last) = self.buf.back_mut() {
                    *last |= MARK;
                }
                self.canon = self.buf.len();
            }
            self.erasing = false;
            self.lnext = false;
        }
        self.icanon = t.l(ICANON);
        if t.i(ISTRIP)
            || t.i(IUCLC)
            || t.i(IGNCR)
            || t.i(ICRNL)
            || t.i(INLCR)
            || t.l(ICANON)
            || t.i(IXON)
            || t.l(ISIG)
            || t.l(ECHO)
            || t.i(PARMRK)
        {
            let mut map = CharMap::default();
            if t.i(IGNCR) || t.i(ICRNL) {
                map.set(b'\r');
            }
            if t.i(INLCR) {
                map.set(b'\n');
            }
            if t.l(ICANON) {
                for i in [VERASE, VKILL, VEOF, VEOL] {
                    map.set(t.cc[i]);
                }
                map.set(b'\n');
                if t.l(IEXTEN) {
                    for i in [VWERASE, VLNEXT, VEOL2] {
                        map.set(t.cc[i]);
                    }
                    if t.l(ECHO) {
                        map.set(t.cc[VREPRINT]);
                    }
                }
            }
            if t.i(IXON) {
                map.set(t.cc[VSTART]);
                map.set(t.cc[VSTOP]);
            }
            if t.l(ISIG) {
                for i in [VINTR, VQUIT, VSUSP] {
                    map.set(t.cc[i]);
                }
            }
            map.clear(DISABLED);
            self.char_map = map;
            self.raw = false;
        } else {
            self.raw = true;
        }
    }

    /// TIOCSSOFTCAR (`tty_change_softcar`): CLOCAL on or off; EINVAL if
    /// the driver refused (a pty never does).
    pub fn set_softcar(&mut self, on: bool) {
        let bit = if on { CLOCAL } else { 0 };
        self.termios.cflag = (self.termios.cflag & !CLOCAL) | bit;
        if self.pty {
            self.termios.cflag &= !(CSIZE | PARENB);
            self.termios.cflag |= CS8 | CREAD;
        }
    }
}

// --- a pty pair -------------------------------------------------------

/// Which end of a pty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Master,
    Slave,
}

/// A pty's flip buffer, as the other end's output (`pty_write`).
struct Flip<'a>(&'a mut Tty);

impl Sink for Flip<'_> {
    fn room(&self) -> usize {
        self.0.flip_room()
    }
    fn put(&mut self, bytes: &[u8]) {
        self.0.push_input(bytes);
    }
    fn flush(&mut self) {
        self.0.flush_flip();
    }
}

/// The input buffer of each end of a pty (`pty_common_install`).
pub const PTY_FLIP_LIMIT: usize = 8192;

/// A pseudo-terminal pair (`drivers/tty/pty.c`, Unix98): what the master
/// writes is the slave's input, and the slave's output (its echo
/// included) is the master's input.
#[derive(Debug)]
pub struct Pty {
    pub master: Tty,
    pub slave: Tty,
    /// TTY_PTY_LOCK: the slave cannot be opened (set by /dev/ptmx).
    pub locked: bool,
    /// Open descriptions of the slave.
    pub slave_opens: usize,
    /// The master is closed: the slave is hung up (`tty_vhangup`).
    pub master_closed: bool,
    /// TTY_OTHER_CLOSED on the master: the slave was opened and its last
    /// description closed. Master reads with nothing to read are EIO.
    pub slave_closed: bool,
    /// TTY_IO_ERROR on the slave: an open of it failed (`pty_open` sets
    /// it), so reads and writes of its open descriptions are EIO until an
    /// open succeeds.
    pub slave_io_error: bool,
}

impl Default for Pty {
    fn default() -> Self {
        Pty::new()
    }
}

impl Pty {
    pub fn new() -> Self {
        Pty {
            master: Tty::new(Termios::pty_master(), PTY_FLIP_LIMIT, true),
            slave: Tty::new(Termios::pty_slave(), PTY_FLIP_LIMIT, true),
            locked: true,
            slave_opens: 0,
            master_closed: false,
            slave_closed: false,
            slave_io_error: false,
        }
    }

    /// The end `end` and its peer.
    pub fn ends(&mut self, end: End) -> (&mut Tty, &mut Tty) {
        match end {
            End::Master => (&mut self.master, &mut self.slave),
            End::Slave => (&mut self.slave, &mut self.master),
        }
    }

    pub fn end(&self, end: End) -> &Tty {
        match end {
            End::Master => &self.master,
            End::Slave => &self.slave,
        }
    }

    /// Runs `f` on `end` with its peer's flip buffer as the output.
    pub fn look<R>(&mut self, end: End, f: impl FnOnce(&mut Tty, &mut dyn Sink) -> R) -> R {
        let (this, peer) = self.ends(end);
        f(this, &mut Flip(peer))
    }

    /// As [`Pty::look`], then moves input on both sides; also returns the
    /// signals the slave's input raised.
    pub fn with_output<R>(
        &mut self,
        end: End,
        f: impl FnOnce(&mut Tty, &mut dyn Sink) -> R,
    ) -> (R, Vec<u8>) {
        let r = self.look(end, f);
        let signals = self.pump();
        (r, signals)
    }

    /// Moves input into both line disciplines until neither takes more
    /// (the flush_to_ldisc work, run at once). Returns the signals the
    /// slave's input raised.
    pub fn pump(&mut self) -> Vec<u8> {
        let mut signals = Vec::new();
        // Bounded: a master never echoes (its settings cannot change), so
        // the slave's echo ends here.
        for _ in 0..4 {
            let a = self.slave.receive(&mut Flip(&mut self.master));
            signals.extend(a.signals);
            let b = self.master.receive(&mut Flip(&mut self.slave));
            if !a.progress && !b.progress {
                break;
            }
        }
        signals
    }

    /// Writes from `end`: what was taken, and the signals raised.
    pub fn write(&mut self, end: End, data: &[u8]) -> (usize, Vec<u8>) {
        self.with_output(end, |t, out| t.write(data, out))
    }

    /// Whether `end` can be written (n_tty_poll's EPOLLOUT; a pty has no
    /// unsent bytes of its own).
    pub fn writable(&mut self, end: End) -> bool {
        let (this, peer) = self.ends(end);
        this.writable(0, &Flip(peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A slave fed bytes as if written to its master; returns the echo.
    fn type_(p: &mut Pty, s: &[u8]) -> Vec<u8> {
        p.write(End::Master, s);
        read_all(p, End::Master, 65536)
    }

    fn read_all(p: &mut Pty, end: End, size: usize) -> Vec<u8> {
        let mut buf = alloc::vec![0; size];
        let (this, _) = p.ends(end);
        let n = if this.canonical() {
            this.read_canon(&mut buf)
        } else {
            this.read_raw(&mut buf)
        };
        p.pump();
        buf.truncate(n);
        buf
    }

    fn set(p: &mut Pty, f: impl FnOnce(&mut Termios)) {
        let mut t = p.slave.termios;
        f(&mut t);
        p.with_output(End::Slave, |tty, out| tty.set_termios(t, out));
    }

    #[test]
    fn defaults_match_linux() {
        let s = Termios::pty_slave();
        assert_eq!(s.iflag, 0x500, "ICRNL|IXON");
        assert_eq!(s.oflag, 0x5, "OPOST|ONLCR");
        assert_eq!(s.cflag, 0xbf, "B38400|CS8|CREAD");
        assert_eq!(s.lflag, 0x8a3b);
        assert_eq!(
            &s.to_bytes()[17..36],
            b"\x03\x1c\x7f\x15\x04\x00\x01\x00\x11\x13\x1a\x00\x12\x0f\x17\x16\x00\x00\x00"
        );
        let m = Termios::pty_master();
        assert_eq!((m.iflag, m.oflag, m.lflag), (0, 0, 0));
        assert_eq!(s.input_speed(), 38400);
    }

    #[test]
    fn speeds() {
        let mut t = Termios::standard();
        t.cflag = (t.cflag & !CBAUD) | B115200;
        assert_eq!(t.output_speed(), 115200);
        assert_eq!(t.input_speed(), 115200, "no CIBAUD: the output speed");
        t.cflag |= B9600 << IBSHIFT;
        assert_eq!(t.input_speed(), 9600);
        t.cflag = (t.cflag & !CBAUD) | BOTHER;
        t.ospeed = 12345;
        assert_eq!(t.output_speed(), 12345);
    }

    #[test]
    fn termios_round_trips() {
        let mut t = Termios::standard();
        t.cc[VMIN] = 7;
        let b = t.to_bytes2();
        assert_eq!(Termios::standard().with_bytes(&b), t);
        let mut old = Termios::standard();
        old.iflag |= 0x1_0000;
        let back = old.with_termio(&t.to_termio());
        assert_eq!(
            back.iflag,
            t.iflag | 0x1_0000,
            "termio keeps the high halves"
        );
        assert_eq!(back.cc[..NCC], t.cc[..NCC]);
    }

    #[test]
    fn canonical_lines_and_echo() {
        let mut p = Pty::new();
        assert_eq!(type_(&mut p, b"ab"), b"ab");
        assert!(!p.slave.input_available(false));
        assert_eq!(
            type_(&mut p, b"\r"),
            b"\r\n",
            "ICRNL, then ONLCR on the echo"
        );
        assert_eq!(p.slave.inq(), 3);
        assert_eq!(read_all(&mut p, End::Slave, 64), b"ab\n");
    }

    #[test]
    fn reads_stop_at_line_ends_and_buffer_size() {
        let mut p = Pty::new();
        type_(&mut p, b"one\ntwo\n");
        assert_eq!(read_all(&mut p, End::Slave, 2), b"on");
        assert_eq!(read_all(&mut p, End::Slave, 64), b"e\n");
        assert_eq!(read_all(&mut p, End::Slave, 64), b"two\n");
    }

    #[test]
    fn end_of_file() {
        let mut p = Pty::new();
        type_(&mut p, b"\x04");
        assert!(p.slave.input_available(false));
        assert_eq!(p.slave.inq(), 0, "an end of file counts nothing");
        assert_eq!(read_all(&mut p, End::Slave, 64), b"");
        assert!(!p.slave.input_available(false));
        type_(&mut p, b"abc\x04");
        assert_eq!(read_all(&mut p, End::Slave, 3), b"abc");
        assert!(
            !p.slave.input_available(false),
            "a full buffer takes the mark"
        );
        type_(&mut p, b"ab\x04");
        assert_eq!(read_all(&mut p, End::Slave, 64), b"ab");
    }

    #[test]
    fn erase_kill_and_werase() {
        let mut p = Pty::new();
        assert_eq!(type_(&mut p, b"kex\x7fl"), b"kex\x08 \x08l");
        assert_eq!(
            type_(&mut p, b"\x1b\x7f"),
            b"^[\x08 \x08\x08 \x08",
            "^[ is two cells"
        );
        assert_eq!(
            type_(&mut p, b"\x15"),
            b"\x08 \x08\x08 \x08\x08 \x08",
            "ECHOKE"
        );
        assert_eq!(
            type_(&mut p, b"foo bar_1 \x17"),
            b"foo bar_1 \x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08"
        );
        type_(&mut p, b"\n");
        assert_eq!(read_all(&mut p, End::Slave, 64), b"foo \n");
        assert_eq!(type_(&mut p, b"\x7f"), b"", "nothing to erase");
    }

    #[test]
    fn kill_without_echoke() {
        let mut p = Pty::new();
        set(&mut p, |t| t.lflag &= !ECHOKE);
        assert_eq!(
            type_(&mut p, b"ab\x15"),
            b"ab^U\r\n",
            "the kill char and ECHOK's newline"
        );
    }

    #[test]
    fn echoprt() {
        let mut p = Pty::new();
        set(&mut p, |t| t.lflag |= ECHOPRT);
        assert_eq!(type_(&mut p, b"abc\x7f\x7fd"), b"abc\\cb/d");
    }

    #[test]
    fn tab_erase_goes_back_to_its_column() {
        let mut p = Pty::new();
        assert_eq!(type_(&mut p, b"ab\t\x7f"), b"ab\t\x08\x08\x08\x08\x08\x08");
    }

    #[test]
    fn interrupt_flushes_and_echoes_without_newline() {
        let mut p = Pty::new();
        type_(&mut p, b"lost");
        let (_, signals) = p.write(End::Master, b"\x03");
        assert_eq!(signals, [SIGINT]);
        assert_eq!(read_all(&mut p, End::Master, 64), b"^C");
        assert!(!p.slave.input_available(false));
        type_(&mut p, b"\n");
        assert_eq!(
            read_all(&mut p, End::Slave, 64),
            b"\n",
            "the line was discarded"
        );
        // Echo still pending in the same batch is discarded with it.
        let (_, signals) = p.write(End::Master, b"xy\x1c");
        assert_eq!(signals, [SIGQUIT]);
        assert_eq!(read_all(&mut p, End::Master, 64), b"^\\");
    }

    #[test]
    fn noflsh_keeps_input() {
        let mut p = Pty::new();
        set(&mut p, |t| t.lflag |= NOFLSH);
        p.write(End::Master, b"ab\x03c\n");
        assert_eq!(read_all(&mut p, End::Slave, 64), b"abc\n");
    }

    #[test]
    fn lnext_and_reprint() {
        let mut p = Pty::new();
        assert_eq!(type_(&mut p, b"\x16"), b"^\x08");
        assert_eq!(type_(&mut p, b"\x03"), b"^C", "taken literally, no signal");
        assert_eq!(type_(&mut p, b"x\x12"), b"x^R\r\n^Cx");
        type_(&mut p, b"\n");
        assert_eq!(read_all(&mut p, End::Slave, 64), b"\x03x\n");
    }

    #[test]
    fn non_canonical_reads_what_is_there() {
        let mut p = Pty::new();
        set(&mut p, |t| t.lflag &= !(ICANON | ECHO));
        p.write(End::Master, b"abc");
        assert_eq!(p.slave.inq(), 3);
        assert_eq!(read_all(&mut p, End::Slave, 2), b"ab");
        assert_eq!(read_all(&mut p, End::Slave, 64), b"c");
        set(&mut p, |t| t.cc[VMIN] = 4);
        p.write(End::Master, b"xyz");
        assert!(p.slave.input_available(false));
        assert!(!p.slave.input_available(true), "poll waits for VMIN");
    }

    #[test]
    fn switching_to_canonical_makes_pending_input_a_line() {
        let mut p = Pty::new();
        set(&mut p, |t| t.lflag &= !ICANON);
        p.write(End::Master, b"raw");
        set(&mut p, |t| t.lflag |= ICANON);
        assert_eq!(p.slave.inq(), 3);
        assert_eq!(read_all(&mut p, End::Slave, 64), b"raw");
    }

    #[test]
    fn output_processing() {
        let mut p = Pty::new();
        p.write(End::Slave, b"a\nb\t|");
        assert_eq!(read_all(&mut p, End::Master, 64), b"a\r\nb\t|");
        set(&mut p, |t| t.oflag |= XTABS | OLCUC);
        p.write(End::Slave, b"\nab\tc\xe9\xdf\n");
        assert_eq!(
            read_all(&mut p, End::Master, 64),
            b"\r\nAB      C\xc9\xbf\r\n"
        );
        set(&mut p, |t| t.oflag = OPOST | OCRNL | ONOCR);
        p.write(End::Slave, b"\rx\r");
        assert_eq!(
            read_all(&mut p, End::Master, 64),
            b"x\n",
            "ONOCR drops a CR at column 0"
        );
        set(&mut p, |t| t.oflag = 0);
        p.write(End::Slave, b"a\n");
        assert_eq!(read_all(&mut p, End::Master, 64), b"a\n");
    }

    #[test]
    fn input_mapping() {
        let mut p = Pty::new();
        set(&mut p, |t| {
            t.iflag = INLCR | ISTRIP | IUCLC;
            t.lflag &= !ECHO;
        });
        p.write(End::Master, b"AB\xc1\n\r");
        assert_eq!(
            p.slave.inq(),
            0,
            "INLCR: no newline, IGNCR off, CR is ordinary"
        );
        set(&mut p, |t| t.iflag = IGNCR);
        p.write(End::Master, b"\r\n");
        assert_eq!(
            read_all(&mut p, End::Slave, 64),
            b"aba\r\r\n",
            "ISTRIP, then IUCLC"
        );
    }

    #[test]
    fn non_canonical_newline_echoes_as_control() {
        let mut p = Pty::new();
        set(&mut p, |t| t.lflag &= !ICANON);
        assert_eq!(type_(&mut p, b"\n"), b"^J");
        assert_eq!(
            type_(&mut p, b"\r"),
            b"\r\n",
            "CR is mapped by ICRNL as a special"
        );
    }

    #[test]
    fn flow_control_stops_output() {
        let mut p = Pty::new();
        p.write(End::Master, b"\x13");
        assert!(p.slave.stopped());
        assert!(!p.writable(End::Slave));
        assert_eq!(p.write(End::Slave, b"held").0, 0);
        assert_eq!(type_(&mut p, b"e"), b"", "echo waits too");
        assert_eq!(type_(&mut p, b"\x11"), b"e");
        assert_eq!(p.write(End::Slave, b"go").0, 2);
        assert_eq!(read_all(&mut p, End::Master, 64), b"go");
        // IXANY: any character restarts.
        set(&mut p, |t| t.iflag |= IXANY);
        p.write(End::Master, b"\x13");
        type_(&mut p, b"z");
        assert!(!p.slave.stopped());
        // TCOOFF holds even against START.
        p.with_output(End::Slave, |t, out| t.tcxonc(TCOOFF, out).unwrap());
        type_(&mut p, b"\x11");
        assert!(p.slave.stopped());
        p.with_output(End::Slave, |t, out| t.tcxonc(TCOON, out).unwrap());
        assert!(!p.slave.stopped());
    }

    #[test]
    fn canonical_overflow_keeps_room_for_a_newline() {
        let mut p = Pty::new();
        set(&mut p, |t| t.lflag &= !ECHO);
        let long = alloc::vec![b'x'; 5000];
        for chunk in long.chunks(1000) {
            p.write(End::Master, chunk);
        }
        p.write(End::Master, b"\n");
        let line = read_all(&mut p, End::Slave, 8192);
        assert_eq!(line.len(), N_TTY_BUF_SIZE);
        assert_eq!(line.last(), Some(&b'\n'));
    }

    #[test]
    fn raw_input_waits_in_the_flip_buffer() {
        let mut p = Pty::new();
        set(&mut p, |t| {
            t.lflag &= !(ICANON | ECHO);
            t.iflag = 0;
        });
        let data = alloc::vec![b'y'; 20000];
        let mut total = 0;
        loop {
            let (n, _) = p.write(End::Master, &data);
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(
            total,
            N_TTY_BUF_SIZE - 1 + PTY_FLIP_LIMIT,
            "read buffer less one, then the flip"
        );
        assert!(!p.writable(End::Master));
        assert_eq!(read_all(&mut p, End::Slave, 100).len(), 100);
        assert!(p.writable(End::Master), "reading made room");
    }

    #[test]
    fn locked_termios_and_addrb() {
        let mut p = Pty::new();
        p.slave.locked.lflag = ECHO;
        p.slave.locked.cc[VINTR] = 1;
        set(&mut p, |t| {
            t.lflag &= !(ECHO | ICANON);
            t.cc[VINTR] = 0x01;
            t.cflag = CS7 | PARENB | ADDRB;
        });
        assert!(p.slave.termios.lflag & ECHO != 0, "ECHO is locked");
        assert_eq!(p.slave.termios.lflag & ICANON, 0);
        assert_eq!(p.slave.termios.cc[VINTR], 0x03);
        assert_eq!(
            p.slave.termios.cflag,
            CS8 | CREAD,
            "a pty: CS8 CREAD, no PARENB, ADDRB kept"
        );
    }
}
