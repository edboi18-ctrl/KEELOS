//! Terminals (P1-T14, P3-T12; ADR 0029): the console and pseudo-terminals,
//! each with Linux's N_TTY line discipline (`keel_core::tty`).
//!
//! - **The console** (`/dev/console`) takes input from the keyboard
//!   (scancode set 1, US layout) and COM1, both by interrupt, and writes to
//!   COM1 and the screen. Interrupt context only takes `IrqMutex` locks and
//!   wakes queues, so echo is printed by a kernel thread (the console
//!   output locks are spinlocks the interrupted code could hold). A
//!   program's writes are printed by the writer itself.
//! - **Ptys** (`/dev/ptmx`, `/dev/pts/N`; `drivers/tty/pty.c`,
//!   `fs/devpts/inode.c` at v6.12): opening /dev/ptmx makes a pair and
//!   its slave node, locked until TIOCSPTLCK unlocks it. The master's
//!   writes are the slave's input; the slave's output, its echo included,
//!   is the master's input.
//!
//! A terminal is an open file whose description carries a [`TtyOpen`]:
//! reads, writes, ioctls and poll come here; stat, fcntl and the rest
//! treat it as the device node it was opened through.

use alloc::string::ToString;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use keel_core::compartment::Compartment;
use keel_core::epoll::Wakes;
use keel_core::errno::Errno;
use keel_core::keyboard::Decoder;
use keel_core::signal::{SIGCONT, SIGHUP, SigInfo};
use keel_core::tty::{
    self as core_tty, Collect, End, N_TTY_BUF_SIZE, Pty, Sink, TCIFLUSH, TCIOFLUSH, TCOFLUSH,
    Termios, Tty, Winsize,
};
use keel_core::vfs::{Device, Ino};
use keel_hal::drivers::ps2;
use keel_hal::sched::{self, WaitQueue, Waited};
use keel_hal::sync::IrqMutex;
use keel_hal::vm::{copy_from_user, copy_to_user};

use crate::ready::{changed, copy_in, copy_out, total, wait};

type SysResult = Result<u64, Errno>;

// --- the console ------------------------------------------------------

struct Console {
    tty: Tty,
    decoder: Decoder,
    /// Echo waiting for the echo thread (the UART's transmit buffer).
    out: Vec<u8>,
    /// Signals the input raised (ISIG) for the foreground process group;
    /// the echo thread sends them, as interrupt context cannot.
    signals: Vec<u8>,
}

/// UART_XMIT_SIZE (a page): the console's unsent output at most.
const CONSOLE_OUT_MAX: usize = 4096;
/// Console input not yet taken by the line discipline at most.
const CONSOLE_FLIP_LIMIT: usize = 65536;

static CONSOLE: IrqMutex<Option<Console>> = IrqMutex::new(None);
/// The echo thread waiting for output.
static ECHO: WaitQueue = WaitQueue::new();

fn console(slot: &mut Option<Console>) -> &mut Console {
    slot.get_or_insert_with(|| {
        // A serial console's settings (`tty_std_termios`, the 8250
        // console at 115200 8N1: B115200 CS8 CREAD HUPCL CLOCAL), and the
        // screen's size, or 80x25 without one.
        let mut termios = Termios::standard();
        termios.cflag = core_tty::B115200 | core_tty::CS8 | core_tty::CREAD | core_tty::HUPCL;
        termios.cflag |= core_tty::CLOCAL;
        termios.ispeed = 115200;
        termios.ospeed = 115200;
        let mut tty = Tty::new(termios, CONSOLE_FLIP_LIMIT, false);
        let (cols, rows) = keel_hal::console::framebuffer_size_chars().unwrap_or((80, 25));
        tty.winsize = Winsize {
            row: u16::try_from(rows).unwrap_or(u16::MAX),
            col: u16::try_from(cols).unwrap_or(u16::MAX),
            xpixel: 0,
            ypixel: 0,
        };
        Console {
            tty,
            decoder: Decoder::new(),
            out: Vec::new(),
            signals: Vec::new(),
        }
    })
}

/// The console's output queue as a line discipline's output.
struct EchoOut<'a>(&'a mut Vec<u8>);

impl Sink for EchoOut<'_> {
    fn room(&self) -> usize {
        CONSOLE_OUT_MAX - self.0.len()
    }
    fn put(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(self.room());
        self.0.extend_from_slice(&bytes[..n]);
    }
    fn flush(&mut self) {
        self.0.clear();
    }
}

/// Interrupt context: input from the keyboard or COM1.
fn console_input(bytes: &[u8], keyboard: bool) {
    {
        let mut slot = CONSOLE.lock();
        let c = console(&mut slot);
        if keyboard {
            for &b in bytes {
                if let Some(ch) = c.decoder.feed(b) {
                    c.tty.push_input(&[ch]);
                }
            }
        } else {
            // A full flip buffer drops the rest, as a UART overrun.
            c.tty.push_input(bytes);
        }
        let Console {
            tty, out, signals, ..
        } = c;
        let received = tty.receive(&mut EchoOut(out));
        signals.extend(received.signals);
    }
    ECHO.wake_all();
    changed();
}

fn on_keyboard_byte(byte: u8) {
    console_input(&[byte], true);
}

fn on_serial_bytes(bytes: &[u8]) {
    console_input(bytes, false);
}

/// Prints the console's echo and sends the signals its input raised.
fn echo_thread() {
    loop {
        ECHO.wait_until(|| {
            CONSOLE
                .lock()
                .as_ref()
                .is_some_and(|c| !c.out.is_empty() || !c.signals.is_empty())
        });
        let (echo, signals) = CONSOLE
            .lock()
            .as_mut()
            .map(|c| (core::mem::take(&mut c.out), core::mem::take(&mut c.signals)))
            .unwrap_or_default();
        signal_foreground(&Ctty::Console, &signals);
        keel_hal::console::write_tty_bytes(&echo);
        if let Some(c) = CONSOLE.lock().as_mut() {
            // `uart_write_wakeup`: the writers' queue.
            c.tty.wakes.wake(EPOLLOUT);
        }
        changed();
    }
}

/// What [`init`] found.
pub struct InitReport {
    pub keyboard: Result<(), ps2::Ps2Error>,
    /// COM1 delivers its input to the console.
    pub serial: bool,
}

/// Sets up the console's input (the keyboard and COM1) and starts the
/// echo thread.
pub fn init() -> InitReport {
    let _ = console(&mut CONSOLE.lock());
    let keyboard = ps2::init(on_keyboard_byte);
    let serial = keel_hal::console::init_serial_input(on_serial_bytes);
    let echo = sched::spawn("console-echo", echo_thread);
    InitReport {
        keyboard: keyboard.and(echo.map(|_| ()).map_err(|_| ps2::Ps2Error::Interrupt)),
        serial,
    }
}

/// Types `bytes` (set-1 scancodes) through the controller, for tests.
pub fn type_scancodes(bytes: &[u8]) -> Result<(), ps2::Ps2Error> {
    for &b in bytes {
        ps2::inject(b)?;
    }
    Ok(())
}

/// Makes COM1 receive `bytes` (at most 14: below the FIFO's size), for
/// tests.
pub fn type_serial(bytes: &[u8]) -> bool {
    bytes.len() <= 14 && keel_hal::console::serial_loop_back(bytes)
}

// --- ptys -------------------------------------------------------------

/// Ptys at most (`kernel.pty.max` is 4096 on Linux; Keel's is smaller
/// until compartments have a pty quota).
pub const PTY_MAX: usize = 64;

/// A pty pair.
pub struct PtyLine {
    pub index: u32,
    pub pty: IrqMutex<Pty>,
    /// The slave's node in /dev/pts while the master is open.
    node: IrqMutex<Option<Ino>>,
    /// The slave's session and foreground group (ADR 0030).
    job: IrqMutex<Option<Job>>,
}

/// Index -> pair; an index is free again once its pair is gone
/// (`devpts_kill_index` when the last end closes).
static PTYS: IrqMutex<Vec<Weak<PtyLine>>> = IrqMutex::new(Vec::new());

/// Which terminal an open file is.
pub enum Line {
    Console,
    Pty(Arc<PtyLine>, End),
}

/// The terminal end an open file description holds. Dropping it closes
/// that end (`pty_close`).
pub struct TtyOpen {
    pub line: Line,
}

impl core::fmt::Debug for TtyOpen {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.line {
            Line::Console => write!(f, "TtyOpen(console)"),
            Line::Pty(line, end) => write!(f, "TtyOpen(pty {} {end:?})", line.index),
        }
    }
}

impl Drop for TtyOpen {
    fn drop(&mut self) {
        let Line::Pty(line, end) = &self.line else {
            return;
        };
        match end {
            End::Master => {
                // tty_vhangup of the slave (its session leader gets SIGHUP
                // and SIGCONT); devpts_pty_kill removes its node.
                line.pty.lock().master_closed = true;
                hang_up(&Ctty::Pty(Arc::downgrade(line)), false);
                let node = line.node.lock().take();
                if node.is_some() {
                    let name = line.index.to_string();
                    let _ = crate::fs::with(|fs| {
                        let dir =
                            fs.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, b"/dev/pts")?;
                        fs.unlink(dir, name.as_bytes())
                    });
                }
            }
            End::Slave => {
                let mut pty = line.pty.lock();
                pty.slave_opens -= 1;
                if pty.slave_opens == 0 {
                    // TTY_OTHER_CLOSED on the master.
                    pty.slave_closed = true;
                }
            }
        }
        changed();
    }
}

/// The terminal `device` opens with open(2) `flags`, or None if it is not
/// one. /dev/ptmx makes a new pair (ENOSPC past [`PTY_MAX`]); a slave
/// opens only while its master is open and it is unlocked (EIO, as
/// `pty_open`); /dev/tty is the caller's controlling terminal (ENXIO
/// without one, `tty_open_current_tty`). Opening a terminal can make it
/// the caller's controlling terminal (`tty_open_proc_set_tty`).
pub fn open(device: Device, flags: u64) -> Result<Option<Arc<TtyOpen>>, Errno> {
    let line = match device {
        Device::Console => Line::Console,
        Device::Ptmx => Line::Pty(new_pty()?, End::Master),
        Device::Pts(n) => Line::Pty(open_slave(n)?, End::Slave),
        Device::Tty => {
            let ctty = caller().and_then(|p| p.lock().ctty.clone());
            match ctty {
                Some(Ctty::Console) => Line::Console,
                Some(Ctty::Pty(w)) => {
                    let line = w.upgrade().ok_or(Errno::ENXIO)?;
                    Line::Pty(open_slave(line.index)?, End::Slave)
                }
                None => return Err(Errno::ENXIO),
            }
        }
        _ => return Ok(None),
    };
    let open = Arc::new(TtyOpen { line });
    take_on_open(&open, device, flags);
    Ok(Some(open))
}

fn new_pty() -> Result<Arc<PtyLine>, Errno> {
    let line = {
        let mut ptys = PTYS.lock();
        // devpts_new_index: the lowest free index.
        let index = match ptys.iter().position(|w| w.strong_count() == 0) {
            Some(i) => i,
            None if ptys.len() < PTY_MAX => {
                ptys.push(Weak::new());
                ptys.len() - 1
            }
            None => return Err(Errno::ENOSPC),
        };
        let line = Arc::new(PtyLine {
            index: index as u32,
            pty: IrqMutex::new(Pty::new()),
            node: IrqMutex::new(None),
            job: IrqMutex::new(None),
        });
        ptys[index] = Arc::downgrade(&line);
        line
    };
    // devpts_pty_new: a character device 136:N, mode 0600 (devpts's
    // default), named N.
    let name = line.index.to_string();
    let ino = crate::fs::with(|fs| {
        let dir = fs.lookup(keel_core::vfs::ROOT, keel_core::vfs::ROOT, b"/dev/pts")?;
        fs.create_device_mode(dir, name.as_bytes(), Device::Pts(line.index), 0o600)
    })?;
    *line.node.lock() = Some(ino);
    Ok(line)
}

fn open_slave(n: u32) -> Result<Arc<PtyLine>, Errno> {
    // pts_unix98_lookup: no pair is EIO.
    let line = PTYS
        .lock()
        .get(n as usize)
        .and_then(Weak::upgrade)
        .ok_or(Errno::EIO)?;
    {
        let mut pty = line.pty.lock();
        if pty.master_closed || pty.locked {
            // pty_open's failure path: TTY_IO_ERROR on the slave.
            pty.slave_io_error = true;
            return Err(Errno::EIO);
        }
        pty.slave_opens += 1;
        pty.slave_closed = false;
        pty.slave_io_error = false;
    }
    changed();
    Ok(line)
}

// --- job control (P3-T12 part 2; ADR 0030) -------------------------------
//
// `drivers/tty/tty_jobctrl.c`, `tty_io.c` (`tty_open`, `__tty_hangup`) and
// `n_tty.c`'s `job_control` at v6.12.

/// A controlling terminal: the console or a pty's slave (a master never
/// is one). A pty is held weakly: once both its ends are closed it is no
/// one's, as `session_clear_tty` makes it at the final close.
#[derive(Clone)]
pub enum Ctty {
    Console,
    Pty(Weak<PtyLine>),
}

impl Ctty {
    /// Whether it is still a terminal: a pty with both ends closed is
    /// no one's (`tty_release` clears the sessions at the final close).
    fn alive(&self) -> bool {
        match self {
            Ctty::Console => true,
            Ctty::Pty(w) => w.strong_count() > 0,
        }
    }

    fn same(&self, other: &Ctty) -> bool {
        match (self, other) {
            (Ctty::Console, Ctty::Console) => true,
            (Ctty::Pty(a), Ctty::Pty(b)) => Weak::ptr_eq(a, b),
            _ => false,
        }
    }
}

/// A terminal's session and foreground process group (`tty->ctrl`), by
/// number in a compartment.
#[derive(Clone)]
struct Job {
    compartment: Weak<Compartment>,
    sid: u32,
    pgrp: u32,
}

/// The console's session and foreground group.
static CONSOLE_JOB: IrqMutex<Option<Job>> = IrqMutex::new(None);

/// The console's session and foreground group, if it has a session, for
/// the kernel's tests (they wait for a shell to hand the console over).
pub fn console_job() -> Option<(u32, u32)> {
    CONSOLE_JOB.lock().as_ref().map(|j| (j.sid, j.pgrp))
}

/// Runs `f` on `tty`'s session record; None if the pty is gone.
fn with_job<R>(tty: &Ctty, f: impl FnOnce(&mut Option<Job>) -> R) -> Option<R> {
    match tty {
        Ctty::Console => Some(f(&mut CONSOLE_JOB.lock())),
        Ctty::Pty(w) => w.upgrade().map(|line| f(&mut line.job.lock())),
    }
}

/// `tty`'s session: its compartment, session and foreground group, if it
/// has one (and the compartment is still there).
fn job_of(tty: &Ctty) -> Option<(Arc<Compartment>, u32, u32)> {
    let job = with_job(tty, |j| j.clone()).flatten()?;
    Some((job.compartment.upgrade()?, job.sid, job.pgrp))
}

type ProcessRef = Arc<IrqMutex<crate::process::Process>>;

/// The calling process.
fn caller() -> Option<ProcessRef> {
    crate::process::current()
}

/// Whether `p`'s controlling terminal is `tty`.
fn controls(p: &ProcessRef, tty: &Ctty) -> bool {
    p.lock().ctty.as_ref().is_some_and(|c| c.same(tty))
}

impl TtyOpen {
    /// This file's terminal as a controlling terminal (none for a master).
    fn as_ctty(&self) -> Option<Ctty> {
        match &self.line {
            Line::Console => Some(Ctty::Console),
            Line::Pty(line, End::Slave) => Some(Ctty::Pty(Arc::downgrade(line))),
            Line::Pty(_, End::Master) => None,
        }
    }

    /// The terminal a request acts on (`tty_pair_get_tty`: a master's
    /// slave).
    fn real_ctty(&self) -> Ctty {
        match &self.line {
            Line::Console => Ctty::Console,
            Line::Pty(line, _) => Ctty::Pty(Arc::downgrade(line)),
        }
    }
}

/// `__tty_check_change`: a process in the background of its controlling
/// terminal `tty` asking for `signal`'s permission (SIGTTIN to read,
/// SIGTTOU to write with TOSTOP or change the settings). With the signal
/// blocked or ignored: EIO for SIGTTIN, allowed for SIGTTOU. In an
/// orphaned group: EIO. Otherwise the signal goes to its whole group and
/// call is ERESTARTSYS: restarted once the process is continued, or EINTR
/// after a handler without SA_RESTART (ADR 0031).
fn check_change(tty: &Ctty, signal: i32) -> Result<(), Errno> {
    let Some(me) = caller() else {
        return Ok(());
    };
    let (mine, pgid, compartment, ignored) = {
        let q = me.lock();
        let blocked = q
            .threads
            .get(&sched::current().0)
            .is_some_and(|t| t.signals.blocked() & keel_core::signal::sigmask(signal) != 0);
        let ignored = q
            .signals
            .action(signal)
            .is_some_and(|a| a.handler == keel_core::signal::SIG_IGN);
        (
            q.ctty.as_ref().is_some_and(|c| c.same(tty)),
            q.pgid,
            q.member.compartment().clone(),
            blocked || ignored,
        )
    };
    if !mine {
        return Ok(());
    }
    match job_of(tty) {
        Some((_, _, fg)) if fg != pgid => {
            if ignored {
                return if signal == keel_core::signal::SIGTTIN {
                    Err(Errno::EIO)
                } else {
                    Ok(())
                };
            }
            if crate::jobs::orphaned(&compartment, pgid) {
                return Err(Errno::EIO);
            }
            crate::jobs::signal_group(&compartment, pgid, signal);
            Err(Errno::ERESTARTSYS)
        }
        _ => Ok(()),
    }
}

/// Signals for `tty`'s foreground process group (ISIG's, TIOCSIG's,
/// SIGWINCH): `kill_pgrp(tty_pgrp, sig, 1)`, so `si_code` SI_KERNEL.
fn signal_foreground(tty: &Ctty, signals: &[u8]) {
    if signals.is_empty() {
        return;
    }
    if let Some((compartment, _, fg)) = job_of(tty) {
        for &s in signals {
            crate::jobs::signal_group(&compartment, fg, i32::from(s));
        }
    }
}

/// Clears the controlling terminal of every process of session `sid`
/// (`session_clear_tty`).
fn clear_session(compartment: &Arc<Compartment>, sid: u32) {
    for m in crate::jobs::session_members(compartment, sid) {
        m.lock().ctty = None;
    }
}

/// `__tty_hangup`'s session part (`tty_signal_session_leader`): the
/// session's processes lose `tty` as their controlling terminal, its
/// leader gets SIGHUP and SIGCONT and keeps the foreground group
/// (`tty_old_pgrp`), and with `exit_session` (the leader exiting) the
/// foreground group gets SIGHUP. The terminal then has no session.
fn hang_up(tty: &Ctty, exit_session: bool) {
    let Some((compartment, sid, fg)) = job_of(tty) else {
        with_job(tty, |j| *j = None);
        return;
    };
    for m in crate::jobs::session_members(&compartment, sid) {
        let leader = {
            let mut q = m.lock();
            if q.ctty.as_ref().is_some_and(|c| c.same(tty)) {
                q.ctty = None;
            }
            if q.leader {
                q.old_pgrp = Some(fg);
            }
            q.leader
        };
        if leader {
            crate::signal::send_to_process(&m, SigInfo::kernel(SIGHUP));
            crate::signal::send_to_process(&m, SigInfo::kernel(SIGCONT));
        }
    }
    if exit_session {
        crate::jobs::signal_group(&compartment, fg, SIGHUP);
    }
    with_job(tty, |j| *j = None);
}

/// A process's exit (`disassociate_ctty(1)`, when its last thread goes):
/// a session leader's controlling terminal is hung up (the console:
/// `tty_vhangup_session`, its foreground group SIGHUP and its input
/// discarded; a pty: its foreground group SIGHUP), the terminal leaves
/// the session, and the session's processes lose it. A leader whose
/// terminal was hung up earlier sends its old foreground group SIGHUP and
/// SIGCONT.
pub fn on_exit(p: &ProcessRef) {
    let (leader, ctty, compartment, sid, old) = {
        let mut q = p.lock();
        (
            q.leader,
            q.ctty.take(),
            q.member.compartment().clone(),
            q.sid,
            q.old_pgrp.take(),
        )
    };
    if !leader {
        return;
    }
    let tty = ctty.filter(Ctty::alive);
    let Some(tty) = tty else {
        if let Some(old) = old {
            crate::jobs::signal_group(&compartment, old, SIGHUP);
            crate::jobs::signal_group(&compartment, old, SIGCONT);
        }
        return;
    };
    match tty {
        Ctty::Console => {
            hang_up(&tty, true);
            if let Some(c) = CONSOLE.lock().as_mut() {
                c.tty.flush_flip();
                c.tty.flush_input();
            }
        }
        Ctty::Pty(_) => {
            if let Some((c, _, fg)) = job_of(&tty) {
                crate::jobs::signal_group(&c, fg, SIGHUP);
            }
            with_job(&tty, |j| *j = None);
        }
    }
    clear_session(&compartment, sid);
    changed();
}

/// `tty_open_proc_set_tty`: a session leader with no controlling terminal
/// that opens one without O_NOCTTY, for reading, gets it if the terminal
/// has no session. /dev/console and a pty master never become one by
/// being opened.
fn take_on_open(open: &TtyOpen, device: Device, flags: u64) {
    use crate::abi::{O_ACCMODE, O_NOCTTY, O_WRONLY};
    if flags & O_NOCTTY != 0 || matches!(device, Device::Console | Device::Ptmx) {
        return;
    }
    let (Some(me), Some(tty)) = (caller(), open.as_ctty()) else {
        return;
    };
    let (leader, has) = {
        let q = me.lock();
        (q.leader, q.ctty.as_ref().is_some_and(Ctty::alive))
    };
    if leader && !has && flags & O_ACCMODE != O_WRONLY && job_of(&tty).is_none() {
        set_ctty(&me, tty);
    }
}

/// `__proc_set_tty`: `tty` becomes `p`'s controlling terminal, with `p`'s
/// session and group as its session and foreground group.
fn set_ctty(p: &ProcessRef, tty: Ctty) {
    let (compartment, sid, pgid) = {
        let q = p.lock();
        (q.member.compartment().clone(), q.sid, q.pgid)
    };
    with_job(&tty, |j| {
        *j = Some(Job {
            compartment: Arc::downgrade(&compartment),
            sid,
            pgrp: pgid,
        })
    });
    let mut q = p.lock();
    q.ctty = Some(tty);
    q.old_pgrp = None;
}

/// TIOCSCTTY (`tiocsctty`): the terminal (a master's slave) becomes the
/// caller's controlling terminal. Nothing to do if it already is its
/// session's; EPERM unless the caller leads its session and has none; a
/// terminal of another session is taken from it only with `arg` 1 (root,
/// as every Keel process is) and within the caller's compartment, else
/// EPERM.
fn tiocsctty(open: &TtyOpen, arg: u64) -> SysResult {
    let me = caller().ok_or(Errno::ESRCH)?;
    let tty = open.real_ctty();
    let (leader, sid, has, compartment) = {
        let q = me.lock();
        (
            q.leader,
            q.sid,
            q.ctty.as_ref().is_some_and(Ctty::alive),
            q.member.compartment().clone(),
        )
    };
    let job = job_of(&tty);
    let same = |c: &Arc<Compartment>| Arc::ptr_eq(c, &compartment);
    if leader && job.as_ref().is_some_and(|(c, s, _)| same(c) && *s == sid) {
        return Ok(0);
    }
    if !leader || has {
        return Err(Errno::EPERM);
    }
    if let Some((c, s, _)) = &job {
        if arg == 1 && same(c) {
            clear_session(c, *s);
        } else {
            return Err(Errno::EPERM);
        }
    }
    set_ctty(&me, tty);
    Ok(0)
}

/// TIOCNOTTY: the caller gives up its controlling terminal (ENOTTY if
/// this is not it). A session leader's foreground group gets SIGHUP and
/// SIGCONT, the terminal leaves the session and every process of the
/// session loses it (`disassociate_ctty(0)`).
fn tiocnotty(open: &TtyOpen) -> SysResult {
    let me = caller().ok_or(Errno::ESRCH)?;
    let Some(tty) = open.as_ctty().filter(|t| controls(&me, t)) else {
        return Err(Errno::ENOTTY);
    };
    let (leader, compartment, sid, pid) = {
        let q = me.lock();
        (q.leader, q.member.compartment().clone(), q.sid, q.pid())
    };
    if leader {
        if let Some((c, _, fg)) = job_of(&tty) {
            // kill_pgrp(..., 0): SEND_SIG_NOINFO, from the caller.
            let info = |s| SigInfo::from_process(s, keel_core::signal::SI_USER, pid, 0);
            let _ = crate::jobs::kill_group(&c, fg, info(SIGHUP));
            let _ = crate::jobs::kill_group(&c, fg, info(SIGCONT));
        }
        with_job(&tty, |j| *j = None);
        me.lock().old_pgrp = None;
        clear_session(&compartment, sid);
    }
    me.lock().ctty = None;
    Ok(0)
}

/// TIOCGPGRP and TIOCGSID (`tiocgpgrp`, `tiocgsid`): ENOTTY unless this
/// is the caller's controlling terminal or a master; a group or session
/// of another compartment reads as 0 (`pid_vnr`). TIOCGSID with no
/// session is ENOTTY.
fn tiocgpgrp(open: &TtyOpen, arg: u64, session: bool) -> SysResult {
    let me = caller().ok_or(Errno::ESRCH)?;
    if !open.is_master() && !open.as_ctty().is_some_and(|t| controls(&me, &t)) {
        return Err(Errno::ENOTTY);
    }
    let compartment = me.lock().member.compartment().clone();
    let job = job_of(&open.real_ctty());
    let visible = |c: &Arc<Compartment>, n: u32| if Arc::ptr_eq(c, &compartment) { n } else { 0 };
    let n = match (job, session) {
        (Some((c, sid, _)), true) => visible(&c, sid),
        (None, true) => return Err(Errno::ENOTTY),
        (Some((c, _, fg)), false) => visible(&c, fg),
        (None, false) => 0,
    };
    put_int(arg, n as i32)
}

/// TIOCSPGRP (`tiocspgrp`): the caller, in its terminal's session, makes
/// `*arg` the foreground group. The background check first (its EIO is
/// ENOTTY); EFAULT; a negative group EINVAL; not the caller's terminal,
/// or not its session, ENOTTY; a number that names nothing ESRCH; a group
/// of another session EPERM.
fn tiocspgrp(open: &TtyOpen, arg: u64) -> SysResult {
    let tty = open.real_ctty();
    match check_change(&tty, keel_core::signal::SIGTTOU) {
        Err(Errno::EIO) => return Err(Errno::ENOTTY),
        Err(e) => return Err(e),
        Ok(()) => {}
    }
    let pgrp = get_int(arg)?;
    if pgrp < 0 {
        return Err(Errno::EINVAL);
    }
    let pgrp = pgrp as u32;
    let me = caller().ok_or(Errno::ESRCH)?;
    let (sid, compartment) = {
        let q = me.lock();
        (q.sid, q.member.compartment().clone())
    };
    let ours = job_of(&tty).is_some_and(|(c, s, _)| Arc::ptr_eq(&c, &compartment) && s == sid);
    if !controls(&me, &tty) || !ours {
        return Err(Errno::ENOTTY);
    }
    // find_vpid, then session_of_pgrp: a member of the group, else the
    // process (or thread) with that PID.
    // A zombie counts: it stays in its group until reaped.
    let mut in_group = crate::process::members(&compartment, |q| q.pgid == pgrp);
    if in_group.is_empty() {
        in_group = crate::process::zombies(&compartment, |q| q.pgid == pgrp);
    }
    let session_of = if let Some(m) = in_group.first() {
        Some(m.lock().sid)
    } else if let Some(p) = crate::process::find_in(&compartment, pgrp) {
        Some(p.lock().sid)
    } else if let Some((p, _)) = crate::process::find_thread(&compartment, pgrp) {
        Some(p.lock().sid)
    } else if !crate::process::members(&compartment, |q| q.sid == pgrp).is_empty() {
        None
    } else {
        return Err(Errno::ESRCH);
    };
    if session_of != Some(sid) {
        return Err(Errno::EPERM);
    }
    with_job(&tty, |j| {
        if let Some(j) = j {
            j.pgrp = pgrp;
        }
    });
    Ok(0)
}

// --- operations ---------------------------------------------------------

const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;
const EPOLLRDNORM: u32 = 0x040;
const EPOLLWRNORM: u32 = 0x100;

/// What the other end's state says.
#[derive(Clone, Copy, Default)]
struct Other {
    /// TTY_OTHER_CLOSED: reads with nothing to read are EIO, poll HUP.
    closed: bool,
    /// This file is hung up (a slave whose master closed).
    hung_up: bool,
    /// Unsent output of its own (the console's queue).
    chars: usize,
}

impl TtyOpen {
    /// Runs `f` on this end's terminal (or, with `real`, the slave of a
    /// master: `tty_pair_get_tty`), with its output, then moves input on.
    fn run<R>(&self, real: bool, f: impl FnOnce(&mut Tty, &mut dyn Sink, Other) -> R) -> R {
        let r = match &self.line {
            Line::Console => {
                let mut slot = CONSOLE.lock();
                let Console {
                    tty, out, signals, ..
                } = console(&mut slot);
                let other = Other {
                    chars: out.len(),
                    ..Other::default()
                };
                let r = f(tty, &mut EchoOut(out), other);
                signals.extend(tty.receive(&mut EchoOut(out)).signals);
                r
            }
            Line::Pty(line, end) => {
                let mut pty = line.pty.lock();
                let end = if real { End::Slave } else { *end };
                let other = Other {
                    closed: match end {
                        End::Master => pty.slave_closed,
                        End::Slave => pty.master_closed,
                    },
                    hung_up: end == End::Slave && pty.master_closed,
                    chars: 0,
                };
                let (r, signals) = pty.with_output(end, |tty, out| f(tty, out, other));
                drop(pty);
                // ISIG: the slave's input raised them, for its foreground
                // process group.
                signal_foreground(&Ctty::Pty(Arc::downgrade(line)), &signals);
                r
            }
        };
        if matches!(self.line, Line::Console) {
            ECHO.wake_all();
        }
        changed();
        r
    }

    /// As [`TtyOpen::run`] but changing nothing else and waking no one:
    /// for wait conditions, which run under the ready queue's lock.
    fn look<R>(&self, f: impl FnOnce(&mut Tty, &mut dyn Sink, Other) -> R) -> R {
        match &self.line {
            Line::Console => {
                let mut slot = CONSOLE.lock();
                let Console { tty, out, .. } = console(&mut slot);
                let other = Other {
                    chars: out.len(),
                    ..Other::default()
                };
                f(tty, &mut EchoOut(out), other)
            }
            Line::Pty(line, end) => {
                let mut pty = line.pty.lock();
                let other = Other {
                    closed: match end {
                        End::Master => pty.slave_closed,
                        End::Slave => pty.master_closed,
                    },
                    hung_up: *end == End::Slave && pty.master_closed,
                    chars: 0,
                };
                pty.look(*end, |tty, out| f(tty, out, other))
            }
        }
    }

    /// Whether this file is hung up (`hung_up_tty_fops`).
    fn hung_up(&self) -> bool {
        match &self.line {
            Line::Console => false,
            Line::Pty(line, end) => *end == End::Slave && line.pty.lock().master_closed,
        }
    }

    /// TTY_IO_ERROR (`tty_io_error`): reads and writes are EIO.
    fn io_error(&self) -> bool {
        match &self.line {
            Line::Pty(line, End::Slave) => line.pty.lock().slave_io_error,
            _ => false,
        }
    }

    fn is_master(&self) -> bool {
        matches!(self.line, Line::Pty(_, End::Master))
    }

    /// After a read: the other end's writers may go on (`n_tty_check_unthrottle`
    /// for a pty: `tty_wakeup` of the other end).
    fn read_done(&self) {
        if let Line::Pty(line, end) = &self.line {
            let mut pty = line.pty.lock();
            let (_, peer) = pty.ends(*end);
            peer.wakes.wake(EPOLLOUT);
        }
    }

    /// The wakes epoll watches (its read and write queues).
    pub fn wakes(&self) -> Wakes {
        match &self.line {
            Line::Console => CONSOLE
                .lock()
                .as_ref()
                .map_or(Wakes::new(), |c| c.tty.wakes),
            Line::Pty(line, end) => line.pty.lock().end(*end).wakes,
        }
    }

    /// The device number TIOCGDEV reports (`tty_devnum`).
    fn device(&self) -> (u32, u32) {
        match &self.line {
            Line::Console => Device::Console.number(),
            Line::Pty(line, _) => Device::Pts(line.index).number(),
        }
    }
}

/// read(2) of a terminal (`tty_read`, `n_tty_read`), into `segs`:
/// - a hung-up file reads 0; after a failed open of a pty's slave, its
///   descriptions read EIO until an open succeeds (TTY_IO_ERROR);
/// - canonical mode: a line (or what fits), 0 at an end of file;
/// - otherwise VMIN and VTIME (tenths of a second) decide: MIN 0 TIME 0
///   returns what there is; MIN 0 TIME t waits up to t for a byte; MIN m
///   TIME 0 waits for m; MIN m TIME t waits for the first byte, then up to
///   t between bytes, for m;
/// - with nothing to read: EIO once the other end of a pty has closed;
///   EAGAIN with O_NONBLOCK; else it waits (a signal: EINTR, or what was
///   read).
pub fn read(open: &TtyOpen, nonblock: bool, segs: &[(u64, u64)]) -> SysResult {
    if open.hung_up() {
        return Ok(0);
    }
    if open.io_error() {
        return Err(Errno::EIO);
    }
    // job_control: a background reader of its controlling terminal.
    if let Some(tty) = open.as_ctty() {
        check_change(&tty, keel_core::signal::SIGTTIN)?;
    }
    let count = total(segs) as usize;
    if count == 0 {
        return Ok(0);
    }
    let mut kbuf = alloc::vec![0u8; count.min(2 * N_TTY_BUF_SIZE)];
    let (minimum, time, mut deadline) = open.run(false, |tty, _, _| {
        if tty.canonical() {
            return (0usize, 0u64, None);
        }
        let (min, time) = (
            tty.termios.cc[core_tty::VMIN],
            tty.termios.cc[core_tty::VTIME],
        );
        // (HZ / 10) * TIME_CHAR: tenths of a second.
        let time = u64::from(time) * 100_000_000;
        if min > 0 {
            (usize::from(min), time, None)
        } else {
            (1, 0, Some(keel_hal::time::monotonic_nanos() + time))
        }
    });
    enum Step {
        Data(usize, bool),
        Eio,
        Hup,
        Empty,
    }
    let mut done = 0usize;
    let mut error = None;
    while done < kbuf.len() {
        let step = open.run(false, |tty, _, other| {
            if !tty.input_available(false) {
                return if other.closed && !other.hung_up {
                    Step::Eio
                } else if other.hung_up {
                    Step::Hup
                } else {
                    Step::Empty
                };
            }
            let canonical = tty.canonical();
            let n = if canonical {
                tty.read_canon(&mut kbuf[done..])
            } else {
                tty.read_raw(&mut kbuf[done..])
            };
            Step::Data(n, canonical)
        });
        match step {
            Step::Data(n, canonical) => {
                open.read_done();
                done += n;
                if canonical || done >= minimum {
                    break;
                }
                if time != 0 {
                    deadline = Some(keel_hal::time::monotonic_nanos() + time);
                }
            }
            Step::Eio => {
                error = Some(Errno::EIO);
                break;
            }
            Step::Hup => break,
            Step::Empty => {
                if deadline.is_some_and(|d| keel_hal::time::monotonic_nanos() >= d) {
                    break;
                }
                if nonblock {
                    error = Some(Errno::EAGAIN);
                    break;
                }
                let ready =
                    || open.look(|tty, _, other| tty.input_available(false) || other.closed);
                if wait(ready, deadline) == Waited::Interrupted {
                    // n_tty_read: ERESTARTSYS.
                    error = Some(Errno::ERESTARTSYS);
                    break;
                }
            }
        }
    }
    if done == 0 {
        return error.map_or(Ok(0), Err);
    }
    // iterate_tty_read: what was taken is gone even if the copy faults.
    match copy_out(segs, &kbuf[..done]) {
        0 => Err(Errno::EFAULT),
        n => Ok(n as u64),
    }
}

/// tty_write's chunk (`iterate_tty_write`).
const WRITE_CHUNK: usize = 2048;

/// write(2) to a terminal (`tty_write`, `n_tty_write`) from `segs`:
/// pending echo first, then the bytes, with output processing (OPOST).
/// A hung-up file is EIO. Without room (a pty's other end not reading,
/// output stopped by STOP): EAGAIN with O_NONBLOCK, else it waits. A
/// pending signal ends it before anything is written (EINTR), or between
/// chunks (the count so far).
pub fn write(open: &TtyOpen, nonblock: bool, segs: &[(u64, u64)]) -> SysResult {
    if open.hung_up() || open.io_error() {
        return Err(Errno::EIO);
    }
    // n_tty_write: with TOSTOP, a background writer is checked.
    if let Some(tty) = open.as_ctty() {
        let tostop = open.look(|t, _, _| t.termios.lflag & core_tty::TOSTOP != 0);
        if tostop {
            check_change(&tty, keel_core::signal::SIGTTOU)?;
        }
    }
    let count = total(segs) as usize;
    let mut written = 0usize;
    let mut chunk = alloc::vec![0u8; count.min(WRITE_CHUNK)];
    while written < count {
        let size = (count - written).min(WRITE_CHUNK);
        if !copy_in(segs, written as u64, &mut chunk[..size]) {
            return if written > 0 {
                Ok(written as u64)
            } else {
                Err(Errno::EFAULT)
            };
        }
        match write_chunk(open, nonblock, &chunk[..size]) {
            Ok(n) => {
                written += n;
                if n < size {
                    break;
                }
            }
            Err(e) if written == 0 => return Err(e),
            Err(_) => break,
        }
        if written < count && sched::interrupted() {
            break;
        }
    }
    Ok(written as u64)
}

/// `n_tty_write` for one chunk: the bytes taken, or the error if none.
fn write_chunk(open: &TtyOpen, nonblock: bool, data: &[u8]) -> Result<usize, Errno> {
    let mut done = 0usize;
    loop {
        if sched::interrupted() {
            return if done > 0 {
                Ok(done)
            } else {
                Err(Errno::ERESTARTSYS)
            };
        }
        if open.hung_up() {
            return if done > 0 { Ok(done) } else { Err(Errno::EIO) };
        }
        let rest = &data[done..];
        let n = match &open.line {
            Line::Console => {
                // Printed here, by the writer: echo waiting in the queue
                // goes first, so the order on the screen is kept.
                let mut out = Collect::new(1 << 20);
                let n = {
                    let mut slot = CONSOLE.lock();
                    let c = console(&mut slot);
                    let pending = core::mem::take(&mut c.out);
                    out.put(&pending);
                    c.tty.write(rest, &mut out)
                };
                keel_hal::console::write_tty_bytes(&out.bytes);
                changed();
                n
            }
            Line::Pty(..) => open.run(false, |tty, out, _| tty.write(rest, out)),
        };
        done += n;
        if done == data.len() {
            return Ok(done);
        }
        if nonblock {
            return if done > 0 {
                Ok(done)
            } else {
                Err(Errno::EAGAIN)
            };
        }
        let ready =
            || open.hung_up() || open.look(|tty, out, other| tty.writable(other.chars, out));
        if wait(ready, None) == Waited::Interrupted {
            return if done > 0 {
                Ok(done)
            } else {
                Err(Errno::ERESTARTSYS)
            };
        }
    }
}

/// poll's mask (`n_tty_poll`): EPOLLIN with input (VMIN of it with VTIME
/// 0, in non-canonical mode); EPOLLHUP once a pty's other end closed;
/// EPOLLOUT with room. A hung-up file is everything (`hung_up_tty_poll`).
/// It only looks: poll, select and epoll call it inside their wait
/// conditions, under the ready queue's lock.
pub fn poll(open: &TtyOpen) -> u32 {
    if open.hung_up() {
        return EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLRDNORM | EPOLLWRNORM;
    }
    open.look(|tty, out, other| {
        let mut mask = 0;
        if tty.input_available(true) {
            mask |= EPOLLIN | EPOLLRDNORM;
        }
        if other.closed {
            mask |= EPOLLHUP;
        }
        if tty.writable(other.chars, out) {
            mask |= EPOLLOUT | EPOLLWRNORM;
        }
        mask
    })
}

// --- ioctl ----------------------------------------------------------------

const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TCSETSW: u32 = 0x5403;
const TCSETSF: u32 = 0x5404;
const TCGETA: u32 = 0x5405;
const TCSETA: u32 = 0x5406;
const TCSETAW: u32 = 0x5407;
const TCSETAF: u32 = 0x5408;
const TCSBRK: u32 = 0x5409;
const TCXONC: u32 = 0x540A;
const TCFLSH: u32 = 0x540B;
const TIOCEXCL: u32 = 0x540C;
const TIOCNXCL: u32 = 0x540D;
const TIOCOUTQ: u32 = 0x5411;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCSWINSZ: u32 = 0x5414;
const TIOCGSOFTCAR: u32 = 0x5419;
const TIOCSSOFTCAR: u32 = 0x541A;
const TIOCINQ: u32 = 0x541B;
const TIOCPKT: u32 = 0x5420;
const TIOCSETD: u32 = 0x5423;
const TIOCGETD: u32 = 0x5424;
const TCSBRKP: u32 = 0x5425;
/// _IOR('T', 0x2A, struct termios2) and its _IOW setters.
const TCGETS2: u32 = 0x802C_542A;
const TCSETS2: u32 = 0x402C_542B;
const TCSETSW2: u32 = 0x402C_542C;
const TCSETSF2: u32 = 0x402C_542D;
const TIOCGPTN: u32 = 0x8004_5430;
const TIOCSPTLCK: u32 = 0x4004_5431;
const TIOCGDEV: u32 = 0x8004_5432;
const TIOCSIG: u32 = 0x4004_5436;
const TIOCGPKT: u32 = 0x8004_5438;
const TIOCGPTLCK: u32 = 0x8004_5439;
const TIOCGEXCL: u32 = 0x8004_5440;
const TIOCGPTPEER: u32 = 0x5441;
const TIOCGLCKTRMIOS: u32 = 0x5456;
const TIOCSLCKTRMIOS: u32 = 0x5457;
const TIOCSCTTY: u32 = 0x540E;
const TIOCGPGRP: u32 = 0x540F;
const TIOCSPGRP: u32 = 0x5410;
const TIOCNOTTY: u32 = 0x5422;
const TIOCGSID: u32 = 0x5429;
/// NR_LDISCS: line discipline numbers are 0 to 29.
const NR_LDISCS: i32 = 30;

fn fault<T>(_: T) -> Errno {
    Errno::EFAULT
}

fn put_int(at: u64, v: i32) -> SysResult {
    copy_to_user(at, &v.to_le_bytes()).map_err(fault)?;
    Ok(0)
}

fn get_int(at: u64) -> Result<i32, Errno> {
    let mut b = [0u8; 4];
    copy_from_user(&mut b, at).map_err(fault)?;
    Ok(i32::from_le_bytes(b))
}

/// How a TCSETS-family call changes the settings.
#[derive(Clone, Copy, PartialEq)]
enum SetHow {
    Now,
    /// TCSETSW: after output drains (`TERMIOS_WAIT`).
    Wait,
    /// TCSETSF: after output drains, and pending input discarded.
    Flush,
}

/// The ioctls of a terminal (`tty_ioctl`, `tty_mode_ioctl`,
/// `n_tty_ioctl_helper`, `n_tty_ioctl`, `pty_unix98_ioctl` at v6.12). A
/// master's termios and window-size requests act on its slave. Requests
/// that change the terminal are first checked for a background caller
/// (`tty_check_change`: SIGTTOU). ENOTTY for requests Keel does not have
/// (packet mode, TIOCSTI, TIOCCONS, TIOCVHANGUP and the modem lines: ADR
/// 0029).
pub fn ioctl(open: &TtyOpen, request: u32, arg: u64) -> SysResult {
    let ttou = keel_core::signal::SIGTTOU;
    if open.hung_up() {
        // hung_up_tty_ioctl.
        return Err(if request == TIOCSPGRP {
            Errno::ENOTTY
        } else {
            Errno::EIO
        });
    }
    match request {
        TCGETS => {
            copy_to_user(arg, &open.run(true, |t, _, _| t.termios.to_bytes())).map_err(fault)?
        }
        TCGETS2 => {
            copy_to_user(arg, &open.run(true, |t, _, _| t.termios.to_bytes2())).map_err(fault)?
        }
        TCGETA => {
            copy_to_user(arg, &open.run(true, |t, _, _| t.termios.to_termio())).map_err(fault)?
        }
        TCSETS | TCSETSW | TCSETSF | TCSETS2 | TCSETSW2 | TCSETSF2 | TCSETA | TCSETAW | TCSETAF => {
            let how = match request {
                TCSETS | TCSETS2 | TCSETA => SetHow::Now,
                TCSETSW | TCSETSW2 | TCSETAW => SetHow::Wait,
                _ => SetHow::Flush,
            };
            let size = match request {
                TCSETS | TCSETSW | TCSETSF => core_tty::TERMIOS_SIZE,
                TCSETA | TCSETAW | TCSETAF => core_tty::TERMIO_SIZE,
                _ => core_tty::TERMIOS2_SIZE,
            };
            check_change(&open.real_ctty(), ttou)?;
            let mut user = [0u8; core_tty::TERMIOS2_SIZE];
            copy_from_user(&mut user[..size], arg).map_err(fault)?;
            set_termios(open, &user[..size], size == core_tty::TERMIO_SIZE, how)?;
        }
        TIOCGWINSZ => {
            copy_to_user(arg, &open.run(true, |t, _, _| t.winsize.to_bytes())).map_err(fault)?
        }
        TIOCSWINSZ => {
            let mut b = [0u8; 8];
            copy_from_user(&mut b, arg).map_err(fault)?;
            // tty_do_resize: SIGWINCH to the foreground process group if
            // it changed.
            let new = Winsize::from_bytes(&b);
            let changed = open.run(true, |t, _, _| {
                core::mem::replace(&mut t.winsize, new) != new
            });
            if changed {
                signal_foreground(&open.real_ctty(), &[keel_core::signal::SIGWINCH as u8]);
            }
        }
        TCFLSH => {
            let which = u64::from(arg as u32);
            // tty_ioctl empties the flip buffer before the check.
            if which == TCIFLUSH || which == TCIOFLUSH {
                open.run(false, |t, _, _| t.flush_flip());
            }
            if let Some(tty) = open.as_ctty() {
                check_change(&tty, ttou)?;
            }
            match which {
                TCIFLUSH => open.run(false, |t, _, _| t.flush_input()),
                TCIOFLUSH => open.run(false, |t, out, _| {
                    t.flush_input();
                    out.flush();
                }),
                TCOFLUSH => open.run(false, |_, out, _| out.flush()),
                _ => return Err(Errno::EINVAL),
            }
        }
        TCXONC => {
            if let Some(tty) = open.as_ctty() {
                check_change(&tty, ttou)?;
            }
            open.run(false, |t, out, _| t.tcxonc(u64::from(arg as u32), out))?;
        }
        TIOCINQ => {
            let n = open.run(false, |t, _, _| t.inq());
            return put_int(arg, n as i32);
        }
        TIOCOUTQ => {
            let n = open.run(false, |_, _, other| other.chars);
            return put_int(arg, n as i32);
        }
        TCSBRK | TCSBRKP => {
            // The check, tty_wait_until_sent, then a break the console's
            // and a pty's drivers do not send (no break_ctl: send_break
            // returns 0).
            if let Some(tty) = open.as_ctty() {
                check_change(&tty, ttou)?;
            }
            wait_until_sent(open, Errno::EINTR)?;
        }
        TIOCEXCL | TIOCNXCL => open.run(false, |t, _, _| t.exclusive = request == TIOCEXCL),
        TIOCGEXCL => return put_int(arg, i32::from(open.run(false, |t, _, _| t.exclusive))),
        TIOCGETD => return put_int(arg, 0),
        TIOCSETD => {
            // The check and the wait come first (tty_ioctl); then
            // tty_set_ldisc, where only N_TTY (0) is here.
            if let Some(tty) = open.as_ctty() {
                check_change(&tty, ttou)?;
            }
            wait_until_sent(open, Errno::EINTR)?;
            let disc = get_int(arg)?;
            if !(0..NR_LDISCS).contains(&disc) || disc != 0 {
                return Err(Errno::EINVAL);
            }
        }
        TIOCGDEV => {
            let (major, minor) = open.device();
            let n = crate::abi::encode_dev(major, minor) as u32;
            copy_to_user(arg, &n.to_le_bytes()).map_err(fault)?;
        }
        TIOCGSOFTCAR => {
            let clocal = open.run(true, |t, _, _| t.termios.cflag & core_tty::CLOCAL != 0);
            return put_int(arg, i32::from(clocal));
        }
        TIOCSSOFTCAR => {
            let on = get_int(arg)? != 0;
            open.run(true, |t, _, _| t.set_softcar(on));
        }
        TIOCGLCKTRMIOS => {
            copy_to_user(arg, &open.run(true, |t, _, _| t.locked.to_bytes())).map_err(fault)?
        }
        TIOCSLCKTRMIOS => {
            // CAP_CHECKPOINT_RESTORE, which every Keel process has.
            let mut b = [0u8; core_tty::TERMIOS_SIZE];
            copy_from_user(&mut b, arg).map_err(fault)?;
            open.run(true, |t, _, _| t.locked = t.locked.with_bytes(&b));
        }
        TIOCGPTPEER => {
            return Err(Errno::EIO);
        }
        TIOCSCTTY => return tiocsctty(open, arg),
        TIOCNOTTY => return tiocnotty(open),
        TIOCGPGRP => return tiocgpgrp(open, arg, false),
        TIOCGSID => return tiocgpgrp(open, arg, true),
        TIOCSPGRP => return tiocspgrp(open, arg),
        TIOCSPTLCK | TIOCGPTLCK | TIOCGPTN | TIOCSIG | TIOCPKT | TIOCGPKT if open.is_master() => {
            return master_ioctl(open, request, arg);
        }
        _ => return Err(Errno::ENOTTY),
    }
    Ok(0)
}

/// `pty_unix98_ioctl`: the master's own requests.
fn master_ioctl(open: &TtyOpen, request: u32, arg: u64) -> SysResult {
    let Line::Pty(line, _) = &open.line else {
        return Err(Errno::ENOTTY);
    };
    match request {
        TIOCSPTLCK => {
            let locked = get_int(arg)? != 0;
            line.pty.lock().locked = locked;
            Ok(0)
        }
        TIOCGPTLCK => put_int(arg, i32::from(line.pty.lock().locked)),
        TIOCGPTN => put_int(arg, line.index as i32),
        TIOCSIG => {
            // pty_signal: SIGINT, SIGQUIT or SIGTSTP to the slave's
            // foreground process group.
            let sig = arg as i32;
            if ![2, 3, 20].contains(&sig) {
                return Err(Errno::EINVAL);
            }
            signal_foreground(&open.real_ctty(), &[sig as u8]);
            Ok(0)
        }
        // Packet mode is not supported: turning it off is all that works.
        TIOCPKT => {
            if get_int(arg)? != 0 {
                return Err(Errno::ENOTTY);
            }
            Ok(0)
        }
        TIOCGPKT => put_int(arg, 0),
        _ => Err(Errno::ENOTTY),
    }
}

/// `tty_wait_until_sent`: until the terminal's own output has gone (a
/// pty has none). A signal ends it with `interrupted`: EINTR for
/// tty_ioctl's TCSBRK, TCSBRKP and TIOCSETD, ERESTARTSYS for set_termios.
fn wait_until_sent(open: &TtyOpen, interrupted: Errno) -> Result<(), Errno> {
    if wait(|| open.look(|_, _, other| other.chars == 0), None) == Waited::Interrupted {
        return Err(interrupted);
    }
    Ok(())
}

/// `set_termios`: the user's struct over the current settings, the
/// speeds worked out from the CBAUD bits (`tty_termios_baud_rate`), then
/// for TCSETSW and TCSETSF a wait for output to drain (and for TCSETSF the
/// read buffer emptied), then `tty_set_termios`.
fn set_termios(open: &TtyOpen, user: &[u8], termio: bool, how: SetHow) -> Result<(), Errno> {
    if how != SetHow::Now {
        wait_until_sent(open, Errno::ERESTARTSYS)?;
    }
    open.run(true, |t, out, _| {
        let mut new = if termio {
            t.termios.with_termio(user)
        } else {
            t.termios.with_bytes(user)
        };
        new.ispeed = new.input_speed();
        new.ospeed = new.output_speed();
        if how == SetHow::Flush {
            t.flush_input();
        }
        t.set_termios(new, out);
    });
    Ok(())
}

/// TIOCGPTPEER on a master: a new description of its slave, opened with
/// `flags` (`ptm_open_peer`). The caller installs it.
pub fn peer(open: &TtyOpen, flags: u64) -> Result<(Arc<TtyOpen>, Ino), Errno> {
    let Line::Pty(line, End::Master) = &open.line else {
        return Err(Errno::EIO);
    };
    let ino = (*line.node.lock()).ok_or(Errno::EIO)?;
    let slave = open_slave(line.index)?;
    let slave = Arc::new(TtyOpen {
        line: Line::Pty(slave, End::Slave),
    });
    // dentry_open goes through tty_open, so it can become the caller's
    // controlling terminal as an open of the node would.
    take_on_open(&slave, Device::Pts(line.index), flags);
    Ok((slave, ino))
}

/// Whether `request` is TIOCGPTPEER, which the caller handles (it makes a
/// descriptor).
pub fn is_peer_request(request: u32) -> bool {
    request == TIOCGPTPEER
}
