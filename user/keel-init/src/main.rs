//! keel-init: the first user program of a normal boot (P3-T13, ADR 0032).
//!
//! The kernel starts `/sbin/keel-init` with the console on fds 0 to 2.
//! It starts the shell, `/bin/keel-shell`, in a new session (setsid(2))
//! that has the console as its controlling terminal (TIOCSCTTY,
//! ioctl_tty(2)), so the shell can do job control there. Then it reaps
//! every child (wait4(2) with PID -1), and when the shell ends it starts
//! another, after a second if the last one lasted less than that, so a
//! shell that cannot start does not make it spin.
//!
//! `keel-init --once` runs one shell and exits with its status (the
//! shell's exit code, or 128 plus the signal that ended it), for the
//! kernel's self-tests. `--shell PATH [ARG ...]`, last, runs PATH with
//! those arguments instead (argv[0] is PATH), such as
//! `--shell /bin/busybox sh` for BusyBox's shell.
//!
//! Safe Rust on keel-rt, like keel-shell.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys;

const ECHILD: i64 = -10;
const EINTR: i64 = -4;
/// include/uapi/asm-generic/ioctls.h.
const TIOCSCTTY: u64 = 0x540E;

/// The shell to run: NUL-terminated strings in a fixed buffer.
struct Shell {
    buf: [u8; 1024],
    used: usize,
    /// (start, length) of each argument; the first is also the path.
    spans: [(usize, usize); 16],
    count: usize,
    /// The first argument that is argv: 1 for the default, whose argv[0]
    /// is not its path.
    argv_from: usize,
}

impl Shell {
    /// `/bin/keel-shell`, argv `keel-shell`; or what follows `--shell`.
    fn from_args(startup: &Startup) -> Option<Self> {
        let mut shell = Shell {
            buf: [0; 1024],
            used: 0,
            spans: [(0, 0); 16],
            count: 0,
            argv_from: 0,
        };
        let mut args = startup.args().skip(1).skip_while(|a| *a != b"--shell");
        if args.next().is_some() {
            for a in args {
                shell.push(a)?;
            }
            if shell.count == 0 {
                return None;
            }
        } else {
            shell.push(b"/bin/keel-shell")?;
            shell.push(b"keel-shell")?;
            shell.argv_from = 1;
        }
        Some(shell)
    }

    fn push(&mut self, arg: &[u8]) -> Option<()> {
        let end = self.used + arg.len();
        if end >= self.buf.len() || self.count == self.spans.len() || arg.contains(&0) {
            return None;
        }
        self.buf[self.used..end].copy_from_slice(arg);
        self.buf[end] = 0;
        self.spans[self.count] = (self.used, arg.len());
        self.count += 1;
        self.used = end + 1;
        Some(())
    }

    fn arg(&self, i: usize) -> &CStr {
        let (start, len) = self.spans[i];
        CStr::from_bytes_until_nul(&self.buf[start..=start + len]).unwrap_or(c"")
    }

    fn path(&self) -> &[u8] {
        let (start, len) = self.spans[0];
        &self.buf[start..start + len]
    }
}

const ENV: [&CStr; 3] = [
    c"PATH=/bin:/sbin:/usr/bin",
    c"HOME=/",
    c"SHELL=/bin/keel-shell",
];

fn say(parts: &[&[u8]]) {
    let mut line = [0u8; 256];
    let mut len = 0;
    for p in [&b"keel-init: "[..]].iter().chain(parts) {
        let n = p.len().min(line.len() - len);
        line[len..len + n].copy_from_slice(&p[..n]);
        len += n;
    }
    sys::write(2, &line[..len]);
}

fn decimal(value: i64, out: &mut [u8; 20]) -> &[u8] {
    let mut at = out.len();
    let mut rest = value.unsigned_abs();
    loop {
        at -= 1;
        out[at] = b'0' + (rest % 10) as u8;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    if value < 0 {
        at -= 1;
        out[at] = b'-';
    }
    &out[at..]
}

/// Monotonic time in milliseconds.
fn now_ms() -> i64 {
    let mut ts = [0u8; 16];
    sys::clock_gettime(1, &mut ts); // CLOCK_MONOTONIC
    let mut sec = [0u8; 8];
    let mut nsec = [0u8; 8];
    sec.copy_from_slice(&ts[..8]);
    nsec.copy_from_slice(&ts[8..]);
    i64::from_le_bytes(sec)
        .saturating_mul(1000)
        .saturating_add(i64::from_le_bytes(nsec) / 1_000_000)
}

/// A wait status as a shell reports it: the exit code, or 128 plus the
/// signal (POSIX XCU 2.8.2).
fn shell_status(raw: i32) -> i32 {
    if raw & 0x7f == 0 {
        (raw >> 8) & 0xff
    } else {
        128 + (raw & 0x7f)
    }
}

/// Starts the shell in a new session on the console; its PID.
fn start_shell(shell: &Shell) -> i64 {
    say(&[b"starting ", shell.path(), b"\n"]);
    let pid = sys::fork();
    if pid == 0 {
        // A new session (this child is not a group leader, so setsid
        // works) that takes the console as its controlling terminal.
        sys::setsid();
        let e = sys::ioctl_value(0, TIOCSCTTY, 0);
        if e < 0 {
            let mut d = [0u8; 20];
            say(&[
                b"TIOCSCTTY on the console: error ",
                decimal(e, &mut d),
                b"\n",
            ]);
        }
        // argv: the default's own argv[0], or PATH and its arguments.
        let mut argv = [c""; 16];
        let mut argc = 0;
        for i in shell.argv_from..shell.count {
            argv[argc] = shell.arg(i);
            argc += 1;
        }
        let e = sys::execve(shell.arg(0), Some(&argv[..argc]), &ENV);
        let mut d = [0u8; 20];
        say(&[
            b"cannot run ",
            shell.path(),
            b": error ",
            decimal(e, &mut d),
            b"\n",
        ]);
        keel_rt::exit(127);
    }
    pid
}

fn main(startup: &Startup) -> i32 {
    let once = startup
        .args()
        .skip(1)
        .take_while(|a| *a != b"--shell")
        .any(|a| a == b"--once");
    let Some(command) = Shell::from_args(startup) else {
        say(&[b"usage: keel-init [--once] [--shell PATH [ARG ...]]\n"]);
        return 2;
    };
    loop {
        let started = now_ms();
        let shell = start_shell(&command);
        if shell < 0 {
            let mut d = [0u8; 20];
            say(&[b"fork failed: error ", decimal(shell, &mut d), b"\n"]);
            if once {
                return 1;
            }
        }
        // Reap whatever ends (an orphan given to init too, on Linux) until
        // the shell does.
        let mut status = 0;
        // Ends at the shell's exit, or when no child is left.
        if shell > 0 {
            loop {
                let mut raw = 0;
                let pid = sys::wait4(-1, &mut raw, 0);
                if pid == shell {
                    status = shell_status(raw);
                    break;
                }
                if pid == ECHILD || (pid < 0 && pid != EINTR) {
                    break;
                }
            }
        }
        if once {
            return status;
        }
        let mut d = [0u8; 20];
        say(&[
            b"the shell ended (status ",
            decimal(i64::from(status), &mut d),
            b"); starting another\n",
        ]);
        if now_ms() - started < 1000 {
            sys::poll(&mut [], 1000);
        }
    }
}

keel_rt::main!(main);
