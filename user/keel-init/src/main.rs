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
//! The launch service (P3-S2, ADR 0040): the kernel gives keel-init the
//! compartment factory on fd 3, close-on-exec. Before the shell, keel-init
//! binds `/run/keel-launch.sock` and starts `keel-launch --serve` with the
//! listener on fd 4 and a factory derived from its own beneath
//! [`LAUNCH_CEILING`], restricted to CREATE and STAT so it cannot be
//! copied on, as its fd 3. A user at the shell runs `keel-launch
//! MANIFEST`, which asks the service. Nothing else keel-init runs has a
//! factory. If the service ends, keel-init starts it again.
//!
//! `keel-init --launch MANIFEST` instead runs `keel-launch --direct
//! MANIFEST` with such a factory, and exits with its status.
//!
//! `keel-init --once` runs one shell and exits with its status (the
//! shell's exit code, or 128 plus the signal that ended it), for the
//! kernel's self-tests; without the launch service unless
//! `--launch-service` is given, which is stopped (SIGTERM) before it
//! exits. `--shell PATH [ARG ...]`, last, runs PATH with
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

/// The most a compartment keel-launch makes may have (ADR 0040).
/// Its profile ceiling is the full one: a manifest names its own profile
/// (the default unless it says otherwise, ADR 0041).
const LAUNCH_CEILING: sys::Limits = sys::Limits {
    processes: 256,
    profile: sys::PROFILE_FULL,
    memory_bytes: 1 << 30,
    tmpfs_bytes: 256 << 20,
    tmpfs_nodes: 65536,
};
/// Rights (keel_core::handle::Rights): STAT and CREATE.
const STAT_AND_CREATE: u64 = (1 << 4) | (1 << 6);

/// Where the launch service listens (keel-launch's `SOCKET`).
const LAUNCH_SOCKET: &CStr = c"/run/keel-launch.sock";
const AF_UNIX: i32 = 1;
const SOCK_STREAM: u32 = 1;
const SOCK_CLOEXEC: u32 = 0o2000000;
const SIGTERM: i32 = 15;
/// fcntl(2) F_SETFD.
const F_SETFD: u32 = 2;

/// Starts `/sbin/keel-launch` with `argv` and a factory on fd 3, derived
/// from keel-init's beneath [`LAUNCH_CEILING`] and restricted to CREATE
/// and STAT; with `listener`, if given, as its fd 4. Its PID.
fn start_launcher(argv: &[&CStr], listener: Option<i32>) -> i64 {
    let pid = sys::fork();
    if pid != 0 {
        return pid;
    }
    // The listener on fd 4 first (it may already be there, close-on-exec),
    // then the derived factory, then this process's own (fd 3) closed, so
    // the restricted copy takes the lowest free descriptor: 3.
    if let Some(s) = listener {
        let placed = if s == 4 {
            sys::fcntl(4, F_SETFD, 0)
        } else {
            sys::dup2(s, 4)
        };
        if placed < 0 {
            say(&[b"could not place the listener on fd 4\n"]);
            keel_rt::exit(2);
        }
    }
    let derived = sys::factory_derive(3, &LAUNCH_CEILING.bytes());
    if derived < 0 {
        let mut d = [0u8; 20];
        say(&[
            b"no factory to give: error ",
            decimal(derived, &mut d),
            b"\n",
        ]);
        keel_rt::exit(2);
    }
    sys::close(3);
    let restricted = sys::native_restrict(derived as i32, STAT_AND_CREATE);
    sys::close(derived as i32);
    if restricted != 3 {
        say(&[b"could not place the factory on fd 3\n"]);
        keel_rt::exit(2);
    }
    let e = sys::execve(c"/sbin/keel-launch", Some(argv), &ENV);
    let mut d = [0u8; 20];
    say(&[
        b"cannot run /sbin/keel-launch: error ",
        decimal(e, &mut d),
        b"\n",
    ]);
    keel_rt::exit(127);
}

/// `--launch MANIFEST`: `keel-launch --direct MANIFEST`; its status as a
/// shell reports it.
fn launch(manifest: &[u8]) -> i32 {
    let mut path = [0u8; 512];
    if manifest.len() >= path.len() || manifest.contains(&0) {
        say(&[b"manifest path too long\n"]);
        return 2;
    }
    path[..manifest.len()].copy_from_slice(manifest);
    let arg = CStr::from_bytes_until_nul(&path[..=manifest.len()]).unwrap_or(c"");
    let pid = start_launcher(&[c"keel-launch", c"--direct", arg], None);
    if pid < 0 {
        return 2;
    }
    loop {
        let mut raw = 0;
        let got = sys::wait4(pid as i32, &mut raw, 0);
        if got == pid {
            return shell_status(raw);
        }
        if got != EINTR {
            return 2;
        }
    }
}

/// The launch service (ADR 0040): binds [`LAUNCH_SOCKET`] (a stale one
/// from an earlier run removed first), then starts `keel-launch --serve`
/// with the listener, so it is ready before anything can ask. Its PID, or
/// None if it could not start.
fn start_service() -> Option<i64> {
    sys::mkdir(c"/run", 0o755);
    sys::unlink(LAUNCH_SOCKET);
    let s = sys::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    let mut addr = [0u8; 110];
    addr[..2].copy_from_slice(&(AF_UNIX as u16).to_le_bytes());
    let path = LAUNCH_SOCKET.to_bytes_with_nul();
    addr[2..2 + path.len()].copy_from_slice(path);
    if s < 0 || sys::bind(s as i32, &addr[..2 + path.len()]) != 0 || sys::listen(s as i32, 16) != 0
    {
        say(&[b"the launch service cannot listen\n"]);
        if s >= 0 {
            sys::close(s as i32);
        }
        return None;
    }
    let pid = start_launcher(&[c"keel-launch", c"--serve"], Some(s as i32));
    sys::close(s as i32);
    (pid > 0).then_some(pid)
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
    let mut args = startup.args().skip(1);
    if args.next() == Some(b"--launch") {
        return match (args.next(), args.next()) {
            (Some(manifest), None) => launch(manifest),
            _ => {
                say(&[b"usage: keel-init --launch MANIFEST\n"]);
                2
            }
        };
    }
    let flag = |name: &[u8]| {
        startup
            .args()
            .skip(1)
            .take_while(|a| *a != b"--shell")
            .any(|a| a == name)
    };
    let once = flag(b"--once");
    let Some(command) = Shell::from_args(startup) else {
        say(&[b"usage: keel-init [--once [--launch-service]] [--shell PATH [ARG ...]] | --launch MANIFEST\n"]);
        return 2;
    };
    // The launch service: always in a normal boot; with --once only if
    // asked (the self-tests).
    let with_service = !once || flag(b"--launch-service");
    let mut service = if with_service { start_service() } else { None };
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
        // the shell does; start the service again if it ends.
        let mut status = 0;
        if shell > 0 {
            loop {
                let mut raw = 0;
                let pid = sys::wait4(-1, &mut raw, 0);
                if pid == shell {
                    status = shell_status(raw);
                    break;
                }
                if service == Some(pid) {
                    say(&[b"the launch service ended; starting it again\n"]);
                    service = start_service();
                    continue;
                }
                if pid == ECHILD || (pid < 0 && pid != EINTR) {
                    break;
                }
            }
        }
        if once {
            if let Some(pid) = service {
                sys::kill(pid as i32, SIGTERM);
                let mut raw = 0;
                while sys::wait4(pid as i32, &mut raw, 0) == EINTR {}
            }
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
