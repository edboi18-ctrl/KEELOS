//! P3-T13: keel-shell, checked against Linux. Runs under Linux
//! (`host.shellprobe`) and on Keel (`exec.shell`) and must pass on both.
//!
//! The shell is `keel-shell` beside this program if there is one (the
//! host build), else `/bin/keel-shell` (Keel's initramfs).
//!
//! 1. **A script on a pipe** (no terminal, so no job control): quoting
//!    and parameters (POSIX XCU 2.2, 2.6.2), `;`, `&&`, `||`, pipelines,
//!    `<`, `>`, `>>`, `2>`, `2>&1` and `1>&2`, `$?` for a missing file (1), a missing
//!    command (127, XCU 2.8.2) and a killed job (143), PATH search, `-c`,
//!    `&` with `$!` and `wait`, `export` and `unset`, `cd` and `pwd`,
//!    and `exit 7`. Its whole output is compared.
//! 2. **An interactive session on a pty**, the shell a session leader
//!    with the slave as its controlling terminal, as keel-init starts it
//!    on the console. Typed on the master, as a user would:
//!    - `cat`, ^Z: the job stops ("[1]+ Stopped"), the shell has the
//!      terminal back (TIOCGPGRP on the master), `jobs` lists it, `fg`
//!      resumes it, it reads a line, ^D ends it, `$?` is 0;
//!    - `cat`, ^C: `$?` is 130;
//!    - `cat &`: it stops on SIGTTIN ("Stopped (tty input)"), `fg %1`
//!      gives it the terminal and it reads;
//!    - `sleep 1`, ^Z, `bg`, `wait`: `$?` 0;
//!    - ^C at the prompt: a new prompt, `$?` 130;
//!    - `exit 5`: the shell's status is 5.
//!
//!    Each step waits for the terminal's foreground group to change, so
//!    the keys reach the job and not the shell.
//!
//! Each failed check exits with its own status, and prints the shell's
//! output so far to standard error.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, O_RDWR};

const O_NOCTTY: u64 = 0o400;
const TIOCSCTTY: u64 = 0x540E;
const TIOCGPGRP: u64 = 0x540F;
const TIOCGPTN: u64 = 0x8004_5430;
const TIOCSPTLCK: u64 = 0x4004_5431;
const SIGKILL: i32 = 9;
const POLLIN: u16 = 1;

fn nap(ms: i32) {
    sys::poll(&mut [], ms);
}

fn readable(fd: i32, ms: i32) -> bool {
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&fd.to_le_bytes());
    e[4..6].copy_from_slice(&POLLIN.to_le_bytes());
    let mut fds = [e];
    sys::poll(&mut fds, ms);
    u16::from_le_bytes([fds[0][6], fds[0][7]]) & POLLIN != 0
}

fn int_ioctl(fd: i32, request: u64) -> Option<i32> {
    let mut b = [0u8; 64];
    (sys::ioctl(fd, request, &mut b) == 0).then(|| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Bytes put together in a fixed buffer.
struct Buf<const N: usize> {
    data: [u8; N],
    len: usize,
}

impl<const N: usize> Buf<N> {
    const fn new() -> Self {
        Self {
            data: [0; N],
            len: 0,
        }
    }

    fn put(&mut self, bytes: &[u8]) -> &mut Self {
        let n = bytes.len().min(N - self.len);
        self.data[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        self
    }

    fn num(&mut self, mut v: u64) -> &mut Self {
        let mut digits = [0u8; 20];
        let mut at = digits.len();
        loop {
            at -= 1;
            digits[at] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&digits[at..])
    }

    fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    /// The contents with a NUL after them, as a C string.
    fn c(&mut self) -> &CStr {
        if self.len == N {
            self.len -= 1;
        }
        self.data[self.len] = 0;
        CStr::from_bytes_until_nul(&self.data[..=self.len]).unwrap_or(c"")
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn report(what: &[u8], output: &[u8]) {
    sys::writev(
        2,
        &[b"shellprobe: ", what, b"; output so far:\n", output, b"\n"],
    );
}

/// The shell to test: beside this program, else /bin/keel-shell.
fn shell_path(argv0: &[u8], out: &mut Buf<512>) {
    if let Some(slash) = argv0.iter().rposition(|&c| c == b'/') {
        out.put(&argv0[..=slash]).put(b"keel-shell");
        let mut st = [0u8; 144];
        if sys::stat(out.c(), &mut st) == 0 {
            return;
        }
    }
    out.len = 0;
    out.put(b"/bin/keel-shell");
}

/// The directory part of `path` (up to its last slash).
fn dir_of(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&c| c == b'/') {
        Some(0) => b"/",
        Some(i) => &path[..i],
        None => b".",
    }
}

// --- 1. a script ------------------------------------------------------------

const SCRIPT: &[u8] = br#"echo hello world
echo 'single $HOME' "double $X" \$X
X=1; echo $X ${X}y
false; echo $?
true && echo and1
false && echo and2
false || echo or1
echo one | cat | cat
echo a >$D/b; echo c >$D/a; echo d >>$D/a; cat $D/a $D/b
ls $D
cat <$D/b
cat $D/none 2>/dev/null; echo $?
nosuch 2>/dev/null; echo $?
keel-shell -c "exit 3"; echo $?
sleep 5 & kill $!; wait $!; echo $?
echo bg & wait; echo waited
export Y=2; keel-shell -c 'echo [$Y] [$X]'
unset X; echo "[$X]" $X end
echo err 2>&1 >/dev/null | cat
echo to-err 2>&1 1>&2 | cat
cat $D/none 2>&1 | cat
cd $D; pwd
true | true | false; echo $?
# a comment
exit 7
echo not reached
"#;

/// What SCRIPT prints, with `dir` for $D.
fn expected(dir: &[u8], out: &mut Buf<2048>) {
    out.put(b"hello world\n")
        .put(b"single $HOME double  $X\n")
        .put(b"1 1y\n")
        .put(b"1\n")
        .put(b"and1\n")
        .put(b"or1\n")
        .put(b"one\n")
        .put(b"c\nd\na\n")
        .put(b"a\nb\n")
        .put(b"a\n")
        .put(b"1\n")
        .put(b"127\n")
        .put(b"3\n")
        .put(b"143\n")
        .put(b"bg\nwaited\n")
        .put(b"[2] []\n")
        .put(b"[] end\n")
        .put(b"to-err\n")
        .put(b"cat: ")
        .put(dir)
        .put(b"/none: No such file or directory\n")
        .put(dir)
        .put(b"\n")
        .put(b"1\n");
}

fn scripted(shell: &mut Buf<512>) -> i32 {
    let mut dir = Buf::<256>::new();
    dir.put(b"/tmp/keel-shellprobe-").num(sys::getpid() as u64);
    if sys::mkdir(dir.c(), 0o700) != 0 {
        return 1;
    }
    let mut env_path = Buf::<512>::new();
    env_path.put(b"PATH=").put(dir_of(shell.bytes()));
    let mut env_d = Buf::<300>::new();
    env_d.put(b"D=").put(dir.bytes());
    let (mut input, mut output) = ([-1i32; 2], [-1i32; 2]);
    if sys::pipe2(&mut input, None) != 0 || sys::pipe2(&mut output, None) != 0 {
        return 2;
    }
    let child = sys::fork();
    if child == 0 {
        sys::dup2(input[0], 0);
        sys::dup2(output[1], 1);
        for fd in input.iter().chain(&output) {
            sys::close(*fd);
        }
        let path = shell.c();
        sys::execve(path, Some(&[path]), &[env_path.c(), env_d.c()]);
        keel_rt::exit(127);
    }
    sys::close(input[0]);
    sys::close(output[1]);
    let wrote = sys::write(input[1], SCRIPT) == SCRIPT.len() as i64;
    sys::close(input[1]);
    let mut got = Buf::<4096>::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = sys::read(output[0], &mut chunk);
        if n <= 0 {
            break;
        }
        got.put(&chunk[..n as usize]);
    }
    sys::close(output[0]);
    let mut status = 0;
    let reaped = sys::wait4(child as i32, &mut status, 0) == child;
    let mut want = Buf::<2048>::new();
    expected(dir.bytes(), &mut want);
    // Tidy up before judging.
    for name in [&b"/a"[..], b"/b"] {
        let mut file = Buf::<300>::new();
        file.put(dir.bytes()).put(name);
        sys::unlink(file.c());
    }
    sys::rmdir(dir.c());
    if !wrote || !reaped {
        return 3;
    }
    if got.bytes() != want.bytes() {
        report(b"the script's output differs", got.bytes());
        report(b"expected", want.bytes());
        return 4;
    }
    // `exit 7`.
    if status != 7 << 8 {
        report(b"the script's exit status is not 7", got.bytes());
        return 5;
    }
    0
}

// --- 2. a session on a pty -------------------------------------------------------

/// The master side, with everything the shell has written.
struct Term {
    m: i32,
    shell: i32,
    out: Buf<16384>,
    /// Where the next `expect` starts looking.
    mark: usize,
}

impl Term {
    fn drain(&mut self, ms: i32) {
        let mut chunk = [0u8; 512];
        while readable(self.m, ms) {
            let n = sys::read(self.m, &mut chunk);
            if n <= 0 {
                return;
            }
            self.out.put(&chunk[..n as usize]);
        }
    }

    fn send(&mut self, keys: &[u8]) {
        sys::write(self.m, keys);
    }

    /// Waits up to 5 s for `text` after the mark; moves the mark past it.
    fn expect(&mut self, text: &[u8]) -> bool {
        for _ in 0..100 {
            if let Some(at) = find(&self.out.bytes()[self.mark..], text) {
                self.mark += at + text.len();
                return true;
            }
            self.drain(50);
        }
        false
    }

    /// Waits up to 5 s for the terminal's foreground group to be the
    /// shell's (`shell` true) or another; then a pause, so a job that has
    /// just been given the terminal has reset its signals too.
    fn foreground(&mut self, shell: bool) -> bool {
        for _ in 0..100 {
            if (int_ioctl(self.m, TIOCGPGRP) == Some(self.shell)) == shell {
                self.drain(100);
                return true;
            }
            self.drain(50);
        }
        false
    }
}

/// A pty's master, and its slave opened with O_NOCTTY.
fn openpty() -> Option<(i32, i32)> {
    let m = sys::open(c"/dev/ptmx", O_RDWR | O_NOCTTY, 0);
    if m < 0 {
        return None;
    }
    let m = m as i32;
    let n = int_ioctl(m, TIOCGPTN)?;
    let mut unlock = [0u8; 64];
    sys::ioctl(m, TIOCSPTLCK, &mut unlock);
    let mut path = Buf::<32>::new();
    path.put(b"/dev/pts/").num(n as u64);
    let s = sys::open(path.c(), O_RDWR | O_NOCTTY, 0);
    (s >= 0).then_some((m, s as i32))
}

/// The steps of the session; 0 or the failed check.
fn session(t: &mut Term) -> i32 {
    let ok = |b: bool, n: i32| if b { 0 } else { n };
    let steps: [&dyn Fn(&mut Term) -> i32; 6] = [
        // ^Z stops the job; jobs; fg; it reads a line; ^D; $? 0.
        &|t| {
            if !t.expect(b"keel$ ") {
                return 10;
            }
            t.send(b"cat\n");
            if !t.foreground(false) {
                return 11;
            }
            t.send(b"\x1a");
            if !t.expect(b"[1]+ Stopped\tcat\r\n") || !t.foreground(true) {
                return 12;
            }
            t.send(b"jobs\n");
            if !t.expect(b"[1]+ Stopped\tcat\r\n") {
                return 13;
            }
            t.send(b"fg\n");
            if !t.expect(b"cat\r\n") || !t.foreground(false) {
                return 14;
            }
            t.send(b"x\n");
            if !t.expect(b"x\r\nx\r\n") {
                return 15;
            }
            t.send(b"\x04");
            if !t.foreground(true) {
                return 16;
            }
            t.send(b"echo st=$?\n");
            ok(t.expect(b"st=0\r\n"), 17)
        },
        // ^C ends the job: 130.
        &|t| {
            t.send(b"cat\n");
            if !t.foreground(false) {
                return 20;
            }
            t.send(b"\x03");
            if !t.foreground(true) {
                return 21;
            }
            t.send(b"echo st=$?\n");
            ok(t.expect(b"st=130\r\n"), 22)
        },
        // A background reader stops on SIGTTIN; fg %1 lets it read.
        &|t| {
            t.send(b"cat &\n");
            if !t.expect(b"[1] ") {
                return 30;
            }
            let mut stopped = false;
            for _ in 0..20 {
                t.send(b"jobs\n");
                if t.expect(b"jobs\r\n") && t.expect(b"[1]+ ") && t.expect(b"\tcat\r\n") {
                    let line = t.out.bytes();
                    let line = &line[..t.mark];
                    if line.ends_with(b"Stopped (tty input)\tcat\r\n") {
                        stopped = true;
                        break;
                    }
                }
                nap(100);
            }
            if !stopped {
                return 31;
            }
            t.send(b"fg %1\n");
            if !t.expect(b"cat\r\n") || !t.foreground(false) {
                return 32;
            }
            t.send(b"y\n");
            if !t.expect(b"y\r\ny\r\n") {
                return 33;
            }
            t.send(b"\x04");
            if !t.foreground(true) {
                return 34;
            }
            t.send(b"echo st=$?\n");
            ok(t.expect(b"st=0\r\n"), 35)
        },
        // ^Z, bg, wait.
        &|t| {
            t.send(b"sleep 1\n");
            if !t.foreground(false) {
                return 40;
            }
            t.send(b"\x1a");
            if !t.expect(b"[1]+ Stopped\tsleep 1\r\n") || !t.foreground(true) {
                return 41;
            }
            t.send(b"bg\n");
            if !t.expect(b"[1]+ sleep 1 &\r\n") {
                return 42;
            }
            t.send(b"wait; echo st=$?\n");
            ok(t.expect(b"st=0\r\n"), 43)
        },
        // ^C at the prompt: a fresh prompt and $? 130.
        &|t| {
            if !t.expect(b"keel$ ") {
                return 50;
            }
            t.send(b"\x03");
            if !t.expect(b"keel$ ") {
                return 51;
            }
            t.send(b"echo st=$?\n");
            ok(t.expect(b"st=130\r\n"), 52)
        },
        &|t| {
            t.send(b"exit 5\n");
            0
        },
    ];
    for step in steps {
        let r = step(t);
        if r != 0 {
            return r;
        }
    }
    0
}

fn interactive(shell: &mut Buf<512>) -> i32 {
    let Some((m, s)) = openpty() else {
        return 6;
    };
    let mut env_path = Buf::<512>::new();
    env_path.put(b"PATH=").put(dir_of(shell.bytes()));
    let child = sys::fork();
    if child == 0 {
        // As keel-init: a new session, the terminal its controlling one.
        sys::setsid();
        if sys::ioctl_value(s, TIOCSCTTY, 0) != 0 {
            keel_rt::exit(126);
        }
        for fd in 0..3 {
            sys::dup2(s, fd);
        }
        sys::close(s);
        sys::close(m);
        let path = shell.c();
        sys::execve(path, Some(&[path]), &[env_path.c()]);
        keel_rt::exit(127);
    }
    sys::close(s);
    let mut t = Term {
        m,
        shell: child as i32,
        out: Buf::new(),
        mark: 0,
    };
    let r = session(&mut t);
    if r != 0 {
        t.drain(100);
        sys::kill(child as i32, SIGKILL);
    }
    let mut status = 0;
    let reaped = sys::wait4(child as i32, &mut status, 0) == child;
    t.drain(10);
    sys::close(m);
    if r != 0 {
        report(b"the session failed", t.out.bytes());
        return r;
    }
    if !reaped || status != 5 << 8 {
        report(b"the shell did not exit 5", t.out.bytes());
        return 60;
    }
    0
}

fn main(startup: &Startup) -> i32 {
    let mut shell = Buf::<512>::new();
    shell_path(startup.args().next().unwrap_or(b""), &mut shell);
    let r = scripted(&mut shell);
    if r != 0 {
        return r;
    }
    interactive(&mut shell)
}

keel_rt::main!(main);
