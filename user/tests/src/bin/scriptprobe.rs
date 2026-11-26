//! `#!` scripts in execve(2), checked against Linux (ADR 0036). Runs under
//! Linux (`host.scriptprobe`) and on Keel (`exec.scripts`) and must pass
//! on both.
//!
//! Semantics from execve(2) ("Interpreter scripts") and Linux v6.12's
//! `fs/binfmt_script.c` (`load_script`) and `fs/exec.c` (`exec_binprm`,
//! `begin_new_exec`). The interpreter is this program itself: run with
//! SCRIPTPROBE_SHOW in its environment, it prints its argv (joined by
//! `|`), its thread name and AT_EXECFN, and its /proc/self/exe, and
//! exits. The scripts live in a directory of its own under /tmp.
//!
//! Each failed check exits with its own status.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, O_CREAT, O_RDONLY, O_WRONLY};

const ENOENT: i64 = -2;
const ENOEXEC: i64 = -8;
const EACCES: i64 = -13;
const ELOOP: i64 = -40;
const O_TRUNC: u64 = 0o1000;

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

    fn put(&mut self, b: &[u8]) -> &mut Self {
        let n = b.len().min(N - 1 - self.len);
        self.data[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        self
    }

    fn bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    fn c(&mut self) -> &CStr {
        self.data[self.len] = 0;
        CStr::from_bytes_until_nul(&self.data[..=self.len]).unwrap_or(c"")
    }
}

fn number(mut v: u64, out: &mut Buf<512>) {
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
    out.put(&digits[at..]);
}

/// Show mode: what this run was started with.
fn show(startup: &Startup) -> i32 {
    let mut out = Buf::<2048>::new();
    out.put(b"argv:");
    for (i, a) in startup.args().enumerate() {
        if i > 0 {
            out.put(b"|");
        }
        out.put(a);
    }
    out.put(b"\ncomm:");
    let fd = sys::open(c"/proc/self/comm", O_RDONLY, 0);
    if fd >= 0 {
        let mut b = [0u8; 32];
        let n = sys::read(fd as i32, &mut b);
        if n > 0 {
            out.put(&b[..n as usize]);
        }
        sys::close(fd as i32);
    }
    out.put(b"execfn:").put(startup.execfn().unwrap_or(b"?"));
    out.put(b"\nexe:");
    let mut link = [0u8; 512];
    let n = sys::readlink(c"/proc/self/exe", &mut link);
    if n > 0 {
        out.put(&link[..n as usize]);
    }
    out.put(b"\n");
    sys::write(1, out.bytes());
    0
}

/// Writes `text` to `path`, mode 0755.
fn write_file(path: &mut Buf<512>, text: &[u8]) -> bool {
    let fd = sys::open(path.c(), O_WRONLY | O_CREAT | O_TRUNC, 0o755);
    if fd < 0 {
        return false;
    }
    let ok = sys::write(fd as i32, text) == text.len() as i64;
    sys::close(fd as i32);
    ok
}

/// Runs `path` with `argv` and SCRIPTPROBE_SHOW set: what it printed, or
/// the execve error (as the child's exit status 200 + -errno).
fn run(path: &mut Buf<512>, argv: &[&CStr], out: &mut Buf<2048>) -> Result<(), i64> {
    let mut fds = [-1i32; 2];
    if sys::pipe2(&mut fds, None) != 0 {
        return Err(-1000);
    }
    let child = sys::fork();
    if child == 0 {
        sys::dup2(fds[1], 1);
        sys::close(fds[0]);
        sys::close(fds[1]);
        let e = sys::execve(path.c(), Some(argv), &[c"SCRIPTPROBE_SHOW=1"]);
        keel_rt::exit(200 + (-e) as i32);
    }
    sys::close(fds[1]);
    let mut chunk = [0u8; 512];
    loop {
        let n = sys::read(fds[0], &mut chunk);
        if n <= 0 {
            break;
        }
        out.put(&chunk[..n as usize]);
    }
    sys::close(fds[0]);
    let mut status = 0;
    sys::wait4(child as i32, &mut status, 0);
    let code = (status >> 8) & 0xff;
    if status & 0x7f == 0 && code >= 200 {
        return Err(-i64::from(code - 200));
    }
    Ok(())
}

fn report(what: &[u8], got: &[u8]) {
    sys::writev(2, &[b"scriptprobe: ", what, b"\n", got, b"\n"]);
}

/// The expected show output.
fn expect(argv: &[&[u8]], comm: &[u8], execfn: &[u8], exe: &[u8]) -> Buf<2048> {
    let mut out = Buf::<2048>::new();
    out.put(b"argv:");
    for (i, a) in argv.iter().enumerate() {
        if i > 0 {
            out.put(b"|");
        }
        out.put(a);
    }
    out.put(b"\ncomm:").put(comm).put(b"\nexecfn:").put(execfn);
    out.put(b"\nexe:").put(exe).put(b"\n");
    out
}

fn path_in(dir: &[u8], name: &[u8]) -> Buf<512> {
    let mut p = Buf::new();
    p.put(dir).put(b"/").put(name);
    p
}

fn checks(dir: &[u8], me: &[u8]) -> i32 {
    // 1. `#!interpreter argument`: argv becomes the interpreter, the
    //    argument and the script's path, then the original argv after
    //    its first; the thread is named after the script, AT_EXECFN is
    //    the script's path, exe the interpreter.
    let mut script = path_in(dir, b"one");
    let mut text = Buf::<512>::new();
    text.put(b"#!").put(me).put(b" show\n");
    if !write_file(&mut script, text.bytes()) {
        return 1;
    }
    let mut out = Buf::<2048>::new();
    let ok = run(&mut script, &[c"zero", c"x", c"y"], &mut out);
    let want = expect(
        &[me, b"show", script.bytes(), b"x", b"y"],
        b"one",
        script.bytes(),
        me,
    );
    if ok.is_err() || out.bytes() != want.bytes() {
        report(b"one", out.bytes());
        return 1;
    }
    // 2. No argument; blanks around the name; the argument's inner blanks
    //    kept and its trailing ones dropped.
    let mut bare = path_in(dir, b"bare");
    let mut text = Buf::<512>::new();
    text.put(b"#! \t").put(me).put(b" \t\n");
    let mut spaced = path_in(dir, b"spaced");
    let mut text2 = Buf::<512>::new();
    text2.put(b"#!").put(me).put(b"   a  b \t\n");
    if !write_file(&mut bare, text.bytes()) || !write_file(&mut spaced, text2.bytes()) {
        return 2;
    }
    let mut out = Buf::<2048>::new();
    let ok = run(&mut bare, &[c"zero"], &mut out);
    let want = expect(&[me, bare.bytes()], b"bare", bare.bytes(), me);
    if ok.is_err() || out.bytes() != want.bytes() {
        report(b"bare", out.bytes());
        return 2;
    }
    let mut out = Buf::<2048>::new();
    let ok = run(&mut spaced, &[c"zero", c"z"], &mut out);
    let want = expect(
        &[me, b"a  b", spaced.bytes(), b"z"],
        b"spaced",
        spaced.bytes(),
        me,
    );
    if ok.is_err() || out.bytes() != want.bytes() {
        report(b"spaced", out.bytes());
        return 3;
    }
    // 3. A script's interpreter can be a script: each level puts its own
    //    path in. Five levels run; six are ELOOP.
    let mut prev = Buf::<512>::new();
    prev.put(me);
    let mut names: [Buf<512>; 6] = [const { Buf::new() }; 6];
    for (i, slot) in names.iter_mut().enumerate() {
        let mut name = Buf::<512>::new();
        name.put(b"level");
        number(i as u64 + 1, &mut name);
        *slot = path_in(dir, name.bytes());
        let mut text = Buf::<512>::new();
        text.put(b"#!").put(prev.bytes()).put(b"\n");
        if !write_file(slot, text.bytes()) {
            return 4;
        }
        prev = Buf::new();
        prev.put(slot.bytes());
    }
    let mut out = Buf::<2048>::new();
    let mut five = Buf::<512>::new();
    five.put(names[4].bytes());
    let ok = run(&mut five, &[c"zero", c"q"], &mut out);
    let want = expect(
        &[
            me,
            names[0].bytes(),
            names[1].bytes(),
            names[2].bytes(),
            names[3].bytes(),
            names[4].bytes(),
            b"q",
        ],
        b"level5",
        names[4].bytes(),
        me,
    );
    if ok.is_err() || out.bytes() != want.bytes() {
        report(b"five levels", out.bytes());
        return 5;
    }
    let mut six = Buf::<512>::new();
    six.put(names[5].bytes());
    if run(&mut six, &[c"zero"], &mut Buf::new()) != Err(ELOOP) {
        return 6;
    }
    // 4. Refusals: no interpreter named (ENOEXEC), a name cut off by the
    //    256-byte limit (ENOEXEC), a missing interpreter (ENOENT), a
    //    directory (EACCES).
    let mut long = Buf::<512>::new();
    long.put(b"#!/");
    for _ in 0..300 {
        long.put(b"x");
    }
    for (name, text, want, code) in [
        (&b"empty"[..], &b"#!   \n"[..], ENOEXEC, 7),
        (b"long", long.bytes(), ENOEXEC, 8),
        (b"missing", b"#!/nonexistent/interpreter\n", ENOENT, 9),
        (b"dir", b"#!/tmp\n", EACCES, 10),
    ] {
        let mut path = path_in(dir, name);
        if !write_file(&mut path, text) || run(&mut path, &[c"zero"], &mut Buf::new()) != Err(want)
        {
            return code;
        }
    }
    0
}

fn main(startup: &Startup) -> i32 {
    if startup.env().any(|e| e.starts_with(b"SCRIPTPROBE_SHOW=")) {
        return show(startup);
    }
    sys::umask(0o022);
    // This program's absolute path, for the scripts' `#!` lines.
    let arg0 = startup.args().next().unwrap_or(b"");
    let mut me = Buf::<512>::new();
    if arg0.first() != Some(&b'/') {
        let mut cwd = [0u8; 256];
        if sys::getcwd(&mut cwd) > 0 {
            let len = cwd.iter().position(|&c| c == 0).unwrap_or(0);
            me.put(&cwd[..len]).put(b"/");
        }
    }
    me.put(arg0.strip_prefix(b"./").unwrap_or(arg0));
    let mut dir = Buf::<512>::new();
    dir.put(b"/tmp/keel-scriptprobe-");
    number(sys::getpid() as u64, &mut dir);
    if sys::mkdir(dir.c(), 0o700) != 0 {
        return 100;
    }
    let result = checks(dir.bytes(), me.bytes());
    for name in [
        &b"one"[..],
        b"bare",
        b"spaced",
        b"level1",
        b"level2",
        b"level3",
        b"level4",
        b"level5",
        b"level6",
        b"empty",
        b"long",
        b"missing",
        b"dir",
    ] {
        sys::unlink(path_in(dir.bytes(), name).c());
    }
    sys::rmdir(dir.c());
    if result == 0 {
        sys::write(1, b"scriptprobe: 10 checks passed\n");
    }
    result
}

keel_rt::main!(main);
