//! Escape suite: exceeding each resource limit (ADR 0047). Run as
//! `esclimits PROCESSES FRAMES BYTES NODES HANDLES` in a compartment with
//! those limits (ADR 0039, 0042). Each is pushed past, refused in its
//! documented way, and given back:
//!
//! - 1-9: processes: fork stops with EAGAIN after PROCESSES - 1 children,
//!   by fork and by clone; once they are reaped, fork works again.
//! - 10-19: descriptors: dup stops with EMFILE at HANDLES, dup2 and
//!   F_DUPFD beyond it are refused (EBADF, EINVAL, as for RLIMIT_NOFILE).
//! - 20-29: tmpfs bytes: writing stops with ENOSPC at the quota, for a
//!   file and for a memfd; deleting gives the bytes back.
//! - 30-39: tmpfs nodes: creating stops with ENOSPC at the quota.
//! - 40-49: memory: a child touching more than FRAMES pages is ended by
//!   a fault, and this process goes on, its memory given back.
//!
//! Exit 0, or the number of the check that failed.
#![no_std]
#![no_main]

use core::ffi::CStr;

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_EXCL, O_WRONLY, PROT_READ, PROT_WRITE, Region};
use keel_sectests::{
    EAGAIN, EBADF, EINVAL, EMFILE, ENOSPC, SIGKILL, digits, fail, in_child, number, path,
};

const ME: &[u8] = b"esclimits";
const F_DUPFD: u32 = 0;
const MAX_PROCESSES: usize = 64;

fn sleeper() -> i64 {
    let pid = sys::fork();
    if pid == 0 {
        loop {
            keel_sectests::sleep_ms(1000);
        }
    }
    pid
}

fn reap(pids: &[i32]) -> bool {
    pids.iter().all(|&pid| {
        let mut status = 0;
        sys::kill(pid, SIGKILL) == 0
            && sys::wait4(pid, &mut status, 0) == i64::from(pid)
            && status & 0x7f == SIGKILL
    })
}

fn create(name: &CStr) -> i64 {
    sys::openat(AT_FDCWD, name, O_WRONLY | O_CREAT | O_EXCL, 0o644)
}

fn main(startup: &Startup) -> i32 {
    let mut args = startup.args().skip(1).map(number);
    let (
        Some(Some(processes)),
        Some(Some(frames)),
        Some(Some(bytes)),
        Some(Some(nodes)),
        Some(Some(handles)),
    ) = (
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    )
    else {
        return 90;
    };
    let (processes, handles) = (processes as usize, handles as i32);
    if !(2..=MAX_PROCESSES).contains(&processes) || !(4..=1024).contains(&handles) {
        return 91;
    }

    // 1-9: processes.
    let mut kids = [0i32; MAX_PROCESSES];
    let mut n = 0;
    let refused = loop {
        let pid = sleeper();
        if pid < 0 {
            break pid;
        }
        if n == MAX_PROCESSES {
            return fail(ME, 1, pid);
        }
        kids[n] = pid as i32;
        n += 1;
    };
    if refused != EAGAIN || n != processes - 1 {
        return fail(ME, 2, (n as i64) << 16 | -refused);
    }
    let r = sys::clone_fork();
    if r != EAGAIN {
        return fail(ME, 3, r);
    }
    if !reap(&kids[..n]) {
        return fail(ME, 4, -1);
    }
    let again = in_child(|| 7);
    if again.map(|s| s >> 8) != Ok(7) {
        return fail(ME, 5, keel_sectests::outcome(again));
    }

    // 10-19: descriptors. 0, 1 and 2 are open.
    let mut top = 2;
    let refused = loop {
        let fd = sys::dup(0);
        if fd < 0 {
            break fd;
        }
        top = fd;
    };
    if refused != EMFILE || top != i64::from(handles) - 1 {
        return fail(ME, 10, top << 16 | -refused);
    }
    let r = sys::dup2(0, handles);
    if r != EBADF {
        return fail(ME, 11, r);
    }
    sys::close(3);
    let r = sys::fcntl(0, F_DUPFD, handles as u64);
    if r != EINVAL {
        return fail(ME, 12, r);
    }
    // The freed number is reused, and then the table is full again.
    if sys::dup(0) != 3 || sys::dup(0) != EMFILE {
        return fail(ME, 13, -1);
    }
    for fd in 3..handles {
        sys::close(fd);
    }

    // 20-29: tmpfs bytes. Whatever the suite's earlier programs left
    // (a few small files) counts too, so the stop is within a page of
    // the quota.
    let chunk = [0x42u8; 16384];
    let fd = create(c"/big");
    if fd < 0 {
        return fail(ME, 20, fd);
    }
    let fd = fd as i32;
    let mut total: i64 = 0;
    let refused = loop {
        let w = sys::write(fd, &chunk);
        if w < 0 {
            break w;
        }
        total += w;
        if total > bytes {
            return fail(ME, 21, total);
        }
    };
    if refused != ENOSPC || total < bytes - 4096 {
        return fail(ME, 22, total << 8 | -refused);
    }
    // A memfd is tmpfs too: no room for it to grow.
    let m = sys::memfd_create(c"big", 0);
    if m < 0 {
        return fail(ME, 23, m);
    }
    let r = sys::pwrite(m as i32, &chunk, 0);
    if r != ENOSPC {
        return fail(ME, 24, r);
    }
    sys::close(m as i32);
    // Deleting the big file gives its bytes back.
    sys::close(fd);
    if sys::unlinkat(AT_FDCWD, c"/big", 0) != 0 {
        return fail(ME, 25, -1);
    }
    let fd = create(c"/big2");
    if fd < 0 || sys::write(fd as i32, &chunk) != chunk.len() as i64 {
        return fail(ME, 26, fd);
    }
    sys::close(fd as i32);
    sys::unlinkat(AT_FDCWD, c"/big2", 0);

    // 30-39: tmpfs nodes.
    let mut b = [0u8; 256];
    let mut made = 0i64;
    let refused = loop {
        let fd = create(path(&mut b, &[b"/n", digits(made as u64).as_bytes()]));
        if fd < 0 {
            break fd;
        }
        sys::close(fd as i32);
        made += 1;
        if made > nodes {
            return fail(ME, 30, made);
        }
    };
    if refused != ENOSPC || made == 0 {
        return fail(ME, 31, made << 8 | -refused);
    }
    let r = sys::mkdir(c"/ndir", 0o755);
    if r != ENOSPC {
        return fail(ME, 32, r);
    }
    for i in 0..made {
        sys::unlinkat(
            AT_FDCWD,
            path(&mut b, &[b"/n", digits(i as u64).as_bytes()]),
            0,
        );
    }
    if sys::mkdir(c"/ndir", 0o755) != 0 {
        return fail(ME, 33, -1);
    }

    // 40-49: memory. A child maps twice the limit and touches every
    // page; it is ended by a fault before it gets there.
    let length = (frames as u64) * 2 * 4096;
    let hog = in_child(|| {
        let Ok(r) = Region::map(length, PROT_READ | PROT_WRITE) else {
            return 2;
        };
        let mut at = 0;
        while at < length {
            r.write_u64(at, 1);
            at += 4096;
        }
        3
    });
    match hog {
        Ok(status) if status & 0x7f != 0 && status & 0x7f != 0x7f => {}
        other => return fail(ME, 40, keel_sectests::outcome(other)),
    }
    // This process goes on: the child's frames are back.
    let Ok(after) = Region::map(1 << 20, PROT_READ | PROT_WRITE) else {
        return fail(ME, 41, -1);
    };
    let mut at = 0;
    while at < after.length() {
        after.write_u64(at, 1);
        at += 4096;
    }
    0
}

keel_rt::main!(main);
