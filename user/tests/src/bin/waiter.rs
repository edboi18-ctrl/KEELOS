//! ADR 0047 regression (the fuzzer's epoll_wait that SIGKILL could not
//! end): `waiter MODE` blocks for good in one kind of wait, and the
//! kernel's `compartment.kill_waiting` kills it there. Every mode must
//! end by SIGKILL at once. Keel only (it never ends by itself).
//!
//! Modes: `epoll` (epoll_wait, no timeout, nothing watched), `poll`
//! (poll of a pipe's empty read end, no timeout), `select` (the same with
//! select), `sleep` (nanosleep for a day), `sigsuspend` (rt_sigsuspend
//! with every signal blocked but SIGKILL and SIGSTOP), `fifo` (open of a
//! FIFO for reading with no writer), `pipe` (read of an empty pipe whose
//! write end it holds), `accept` (accept4 on a listening socket),
//! `wait4` (for a child that sleeps for a day; the child goes too).
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, Arg, FdSets, O_RDONLY};

fn day() -> [u8; 16] {
    let mut req = [0u8; 16];
    req[..8].copy_from_slice(&86_400u64.to_le_bytes());
    req
}

fn main(startup: &Startup) -> i32 {
    let Some(mode) = startup.args().nth(1) else {
        return 90;
    };
    let mut fds = [0i32; 2];
    if sys::pipe2(&mut fds, None) != 0 {
        return 91;
    }
    let r = match mode {
        b"epoll" => {
            let ep = sys::epoll_create1(Some(0), 0);
            let mut events = [[0u8; 12]; 4];
            sys::epoll_wait(ep as i32, &mut events, -1)
        }
        b"poll" => {
            let mut p = [0u8; 8];
            p[..4].copy_from_slice(&fds[0].to_le_bytes());
            p[4..6].copy_from_slice(&1u16.to_le_bytes()); // POLLIN
            sys::poll(&mut [p], -1)
        }
        b"select" => {
            let mut read = [0u8; 128];
            read[0] = 1 << fds[0];
            sys::select(
                fds[0] + 1,
                FdSets {
                    read: Some(&mut read),
                    write: None,
                    except: None,
                },
                None,
            )
        }
        b"sleep" => sys::nanosleep(&day(), None),
        b"sigsuspend" => {
            let all = u64::MAX;
            sys::rt_sigsuspend(Arg::Buf(&all), 8)
        }
        b"fifo" => {
            if sys::mknodat(AT_FDCWD, c"/waiter-fifo", 0o010600, 0) != 0 {
                return 92;
            }
            sys::openat(AT_FDCWD, c"/waiter-fifo", O_RDONLY, 0)
        }
        b"pipe" => {
            let mut b = [0u8; 1];
            sys::read(fds[0], &mut b)
        }
        b"accept" => {
            let s = sys::socket(1, 1, 0) as i32;
            let mut a = [0u8; 16];
            a[..2].copy_from_slice(&1u16.to_le_bytes());
            a[2..13].copy_from_slice(b"/waiter-soc");
            if sys::bind(s, &a[..14]) != 0 || sys::listen(s, 1) != 0 {
                return 93;
            }
            sys::accept4(s, None, 0)
        }
        b"wait4" => {
            let child = sys::fork();
            if child == 0 {
                sys::nanosleep(&day(), None);
                return 0;
            }
            let mut status = 0;
            sys::wait4(child as i32, &mut status, 0)
        }
        _ => return 94,
    };
    // Any return is wrong: each wait is for something that never comes.
    sys::write_number(b"waiter: returned ", r.unsigned_abs(), b"\n");
    95
}

keel_rt::main!(main);
