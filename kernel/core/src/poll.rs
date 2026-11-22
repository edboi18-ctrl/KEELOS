//! `poll(2)` bookkeeping (Phase 1): the `struct pollfd` layout and which
//! readiness bits are reported.
//!
//! From Linux v6.12: constants from `include/uapi/asm-generic/poll.h`;
//! the rules from `fs/select.c` (`do_pollfd`, `do_sys_poll`) and
//! `include/linux/poll.h` (`DEFAULT_POLLMASK`).

pub const POLLIN: u16 = 0x0001;
pub const POLLPRI: u16 = 0x0002;
pub const POLLOUT: u16 = 0x0004;
pub const POLLERR: u16 = 0x0008;
pub const POLLHUP: u16 = 0x0010;
pub const POLLNVAL: u16 = 0x0020;
pub const POLLRDNORM: u16 = 0x0040;
pub const POLLWRNORM: u16 = 0x0100;

/// What a file without its own poll method reports: always readable and
/// writable (`DEFAULT_POLLMASK`; regular files, directories, `/dev/null`,
/// `/dev/zero`, `/dev/urandom`).
pub const DEFAULT_POLLMASK: u16 = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;

/// `struct pollfd`: `int fd; short events; short revents;`, 8 bytes.
pub const POLLFD_SIZE: usize = 8;
/// Offset of `revents`, the only field written back.
pub const REVENTS_OFFSET: usize = 6;

/// One parsed `struct pollfd`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollFd {
    pub fd: i32,
    pub events: u16,
}

impl PollFd {
    pub fn from_bytes(b: &[u8; POLLFD_SIZE]) -> Self {
        Self {
            fd: i32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            events: u16::from_le_bytes([b[4], b[5]]),
        }
    }
}

/// `do_pollfd`'s mask: a negative fd is skipped (0); a closed one gets
/// `POLLNVAL` alone; otherwise the file's readiness, limited to the
/// requested events plus `POLLERR` and `POLLHUP`, which are always
/// reported. `ready` is `None` for a closed fd.
pub fn revents(fd: i32, events: u16, ready: Option<u16>) -> u16 {
    if fd < 0 {
        return 0;
    }
    match ready {
        None => POLLNVAL,
        Some(ready) => ready & (events | POLLERR | POLLHUP),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert_eq!(revents(-1, POLLIN, Some(POLLIN)), 0);
        assert_eq!(revents(5, POLLIN, None), POLLNVAL);
        assert_eq!(revents(5, 0, None), POLLNVAL, "std's events == 0 probe");
        assert_eq!(revents(0, 0, Some(DEFAULT_POLLMASK)), 0);
        assert_eq!(revents(0, POLLIN, Some(DEFAULT_POLLMASK)), POLLIN);
        assert_eq!(revents(0, 0, Some(POLLHUP | POLLIN)), POLLHUP);
        let fd = PollFd::from_bytes(&[2, 0, 0, 0, 5, 0, 0xff, 0xff]);
        assert_eq!(
            fd,
            PollFd {
                fd: 2,
                events: POLLIN | POLLOUT
            }
        );
        assert_eq!(PollFd::from_bytes(&[0xff; 8]).fd, -1);
    }
}
