//! Pipes and eventfd counters as data (P3-T10, ADR 0025), tested on the
//! host; `keel-linux-abi` adds blocking, signals and descriptors. Rules
//! from Linux v6.12 `fs/pipe.c` and `fs/eventfd.c`.

use alloc::collections::VecDeque;

use crate::epoll::{EPOLLIN, EPOLLOUT, EPOLLRDNORM, EPOLLWRNORM, Wakes};
use crate::poll::{POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};

/// Writes of at most this many bytes are atomic (`PIPE_BUF`,
/// `include/uapi/linux/limits.h`): they go in whole or wait.
pub const PIPE_BUF: usize = 4096;
/// A pipe holds this many bytes: 16 buffers of a page (`PIPE_DEF_BUFFERS`,
/// `include/linux/pipe_fs_i.h`). Linux counts buffers, not bytes, so a pipe
/// filled by many small unmerged writes can be full with fewer bytes; Keel
/// counts bytes (ADR 0025).
pub const PIPE_CAPACITY: usize = 16 * 4096;

/// What a read or write did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Io {
    /// Moved this many bytes (0 on a read: end of file).
    Done(usize),
    /// Nothing could move now; a blocking caller waits.
    WouldBlock,
    /// A write with no reader left: EPIPE, and SIGPIPE to the writer.
    Broken,
}

/// One pipe: the bytes in it and how many open ends of each kind it has.
#[derive(Debug)]
pub struct Pipe {
    data: VecDeque<u8>,
    pub readers: u32,
    pub writers: u32,
    /// The wakes of the readers' queue (`rd_wait`) and the writers'
    /// (`wr_wait`), for epoll (ADR 0026).
    pub rd_wakes: Wakes,
    pub wr_wakes: Wakes,
}

impl Default for Pipe {
    fn default() -> Self {
        Self::new()
    }
}

impl Pipe {
    /// A pipe with one read end and one write end (pipe2).
    pub fn new() -> Self {
        Pipe {
            data: VecDeque::new(),
            readers: 1,
            writers: 1,
            rd_wakes: Wakes::default(),
            wr_wakes: Wakes::default(),
        }
    }

    /// Bytes waiting (FIONREAD).
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// `pipe_read`: what is there, up to `buf.len()`; empty with no writer
    /// left is end of file (0); empty otherwise would block.
    pub fn read(&mut self, buf: &mut [u8]) -> Io {
        if self.data.is_empty() {
            return if self.writers == 0 {
                Io::Done(0)
            } else {
                Io::WouldBlock
            };
        }
        let was_full = self.data.len() == PIPE_CAPACITY;
        let n = buf.len().min(self.data.len());
        for (slot, byte) in buf.iter_mut().zip(self.data.drain(..n)) {
            *slot = byte;
        }
        // `pipe_read` wakes the writers only if the pipe was full.
        if was_full {
            self.wr_wakes.wake(EPOLLOUT | EPOLLWRNORM);
        }
        Io::Done(n)
    }

    /// `pipe_release` for one end: when the last reader or the last
    /// writer goes but not both, both queues are woken for everything.
    pub fn close_end(&mut self, writer: bool) {
        if writer {
            self.writers -= 1;
        } else {
            self.readers -= 1;
        }
        if (self.readers == 0) != (self.writers == 0) {
            self.rd_wakes.wake(0);
            self.wr_wakes.wake(0);
        }
    }

    /// Puts bytes back at the front, as if never read (a read whose copy
    /// out faulted: `pipe_read` leaves them in the pipe).
    pub fn unread(&mut self, bytes: &[u8]) {
        for &b in bytes.iter().rev() {
            self.data.push_front(b);
        }
    }

    /// `pipe_write`: nothing to write is 0 even with no reader; no reader
    /// is broken; an `atomic` write (the whole write(2) is at most
    /// PIPE_BUF, which the caller decides, as the rest of a longer write is
    /// never atomic) goes in whole or would block; any other takes what
    /// room there is (would block if none).
    pub fn write(&mut self, data: &[u8], atomic: bool) -> Io {
        if data.is_empty() {
            return Io::Done(0);
        }
        if self.readers == 0 {
            return Io::Broken;
        }
        let room = PIPE_CAPACITY - self.data.len();
        let n = if atomic {
            if room < data.len() {
                return Io::WouldBlock;
            }
            data.len()
        } else if room == 0 {
            return Io::WouldBlock;
        } else {
            room.min(data.len())
        };
        self.data.extend(&data[..n]);
        // `pipe_write` wakes the readers after every write once the pipe
        // has been polled ("Epoll nonsensically wants a wakeup whether the
        // pipe was already empty or not").
        self.rd_wakes.wake(EPOLLIN | EPOLLRDNORM);
        Io::Done(n)
    }

    /// `pipe_poll` for an end: the read end is readable with data and hung
    /// up with no writer; the write end is writable with room and in error
    /// with no reader.
    pub fn poll(&self, reader: bool) -> u16 {
        let mut mask = 0;
        if reader {
            if !self.data.is_empty() {
                mask |= POLLIN | POLLRDNORM;
            }
            if self.writers == 0 {
                mask |= POLLHUP;
            }
        } else {
            if self.data.len() < PIPE_CAPACITY {
                mask |= POLLOUT | POLLWRNORM;
            }
            if self.readers == 0 {
                mask |= POLLERR;
            }
        }
        mask
    }
}

/// An eventfd's counter (`fs/eventfd.c`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventCounter {
    pub count: u64,
    /// EFD_SEMAPHORE: a read takes 1, not everything.
    pub semaphore: bool,
    /// The wakes of its queue (`wqh`), for epoll: EPOLLOUT after a read,
    /// EPOLLIN after a write (ADR 0026).
    pub wakes: Wakes,
}

impl EventCounter {
    /// `eventfd_read`: the counter (or 1 with EFD_SEMAPHORE), which is
    /// taken off it; None while it is 0 (would block).
    pub fn read(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let n = if self.semaphore { 1 } else { self.count };
        self.count -= n;
        self.wakes.wake(EPOLLOUT);
        Some(n)
    }

    /// `eventfd_write`: adds `n`, which must not be u64::MAX (EINVAL, the
    /// caller's check); false (would block) unless the sum stays below
    /// u64::MAX.
    pub fn write(&mut self, n: u64) -> bool {
        if u64::MAX - self.count > n {
            self.count += n;
            self.wakes.wake(EPOLLIN);
            true
        } else {
            false
        }
    }

    /// `eventfd_poll`: readable above 0; writable below u64::MAX - 1; in
    /// error at u64::MAX (which only the kernel's own signalling reaches).
    pub fn poll(&self) -> u16 {
        let mut mask = 0;
        if self.count > 0 {
            mask |= POLLIN;
        }
        if self.count == u64::MAX {
            mask |= POLLERR;
        }
        if u64::MAX - 1 > self.count {
            mask |= POLLOUT;
        }
        mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipes_read_write_and_hang_up_as_linux() {
        let mut p = Pipe::new();
        let mut buf = [0u8; 8];
        assert_eq!(p.read(&mut buf), Io::WouldBlock, "empty, a writer left");
        assert_eq!(p.poll(true), 0);
        assert_eq!(p.write(b"hello", true), Io::Done(5));
        assert_eq!(p.poll(true), POLLIN | POLLRDNORM);
        assert_eq!(p.read(&mut buf[..3]), Io::Done(3));
        assert_eq!(&buf[..3], b"hel");
        p.unread(b"el");
        assert_eq!(p.read(&mut buf[..4]), Io::Done(4));
        assert_eq!(&buf[..4], b"ello");
        p.write(b"lo", true);
        assert_eq!(p.read(&mut buf), Io::Done(2));
        p.writers = 0;
        assert_eq!(p.read(&mut buf), Io::Done(0), "end of file");
        assert_eq!(p.poll(true), POLLHUP);
        p.readers = 0;
        assert_eq!(p.write(b"x", true), Io::Broken);
        assert_eq!(
            p.write(b"", true),
            Io::Done(0),
            "an empty write is never broken"
        );
        assert_eq!(p.poll(false), POLLOUT | POLLWRNORM | POLLERR);
    }

    #[test]
    fn small_writes_are_atomic_and_large_ones_fill() {
        let mut p = Pipe::new();
        let big = alloc::vec![7u8; PIPE_CAPACITY - 100];
        assert_eq!(p.write(&big, false), Io::Done(PIPE_CAPACITY - 100));
        // 200 bytes do not fit in the 100 left: none go in.
        assert_eq!(p.write(&[1; 200], true), Io::WouldBlock);
        assert_eq!(p.write(&[1; 100], true), Io::Done(100));
        assert_eq!(p.poll(false), 0, "full");
        assert_eq!(p.write(&[1; 1], true), Io::WouldBlock);
        let mut out = alloc::vec![0u8; 5000];
        assert_eq!(p.read(&mut out), Io::Done(5000));
        // A write over PIPE_BUF takes what fits.
        assert_eq!(p.write(&alloc::vec![2u8; 9000], false), Io::Done(5000));
        // So does the tail of one, even under PIPE_BUF.
        p.read(&mut out[..10]);
        assert_eq!(p.write(&[3; 100], false), Io::Done(10));
        assert_eq!(p.len(), PIPE_CAPACITY);
    }

    #[test]
    fn pipes_count_their_wakes_as_linux_wakes() {
        let mut p = Pipe::new();
        let (rd, wr) = (p.rd_wakes, p.wr_wakes);
        p.write(b"x", true);
        assert!(p.rd_wakes.fired_since(&rd, EPOLLIN));
        assert_eq!(p.wr_wakes, wr, "a write wakes only readers");
        let mut b = [0u8; 1];
        p.read(&mut b);
        assert_eq!(
            p.wr_wakes, wr,
            "a read of a pipe that was not full wakes no one"
        );
        p.write(&alloc::vec![0u8; PIPE_CAPACITY], false);
        p.read(&mut b);
        assert!(p.wr_wakes.fired_since(&wr, EPOLLOUT));
        let (rd, wr) = (p.rd_wakes, p.wr_wakes);
        p.readers += 1;
        p.close_end(false);
        assert_eq!((p.rd_wakes, p.wr_wakes), (rd, wr), "a reader is left");
        p.close_end(false);
        assert!(p.rd_wakes.fired_since(&rd, EPOLLIN) && p.wr_wakes.fired_since(&wr, EPOLLOUT));
    }

    #[test]
    fn eventfd_counts_as_linux() {
        let mut c = EventCounter {
            count: 3,
            semaphore: false,
            wakes: Wakes::default(),
        };
        assert_eq!(c.poll(), POLLIN | POLLOUT);
        assert_eq!(c.read(), Some(3));
        assert_eq!(c.read(), None);
        assert_eq!(c.poll(), POLLOUT);
        assert!(c.write(u64::MAX - 1));
        assert_eq!(c.poll(), POLLIN, "at u64::MAX - 1 it is not writable");
        assert!(!c.write(1), "the sum may not reach u64::MAX");
        let mut s = EventCounter {
            count: 2,
            semaphore: true,
            wakes: Wakes::default(),
        };
        assert_eq!((s.read(), s.read(), s.read()), (Some(1), Some(1), None));
    }
}
