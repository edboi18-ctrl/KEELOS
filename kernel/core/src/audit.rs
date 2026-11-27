//! The audit log (P3-S6, ADR 0045; SR-11): compartment creation, every
//! grant, and denied operations, rate-limited, kept in the kernel and
//! readable only through an audit handle (which only the root factory can
//! open). Pure data, tested on the host; the kernel keeps one log behind
//! a lock.
//!
//! - Records are kept in order, each with a sequence number. The log
//!   holds at most `capacity`; when full, the oldest goes.
//! - A reader has a cursor (the next sequence number it wants). Reading
//!   gives whole lines of text, as many as fit. If the cursor is older
//!   than the oldest record kept, the reader first gets a line saying how
//!   many it lost.
//! - Denials are rate-limited per compartment by a token bucket
//!   ([`Limiter`]): a burst, then a steady rate. The next denial recorded
//!   after some were not says how many were suppressed.

use alloc::collections::VecDeque;
use alloc::string::String;
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::errno::Errno;

/// Who did something: a process, by its compartment and PID there, or
/// the kernel itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    Kernel,
    Process { compartment: u32, pid: u32 },
}

/// What was recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A compartment was created.
    Created {
        compartment: u32,
        by: Actor,
        profile: &'static str,
        processes: u32,
    },
    /// A device was granted to a compartment.
    Granted {
        compartment: u32,
        by: Actor,
        device: &'static str,
    },
    /// An operation was refused: a system call, an operation of one or an
    /// ioctl request outside its compartment's profile (ADR 0041), or a
    /// native call above its factory's ceiling (ADR 0040).
    Denied {
        compartment: u32,
        pid: u32,
        what: &'static str,
        number: u64,
        op: Option<u64>,
        errno: i32,
        /// Denials of this compartment not recorded since the last one
        /// that was (the rate limit).
        suppressed: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub time_ms: u64,
    pub event: Event,
}

impl Record {
    /// The record as one line of text.
    pub fn line(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "audit: seq={} time={}.{:03} ",
            self.seq,
            self.time_ms / 1000,
            self.time_ms % 1000
        );
        let by = |s: &mut String, by: Actor| {
            let _ = match by {
                Actor::Kernel => write!(s, " by=kernel"),
                Actor::Process { compartment, pid } => write!(s, " by=c{compartment}:{pid}"),
            };
        };
        match self.event {
            Event::Created {
                compartment,
                by: actor,
                profile,
                processes,
            } => {
                let _ = write!(
                    s,
                    "create c={compartment} profile={profile} processes={processes}"
                );
                by(&mut s, actor);
            }
            Event::Granted {
                compartment,
                by: actor,
                device,
            } => {
                let _ = write!(s, "grant c={compartment} device={device}");
                by(&mut s, actor);
            }
            Event::Denied {
                compartment,
                pid,
                what,
                number,
                op,
                errno,
                suppressed,
            } => {
                let _ = write!(s, "deny c={compartment} pid={pid} {what}({number})");
                if let Some(op) = op {
                    let _ = write!(s, " op={op:#x}");
                }
                let _ = write!(s, " errno={errno}");
                if suppressed > 0 {
                    let _ = write!(s, " suppressed={suppressed}");
                }
            }
        }
        s.push('\n');
        s
    }
}

/// The log.
#[derive(Debug)]
pub struct AuditLog {
    records: VecDeque<Record>,
    capacity: usize,
    next_seq: u64,
}

impl AuditLog {
    pub const fn new(capacity: usize) -> AuditLog {
        AuditLog {
            records: VecDeque::new(),
            capacity,
            next_seq: 0,
        }
    }

    /// Records `event` at `time_ms`, dropping the oldest record if full.
    pub fn push(&mut self, time_ms: u64, event: Event) -> u64 {
        if self.capacity == 0 {
            return self.next_seq;
        }
        if self.records.len() == self.capacity {
            self.records.pop_front();
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        self.records.push_back(Record {
            seq,
            time_ms,
            event,
        });
        seq
    }

    /// The sequence number of the oldest record kept (or the next one,
    /// when none is).
    pub fn oldest(&self) -> u64 {
        self.records.front().map_or(self.next_seq, |r| r.seq)
    }

    /// The records kept, oldest first.
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.iter()
    }

    /// Reads whole lines into `out` from `*cursor` on, and moves the
    /// cursor past them. A cursor older than the oldest record kept gets a
    /// `lost` line first. 0 when there is nothing new; EINVAL if the first
    /// line does not fit (as `/dev/kmsg` answers a buffer too small).
    pub fn read(&self, cursor: &mut u64, out: &mut [u8]) -> Result<usize, Errno> {
        let mut at = 0;
        let mut put = |line: &str, at: &mut usize| -> bool {
            let bytes = line.as_bytes();
            if *at + bytes.len() > out.len() {
                return false;
            }
            out[*at..*at + bytes.len()].copy_from_slice(bytes);
            *at += bytes.len();
            true
        };
        let oldest = self.oldest();
        if *cursor < oldest {
            let lost = alloc::format!("audit: lost={} before seq={oldest}\n", oldest - *cursor);
            if !put(&lost, &mut at) {
                return Err(Errno::EINVAL);
            }
            *cursor = oldest;
        }
        let from = *cursor;
        for record in self.records.iter().filter(|r| r.seq >= from) {
            if !put(&record.line(), &mut at) {
                if at == 0 {
                    return Err(Errno::EINVAL);
                }
                break;
            }
            *cursor = record.seq + 1;
        }
        Ok(at)
    }
}

/// A token bucket for one compartment's denial records: `BURST` at once,
/// then `RATE_PER_S` a second. Lock-free: the state is one atomic word,
/// the time of the last refill (48 bits of milliseconds) and the tokens
/// left (16 bits).
#[derive(Debug, Default)]
pub struct Limiter {
    state: AtomicU64,
    suppressed: AtomicU64,
}

/// Denial records a compartment may make at once.
pub const BURST: u64 = 32;
/// And then each second.
pub const RATE_PER_S: u64 = 1;

impl Limiter {
    /// A full bucket.
    pub const fn new() -> Limiter {
        Limiter {
            state: AtomicU64::new(BURST),
            suppressed: AtomicU64::new(0),
        }
    }

    /// Whether a denial at `now_ms` may be recorded. If so, the number
    /// suppressed since the last recorded one (and that count starts
    /// again); if not, None, and it is counted as suppressed.
    pub fn admit(&self, now_ms: u64) -> Option<u64> {
        let now = now_ms & ((1 << 48) - 1);
        let mut state = self.state.load(Ordering::Relaxed);
        loop {
            let (last, tokens) = (state >> 16, state & 0xffff);
            // Refill whole tokens for the time since `last`; keep the
            // remainder by moving `last` only as far as they account for.
            let elapsed = now.saturating_sub(last);
            let earned = (elapsed * RATE_PER_S / 1000).min(BURST);
            let (last, tokens) = if earned > 0 || tokens >= BURST {
                let tokens = (tokens + earned).min(BURST);
                let last = if tokens == BURST {
                    now
                } else {
                    last + earned * 1000 / RATE_PER_S
                };
                (last, tokens)
            } else {
                (last, tokens)
            };
            let (next, admitted) = if tokens > 0 {
                ((last << 16) | (tokens - 1), true)
            } else {
                ((last << 16) | tokens, false)
            };
            match self
                .state
                .compare_exchange_weak(state, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) if admitted => return Some(self.suppressed.swap(0, Ordering::AcqRel)),
                Ok(_) => {
                    self.suppressed.fetch_add(1, Ordering::AcqRel);
                    return None;
                }
                Err(current) => state = current,
            }
        }
    }

    /// Denials suppressed and not yet reported.
    pub fn pending(&self) -> u64 {
        self.suppressed.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn created(c: u32) -> Event {
        Event::Created {
            compartment: c,
            by: Actor::Process {
                compartment: 0,
                pid: 1,
            },
            profile: "default",
            processes: 64,
        }
    }

    fn read_all(log: &AuditLog, cursor: &mut u64) -> String {
        let mut out = [0u8; 4096];
        let n = log.read(cursor, &mut out).unwrap();
        String::from_utf8(out[..n].to_vec()).unwrap()
    }

    #[test]
    fn lines_read_in_order_and_once() {
        let mut log = AuditLog::new(8);
        log.push(1500, created(3));
        log.push(
            1501,
            Event::Granted {
                compartment: 3,
                by: Actor::Kernel,
                device: "null",
            },
        );
        log.push(
            2000,
            Event::Denied {
                compartment: 3,
                pid: 1,
                what: "getppid",
                number: 110,
                op: None,
                errno: 38,
                suppressed: 0,
            },
        );
        let mut cursor = 0;
        assert_eq!(
            read_all(&log, &mut cursor),
            "audit: seq=0 time=1.500 create c=3 profile=default processes=64 by=c0:1\n\
             audit: seq=1 time=1.501 grant c=3 device=null by=kernel\n\
             audit: seq=2 time=2.000 deny c=3 pid=1 getppid(110) errno=38\n"
        );
        assert_eq!(cursor, 3);
        assert_eq!(read_all(&log, &mut cursor), "");
        // A denial with an operation and suppressed ones.
        log.push(
            2001,
            Event::Denied {
                compartment: 3,
                pid: 2,
                what: "fcntl",
                number: 72,
                op: Some(1),
                errno: 22,
                suppressed: 5,
            },
        );
        assert_eq!(
            read_all(&log, &mut cursor),
            "audit: seq=3 time=2.001 deny c=3 pid=2 fcntl(72) op=0x1 errno=22 suppressed=5\n"
        );
    }

    #[test]
    fn a_small_buffer_gets_whole_lines_or_einval() {
        let mut log = AuditLog::new(8);
        log.push(0, created(1));
        log.push(0, created(2));
        let one = log.records().next().unwrap().line().len();
        let mut cursor = 0;
        let mut tiny = [0u8; 10];
        assert_eq!(log.read(&mut cursor, &mut tiny), Err(Errno::EINVAL));
        assert_eq!(cursor, 0);
        let mut room = alloc::vec![0u8; one + 5];
        assert_eq!(log.read(&mut cursor, &mut room), Ok(one));
        assert_eq!(cursor, 1);
        assert_eq!(log.read(&mut cursor, &mut room), Ok(one));
        assert_eq!(cursor, 2);
    }

    #[test]
    fn a_full_log_drops_the_oldest_and_a_late_reader_hears_of_it() {
        let mut log = AuditLog::new(3);
        for c in 0..5 {
            log.push(0, created(c));
        }
        assert_eq!(log.oldest(), 2);
        let mut cursor = 0;
        let text = read_all(&log, &mut cursor);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "audit: lost=2 before seq=2");
        assert_eq!(lines.len(), 4);
        assert!(lines[1].starts_with("audit: seq=2 "));
        assert_eq!(cursor, 5);
    }

    #[test]
    fn the_limiter_allows_a_burst_then_its_rate() {
        let l = Limiter::new();
        for _ in 0..BURST {
            assert_eq!(l.admit(1000), Some(0));
        }
        assert_eq!(l.admit(1000), None);
        assert_eq!(l.admit(1500), None);
        assert_eq!(l.pending(), 2);
        // One second later, one token, and the two suppressed are told.
        assert_eq!(l.admit(2000), Some(2));
        assert_eq!(l.admit(2000), None);
        assert_eq!(l.admit(2999), None);
        assert_eq!(l.admit(3000), Some(2));
        // A long quiet time refills to the burst, not beyond.
        for _ in 0..BURST {
            assert!(l.admit(1_000_000).is_some());
        }
        assert_eq!(l.admit(1_000_000), None);
    }

    #[test]
    fn the_limiter_never_admits_more_than_its_budget() {
        // Over 10 simulated seconds, at most BURST + 10 * RATE_PER_S.
        // Every denial is either recorded or counted as suppressed, and
        // each suppressed one is reported exactly once.
        let l = Limiter::new();
        let (mut admitted, mut reported) = (0u64, 0u64);
        for t in 0..10_000u64 {
            if let Some(n) = l.admit(t) {
                admitted += 1;
                reported += n;
            }
        }
        assert!(admitted <= BURST + 10 * RATE_PER_S, "{admitted}");
        assert!(admitted >= BURST + 9 * RATE_PER_S, "{admitted}");
        assert_eq!(admitted + reported + l.pending(), 10_000);
    }
}
