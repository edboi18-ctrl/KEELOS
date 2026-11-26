//! epoll's interest set and ready list as data (P3-T10 part 2, ADR 0026),
//! tested on the host; `keel-linux-abi` adds the descriptors, the objects
//! and the waits. Rules from Linux v6.12 `fs/eventpoll.c` and
//! `include/uapi/linux/eventpoll.h`.
//!
//! Linux hooks every item onto its file's wait queues, and a wake whose
//! key (the events it announces) matches the item's interest puts the item
//! on the ready list (`ep_poll_callback`). Keel's objects instead count
//! their wakes by key ([`Wakes`]), and an item compares the counts with
//! those it saw last ([`Set::note`]): a count that moved, for a key that
//! matches, links the item as the callback would have.

use alloc::collections::{BTreeMap, VecDeque};

use crate::errno::Errno;

pub const EPOLLIN: u32 = 0x0001;
pub const EPOLLPRI: u32 = 0x0002;
pub const EPOLLOUT: u32 = 0x0004;
pub const EPOLLERR: u32 = 0x0008;
pub const EPOLLHUP: u32 = 0x0010;
pub const EPOLLRDNORM: u32 = 0x0040;
pub const EPOLLWRNORM: u32 = 0x0100;
pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub const EPOLLWAKEUP: u32 = 1 << 29;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;

/// The bits that are about how an item behaves, not what it waits for
/// (`EP_PRIVATE_BITS`).
pub const EP_PRIVATE_BITS: u32 = EPOLLWAKEUP | EPOLLONESHOT | EPOLLET | EPOLLEXCLUSIVE;
/// What an EPOLLEXCLUSIVE item may ask for (`EPOLLEXCLUSIVE_OK_BITS`).
pub const EPOLLEXCLUSIVE_OK_BITS: u32 =
    EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLWAKEUP | EPOLLET | EPOLLEXCLUSIVE;

/// `struct epoll_event` on x86-64: `__poll_t events; __u64 data;`,
/// packed (`EPOLL_PACKED`), 12 bytes.
pub const EVENT_SIZE: usize = 12;
/// The most events one wait may ask for (`EP_MAX_EVENTS`: INT_MAX / 12).
pub const MAX_EVENTS: i32 = i32::MAX / EVENT_SIZE as i32;

/// The `struct epoll_event` bytes for `events` and `data`.
pub fn event_bytes(events: u32, data: u64) -> [u8; EVENT_SIZE] {
    let mut b = [0u8; EVENT_SIZE];
    b[..4].copy_from_slice(&events.to_le_bytes());
    b[4..].copy_from_slice(&data.to_le_bytes());
    b
}

/// A `struct epoll_event` read from user memory.
pub fn parse_event(b: &[u8; EVENT_SIZE]) -> (u32, u64) {
    let events = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let mut data = [0u8; 8];
    data.copy_from_slice(&b[4..]);
    (events, u64::from_le_bytes(data))
}

/// How many wakes one wait queue has had, per key (the events a wake
/// announces; 0 is a wake for everything, as `wake_up_interruptible_all`).
/// An object has a few keys at most, so a small fixed table does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wakes {
    counts: [(u32, u64); 4],
}

impl Wakes {
    pub const fn new() -> Self {
        Wakes {
            counts: [(0, 0); 4],
        }
    }

    /// A wake with `key`. A fifth distinct key is counted as a wake for
    /// everything, which can only add a spurious edge, never lose one.
    pub fn wake(&mut self, key: u32) {
        let slot = self
            .counts
            .iter()
            .position(|&(k, n)| k == key && n > 0)
            .or_else(|| self.counts.iter().position(|&(_, n)| n == 0));
        match slot {
            Some(i) => {
                self.counts[i].0 = key;
                self.counts[i].1 += 1;
            }
            None => self.wake_all_slot(),
        }
    }

    /// The wakes of two queues as one (an object that waits on both, as a
    /// FIFO opened for reading and writing): each key's counts added. A
    /// key that finds no slot is counted as a wake for everything, so a
    /// wake is never lost, only possibly spurious.
    pub fn merged(&self, other: &Wakes) -> Wakes {
        let mut out = *self;
        for &(key, n) in other.counts.iter().filter(|&&(_, n)| n > 0) {
            let slot = out
                .counts
                .iter()
                .position(|&(k, m)| k == key && m > 0)
                .or_else(|| out.counts.iter().position(|&(_, m)| m == 0));
            match slot {
                Some(i) => {
                    out.counts[i].0 = key;
                    out.counts[i].1 += n;
                }
                None => out.wake_all_slot_by(n),
            }
        }
        out
    }

    fn wake_all_slot(&mut self) {
        self.wake_all_slot_by(1);
    }

    /// `n` wakes for everything.
    fn wake_all_slot_by(&mut self, n: u64) {
        if let Some(i) = self.counts.iter().position(|&(k, _)| k == 0) {
            self.counts[i].1 += n;
        } else {
            // Turn the least used slot into the everything slot.
            let i = (0..4).min_by_key(|&i| self.counts[i].1).unwrap_or(0);
            self.counts[i] = (0, self.counts[i].1 + n);
        }
    }

    /// Whether, since `before`, a wake came whose key matches `events`
    /// (`ep_poll_callback`: a key of 0, or one sharing a bit with the
    /// interest).
    pub fn fired_since(&self, before: &Wakes, events: u32) -> bool {
        self.counts.iter().any(|&(key, n)| {
            let old = before
                .counts
                .iter()
                .find(|&&(k, m)| k == key && m > 0)
                .map_or(0, |&(_, m)| m);
            n > old && (key == 0 || key & events != 0)
        })
    }
}

/// What an `epoll_ctl` asks for: the interest and the user's data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Interest {
    pub events: u32,
    pub data: u64,
}

#[derive(Clone, Copy, Debug)]
struct Item {
    interest: Interest,
    /// On the ready list (`ep_is_linked`).
    linked: bool,
    /// The wakes the item saw last.
    seen: Wakes,
}

impl Item {
    /// `ep_poll_callback`'s first test: an item whose interest has no
    /// event left (after EPOLLONESHOT fired) is disabled.
    fn enabled(&self) -> bool {
        self.interest.events & !EP_PRIVATE_BITS != 0
    }
}

/// One epoll instance: its items by key (Linux's (file, fd) pair) and its
/// ready list (`rdllist`), in order.
#[derive(Debug)]
pub struct Set<K: Ord + Copy> {
    items: BTreeMap<K, Item>,
    ready: VecDeque<K>,
}

impl<K: Ord + Copy> Default for Set<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Ord + Copy> Set<K> {
    pub const fn new() -> Self {
        Set {
            items: BTreeMap::new(),
            ready: VecDeque::new(),
        }
    }

    pub fn contains(&self, key: K) -> bool {
        self.items.contains_key(&key)
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The interest of `key`, if it is in the set.
    pub fn interest(&self, key: K) -> Option<Interest> {
        self.items.get(&key).map(|i| i.interest)
    }

    fn link(&mut self, key: K) {
        if let Some(item) = self.items.get_mut(&key)
            && !item.linked
        {
            item.linked = true;
            self.ready.push_back(key);
        }
    }

    /// EPOLL_CTL_ADD (`ep_insert`): EEXIST if `key` is there; the interest
    /// gains EPOLLERR and EPOLLHUP; an item ready now (`ready`: the
    /// target's poll mask) goes on the ready list. `wakes` is what the
    /// target's queue has seen so far.
    pub fn add(
        &mut self,
        key: K,
        interest: Interest,
        ready: u32,
        wakes: Wakes,
    ) -> Result<(), Errno> {
        if self.items.contains_key(&key) {
            return Err(Errno::EEXIST);
        }
        let interest = Interest {
            events: interest.events | EPOLLERR | EPOLLHUP,
            ..interest
        };
        self.items.insert(
            key,
            Item {
                interest,
                linked: false,
                seen: wakes,
            },
        );
        if ready & interest.events != 0 {
            self.link(key);
        }
        Ok(())
    }

    /// EPOLL_CTL_MOD (`ep_modify`): ENOENT if `key` is not there; EINVAL
    /// for an item added with EPOLLEXCLUSIVE; otherwise the new interest
    /// (with EPOLLERR and EPOLLHUP), and on the ready list if ready now.
    pub fn modify(
        &mut self,
        key: K,
        interest: Interest,
        ready: u32,
        wakes: Wakes,
    ) -> Result<(), Errno> {
        let item = self.items.get_mut(&key).ok_or(Errno::ENOENT)?;
        if item.interest.events & EPOLLEXCLUSIVE != 0 {
            return Err(Errno::EINVAL);
        }
        item.interest = Interest {
            events: interest.events | EPOLLERR | EPOLLHUP,
            ..interest
        };
        item.seen = wakes;
        let events = item.interest.events;
        if ready & events != 0 {
            self.link(key);
        }
        Ok(())
    }

    /// EPOLL_CTL_DEL, and an item whose file went away
    /// (`ep_remove`): ENOENT if `key` is not there.
    pub fn remove(&mut self, key: K) -> Result<(), Errno> {
        self.items.remove(&key).ok_or(Errno::ENOENT)?;
        self.ready.retain(|&k| k != key);
        Ok(())
    }

    /// The keys of every item, for the caller to look at their targets.
    pub fn keys(&self) -> impl Iterator<Item = K> + '_ {
        self.items.keys().copied()
    }

    /// What `key`'s target's queue has seen now: a wake that matches the
    /// item's interest since it last looked links it, as
    /// `ep_poll_callback` would have (unless the item is disabled).
    pub fn note(&mut self, key: K, wakes: Wakes) {
        let Some(item) = self.items.get_mut(&key) else {
            return;
        };
        let fired = item.enabled() && wakes.fired_since(&item.seen, item.interest.events);
        item.seen = wakes;
        if fired {
            self.link(key);
        }
    }

    /// Whether the ready list has anything (`ep_events_available`).
    pub fn has_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// `ep_send_events`: takes the ready list and, for each item while
    /// fewer than `max` are reported, asks `poll` what it is ready for (its
    /// target's mask; None if the target is gone). An item ready for
    /// nothing it wants leaves the list. Otherwise `put` reports it (the
    /// mask & the interest, and the data); if `put` fails (a fault), the
    /// item goes back and the call is EFAULT if nothing was reported, else
    /// the count so far. A reported item:
    /// - with EPOLLONESHOT, is disabled (its interest keeps only the
    ///   private bits) until EPOLL_CTL_MOD;
    /// - with EPOLLET, leaves the list until its next wake;
    /// - otherwise (level-triggered) goes back on the end of the list.
    ///
    /// Items not reached stay first on the list, in their order
    /// (`ep_done_scan` splices them back at the head).
    pub fn send(
        &mut self,
        max: usize,
        mut poll: impl FnMut(K) -> Option<u32>,
        mut put: impl FnMut(u32, u64) -> bool,
    ) -> Result<usize, Errno> {
        let mut taken = core::mem::take(&mut self.ready);
        let mut sent = 0;
        let mut faulted = false;
        while sent < max {
            let Some(key) = taken.pop_front() else {
                break;
            };
            let Some(item) = self.items.get_mut(&key) else {
                continue;
            };
            item.linked = false;
            let mask = poll(key).unwrap_or(0) & item.interest.events;
            if mask == 0 {
                continue;
            }
            if !put(mask, item.interest.data) {
                item.linked = true;
                taken.push_front(key);
                faulted = true;
                break;
            }
            sent += 1;
            if item.interest.events & EPOLLONESHOT != 0 {
                item.interest.events &= EP_PRIVATE_BITS;
            } else if item.interest.events & EPOLLET == 0 {
                item.linked = true;
                self.ready.push_back(key);
            }
        }
        // The rest of the taken list goes first, then the re-added items.
        while let Some(key) = taken.pop_back() {
            self.ready.push_front(key);
        }
        if faulted && sent == 0 {
            Err(Errno::EFAULT)
        } else {
            Ok(sent)
        }
    }

    /// `__ep_eventpoll_poll`, for poll(2) on the epoll descriptor itself:
    /// whether a listed item is ready now; items that are not leave the
    /// list.
    pub fn any_ready(&mut self, mut poll: impl FnMut(K) -> Option<u32>) -> bool {
        while let Some(&key) = self.ready.front() {
            let events = self.items.get(&key).map_or(0, |i| i.interest.events);
            if poll(key).unwrap_or(0) & events != 0 {
                return true;
            }
            self.ready.pop_front();
            if let Some(item) = self.items.get_mut(&key) {
                item.linked = false;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interest(events: u32, data: u64) -> Interest {
        Interest { events, data }
    }

    /// Runs `send` with fixed masks per key; returns (events, data) pairs.
    fn drain(set: &mut Set<u32>, max: usize, masks: &[(u32, u32)]) -> alloc::vec::Vec<(u32, u64)> {
        let mut out = alloc::vec::Vec::new();
        let got = set.send(
            max,
            |k| masks.iter().find(|m| m.0 == k).map(|m| m.1),
            |e, d| {
                out.push((e, d));
                true
            },
        );
        assert_eq!(got, Ok(out.len()));
        out
    }

    #[test]
    fn ctl_errors_and_implicit_bits() {
        let mut s: Set<u32> = Set::new();
        let w = Wakes::default();
        assert_eq!(s.add(1, interest(EPOLLIN, 7), 0, w), Ok(()));
        assert_eq!(s.add(1, interest(EPOLLIN, 7), 0, w), Err(Errno::EEXIST));
        assert_eq!(
            s.interest(1).map(|i| i.events),
            Some(EPOLLIN | EPOLLERR | EPOLLHUP)
        );
        assert_eq!(s.modify(2, interest(EPOLLIN, 0), 0, w), Err(Errno::ENOENT));
        assert_eq!(s.remove(2), Err(Errno::ENOENT));
        assert_eq!(
            s.add(3, interest(EPOLLIN | EPOLLEXCLUSIVE, 0), 0, w),
            Ok(())
        );
        assert_eq!(s.modify(3, interest(EPOLLIN, 0), 0, w), Err(Errno::EINVAL));
        assert_eq!(s.remove(1), Ok(()));
        assert!(!s.contains(1));
    }

    #[test]
    fn level_triggered_items_stay_ready_and_rotate() {
        let mut s: Set<u32> = Set::new();
        let w = Wakes::default();
        s.add(1, interest(EPOLLIN, 10), EPOLLIN, w).unwrap();
        s.add(2, interest(EPOLLIN, 20), EPOLLIN, w).unwrap();
        s.add(3, interest(EPOLLOUT, 30), 0, w).unwrap();
        let masks = [(1, EPOLLIN), (2, EPOLLIN | EPOLLOUT), (3, EPOLLOUT)];
        // Only what the interest asks for is reported; 3 was not ready at
        // ADD and has had no wake, so it is not listed.
        assert_eq!(drain(&mut s, 1, &masks), [(EPOLLIN, 10)]);
        // 2 was not reached: it comes first, then 1 again at the end.
        assert_eq!(drain(&mut s, 8, &masks), [(EPOLLIN, 20), (EPOLLIN, 10)]);
        // Each goes back on the end as it is reported: the same order.
        assert_eq!(drain(&mut s, 8, &masks), [(EPOLLIN, 20), (EPOLLIN, 10)]);
        // No longer ready: it leaves the list.
        assert_eq!(drain(&mut s, 8, &[(2, EPOLLIN)]), [(EPOLLIN, 20)]);
        assert_eq!(drain(&mut s, 8, &[(2, EPOLLIN)]), [(EPOLLIN, 20)]);
    }

    #[test]
    fn edge_triggered_items_need_a_matching_wake() {
        let mut s: Set<u32> = Set::new();
        let mut w = Wakes::default();
        s.add(1, interest(EPOLLIN | EPOLLET, 1), EPOLLIN, w)
            .unwrap();
        let masks = [(1, EPOLLIN)];
        assert_eq!(drain(&mut s, 8, &masks), [(EPOLLIN, 1)]);
        assert!(drain(&mut s, 8, &masks).is_empty(), "no new edge");
        // A wake for writers does not match a reader's interest.
        w.wake(EPOLLOUT | EPOLLWRNORM);
        s.note(1, w);
        assert!(!s.has_ready());
        w.wake(EPOLLIN | EPOLLRDNORM);
        s.note(1, w);
        assert_eq!(drain(&mut s, 8, &masks), [(EPOLLIN, 1)]);
        // A wake for everything (a hang-up) matches anything.
        w.wake(0);
        s.note(1, w);
        assert!(s.has_ready());
        // The same counts again: no new edge.
        let _ = drain(&mut s, 8, &masks);
        s.note(1, w);
        assert!(!s.has_ready());
    }

    #[test]
    fn oneshot_disables_until_modify() {
        let mut s: Set<u32> = Set::new();
        let mut w = Wakes::default();
        s.add(1, interest(EPOLLIN | EPOLLONESHOT, 5), EPOLLIN, w)
            .unwrap();
        let masks = [(1, EPOLLIN)];
        assert_eq!(drain(&mut s, 8, &masks), [(EPOLLIN, 5)]);
        w.wake(EPOLLIN);
        s.note(1, w);
        assert!(!s.has_ready(), "disabled");
        assert_eq!(s.interest(1).map(|i| i.events), Some(EPOLLONESHOT));
        s.modify(1, interest(EPOLLIN, 6), EPOLLIN, w).unwrap();
        assert_eq!(drain(&mut s, 8, &masks), [(EPOLLIN, 6)]);
    }

    #[test]
    fn a_fault_puts_the_item_back() {
        let mut s: Set<u32> = Set::new();
        let w = Wakes::default();
        s.add(1, interest(EPOLLIN, 1), EPOLLIN, w).unwrap();
        s.add(2, interest(EPOLLIN, 2), EPOLLIN, w).unwrap();
        let masks = |_| Some(EPOLLIN);
        assert_eq!(s.send(8, masks, |_, _| false), Err(Errno::EFAULT));
        let mut n = 0;
        assert_eq!(
            s.send(8, masks, |_, _| {
                n += 1;
                n == 1
            }),
            Ok(1)
        );
        assert!(s.has_ready());
    }

    #[test]
    fn poll_on_the_set_drops_items_no_longer_ready() {
        let mut s: Set<u32> = Set::new();
        let w = Wakes::default();
        s.add(1, interest(EPOLLIN, 1), EPOLLIN, w).unwrap();
        assert!(s.any_ready(|_| Some(EPOLLIN)));
        assert!(!s.any_ready(|_| Some(0)));
        assert!(!s.has_ready());
    }

    #[test]
    fn wakes_count_by_key() {
        let mut w = Wakes::default();
        let before = w;
        w.wake(EPOLLIN);
        assert!(w.fired_since(&before, EPOLLIN | EPOLLERR));
        assert!(!w.fired_since(&before, EPOLLOUT | EPOLLERR | EPOLLHUP));
        let mid = w;
        for key in [EPOLLOUT, EPOLLHUP, EPOLLPRI, EPOLLWRNORM] {
            w.wake(key);
        }
        // The fifth key is counted as a wake for everything.
        assert!(w.fired_since(&mid, EPOLLRDNORM));
        let parsed = parse_event(&event_bytes(EPOLLIN | EPOLLET, 0x1122_3344_5566_7788));
        assert_eq!(parsed, (EPOLLIN | EPOLLET, 0x1122_3344_5566_7788));
        assert_eq!(MAX_EVENTS, 178_956_970);
    }
}
