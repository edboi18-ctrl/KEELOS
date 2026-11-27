//! The scheduler's ready queue, fair between compartments (P3-S4, ADR
//! 0042; SR-8, "CPU share").
//!
//! Ready threads are kept per group (a compartment's ID; kernel threads
//! are in the system compartment's, 0). The groups take turns: each pick
//! takes the first thread of the group at the front, and that group goes
//! to the back if it has more ready threads. So when every group is
//! busy, each gets an equal share of the CPU however many threads it
//! has, and a fork bomb or a thread pool in one compartment cannot crowd
//! out another. Within a group, threads take turns in the order they
//! became ready, as the single queue did before.
//!
//! Invariant: a group is in `turns` exactly when its queue is not empty,
//! and then exactly once.

use alloc::collections::{BTreeMap, VecDeque};

/// Ready threads by group, and the order in which groups take turns.
#[derive(Debug, Default)]
pub struct FairQueue {
    turns: VecDeque<u32>,
    queues: BTreeMap<u32, VecDeque<u64>>,
    len: usize,
}

impl FairQueue {
    pub const fn new() -> FairQueue {
        FairQueue {
            turns: VecDeque::new(),
            queues: BTreeMap::new(),
            len: 0,
        }
    }

    /// Adds thread `id` of `group` at the back of its group's queue. A
    /// group that had nothing ready joins the back of the turns.
    pub fn push(&mut self, group: u32, id: u64) {
        let queue = self.queues.entry(group).or_default();
        if queue.is_empty() {
            self.turns.push_back(group);
        }
        queue.push_back(id);
        self.len += 1;
    }

    /// The next thread to run: the first of the group whose turn it is.
    pub fn pop(&mut self) -> Option<u64> {
        let group = self.turns.pop_front()?;
        let queue = self.queues.get_mut(&group)?;
        let id = queue.pop_front();
        if queue.is_empty() {
            self.queues.remove(&group);
        } else {
            self.turns.push_back(group);
        }
        if id.is_some() {
            self.len -= 1;
        }
        id
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// How many groups have a thread ready.
    pub fn groups(&self) -> usize {
        self.turns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Runs `slices` picks where every picked thread stays ready (a CPU
    /// hog), and counts the slices each group got.
    fn share(
        q: &mut FairQueue,
        group_of: impl Fn(u64) -> u32,
        slices: usize,
    ) -> BTreeMap<u32, usize> {
        let mut got = BTreeMap::new();
        for _ in 0..slices {
            let id = q.pop().unwrap();
            *got.entry(group_of(id)).or_insert(0) += 1;
            q.push(group_of(id), id);
        }
        got
    }

    #[test]
    fn groups_share_equally_whatever_their_thread_counts() {
        // Group 1 has 64 hogs (a fork bomb), group 2 one.
        let mut q = FairQueue::new();
        for id in 0..64 {
            q.push(1, id);
        }
        q.push(2, 1000);
        let group_of = |id: u64| if id >= 1000 { 2 } else { 1 };
        let got = share(&mut q, group_of, 1000);
        assert_eq!(got[&1], 500);
        assert_eq!(got[&2], 500);
        assert_eq!(q.len(), 65);
    }

    #[test]
    fn three_groups_take_turns_in_order() {
        let mut q = FairQueue::new();
        q.push(5, 1);
        q.push(5, 2);
        q.push(7, 3);
        q.push(9, 4);
        let order: Vec<u64> = core::iter::from_fn(|| q.pop()).collect();
        assert_eq!(order, [1, 3, 4, 2]);
        assert!(q.is_empty());
        assert_eq!(q.groups(), 0);
    }

    #[test]
    fn within_a_group_threads_keep_their_order() {
        let mut q = FairQueue::new();
        for id in 10..20 {
            q.push(3, id);
        }
        let order: Vec<u64> = core::iter::from_fn(|| q.pop()).collect();
        assert_eq!(order, (10..20).collect::<Vec<_>>());
    }

    #[test]
    fn a_group_that_empties_leaves_the_turns_and_rejoins_at_the_back() {
        let mut q = FairQueue::new();
        q.push(1, 1);
        q.push(2, 2);
        assert_eq!(q.pop(), Some(1));
        assert_eq!(q.groups(), 1);
        q.push(1, 3);
        // Group 2 was waiting; group 1 rejoins behind it.
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), Some(3));
        assert_eq!(q.pop(), None);
        assert!(q.queues.is_empty() && q.turns.is_empty());
    }

    #[test]
    fn the_invariant_holds_under_random_use() {
        // xorshift64 (Marsaglia 2003, shifts 13, 7, 17), a fixed seed.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut q = FairQueue::new();
        let mut model: Vec<(u32, u64)> = Vec::new();
        for id in 0..5_000u64 {
            if next() % 3 == 0 {
                match q.pop() {
                    Some(got) => {
                        let at = model.iter().position(|(_, i)| *i == got).unwrap();
                        model.remove(at);
                    }
                    None => assert!(model.is_empty()),
                }
            } else {
                let group = (next() % 6) as u32;
                q.push(group, id);
                model.push((group, id));
            }
            assert_eq!(q.len(), model.len());
            let mut groups: Vec<u32> = model.iter().map(|(g, _)| *g).collect();
            groups.sort_unstable();
            groups.dedup();
            assert_eq!(q.groups(), groups.len());
            let mut turns: Vec<u32> = q.turns.iter().copied().collect();
            turns.sort_unstable();
            assert_eq!(turns, groups);
        }
    }
}
