//! Kernel threads and the round-robin preemptive scheduler (P1-T8).
//!
//! - Every thread has its own kernel stack with an unmapped guard page
//!   below it (SR-17) and its own FPU/SSE/AVX save area.
//! - The 1 kHz timer requests a reschedule every `QUANTUM_TICKS` ticks and
//!   whenever a sleeping thread is due; the switch happens on the way out
//!   of the interrupt, after the EOI.
//! - All scheduler state is protected by an interrupt-disabling lock, and
//!   switches happen with interrupts disabled. The heap, page-table and
//!   frame locks also disable interrupts (`sync::IrqMutex`), so no thread
//!   is ever preempted while holding one, and the scheduler can always
//!   take them.
//! - Single CPU (decision D8). The design keeps all shared state behind
//!   locks so SMP can be added in Phase 6 without changing the interface.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::fpu::FpuState;
use crate::arch::x86_64::paging::{self, KernelStack};
use crate::arch::x86_64::{gdt, switch};
use crate::sync::IrqMutex;
use crate::time;

/// Pages per kernel stack (64 KiB).
pub const STACK_PAGES: u64 = 16;
/// Timer ticks per time slice (10 ms at 1 kHz).
const QUANTUM_TICKS: u64 = 10;

/// Identifies a thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Running,
    Ready,
    Blocked,
    Sleeping { until_ns: u64 },
    Exited,
}

struct Thread {
    name: &'static str,
    state: State,
    /// Saved stack pointer while not running.
    rsp: u64,
    /// `None` for the boot thread, which runs on the bootloader's stack.
    stack: Option<KernelStack>,
    fpu: FpuState,
}

struct Scheduler {
    /// Boxed so a thread's `rsp` field stays at a fixed address while the
    /// map changes.
    threads: BTreeMap<u64, Box<Thread>>,
    ready: VecDeque<u64>,
    current: u64,
    idle: u64,
    next_id: u64,
}

static SCHED: IrqMutex<Option<Scheduler>> = IrqMutex::new(None);
static NEED_RESCHED: AtomicBool = AtomicBool::new(false);
/// Earliest wake-up time of any sleeping thread, in monotonic ns.
static NEXT_WAKE_NS: AtomicU64 = AtomicU64::new(u64::MAX);
static SWITCHES: AtomicU64 = AtomicU64::new(0);
/// Woken whenever any thread exits.
static EXITS: WaitQueue = WaitQueue::new();

/// Why `init` or `spawn` failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedError {
    NotInitialised,
    AlreadyInitialised,
    OutOfMemory,
}

/// Turns the running code into thread 0 ("boot") and creates the idle
/// thread. Call once, after the heap, paging, interrupts and FPU are set
/// up.
pub fn init() -> Result<(), SchedError> {
    let mut guard = SCHED.lock();
    if guard.is_some() {
        return Err(SchedError::AlreadyInitialised);
    }
    let boot = Box::new(Thread {
        name: "boot",
        state: State::Running,
        rsp: 0,
        stack: None,
        fpu: FpuState::new().ok_or(SchedError::OutOfMemory)?,
    });
    let mut sched = Scheduler {
        threads: BTreeMap::new(),
        ready: VecDeque::new(),
        current: 0,
        idle: 1,
        next_id: 2,
    };
    sched.threads.insert(0, boot);
    let idle = new_thread("idle", idle_loop, 1)?;
    sched.threads.insert(1, idle);
    *guard = Some(sched);
    Ok(())
}

fn idle_loop() {
    loop {
        crate::interrupts::wait();
    }
}

fn new_thread(name: &'static str, entry: fn(), id: u64) -> Result<Box<Thread>, SchedError> {
    let stack = paging::map_kernel_stack(STACK_PAGES).ok_or(SchedError::OutOfMemory)?;
    // SAFETY: the stack was just mapped for this thread alone; its top is
    // page-aligned, hence 16-byte aligned, and it is 64 KiB long.
    let rsp = unsafe { switch::prepare_stack(stack.top, entry as usize as u64, id) };
    Ok(Box::new(Thread {
        name,
        state: State::Ready,
        rsp,
        stack: Some(stack),
        fpu: FpuState::new().ok_or(SchedError::OutOfMemory)?,
    }))
}

/// Starts a new kernel thread running `entry`. It is scheduled after the
/// threads already waiting.
pub fn spawn(name: &'static str, entry: fn()) -> Result<ThreadId, SchedError> {
    // Allocate outside the scheduler lock where possible.
    let id = {
        let mut guard = SCHED.lock();
        let sched = guard.as_mut().ok_or(SchedError::NotInitialised)?;
        let id = sched.next_id;
        sched.next_id += 1;
        id
    };
    let thread = new_thread(name, entry, id)?;
    let mut guard = SCHED.lock();
    let sched = guard.as_mut().ok_or(SchedError::NotInitialised)?;
    sched.threads.insert(id, thread);
    sched.ready.push_back(id);
    Ok(ThreadId(id))
}

/// Entered (via the trampoline) when a new thread runs for the first time,
/// with interrupts still disabled from the switch.
pub(crate) extern "C" fn thread_start(entry: usize, _id: u64) -> ! {
    // The switch that started this thread happened with interrupts off and
    // the scheduler lock already released; turn interrupts back on.
    crate::interrupts::enable_after_switch();
    // The thread that switched to us may have just exited; free it.
    reap();
    // SAFETY: `entry` was produced from a `fn()` in `new_thread`.
    let entry: fn() = unsafe { core::mem::transmute::<usize, fn()>(entry) };
    entry();
    exit();
}

/// The running thread's ID.
pub fn current() -> ThreadId {
    ThreadId(SCHED.lock().as_ref().map_or(0, |s| s.current))
}

/// Number of context switches so far.
pub fn switch_count() -> u64 {
    SWITCHES.load(Ordering::Relaxed)
}

/// Called from the timer interrupt (interrupts disabled).
pub(crate) fn on_tick(tick: u64) {
    if tick.is_multiple_of(QUANTUM_TICKS)
        || time::monotonic_nanos() >= NEXT_WAKE_NS.load(Ordering::Relaxed)
    {
        NEED_RESCHED.store(true, Ordering::Relaxed);
    }
}

/// Called on the way out of a device interrupt, after the EOI.
pub(crate) fn preempt_if_needed() {
    if NEED_RESCHED.swap(false, Ordering::Relaxed) {
        schedule(State::Ready);
    }
}

/// Gives the CPU to the next ready thread, if any.
pub fn yield_now() {
    schedule(State::Ready);
}

/// Sleeps for at least `ms` milliseconds.
pub fn sleep_ms(ms: u64) {
    let until_ns = time::monotonic_nanos().saturating_add(ms.saturating_mul(1_000_000));
    NEXT_WAKE_NS.fetch_min(until_ns, Ordering::Relaxed);
    schedule(State::Sleeping { until_ns });
}

/// Ends the running thread.
pub fn exit() -> ! {
    schedule(State::Exited);
    unreachable!("an exited thread was scheduled again");
}

/// Waits until thread `id` has exited.
pub fn join(id: ThreadId) {
    EXITS.wait_until(|| {
        SCHED.lock().as_ref().is_none_or(|s| {
            s.threads
                .get(&id.0)
                .is_none_or(|t| t.state == State::Exited)
        })
    });
}

/// Moves the current thread to `next_state` and switches to the next
/// runnable thread.
fn schedule(next_state: State) {
    let mut guard = SCHED.lock();
    let Some(sched) = guard.as_mut() else {
        return;
    };
    let now = time::monotonic_nanos();

    // Wake sleepers that are due and recompute the next wake-up.
    let mut next_wake = u64::MAX;
    let mut due = Vec::new();
    for (&id, thread) in sched.threads.iter_mut() {
        if let State::Sleeping { until_ns } = thread.state {
            if until_ns <= now {
                thread.state = State::Ready;
                due.push(id);
            } else {
                next_wake = next_wake.min(until_ns);
            }
        }
    }
    sched.ready.extend(due);
    NEXT_WAKE_NS.store(next_wake, Ordering::Relaxed);

    let current_id = sched.current;
    let keep_running = next_state == State::Ready;
    let next_id = match sched.ready.pop_front() {
        Some(id) => id,
        None if keep_running && current_id != sched.idle => return,
        None => sched.idle,
    };
    if next_id == current_id {
        if let Some(t) = sched.threads.get_mut(&current_id) {
            t.state = State::Running;
        }
        return;
    }

    {
        let current = sched
            .threads
            .get_mut(&current_id)
            .expect("current thread exists");
        // The idle thread is never queued; it runs only when nothing else can.
        current.state = if current_id == sched.idle {
            State::Ready
        } else {
            next_state
        };
        if keep_running && current_id != sched.idle {
            sched.ready.push_back(current_id);
        }
    }
    let current = sched
        .threads
        .get_mut(&current_id)
        .expect("current thread exists");
    current.fpu.save();
    let save: *mut u64 = &raw mut current.rsp;

    let next = sched
        .threads
        .get_mut(&next_id)
        .expect("ready thread exists");
    next.state = State::Running;
    next.fpu.restore();
    let load = next.rsp;
    if let Some(stack) = &next.stack {
        // Interrupts and exceptions from user mode will land on this
        // thread's kernel stack (used from P1-T10 on).
        // SAFETY: the stack is mapped and stays so while the thread lives;
        // interrupts are disabled (the scheduler lock disables them).
        unsafe { gdt::set_kernel_stack(stack.top) };
    }
    sched.current = next_id;
    SWITCHES.fetch_add(1, Ordering::Relaxed);

    // Release the lock but keep interrupts off across the switch: the
    // guard is forgotten, so its drop does not re-enable them; we unlock
    // the inner spinlock by dropping a fresh guard below.
    let interrupts_were_enabled = guard.release_keep_interrupts_disabled();
    // SAFETY: interrupts are disabled. `save` points into a boxed Thread
    // that is not freed while the thread is current or ready (exited
    // threads are reaped only by another thread, below). `load` was saved
    // by an earlier switch or written by `prepare_stack`, and that
    // thread's stack is still mapped.
    unsafe { switch::switch(save, load) };

    // Back on this thread. Free threads that have exited (not ourselves).
    reap();
    if interrupts_were_enabled {
        crate::interrupts::enable_after_switch();
    }
}

/// Frees the stacks and save areas of exited threads, except the current
/// one (whose stack is in use), and wakes joiners. A joiner treats a
/// thread that is gone from the table as exited.
fn reap() {
    let dead: Vec<Box<Thread>> = {
        let mut guard = SCHED.lock();
        let Some(sched) = guard.as_mut() else {
            return;
        };
        let current = sched.current;
        let ids: Vec<u64> = sched
            .threads
            .iter()
            .filter(|&(&id, t)| t.state == State::Exited && id != current)
            .map(|(&id, _)| id)
            .collect();
        ids.iter()
            .filter_map(|id| sched.threads.remove(id))
            .collect()
    };
    if !dead.is_empty() {
        EXITS.wake_all();
    }
    for thread in dead {
        let Thread { stack, .. } = *thread;
        if let Some(stack) = stack {
            paging::unmap_kernel_stack(stack);
        }
    }
}

/// Number of threads that exist (including boot and idle).
pub fn thread_count() -> usize {
    SCHED.lock().as_ref().map_or(0, |s| s.threads.len())
}

/// Name of thread `id`, if it exists.
pub fn thread_name(id: ThreadId) -> Option<&'static str> {
    SCHED.lock().as_ref()?.threads.get(&id.0).map(|t| t.name)
}

/// Threads waiting for a condition. `wait_until` checks the condition and
/// blocks with interrupts disabled, so a `wake_all` that follows a change
/// to the condition can never be missed on a single CPU.
pub struct WaitQueue {
    waiters: IrqMutex<VecDeque<u64>>,
}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            waiters: IrqMutex::new(VecDeque::new()),
        }
    }

    /// Blocks until `condition` returns true.
    pub fn wait_until(&self, mut condition: impl FnMut() -> bool) {
        loop {
            let mut waiters = self.waiters.lock();
            if condition() {
                return;
            }
            let me = SCHED.lock().as_ref().map_or(0, |s| s.current);
            waiters.push_back(me);
            // Keep interrupts disabled until we are blocked: the waker
            // needs the waiters lock, which we release here, but cannot run
            // before `schedule` switches away (single CPU, interrupts off).
            let interrupts_were_enabled = waiters.release_keep_interrupts_disabled();
            schedule(State::Blocked);
            if interrupts_were_enabled {
                crate::interrupts::enable_after_switch();
            }
        }
    }

    /// Makes every waiting thread ready.
    pub fn wake_all(&self) {
        let woken: Vec<u64> = self.waiters.lock().drain(..).collect();
        if woken.is_empty() {
            return;
        }
        let mut guard = SCHED.lock();
        if let Some(sched) = guard.as_mut() {
            for id in woken {
                if let Some(t) = sched.threads.get_mut(&id)
                    && t.state == State::Blocked
                {
                    t.state = State::Ready;
                    sched.ready.push_back(id);
                }
            }
        }
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}
