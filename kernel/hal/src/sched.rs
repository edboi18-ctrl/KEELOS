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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::fpu::FpuState;
use crate::arch::x86_64::paging::{self, KernelStack};
use crate::arch::x86_64::{cpu, entry, switch};
use crate::sync::IrqMutex;
use crate::time;
use crate::vm::AddressSpace;

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
    /// The user address space, for threads that run user code.
    space: Option<Arc<AddressSpace>>,
    /// How the thread first enters user mode, consumed by
    /// `user_thread_start`.
    user_entry: Option<UserEntry>,
    /// User FS and GS base addresses (arch_prctl), loaded into the MSRs
    /// whenever this thread is switched in. The kernel never uses FS or GS
    /// itself (ADR 0005), so these need no saving on kernel entry.
    user_bases: [u64; 2],
    /// Set by `exec_current` during a system call: the new program's RIP
    /// and RSP, which the system-call return path puts in the frame.
    pending_exec: Option<(u64, u64)>,
    /// Set by `request_exit`: the thread ends with this status the next
    /// time it would return to user mode, and stops blocking meanwhile.
    exit_request: Option<i64>,
}

/// A user thread's first entry to user mode.
enum UserEntry {
    /// A new program: RIP, RSP and RDI, every other register 0.
    Start(u64, u64, u64),
    /// A copy of another thread's user registers (fork).
    Frame(Box<crate::arch::x86_64::idt::TrapFrame>),
}

/// How a user thread's last exception looked, for tests and diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserFault {
    pub vector: u64,
    pub error_code: u64,
    pub address: u64,
    pub rip: u64,
    /// RFLAGS of the user code at the fault.
    pub user_rflags: u64,
    /// RFLAGS of the kernel while it handled the fault.
    pub handler_rflags: u64,
}

/// Exit status and last user fault of threads that have exited, and the
/// order they exited in (the oldest is dropped first).
static EXITED: IrqMutex<Exited> = IrqMutex::new(Exited {
    by_id: BTreeMap::new(),
    order: VecDeque::new(),
});

struct Exited {
    by_id: BTreeMap<u64, (i64, Option<UserFault>)>,
    order: VecDeque<u64>,
}
/// How many exit statuses `EXITED` keeps. Callers read a status right
/// after the thread ends (`join`), long before 1024 more threads exit.
const EXITED_LIMIT: usize = 1024;

/// Number of exit statuses held (for tests).
pub fn exited_count() -> usize {
    EXITED.lock().by_id.len()
}
static FAULTS: IrqMutex<BTreeMap<u64, UserFault>> = IrqMutex::new(BTreeMap::new());

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
        // The guarded stack `continue_on_boot_stack` moved to, if any.
        stack: BOOT_STACK.lock().take(),
        fpu: FpuState::new().ok_or(SchedError::OutOfMemory)?,
        space: None,
        user_entry: None,
        user_bases: [0; 2],
        pending_exec: None,
        exit_request: None,
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

/// Pages of the boot thread's own stack (128 KiB).
const BOOT_STACK_PAGES: u64 = 32;
/// The boot stack until `init` hands it to the boot thread.
static BOOT_STACK: IrqMutex<Option<KernelStack>> = IrqMutex::new(None);
/// The boot stack's bounds, for tests: `(guard page, base, top)`.
static BOOT_STACK_BOUNDS: IrqMutex<Option<(u64, u64, u64)>> = IrqMutex::new(None);

/// Leaves the bootloader's stack, which has no guard page, for a kernel
/// stack of its own with an unmapped guard page below it (SR-17, P1-S6),
/// and continues at `next`. Call once, early in boot, after paging is
/// set up and before `init`. Never returns: nothing on the old stack is
/// used again.
pub fn continue_on_boot_stack(next: extern "C" fn() -> !) -> ! {
    let stack = paging::map_kernel_stack(BOOT_STACK_PAGES).expect("frames for the boot stack");
    let top = stack.top;
    *BOOT_STACK_BOUNDS.lock() = Some((stack.guard_page(), stack.base, stack.top));
    *BOOT_STACK.lock() = Some(stack);
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: running on the bootloader's stack; {top} = top of the
    //   new, mapped stack, 16-byte aligned (KernelStack::top).
    // Instructions: `mov rsp, {top}` switches stacks; `xor ebp, ebp` ends
    //   the frame-pointer chain (psABI 3.4.1 asks user code to do the same
    //   for its deepest frame); `call {next}` pushes a return address, so
    //   `next` starts with RSP = 8 mod 16 as the SysV ABI requires at
    //   function entry (psABI 3.2.2). `next` never returns; `ud2` traps
    //   if it did.
    // Exit state: none (does not return). The old stack is abandoned.
    // SAFETY: the new stack is mapped and unused; `next` is an extern "C"
    // function taking no arguments and never returning, and it does not
    // use anything that lived on the old stack.
    unsafe {
        core::arch::asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "call {next}",
            "ud2",
            top = in(reg) top,
            next = in(reg) next,
            options(noreturn),
        );
    }
}

/// `(guard page, base, top)` of the boot thread's stack, if boot moved to
/// one.
pub fn boot_stack_bounds() -> Option<(u64, u64, u64)> {
    *BOOT_STACK_BOUNDS.lock()
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
        space: None,
        user_entry: None,
        user_bases: [0; 2],
        pending_exec: None,
        exit_request: None,
    }))
}

/// Starts a thread that runs user code in `space`, beginning at `rip` with
/// stack pointer `rsp` and `argument` in RDI.
pub fn spawn_user(
    name: &'static str,
    space: Arc<AddressSpace>,
    rip: u64,
    rsp: u64,
    argument: u64,
) -> Result<ThreadId, SchedError> {
    let id = {
        let mut guard = SCHED.lock();
        let sched = guard.as_mut().ok_or(SchedError::NotInitialised)?;
        let id = sched.next_id;
        sched.next_id += 1;
        id
    };
    let mut thread = new_thread(name, user_thread_start, id)?;
    thread.space = Some(space);
    thread.user_entry = Some(UserEntry::Start(rip, rsp, argument));
    let mut guard = SCHED.lock();
    let sched = guard.as_mut().ok_or(SchedError::NotInitialised)?;
    sched.threads.insert(id, thread);
    sched.ready.push_back(id);
    Ok(ThreadId(id))
}

fn user_thread_start() {
    let entry = {
        let mut guard = SCHED.lock();
        guard.as_mut().and_then(|s| {
            let current = s.current;
            s.threads
                .get_mut(&current)
                .and_then(|t| t.user_entry.take())
        })
    };
    match entry {
        Some(UserEntry::Start(rip, rsp, argument)) => entry::enter_user(rip, rsp, argument),
        Some(UserEntry::Frame(frame)) => entry::enter_user_frame(*frame),
        None => exit_with(-1),
    }
}

/// Starts a thread that continues the running user thread (fork): in
/// `space`, with `frame` as its user registers, and the running thread's
/// FS/GS bases and FPU/SSE/AVX state. The FPU registers hold the running
/// thread's own state during a system call (the kernel uses no FPU or SSE
/// registers), so they are saved into the new thread's area here.
///
/// `fs_base` replaces the copied FS base (clone with CLONE_SETTLS); the
/// caller checks it is a user address.
pub fn spawn_user_copy(
    name: &'static str,
    space: Arc<AddressSpace>,
    frame: crate::arch::x86_64::idt::TrapFrame,
    fs_base: Option<u64>,
) -> Result<ThreadId, SchedError> {
    if fs_base.is_some_and(|base| base >= keel_core::vm::USER_END) {
        return Err(SchedError::NotInitialised);
    }
    let bases = {
        let guard = SCHED.lock();
        let sched = guard.as_ref().ok_or(SchedError::NotInitialised)?;
        sched
            .threads
            .get(&sched.current)
            .map_or([0; 2], |t| t.user_bases)
    };
    let id = {
        let mut guard = SCHED.lock();
        let sched = guard.as_mut().ok_or(SchedError::NotInitialised)?;
        let id = sched.next_id;
        sched.next_id += 1;
        id
    };
    let mut thread = new_thread(name, user_thread_start, id)?;
    thread.fpu.save();
    thread.space = Some(space);
    thread.user_bases = bases;
    if let Some(base) = fs_base {
        thread.user_bases[SegmentBase::Fs as usize] = base;
    }
    thread.user_entry = Some(UserEntry::Frame(Box::new(frame)));
    let mut guard = SCHED.lock();
    let sched = guard.as_mut().ok_or(SchedError::NotInitialised)?;
    sched.threads.insert(id, thread);
    sched.ready.push_back(id);
    Ok(ThreadId(id))
}

/// Records the user fault that is about to end the current thread.
pub fn record_user_fault(fault: UserFault) {
    let id = current().0;
    FAULTS.lock().insert(id, fault);
}

/// Exit status of an exited thread, with its last user fault, if known.
pub fn exit_status(id: ThreadId) -> Option<(i64, Option<UserFault>)> {
    EXITED.lock().by_id.get(&id.0).copied()
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

const IA32_PRED_CMD: u32 = 0x49;
const PRED_CMD_IBPB: u64 = 1;
static IBPB_ON_SWITCH: AtomicBool = AtomicBool::new(false);
/// `AddressSpace::id` of the last user address space that ran. An id, not
/// the table address: a new process can get the freed table frame of the
/// last one, and comparing addresses then skipped the barrier between two
/// different processes (audit 2, A4).
static LAST_USER_SPACE: AtomicU64 = AtomicU64::new(0);
/// Switches to a different user address space so far (each one where an
/// IBPB is issued when the CPU has it).
static USER_SPACE_CHANGES: AtomicU64 = AtomicU64::new(0);

/// Records that `space` is about to run. Returns whether it differs from
/// the last user address space, that is, whether a barrier is due.
pub fn note_user_space(space: &AddressSpace) -> bool {
    let changed = LAST_USER_SPACE.swap(space.id(), Ordering::Relaxed) != space.id();
    if changed {
        USER_SPACE_CHANGES.fetch_add(1, Ordering::Relaxed);
    }
    changed
}

/// How many times a different user address space has been switched to.
pub fn user_space_changes() -> u64 {
    USER_SPACE_CHANGES.load(Ordering::Relaxed)
}

/// Issues IBPB when switching between user address spaces (P1-S4). Only
/// call with `true` if the CPU reports IBRS/IBPB (CPUID.(7,0):EDX[26]).
pub fn set_ibpb_on_switch(enabled: bool) {
    IBPB_ON_SWITCH.store(enabled, Ordering::Relaxed);
}

/// Spectre v2 between processes (SR-15; P1-S4): a barrier whenever a
/// different user address space is about to run, so branch predictions
/// trained by one program cannot steer another. Called on every context
/// switch and when execve gives a thread a new program.
fn barrier_if_new_space(space: &AddressSpace) {
    if note_user_space(space) && IBPB_ON_SWITCH.load(Ordering::Relaxed) {
        // SAFETY: IA32_PRED_CMD (49h) bit 0 = IBPB (Linux msr-index.h);
        // enabled only after `set_ibpb_on_switch` checked CPUID for it.
        // Writing it has no effect on memory.
        unsafe { cpu::wrmsr(IA32_PRED_CMD, PRED_CMD_IBPB) };
    }
}

/// Makes `space` the running thread's address space and switches to it;
/// returns the previous one. The scheduler restores a thread's recorded
/// space whenever it runs again, so a temporary switch made this way
/// survives preemption (a bare CR3 write would be undone by the next
/// context switch). Used by `vm::with_address_space`.
pub(crate) fn swap_space(space: Option<Arc<AddressSpace>>) -> Option<Arc<AddressSpace>> {
    let mut guard = SCHED.lock();
    let sched = guard.as_mut()?;
    let current = sched.current;
    let thread = sched
        .threads
        .get_mut(&current)
        .expect("current thread exists");
    let previous = core::mem::replace(&mut thread.space, space);
    let kernel_root = paging::kernel_root().map_or(0, |r| r.address());
    let kernel_cr3 = thread
        .space
        .as_ref()
        .map_or(kernel_root, |s| s.root().address());
    let user_cr3 = thread.space.as_ref().map_or(0, |s| s.user_root().address());
    let stack_top = thread.stack.as_ref().map_or(0, |s| s.top);
    entry::set_current(kernel_cr3, user_cr3, stack_top);
    crate::vm::set_current(thread.space.clone());
    if cpu::read_cr3() & !0xFFF != kernel_cr3 {
        // SAFETY: every kernel view shares the kernel half, which maps all
        // kernel code, data and stacks, so execution continues unchanged.
        unsafe { cpu::write_cr3(kernel_cr3) };
    }
    previous
}

/// Called with the thread's ID whenever a thread exits, before it stops
/// running (process teardown in `linux-abi`).
static EXIT_HOOK: IrqMutex<Option<ExitHook>> = IrqMutex::new(None);

/// The exit hook: the thread, its exit status, and the user fault that
/// ended it, if one did.
pub type ExitHook = fn(ThreadId, i64, Option<UserFault>);

/// Registers the exit hook. Call once at boot.
pub fn set_exit_hook(hook: ExitHook) {
    *EXIT_HOOK.lock() = Some(hook);
}

/// Which user segment base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentBase {
    Fs = 0,
    Gs = 1,
}

/// Why a segment base was not set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseError {
    /// The address is not in the user half.
    NotUserAddress,
    /// The running thread has no user address space.
    NotUserThread,
}

/// Sets the running thread's user FS or GS base (arch_prctl). Refused
/// unless `value` is in the user half, so the MSR write can never fault
/// and no thread can point a segment at kernel memory.
pub fn set_user_base(which: SegmentBase, value: u64) -> Result<(), BaseError> {
    if value >= keel_core::vm::USER_END {
        return Err(BaseError::NotUserAddress);
    }
    let mut guard = SCHED.lock();
    let Some(sched) = guard.as_mut() else {
        return Err(BaseError::NotUserThread);
    };
    let current = sched.current;
    let thread = sched
        .threads
        .get_mut(&current)
        .ok_or(BaseError::NotUserThread)?;
    if thread.space.is_none() {
        return Err(BaseError::NotUserThread);
    }
    thread.user_bases[which as usize] = value;
    let msr = match which {
        SegmentBase::Fs => cpu::IA32_FS_BASE,
        SegmentBase::Gs => cpu::IA32_GS_BASE,
    };
    // SAFETY: `value` is below USER_END, so canonical (SDM Vol. 3 section
    // 4.5.3); the base only affects FS/GS-relative accesses, which the
    // kernel never makes.
    unsafe { cpu::wrmsr(msr, value) };
    Ok(())
}

/// The running thread's user FS or GS base.
pub fn user_base(which: SegmentBase) -> u64 {
    SCHED
        .lock()
        .as_ref()
        .and_then(|s| s.threads.get(&s.current))
        .map_or(0, |t| t.user_bases[which as usize])
}

/// Replaces the running thread's program (execve): from now on it runs in
/// `space`, and when the current system call returns it enters user mode
/// at `rip` with stack pointer `rsp` and every other register cleared.
/// The user FS and GS bases are reset to 0, as Linux's elf_common_init
/// (ELF_PLAT_INIT, `arch/x86/include/asm/elf.h` at v6.12) does, and the
/// FPU/SSE/AVX state to its initial values (x87 control word 037FH, MXCSR
/// 1F80H), as flush_thread's fpu_flush_thread (`arch/x86/kernel/process.c`). The old
/// address space is dropped here, after the switch, unless something else
/// still holds it. Only for a thread that runs user code.
pub fn exec_current(space: Arc<AddressSpace>, rip: u64, rsp: u64) -> Result<(), BaseError> {
    let fresh = FpuState::new().ok_or(BaseError::NotUserThread)?;
    if SCHED
        .lock()
        .as_ref()
        .and_then(|s| s.threads.get(&s.current))
        .is_none_or(|t| t.space.is_none())
    {
        return Err(BaseError::NotUserThread);
    }
    barrier_if_new_space(&space);
    let old = swap_space(Some(space));
    set_user_base(SegmentBase::Fs, 0)?;
    set_user_base(SegmentBase::Gs, 0)?;
    {
        let mut guard = SCHED.lock();
        let sched = guard.as_mut().ok_or(BaseError::NotUserThread)?;
        let current = sched.current;
        let thread = sched
            .threads
            .get_mut(&current)
            .ok_or(BaseError::NotUserThread)?;
        // The CPU's registers belong to this thread now (it is running):
        // load the initial state, and keep the same values as its saved
        // area for the next switch.
        fresh.restore();
        thread.fpu = fresh;
        thread.pending_exec = Some((rip, rsp));
    }
    drop(old);
    Ok(())
}

/// Asks thread `id` to end with `status` (exit_group, kill). It ends the
/// next time it would return to user mode: at once if it is running user
/// code (the next timer interrupt), or when its current system call
/// returns. A thread blocked or sleeping is made ready, and
/// `WaitQueue::wait_until` returns early for it, so a blocked system call
/// ends too. The first request wins. Returns whether the thread exists
/// and has not exited.
pub fn request_exit(id: ThreadId, status: i64) -> bool {
    let mut guard = SCHED.lock();
    let Some(sched) = guard.as_mut() else {
        return false;
    };
    let Some(thread) = sched.threads.get_mut(&id.0) else {
        return false;
    };
    if thread.state == State::Exited {
        return false;
    }
    thread.exit_request.get_or_insert(status);
    if matches!(thread.state, State::Blocked | State::Sleeping { .. }) {
        thread.state = State::Ready;
        sched.ready.push_back(id.0);
    }
    true
}

/// The status the running thread was asked to end with, if any.
pub fn exit_requested() -> Option<i64> {
    SCHED
        .lock()
        .as_ref()
        .and_then(|s| s.threads.get(&s.current))
        .and_then(|t| t.exit_request)
}

/// The entry point and stack `exec_current` left for the running thread,
/// taken (so they are used once).
pub(crate) fn take_pending_exec() -> Option<(u64, u64)> {
    let mut guard = SCHED.lock();
    let sched = guard.as_mut()?;
    let current = sched.current;
    sched.threads.get_mut(&current)?.pending_exec.take()
}

/// Ends the running thread.
pub fn exit() -> ! {
    exit_with(0)
}

/// Ends the running thread with an exit status.
pub fn exit_with(status: i64) -> ! {
    let id = current().0;
    let fault = FAULTS.lock().remove(&id);
    let hook = *EXIT_HOOK.lock();
    if let Some(hook) = hook {
        hook(ThreadId(id), status, fault);
    }
    {
        // Keep the most recent statuses only (audit 2, A7.2): one entry per
        // exited thread for ever would grow without bound. The oldest to
        // exit goes first. Not the smallest id: a parent's id is smaller
        // than its children's, and after 1024 children had exited, the
        // parent's own status was dropped as soon as it was stored (found
        // by `exec.hostile_executables` with 3000 runs).
        let mut exited = EXITED.lock();
        exited.by_id.insert(id, (status, fault));
        exited.order.push_back(id);
        while exited.by_id.len() > EXITED_LIMIT {
            match exited.order.pop_front() {
                Some(oldest) => {
                    exited.by_id.remove(&oldest);
                }
                None => break,
            }
        }
    }
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

/// Waits until thread `id` has exited, for at most `ms` milliseconds.
/// Returns whether it exited.
pub fn join_timeout(id: ThreadId, ms: u64) -> bool {
    let done = || {
        SCHED.lock().as_ref().is_none_or(|s| {
            s.threads
                .get(&id.0)
                .is_none_or(|t| t.state == State::Exited)
        })
    };
    let deadline = crate::time::monotonic_nanos().saturating_add(ms * 1_000_000);
    while !done() {
        if crate::time::monotonic_nanos() >= deadline {
            return false;
        }
        sleep_ms(1);
    }
    true
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
    // Tell the entry code about the incoming thread, and switch to its
    // kernel-view page tables (the kernel's own for kernel threads).
    let kernel_root = paging::kernel_root().map_or(0, |r| r.address());
    let kernel_cr3 = next
        .space
        .as_ref()
        .map_or(kernel_root, |s| s.root().address());
    let user_cr3 = next.space.as_ref().map_or(0, |s| s.user_root().address());
    let stack_top = next.stack.as_ref().map_or(0, |s| s.top);
    entry::set_current(kernel_cr3, user_cr3, stack_top);
    crate::vm::set_current(next.space.clone());
    if let Some(space) = next.space.as_ref() {
        barrier_if_new_space(space);
    }
    if next.space.is_some() {
        // SAFETY: both values were checked to be user (hence canonical)
        // addresses by `set_user_base`, or are 0, so WRMSR cannot fault
        // (SDM Vol. 3 section 4.5.3).
        unsafe {
            cpu::wrmsr(cpu::IA32_FS_BASE, next.user_bases[0]);
            cpu::wrmsr(cpu::IA32_GS_BASE, next.user_bases[1]);
        }
    }
    if cpu::read_cr3() & !0xFFF != kernel_cr3 {
        // SAFETY: every kernel view shares the kernel half, which maps all
        // kernel code, data and stacks, including both threads' stacks.
        unsafe { cpu::write_cr3(kernel_cr3) };
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
    /// Blocks until `condition` returns true, and returns true; or returns
    /// false early if the running thread has been asked to exit
    /// (`request_exit`), so its system call can end.
    pub fn wait_until(&self, mut condition: impl FnMut() -> bool) -> bool {
        loop {
            let mut waiters = self.waiters.lock();
            if condition() {
                return true;
            }
            if exit_requested().is_some() {
                return false;
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
