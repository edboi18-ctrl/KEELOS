# ADR 0020: Signal delivery

Status: accepted (Phase 3, P3-T6). Extends ADR 0008 (signal state),
ADR 0019 (ending threads) and ADR 0014 (signals stay inside a
compartment).

## Context

Wine runs Windows exception handling on Linux signals. A CPU fault in a
Windows program becomes SIGSEGV, SIGILL, SIGFPE, SIGBUS or SIGTRAP. Wine's
handler reads the saved registers and FPU state from the signal frame,
builds a Windows `CONTEXT`, may edit it, and returns through
`rt_sigreturn`. Wine also uses an alternate signal stack, per-thread
signals (`tgkill`, 10 calls in the trace) and masks. Until now Keel only
recorded dispositions (ADR 0008), and every fault ended the thread.

Everything below follows Linux v6.12 (sources in `docs/SOURCES.md`):

- `kernel/signal.c`: send_signal_locked, complete_signal, get_signal,
  force_sig_info_to_task, signal_delivered, do_sigaction.
- `arch/x86/kernel/signal.c` and `signal_64.c`: get_sigframe,
  handle_signal, x64_setup_rt_frame, rt_sigreturn, restore_sigcontext.
- `arch/x86/kernel/fpu/signal.c`: the FPU area in the frame.
- `arch/x86/kernel/traps.c` and `arch/x86/mm/fault.c`: which signal each
  exception raises.

## Decision

1. **Where the state lives.**
   - **Process:** dispositions, and a pending set for signals sent to the
     process as a whole (`shared_pending`).
   - **Thread:** the blocked mask, the alternate stack, its own pending
     set, and its last fault's `trap_nr`, `error_code` and `cr2`.
   - A pending set holds one `siginfo_t` per signal. A standard signal
     already pending is not queued again (`legacy_queue`). Real-time
     signals are coalesced the same way for now; Linux queues each one
     (see "Not yet covered").
   - `fork` gives the child a copy of the caller's mask and alternate
     stack, and nothing pending. A new thread gets the mask but no
     alternate stack, as `copy_process` does for `CLONE_VM` without
     `CLONE_VFORK`.
   - `execve` keeps the mask and anything pending, drops the alternate
     stack, and resets caught signals (ADR 0017).
2. **Sending.**
   - **`kill`** sends to a process in the caller's compartment (ESRCH
     otherwise), with `SI_USER` and the caller's PID.
   - **`tkill` and `tgkill`** send to one thread, with `SI_TKILL`.
   - **SIGKILL** always ends every thread at once (ADR 0019).
   - **Ignored signals.** A signal the process ignores is dropped unless
     it is blocked (`sig_ignored`). Setting a signal to ignored drops it
     wherever it is pending (`do_sigaction`).
   - **Waking a thread.** For a process-wide signal, the first thread
     that does not block it is woken (`wants_signal`). For a thread
     signal, the target is woken unless it blocks the signal. The
     hardware layer's `sched::interrupt` makes a blocked or sleeping
     thread ready, and `WaitQueue::wait_until` returns early for it. So
     `futex` wait, `wait4` and a console `read` return **EINTR**.
3. **Delivery, on every return to user mode.** This is a hook the
   hardware layer runs on every return to user mode (after a system call,
   an interrupt or a fault), with interrupts off. It takes every pending
   signal the thread does not block:
   - the thread's own signals before the process's;
   - synchronous signals (SEGV, BUS, ILL, TRAP, FPE, SYS) first, then
     the lowest number (`next_signal`).
   - What happens to each signal:
     - **SIG_IGN:** dropped.
     - **SIG_DFL:** the default action. "Term" and "Core" end the
       process with the signal as its wait status. Keel writes no core
       files, so there is no core-dump bit. "Ign" and "Cont" do nothing,
       and so does "Stop" until job control exists.
     - **A handler** gets a frame. Several handlers can stack up at
       once, as Linux's `exit_to_user_mode_loop` delivers until nothing
       is left.
4. **The frame** is `struct rt_sigframe`, byte for byte. Its layout is
   pure data in `keel_core::signal::frame`, tested on the host against
   the v6.12 headers.
   - **Contents:** `pretcode` (the restorer), then the `ucontext` (flags,
     link, the alternate stack as stored, the `sigcontext` and the mask
     before delivery), then `siginfo_t` (written only with
     `SA_SIGINFO`).
   - **The `sigcontext`:**
     - every general register, RIP, RFLAGS, CS and SS;
     - `trapno`, `err` and `cr2` from the thread's last fault;
     - `oldmask`;
     - a pointer to the FPU area.
   - **`uc_flags`:** `UC_SIGCONTEXT_SS` and `UC_STRICT_RESTORE_SS`, plus
     `UC_FP_XSTATE` when the area is in XSAVE format.
   - **Placement** follows `get_sigframe`:
     1. 128 bytes of red zone are skipped.
     2. With `SA_ONSTACK`, if the thread is not already on its alternate
        stack, the frame goes at the top of that stack instead.
     3. The FPU area comes next: the thread's XSAVE (standard form) or
        FXSAVE image, plus Linux's software words and `FP_XSTATE_MAGIC2`,
        64-byte aligned.
     4. Then the frame, at 16n − 8.
     5. A frame that would leave the alternate stack it is on fails.
   - **Registers for the handler:** RDI = the signal, RSI = &info,
     RDX = &uc, RAX = 0, RSP = the frame, RIP = the handler.
     - DF, RF and TF are cleared.
     - The FPU is put in its initial state (MXCSR 1F80h).
     - The mask grows by `sa_mask` and the signal itself, unless
       `SA_NODEFER`.
     - `SA_RESETHAND` resets the action as the signal is taken.
     - An `SS_AUTODISARM` stack is disarmed.
   - **Refused:** a handler without `SA_RESTORER` is refused as Linux
     refuses it. That, or a frame that cannot be written, becomes
     SIGSEGV (`force_sigsegv`). A SIGSEGV that cannot be delivered ends
     the process.
5. **`rt_sigreturn`** reads the frame at RSP − 8. It restores, in turn:
   - the mask;
   - the alternate stack, ignoring errors as `restore_altstack` does;
   - the FPU state;
   - every general register, RIP and RSP;
   - the `FIX_EFLAGS` bits of RFLAGS.

   It returns the saved RAX, and ends in SIGSEGV if the frame cannot be
   read. Details:
   - **The FPU area** is taken whole only if both magic words and its
     size match Keel's area (`check_xstate_in_sigframe`). Otherwise only
     the legacy 512 bytes are taken, and the extended state is reset.
     Components left out of the frame's `xfeatures` are reset too.
   - **Validation.** FXRSTOR and XRSTOR raise #GP on bad input, which
     would be a fault inside the kernel. So before loading, Keel checks
     the area: MXCSR within `MXCSR_MASK` (read from the CPU at boot),
     and with XSAVE a standard-form header (XSTATE_BV within XCR0,
     XCOMP_BV and the reserved bytes zero). An area that fails is
     SIGSEGV with the FPU reset, where Linux's restore fails and it
     sends SIGSEGV.
   - **The new registers** pass through `prepare_user_return` like every
     return to user mode. That function forces the user selectors, takes
     only user-controllable RFLAGS bits and keeps RIP and RSP in the
     user half, so no frame contents can make IRETQ fault in the kernel.
     CS and SS are not taken from the frame: Keel has a single user code
     selector and a single user data selector.
6. **Faults become signals.** The hardware layer calls a fault hook
   before ending a faulting thread. The signal and code are Linux's:

   | Exception | Signal | `si_code` |
   | --- | --- | --- |
   | #PF | SIGSEGV | SEGV_MAPERR where no mapping covers the address, SEGV_ACCERR where one does; `si_addr` = CR2; `err` with the user bit |
   | #GP, #TS, #OF, #BR | SIGSEGV | SI_KERNEL |
   | #NP, #SS | SIGBUS | SI_KERNEL |
   | #AC | SIGBUS | BUS_ADRALN |
   | #UD | SIGILL | ILL_ILLOPN, at the RIP |
   | #DE | SIGFPE | FPE_INTDIV |
   | #MF, #XM | SIGFPE | from the unmasked flags (`fpu__exception_code`); a spurious one returns to the program |
   | #DB | SIGTRAP | TRAP_TRACE when TF was set |
   | #BP | SIGTRAP | SI_KERNEL |

   If a handler is installed and the signal is not blocked, the handler
   runs. Otherwise the process ends with that signal, as
   `force_sig_info_to_task` makes a blocked or ignored fault signal fatal.
   The hardware layer's exit statuses (128 + signal) use the same table.
7. **The hardware layer's part** is mechanism only:
   - the two hooks;
   - `sched::interrupt`;
   - a pending frame for `rt_sigreturn` (this generalizes execve's
     pending entry point);
   - the running thread's FPU image: saved out, validated and loaded in,
     and reset. Saved area and registers change together under the
     scheduler lock.

   What a signal means is decided in `keel-linux-abi`, in safe Rust.

## Not yet covered

- **SA_RESTART.** An interrupted call returns EINTR even with
  `SA_RESTART`; Linux would restart `futex`, `wait4` and `read`. `poll`
  is not interrupted at all yet.
- **Real-time signal queueing.** Each real-time signal should be queued
  (up to RLIMIT_SIGPENDING). The calls that need it (`rt_sigqueueinfo`,
  `rt_tgsigqueueinfo`) are also missing.
- **Waiting for signals and asking what is pending:** `rt_sigsuspend`,
  `rt_sigtimedwait`, `rt_sigpending`, `signalfd`, `pause`.
- **Job control and SIGCHLD:** stop and continue, and SIGCHLD to the
  parent at exit (with process groups, P3-T7).
- **Dynamically enabled FPU state (AMX).** It is not granted, so the
  alternate stack needs no size check beyond MINSIGSTKSZ.

## Evidence

- **Host tests** (`keel_core::signal`):
  - The frame and `sigcontext` offsets match the v6.12 headers: `uc` 8,
    `uc_mcontext` 48, `uc_sigmask` 304, `info` 312, size 440; RIP 128,
    `err` 152, `trapno` 160, `cr2` 176, `fpstate` 184.
  - The `siginfo_t` fields.
  - Placement:
    - the red zone and 16n − 8 alignment;
    - the top of the alternate stack with `SA_ONSTACK`;
    - nesting on it;
    - overflowing it;
    - no wrap near 0.
  - Dequeue order (synchronous first), no double queueing, default
    actions.
  - The FPU area:
    - a frame Keel wrote is taken whole;
    - a legacy-only frame resets the extended state;
    - `xfeatures` without AVX resets AVX.
  - A child thread's mask and alternate stack.
- **`exec.signals` (phase 3):** `fixtures/musl-dynamic/signals.c`, 24
  checks, which pass under Linux (`cargo xtask test` runs it there too)
  and under Keel:
  - `raise` (SI_TKILL, `si_pid`) and `kill` (SI_USER).
  - `sa_mask` and the signal blocked in the handler, and the mask back
    afterwards.
  - Blocked signals delivered when unblocked, and not queued twice.
  - `SA_RESETHAND` and `SIG_IGN`.
  - The alternate stack with `SA_ONSTACK`, which reports SS_ONSTACK.
  - SIGSEGV handlers that move RIP past the faulting store:
    - SEGV_MAPERR at 0x10, with `trapno` 14, the write and user bits in
      `err`, and `cr2`;
    - SEGV_ACCERR on a PROT_NONE page.
  - SIGILL from UD2 (ILL_ILLOPN, `si_addr` and RIP at the UD2).
  - The FPU state:
    - the handler starts with MXCSR 1F80h, while the frame holds the
      interrupted 7F80h;
    - a live XMM0 the handler clobbers comes back;
    - a saved XMM1 it edits is loaded.
  - Default actions in forked children:
    - SIGTERM gives wait status 15;
    - an ignored SIGTERM does nothing;
    - a fault with SIGSEGV blocked kills even with a handler installed.
  - `pthread_kill`:
    - it interrupts a thread's `futex` wait with EINTR;
    - it reaches the thread while it spins in user mode, so delivery
      happens at a timer interrupt;
    - the handler runs on that thread.
  - No process or frame is left over afterwards.
- **Mutations**, each of which makes `exec.signals` fail (the check it
  fails in brackets; "times out" where the program then hangs):
  - delivery only after system calls, not interrupts (times out: the
    first fault, check 12, retries for ever);
  - `rt_sigreturn` that does not load the FPU area (18);
  - a handler that keeps the interrupted FPU state (17);
  - no `sa_mask` (3);
  - `rt_sigreturn` that keeps the handler's mask (4);
  - SEGV_ACCERR reported as SEGV_MAPERR (15);
  - a wait that a signal does not cut short (times out at 23);
  - `SA_ONSTACK` ignored (11);
  - `SA_RESETHAND` ignored (8);
  - a blocked fault signal neither refused by the fault hook nor made
    fatal by `force` (times out at 21: the child's fault retries for
    ever).
  - Either of those last two safeguards alone is enough: with only the
    fault hook's check removed, `force` still resets the blocked signal
    to SIG_DFL and the child dies with SIGSEGV, so that mutant passes.

## Consequences

- Programs that never install handlers behave as before: faults end
  them with the same status, and the unhandled-fault line is still
  printed.
- The fuzzer never makes `rt_sigreturn` (it would jump to whatever lies
  on the stack), `tkill` or `tgkill` (a random fatal signal, as `kill`).
- Every return to user mode now takes the process lock once to look for
  pending signals.
