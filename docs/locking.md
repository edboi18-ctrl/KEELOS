# Lock ordering

Locks must be taken in the order listed. Never block while holding a
spinlock. Update this file whenever a lock is added.

| Order | Lock | Crate | Protects |
| --- | --- | --- | --- |
| 0 | `sched::WaitQueue::waiters` (each queue) | `keel-hal` | Threads blocked on that queue. Taken before `sched::SCHED`. |
| 0.5 | `sched::SCHED` | `keel-hal` | Thread table, run queue, current thread. May take the heap lock (queue growth) and, when reaping, the page-table and frame locks. |
| 1 | `heap::KERNEL_HEAP` | `keel-hal` | Kernel heap free lists. May take `paging::TABLES` (to map pages), which takes `memory::FRAMES`. |
| 2 | `paging::TABLES` | `keel-hal` | The kernel's page tables after boot. May take `memory::FRAMES`. |
| 3 | `memory::FRAMES` | `keel-hal` | The physical frame allocator. Takes no other lock. |
| 4 | `console::SERIAL` | `keel-hal` | The COM1 UART. Takes no lock except `FRAMEBUFFER`. |
| 5 | `console::FRAMEBUFFER` | `keel-hal` | The framebuffer text console |
| 6 | `interrupts::ROUTING` | `keel-hal` | I/O APIC list and IRQ overrides. Taken only by code that changes routing, never from an interrupt handler. |

Notes:

- The console locks are independent of the memory locks: printing never
  allocates, and no memory code prints while holding a memory lock.
- Never allocate from an interrupt or exception handler: the interrupted
  code may hold the heap lock. The fatal-exception path does not allocate.

- `heap::KERNEL_HEAP`, `paging::TABLES`, `memory::FRAMES`, `sched::SCHED`
  and every `WaitQueue` are `sync::IrqMutex`es: interrupts are disabled
  while one is held, so the scheduler never preempts a thread inside
  them. Keep those critical sections short.
- Interrupts are enabled from P1-T7 on. Interrupt handlers take no lock
  at all (the timer handler only increments an atomic counter), so no
  lock above can be re-entered by an interrupt. Any future handler that
  needs a lock must use one that is only ever taken with interrupts
  disabled.
- System calls run with interrupts enabled (F-0008): a thread can be
  preempted anywhere in a system call except inside an `IrqMutex`. So
  every lock a system call takes must be an `IrqMutex` (all of them are),
  and code in a system call must not assume it runs uninterrupted.
- The panic path takes no lock unconditionally: it writes to COM1 through
  a fresh handle and uses `FRAMEBUFFER.try_lock()`.
