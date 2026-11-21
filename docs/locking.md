# Lock ordering

Locks must be taken in the order listed. Never block while holding a
spinlock. Update this file whenever a lock is added.

| Order | Lock | Crate | Protects |
| --- | --- | --- | --- |
| 1 | `heap::KERNEL_HEAP` | `keel-hal` | Kernel heap free lists. May take `paging::TABLES` (to map pages), which takes `memory::FRAMES`. |
| 2 | `paging::TABLES` | `keel-hal` | The kernel's page tables after boot. May take `memory::FRAMES`. |
| 3 | `memory::FRAMES` | `keel-hal` | The physical frame allocator. Takes no other lock. |
| 4 | `console::SERIAL` | `keel-hal` | The COM1 UART. Takes no lock except `FRAMEBUFFER`. |
| 5 | `console::FRAMEBUFFER` | `keel-hal` | The framebuffer text console |

Notes:

- The console locks are independent of the memory locks: printing never
  allocates, and no memory code prints while holding a memory lock.
- Never allocate from an interrupt or exception handler: the interrupted
  code may hold the heap lock. The fatal-exception path does not allocate.

- Interrupts are disabled for the whole of Phase 0, so neither lock can
  be re-entered from an interrupt handler. Phase 1 (interrupts on) must
  revisit this: either disable interrupts while a console lock is held or
  keep interrupt handlers off these locks.
- The panic path takes no lock unconditionally: it writes to COM1 through
  a fresh handle and uses `FRAMEBUFFER.try_lock()`.
