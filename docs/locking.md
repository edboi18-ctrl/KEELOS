# Lock ordering

Locks must be taken in the order listed. Never block while holding a
spinlock. Update this file whenever a lock is added.

| Order | Lock | Crate | Protects |
| --- | --- | --- | --- |
| 1 | `console::SERIAL` | `keel-hal` | The COM1 UART |
| 2 | `console::FRAMEBUFFER` | `keel-hal` | The framebuffer text console |
| 3 | `memory::FRAMES` | `keel-hal` | The physical frame allocator. Never held while printing; nothing else is locked while it is held. |

Notes:

- Interrupts are disabled for the whole of Phase 0, so neither lock can
  be re-entered from an interrupt handler. Phase 1 (interrupts on) must
  revisit this: either disable interrupts while a console lock is held or
  keep interrupt handlers off these locks.
- The panic path takes no lock unconditionally: it writes to COM1 through
  a fresh handle and uses `FRAMEBUFFER.try_lock()`.
