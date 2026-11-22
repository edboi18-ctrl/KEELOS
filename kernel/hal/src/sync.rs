//! A spinlock that disables interrupts while held.
//!
//! Needed once the scheduler preempts threads (P1-T8): if a thread were
//! preempted while holding the heap, page-table or frame lock, and the
//! scheduler (which runs with interrupts off) then needed the same lock,
//! it would spin forever on a uniprocessor. Holding these locks with
//! interrupts disabled means no thread is ever switched out while holding
//! one. Critical sections must therefore be short.
//!
//! Rule: any lock that code with interrupts disabled may take (interrupt
//! handlers, system calls, the scheduler) must be an `IrqMutex`. A plain
//! spinlock held by a preempted thread makes such code spin forever on
//! one CPU. That happened with the console locks (F-0004).

use core::ops::{Deref, DerefMut};

/// A mutex whose guard keeps maskable interrupts disabled.
pub struct IrqMutex<T> {
    inner: spin::Mutex<T>,
}

/// Guard for [`IrqMutex`]; restores the previous interrupt state on drop.
pub struct IrqGuard<'a, T> {
    guard: Option<spin::MutexGuard<'a, T>>,
    interrupts_were_enabled: bool,
}

impl<T> IrqMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: spin::Mutex::new(value),
        }
    }

    /// Disables interrupts, then takes the lock.
    pub fn lock(&self) -> IrqGuard<'_, T> {
        let interrupts_were_enabled = disable();
        IrqGuard {
            guard: Some(self.inner.lock()),
            interrupts_were_enabled,
        }
    }
}

impl<T> IrqMutex<T> {
    /// Like `lock`, but gives up at once if the lock is taken (for the
    /// panic path, which must not wait on a lock its own CPU may hold).
    pub fn try_lock(&self) -> Option<IrqGuard<'_, T>> {
        let interrupts_were_enabled = disable();
        match self.inner.try_lock() {
            Some(guard) => Some(IrqGuard {
                guard: Some(guard),
                interrupts_were_enabled,
            }),
            None => {
                if interrupts_were_enabled {
                    enable();
                }
                None
            }
        }
    }
}

impl<T> IrqGuard<'_, T> {
    /// Releases the lock but leaves interrupts disabled, returning whether
    /// they were enabled before `lock`. Used by the scheduler, which must
    /// switch threads with interrupts off after releasing its locks.
    pub fn release_keep_interrupts_disabled(mut self) -> bool {
        let were_enabled = self.interrupts_were_enabled;
        self.interrupts_were_enabled = false;
        drop(self);
        were_enabled
    }
}

impl<T> Deref for IrqGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.guard.as_ref().expect("guard is present until drop")
    }
}

impl<T> DerefMut for IrqGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.guard.as_mut().expect("guard is present until drop")
    }
}

impl<T> Drop for IrqGuard<'_, T> {
    fn drop(&mut self) {
        // Release the lock before interrupts can arrive again.
        drop(self.guard.take());
        if self.interrupts_were_enabled {
            enable();
        }
    }
}

#[cfg(target_os = "none")]
fn disable() -> bool {
    crate::arch::x86_64::cpu::disable_interrupts()
}

#[cfg(target_os = "none")]
fn enable() {
    // SAFETY: interrupts were enabled when this guard was created, so
    // re-enabling restores the caller's state; the lock is already
    // released, so no handler can find it held by this context.
    unsafe { crate::arch::x86_64::cpu::enable_interrupts() }
}

// Host unit tests have no interrupts to manage.
#[cfg(not(target_os = "none"))]
fn disable() -> bool {
    false
}

#[cfg(not(target_os = "none"))]
fn enable() {}
