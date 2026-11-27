//! The kernel's audit log (P3-S6, ADR 0045; SR-11). One log
//! (`keel_core::audit::AuditLog`) of compartment creations, device
//! grants and denied operations, the last rate-limited per compartment.
//! It is read only through an audit handle, which only a factory with the
//! AUDIT right can open (`native::audit_open`), and only the root factory
//! the kernel gives keel-init has that right.

use alloc::sync::Arc;
use alloc::vec::Vec;

use keel_core::audit::{Actor, AuditLog, Event, Record};
use keel_core::compartment::Compartment;
use keel_core::errno::Errno;
use keel_hal::sync::IrqMutex;

use crate::process::Process;

/// Records kept: about 100 bytes of text each when read, under 64 bytes
/// each held.
const CAPACITY: usize = 1024;

static LOG: IrqMutex<AuditLog> = IrqMutex::new(AuditLog::new(CAPACITY));

fn now_ms() -> u64 {
    keel_hal::time::monotonic_nanos() / 1_000_000
}

/// The process `p` as an actor, or the kernel when there is none.
pub fn actor(p: Option<&Arc<IrqMutex<Process>>>) -> Actor {
    match p {
        Some(p) => {
            let process = p.lock();
            Actor::Process {
                compartment: process.member.compartment().id(),
                pid: process.pid(),
            }
        }
        None => Actor::Kernel,
    }
}

/// Records `event` (a creation or a grant: never rate-limited).
pub fn record(event: Event) {
    LOG.lock().push(now_ms(), event);
}

/// Records a denial in `compartment`, if its rate limit allows; else it
/// is counted, and the next one recorded says how many were not.
pub fn denied(
    compartment: &Compartment,
    pid: u32,
    what: &'static str,
    number: u64,
    op: Option<u64>,
    errno: Errno,
) {
    if let Some(suppressed) = compartment.audit_limiter().admit(now_ms()) {
        record(Event::Denied {
            compartment: compartment.id(),
            pid,
            what,
            number,
            op,
            errno: errno as i32,
            suppressed,
        });
    }
}

/// An open audit handle: its cursor, the next sequence number it reads.
pub struct AuditReader {
    cursor: IrqMutex<u64>,
}

impl AuditReader {
    /// A reader from the oldest record kept, so keel-init sees what
    /// happened since boot, as far as the log reaches.
    pub fn new() -> AuditReader {
        AuditReader {
            cursor: IrqMutex::new(LOG.lock().oldest()),
        }
    }

    /// read(2): whole lines into `out` (see `AuditLog::read`).
    pub fn read(&self, out: &mut [u8]) -> Result<usize, Errno> {
        let mut cursor = self.cursor.lock();
        LOG.lock().read(&mut cursor, out)
    }
}

impl Default for AuditReader {
    fn default() -> Self {
        Self::new()
    }
}

/// The records about `compartment` now kept (for the kernel's tests).
pub fn records_for(compartment: u32) -> Vec<Record> {
    LOG.lock()
        .records()
        .filter(|r| match r.event {
            Event::Created { compartment: c, .. }
            | Event::Granted { compartment: c, .. }
            | Event::Denied { compartment: c, .. } => c == compartment,
        })
        .copied()
        .collect()
}
