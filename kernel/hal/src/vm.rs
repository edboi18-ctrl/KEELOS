//! User address spaces (P1-T9) and the checked user-memory copy routines
//! (P1-S2; SR-13, SR-19).
//!
//! An address space is a top-level page table whose upper half is the
//! kernel's (shared entries 256-511, created at boot) and whose lower half
//! starts empty. User pages are created on first touch (demand paging) as
//! fresh zeroed frames (SR-18), so reservations such as a 64 GiB
//! PROT_NONE region cost no memory. `duplicate` shares every page
//! copy-on-write; the first write through either copy gets a private page.
//!
//! The kernel touches user memory only through `copy_to_user` and
//! `copy_from_user`. They check the range against the user half with
//! checked arithmetic before touching anything, lift SMAP only around one
//! `rep movsb`, and turn an unresolvable fault into EFAULT instead of a
//! panic. No other kernel code dereferences user addresses.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use keel_core::frame::Frame;
use keel_core::paging::{self, Flags, PageSize, TableAccess};
use keel_core::vm::{self, FaultAction, Layout, Placement, Prot, VmError};

use crate::arch::x86_64::cpu;
use crate::arch::x86_64::idt::{TrapFrame, page_fault};
use crate::arch::x86_64::paging::{DirectMapTables, kernel_root};
use crate::memory;
use crate::sync::IrqMutex;

const PAGE: u64 = vm::PAGE;

/// Page-table rights for a user page with VMA protection `prot`.
/// `writable` is false for pages shared copy-on-write.
fn user_flags(prot: Prot, writable: bool) -> Flags {
    Flags {
        writable: writable && prot.write,
        executable: prot.exec,
        user: true,
        ..Flags::READ_ONLY
    }
}

struct Inner {
    layout: Layout,
    /// Frames of pages made PROT_NONE after they were populated. Their
    /// page-table entries are cleared to zero rather than marked not
    /// present, so no not-present entry ever holds a real frame address
    /// (L1TF, SR-15), and the page cannot be read (F-0002). Raising the
    /// protection maps the frame back.
    parked: BTreeMap<u64, Frame>,
}

/// One user address space, as two top-level tables:
/// - the kernel view (`root`), active while the kernel runs on behalf of
///   this process: user half plus the whole kernel;
/// - the user view (`user_root`), active while user code runs: the same
///   user half, and in the kernel half only the entry trampoline
///   (page-table isolation, SR-14).
///
/// The user half is shared: both tables point at the same lower-level
/// tables, and `sync_user_view` copies any new top-level entry across.
pub struct AddressSpace {
    root: Frame,
    user_root: Frame,
    inner: IrqMutex<Inner>,
}

/// Why an address-space operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsError {
    Vm(VmError),
    OutOfMemory,
}

impl From<VmError> for AsError {
    fn from(error: VmError) -> Self {
        AsError::Vm(error)
    }
}

impl AddressSpace {
    /// An empty address space sharing the kernel's upper half.
    pub fn new() -> Result<Arc<AddressSpace>, AsError> {
        let kernel = kernel_root().ok_or(AsError::OutOfMemory)?;
        let root = memory::allocate_zeroed().ok_or(AsError::OutOfMemory)?;
        let mut tables = DirectMapTables;
        let upper: [u64; 256] = tables.table(kernel)[256..].try_into().expect("256 entries");
        tables.table(root)[256..].copy_from_slice(&upper);
        let Some(user_root) = memory::allocate_zeroed() else {
            let _ = memory::release(root);
            return Err(AsError::OutOfMemory);
        };
        tables.table(user_root)[511] = crate::arch::x86_64::paging::trampoline_pml4e();
        Ok(Arc::new(AddressSpace {
            root,
            user_root,
            inner: IrqMutex::new(Inner {
                layout: Layout::new(),
                parked: BTreeMap::new(),
            }),
        }))
    }

    /// The user view's top-level table (CR3 while user code runs).
    pub fn user_root(&self) -> Frame {
        self.user_root
    }

    /// Copies the user-half top-level entries into the user view. Called
    /// after any change that may have created a new top-level entry.
    fn sync_user_view(&self) {
        let mut tables = DirectMapTables;
        let lower: [u64; 256] = tables.table(self.root)[..256]
            .try_into()
            .expect("256 entries");
        tables.table(self.user_root)[..256].copy_from_slice(&lower);
    }

    /// Effective rights of `address` in the user view, if mapped there.
    pub fn user_view_flags(&self, address: u64) -> Option<Flags> {
        paging::translate(&mut DirectMapTables, self.user_root, address & !(PAGE - 1))
            .map(|t| t.flags)
    }

    /// Walks the user view (the page-table self-test for user tables).
    pub fn user_view_walk(
        &self,
        visit: impl FnMut(u64, paging::Translation),
    ) -> paging::WalkSummary {
        let _inner = self.inner.lock();
        paging::walk(&mut DirectMapTables, self.user_root, visit)
    }

    /// Physical address of the top-level table (for CR3).
    pub fn root(&self) -> Frame {
        self.root
    }

    /// Sets where mmap(NULL, ...) starts its top-down search (the
    /// randomized mmap base, SR-16).
    pub fn set_mmap_top(&self, top: u64) -> Result<(), AsError> {
        Ok(self.inner.lock().layout.set_mmap_top(top)?)
    }

    /// Adds a mapping (mmap). No memory is used until pages are touched.
    pub fn map(&self, placement: Placement, length: u64, prot: Prot) -> Result<u64, AsError> {
        let mut inner = self.inner.lock();
        let (start, replaced) = inner.layout.map(placement, length, prot)?;
        for (from, to) in replaced {
            self.unmap_pages(&mut inner, from, to);
        }
        Ok(start)
    }

    /// Removes a range (munmap) and frees its pages.
    pub fn unmap(&self, start: u64, length: u64) -> Result<(), AsError> {
        let mut inner = self.inner.lock();
        for (from, to) in inner.layout.unmap(start, length)? {
            self.unmap_pages(&mut inner, from, to);
        }
        Ok(())
    }

    /// Changes protection (mprotect). Pages already present get the new
    /// rights; copy-on-write pages stay read-only until written.
    pub fn protect(&self, start: u64, length: u64, prot: Prot) -> Result<(), AsError> {
        let mut inner = self.inner.lock();
        let none = prot == Prot::NONE;
        for (from, to) in inner.layout.protect(start, length, prot)? {
            let mut page = from;
            while page < to {
                if none {
                    // Take the frame out of the page tables entirely.
                    if let Some(phys) = paging::unmap_small(&mut DirectMapTables, self.root, page) {
                        cpu::invalidate_page(page);
                        inner.parked.insert(page, Frame::containing(phys));
                    }
                } else if let Some(frame) = inner.parked.remove(&page) {
                    let exclusive = memory::references(frame) == 1;
                    let mapped = paging::map(
                        &mut DirectMapTables,
                        self.root,
                        page,
                        frame.address(),
                        PageSize::Small,
                        user_flags(prot, exclusive),
                    );
                    if mapped.is_err() {
                        // Only possible when a page table cannot be
                        // allocated: keep the data parked and report it.
                        inner.parked.insert(page, frame);
                        return Err(AsError::OutOfMemory);
                    }
                } else if let Some(t) = paging::translate(&mut DirectMapTables, self.root, page) {
                    let exclusive = memory::references(Frame::containing(t.phys)) == 1;
                    let _ = paging::replace_small(
                        &mut DirectMapTables,
                        self.root,
                        page,
                        t.phys,
                        user_flags(prot, exclusive),
                    );
                    cpu::invalidate_page(page);
                }
                page += PAGE;
            }
        }
        self.sync_user_view();
        Ok(())
    }

    fn unmap_pages(&self, inner: &mut Inner, from: u64, to: u64) {
        let mut page = from;
        while page < to {
            if let Some(phys) = paging::unmap_small(&mut DirectMapTables, self.root, page) {
                cpu::invalidate_page(page);
                let _ = memory::release(Frame::containing(phys));
            }
            if let Some(frame) = inner.parked.remove(&page) {
                let _ = memory::release(frame);
            }
            page += PAGE;
        }
    }

    /// Resolves a fault at `address`; returns whether the access can now
    /// be retried.
    fn resolve_fault(&self, address: u64, error_code: u64) -> bool {
        let inner = self.inner.lock();
        let page = address & !(PAGE - 1);
        let action = vm::classify_fault(
            &inner.layout,
            address,
            error_code & page_fault::WRITE != 0,
            error_code & page_fault::INSTRUCTION_FETCH != 0,
            error_code & page_fault::PRESENT != 0,
        );
        match action {
            FaultAction::Violation => false,
            FaultAction::DemandZero(prot) => {
                let Some(frame) = memory::allocate_zeroed() else {
                    return false;
                };
                let mapped = paging::map(
                    &mut DirectMapTables,
                    self.root,
                    page,
                    frame.address(),
                    PageSize::Small,
                    user_flags(prot, true),
                );
                if mapped.is_err() {
                    let _ = memory::release(frame);
                }
                self.sync_user_view();
                // AlreadyMapped means another path mapped it first: retry.
                matches!(mapped, Ok(()) | Err(paging::MapError::AlreadyMapped))
            }
            FaultAction::CopyOnWrite(prot) => {
                let Some(old) = paging::translate(&mut DirectMapTables, self.root, page) else {
                    return false;
                };
                let old_frame = Frame::containing(old.phys);
                let target = if memory::references(old_frame) == 1 {
                    // Last user: take the page over.
                    old_frame
                } else {
                    let Some(copy) = memory::allocate_zeroed() else {
                        return false;
                    };
                    if memory::copy_frame(old_frame, copy).is_err() {
                        let _ = memory::release(copy);
                        return false;
                    }
                    let _ = memory::release(old_frame);
                    copy
                };
                let replaced = paging::replace_small(
                    &mut DirectMapTables,
                    self.root,
                    page,
                    target.address(),
                    user_flags(prot, true),
                );
                cpu::invalidate_page(page);
                replaced.is_ok()
            }
        }
    }

    /// A copy of this address space in which every present page is shared
    /// copy-on-write (for fork). Both copies lose write access to shared
    /// pages until they write.
    pub fn duplicate(&self) -> Result<Arc<AddressSpace>, AsError> {
        let child = AddressSpace::new()?;
        let inner = self.inner.lock();
        child.inner.lock().layout = inner.layout.clone();
        let mut leaves = alloc::vec::Vec::new();
        paging::walk(&mut DirectMapTables, self.root, |virt, t| {
            if virt < vm::USER_END && t.size == PageSize::Small {
                leaves.push((virt, t.phys));
            }
        });
        for (virt, phys) in leaves {
            let Some(vma) = inner.layout.find(virt) else {
                continue;
            };
            let frame = Frame::containing(phys);
            memory::retain(frame).map_err(|_| AsError::OutOfMemory)?;
            let shared = user_flags(vma.prot, false);
            paging::map(
                &mut DirectMapTables,
                child.root,
                virt,
                phys,
                PageSize::Small,
                shared,
            )
            .map_err(|_| AsError::OutOfMemory)?;
            let _ = paging::replace_small(&mut DirectMapTables, self.root, virt, phys, shared);
            cpu::invalidate_page(virt);
        }
        // Parked (PROT_NONE) pages are shared the same way: the child
        // parks the same frame, and whichever side raises the protection
        // first sees a shared frame and gets it read-only (copy on write).
        let mut child_inner = child.inner.lock();
        for (&page, &frame) in &inner.parked {
            memory::retain(frame).map_err(|_| AsError::OutOfMemory)?;
            child_inner.parked.insert(page, frame);
        }
        drop(child_inner);
        child.sync_user_view();
        Ok(child)
    }

    /// Bytes of user address space covered by mappings (reserved or not).
    pub fn mapped_bytes(&self) -> u64 {
        self.inner
            .lock()
            .layout
            .vmas()
            .map(|v| v.end - v.start)
            .sum()
    }

    /// Bytes of user memory currently backed by frames.
    pub fn resident_bytes(&self) -> u64 {
        let inner = self.inner.lock();
        let mut bytes = inner.parked.len() as u64 * PAGE;
        paging::walk(&mut DirectMapTables, self.root, |virt, t| {
            if virt < vm::USER_END {
                bytes += t.size.bytes();
            }
        });
        bytes
    }

    /// Effective rights of the user page at `address`, if present.
    pub fn page_flags(&self, address: u64) -> Option<Flags> {
        let _inner = self.inner.lock();
        paging::translate(&mut DirectMapTables, self.root, address & !(PAGE - 1)).map(|t| t.flags)
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        for (_, frame) in core::mem::take(&mut self.inner.lock().parked) {
            let _ = memory::release(frame);
        }
        let (tables, leaves) = paging::clear_user_half(&mut DirectMapTables, self.root);
        for phys in leaves {
            let _ = memory::release(Frame::containing(phys));
        }
        for table in tables {
            let _ = memory::release(table);
        }
        let _ = memory::release(self.root);
        // The user view shares the (now freed) lower-level tables and the
        // permanent trampoline entry; only its own top-level frame is freed.
        let _ = memory::release(self.user_root);
    }
}

/// The address space the CPU is using, if any. Single CPU for now (D8);
/// per-thread with user mode (P1-T10).
static CURRENT: IrqMutex<Option<Arc<AddressSpace>>> = IrqMutex::new(None);

/// Sets the address space page faults resolve against. Called by the
/// scheduler on every switch.
pub(crate) fn set_current(space: Option<Arc<AddressSpace>>) {
    *CURRENT.lock() = space;
}

/// Runs `f` with `space` active (CR3 switched), then switches back to the
/// kernel tables. Used by kernel threads (and self-tests) to work in
/// another address space.
pub fn with_address_space<R>(space: &Arc<AddressSpace>, f: impl FnOnce() -> R) -> R {
    // The space becomes the thread's own for the duration, so a context
    // switch in the middle restores it instead of the thread's usual
    // tables; afterwards whatever was there before comes back (the
    // kernel's tables for a kernel thread, the process's own space for a
    // thread in a system call).
    let previous = crate::sched::swap_space(Some(space.clone()));
    let result = f();
    crate::sched::swap_space(previous);
    result
}

// ---- Checked user copies --------------------------------------------------

/// Error returned for any bad user pointer (EFAULT).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault;

static SMAP: AtomicBool = AtomicBool::new(false);

/// Records whether SMAP is on, so the copy routine knows whether it may
/// (and must) use STAC/CLAC. Called by paging setup.
pub fn set_smap_enabled(enabled: bool) {
    SMAP.store(enabled, Ordering::Relaxed);
}

// Assembly reasoning (spec section 1, rule 4)
//
// keel_user_copy_smap(dst = rdi, src = rsi, len = rdx) -> rax
// keel_user_copy_plain(...)   (same without STAC/CLAC, for CPUs without
//                              SMAP, where STAC raises #UD: SDM Vol. 2B
//                              "STAC", exceptions)
//   Entry state: System V call; DF = 0 (ABI); interrupts in any state.
//     The caller has checked that the user side of [dst/src, +len) lies in
//     the user half and the kernel side is a valid kernel buffer.
//   1. `stac` sets RFLAGS.AC, allowing supervisor access to user pages
//      while CR4.SMAP = 1 (SDM Vol. 2B "STAC").
//   2. `mov rcx, rdx; rep movsb` copies len bytes from [rsi] to [rdi].
//      If a byte faults, the CPU leaves RSI, RDI and RCX describing the
//      remaining work and RIP pointing at `rep movsb` (SDM Vol. 2B "REP"),
//      so the page-fault handler can map the page and simply return, or
//      redirect RIP to the fixup label.
//   3. `clac` clears AC again; `xor eax, eax` returns 0.
//   Fixup (reached only by the page-fault handler moving RIP there): clear
//   AC and return 1.
//   Exit state: rax = 0 or 1; rcx, rsi, rdi clobbered (caller-saved);
//   RFLAGS.AC = 0 in both paths.
core::arch::global_asm!(
    r#"
    .pushsection .text, "ax", @progbits
    .global keel_user_copy_smap
    .global keel_user_copy_smap_fault
    .global keel_user_copy_smap_fixup
    keel_user_copy_smap:
        stac
        mov rcx, rdx
    keel_user_copy_smap_fault:
        rep movsb
        clac
        xor eax, eax
        ret
    keel_user_copy_smap_fixup:
        clac
        mov eax, 1
        ret

    .global keel_user_copy_plain
    .global keel_user_copy_plain_fault
    .global keel_user_copy_plain_fixup
    keel_user_copy_plain:
        mov rcx, rdx
    keel_user_copy_plain_fault:
        rep movsb
        xor eax, eax
        ret
    keel_user_copy_plain_fixup:
        mov eax, 1
        ret
    .popsection
    "#
);

unsafe extern "C" {
    fn keel_user_copy_smap(dst: *mut u8, src: *const u8, len: usize) -> u64;
    fn keel_user_copy_plain(dst: *mut u8, src: *const u8, len: usize) -> u64;
    static keel_user_copy_smap_fault: u8;
    static keel_user_copy_smap_fixup: u8;
    static keel_user_copy_plain_fault: u8;
    static keel_user_copy_plain_fixup: u8;
}

/// The fixup address for a fault at `rip` inside a user-copy routine.
fn copy_fixup(rip: u64) -> Option<u64> {
    if rip == &raw const keel_user_copy_smap_fault as u64 {
        Some(&raw const keel_user_copy_smap_fixup as u64)
    } else if rip == &raw const keel_user_copy_plain_fault as u64 {
        Some(&raw const keel_user_copy_plain_fixup as u64)
    } else {
        None
    }
}

/// Whether `[address, address + length)` lies inside the user half.
/// Checked arithmetic: a range that wraps is rejected (SR-19).
pub fn user_range_ok(address: u64, length: usize) -> bool {
    address
        .checked_add(length as u64)
        .is_some_and(|end| address >= vm::USER_START && end <= vm::USER_END)
}

fn copy(dst: *mut u8, src: *const u8, len: usize) -> Result<(), Fault> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: the callers check the user side against the user half and
    // pass a kernel slice of exactly `len` bytes for the other side. A
    // fault on the user side is handled by the page-fault handler (demand
    // paging) or turned into a return value of 1 via the fixup.
    let failed = unsafe {
        if SMAP.load(Ordering::Relaxed) {
            keel_user_copy_smap(dst, src, len)
        } else {
            keel_user_copy_plain(dst, src, len)
        }
    };
    if failed == 0 { Ok(()) } else { Err(Fault) }
}

/// Copies `data` to user address `dst` in the active address space.
pub fn copy_to_user(dst: u64, data: &[u8]) -> Result<(), Fault> {
    if !user_range_ok(dst, data.len()) {
        return Err(Fault);
    }
    copy(dst as *mut u8, data.as_ptr(), data.len())
}

/// Copies from user address `src` in the active address space into `buf`.
pub fn copy_from_user(buf: &mut [u8], src: u64) -> Result<(), Fault> {
    if !user_range_ok(src, buf.len()) {
        return Err(Fault);
    }
    copy(buf.as_mut_ptr(), src as *const u8, buf.len())
}

// ---- Page-fault entry ------------------------------------------------------

/// Called for every #PF. Returns true if the fault was handled (the
/// faulting instruction may be retried, or RIP was moved to a fixup).
pub(crate) fn handle_page_fault(frame: &mut TrapFrame, address: u64) -> bool {
    let from_user = frame.cs & 3 == 3;
    let fixup = if from_user {
        None
    } else {
        copy_fixup(frame.rip)
    };
    // Kernel-mode faults on user addresses are only legitimate inside the
    // copy routines; anything else is a kernel bug and stays fatal.
    if !from_user && fixup.is_none() {
        return false;
    }
    if address < vm::USER_END {
        let space = CURRENT.lock().clone();
        if let Some(space) = space
            && space.resolve_fault(address, frame.error_code)
        {
            return true;
        }
    }
    match fixup {
        Some(target) => {
            frame.rip = target;
            true
        }
        // User-mode faults become signals with user mode (P1-T10).
        None => false,
    }
}
