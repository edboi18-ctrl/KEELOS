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

use keel_core::compartment::Budget;
use keel_core::frame::Frame;
use keel_core::paging::{self, Flags, PageSize, TableAccess};
use keel_core::vm::{self, Backing, FaultAction, Layout, Placement, Prot, VmError};

use crate::arch::x86_64::cpu;
use crate::arch::x86_64::idt::{TrapFrame, page_fault};
use crate::arch::x86_64::paging::{DirectMapTables, kernel_root};
use crate::memory;
use crate::sync::IrqMutex;

/// Page tables for the user half. Same as `DirectMapTables`, except that
/// new tables come from the reserve-checked allocator
/// (`memory::allocate_zeroed_user`): a program touching one page in each
/// of many 2 MiB or 1 GiB regions makes the kernel allocate a table per
/// page, and those frames must not come out of the kernel's reserve either
/// (F-0011). Each table is also charged to the address space's account,
/// so it counts against its compartment's memory limit (P3-S4).
struct UserTables<'a>(DirectMapTables, &'a mut Account);

impl TableAccess for UserTables<'_> {
    fn allocate_table(&mut self) -> Option<Frame> {
        if !self.1.charge(1) {
            return None;
        }
        let frame = memory::allocate_zeroed_user();
        if frame.is_none() {
            self.1.uncharge(1);
        }
        frame
    }

    fn table(&mut self, frame: Frame) -> &mut [u64; 512] {
        self.0.table(frame)
    }
}

/// The user frames an address space holds, counted for its compartment's
/// memory limit (P3-S4, ADR 0014): every present user page and every
/// parked one (a page counts in each space that maps it, so pages shared
/// copy-on-write are counted more than once, never less), plus every user
/// page table. Updated only with the space's lock held. Before a budget is
/// attached the count only grows locally; attaching charges it all.
struct Account {
    frames: usize,
    budget: Option<Arc<Budget>>,
}

impl Account {
    /// Counts `n` more frames, if the budget (when attached) allows.
    fn charge(&mut self, n: usize) -> bool {
        if let Some(budget) = &self.budget
            && !budget.try_charge(n)
        {
            return false;
        }
        self.frames += n;
        true
    }

    fn uncharge(&mut self, n: usize) {
        self.frames = self.frames.saturating_sub(n);
        if let Some(budget) = &self.budget {
            budget.uncharge(n);
        }
    }
}

const PAGE: u64 = vm::PAGE;

/// Reads one page of a mapped file: fills `page` from file `object` at
/// `offset` and returns how many bytes the file had there (the rest stays
/// zero), or `None` if the page starts at or beyond the end of the file.
pub type FileReader = fn(object: u64, offset: u64, page: &mut [u8; 4096]) -> Option<usize>;

/// Installed by the personality that owns the files (`linux-abi`). Called
/// from the page-fault path with the address-space lock held, so it may
/// take the filesystem lock: nothing takes an address-space lock while
/// holding the filesystem lock (no user memory is touched under it).
static FILE_READER: IrqMutex<Option<FileReader>> = IrqMutex::new(None);

pub fn set_file_reader(reader: FileReader) {
    *FILE_READER.lock() = Some(reader);
}

/// Told when an address space starts (true) or stops (false) mapping a
/// file, by `Backing::object`, so the owner of the files keeps a mapped
/// file alive after its last name and handle are gone (ADR 0022). Called
/// without any address-space lock held; it may take the filesystem lock.
pub type ObjectHook = fn(object: u64, mapped: bool);

static OBJECT_HOOK: IrqMutex<Option<ObjectHook>> = IrqMutex::new(None);

pub fn set_object_hook(hook: ObjectHook) {
    *OBJECT_HOOK.lock() = Some(hook);
}

/// Reports one operation's changes, netted per file (MAP_FIXED over a
/// mapping of the same file removes and adds it in one operation, which
/// must not look like an unmap): the hook sees a file only if the
/// operation really started or stopped mapping it.
fn report_objects(changes: alloc::vec::Vec<(u64, bool)>) {
    if changes.is_empty() {
        return;
    }
    let mut net: BTreeMap<u64, i64> = BTreeMap::new();
    for (object, mapped) in changes {
        *net.entry(object).or_insert(0) += if mapped { 1 } else { -1 };
    }
    let Some(hook) = *OBJECT_HOOK.lock() else {
        return;
    };
    // Pins first, then unpins: nothing is freed that this operation also
    // keeps.
    for (&object, &n) in &net {
        if n > 0 {
            hook(object, true);
        }
    }
    for (&object, &n) in &net {
        if n < 0 {
            hook(object, false);
        }
    }
}

/// The frames of file pages mapped MAP_SHARED (ADR 0021), by (file,
/// page-aligned offset). Every shared mapping of a page maps this frame,
/// so their stores are seen by each other; the cache holds one reference
/// to each frame, each mapping one more. Pages enter at a mapping's first
/// fault and stay while the file has them: `shared_truncate` drops those
/// past a new end, `shared_forget` all of a file's. They are file data,
/// bounded by the file's size (and so by the tmpfs limits and the owner's
/// quota); each mapping charges its address space one frame per page, as
/// for any present page.
///
/// Lock order: an address-space lock, then this one. The `FileReader` is
/// called with neither this lock nor the filesystem's held by the caller
/// beyond the call, and `keel-linux-abi` takes this lock after the
/// filesystem's, never the reverse.
static SHARED_PAGES: IrqMutex<BTreeMap<(u64, u64), Frame>> = IrqMutex::new(BTreeMap::new());

/// Copies the bytes of `object` from `offset` that shared pages hold over
/// `buf` (which read(2) filled from the file): a store through a shared
/// mapping is the file's newest data.
pub fn shared_read(object: u64, offset: u64, buf: &mut [u8]) {
    each_shared_page(object, offset, buf.len(), |frame, at, range| {
        let _ = memory::read_frame_at(frame, at, &mut buf[range]);
    });
}

/// Copies `data`, just written to `object` at `offset` by write(2), into
/// the shared pages that hold that part of the file, so every mapping
/// sees it.
pub fn shared_write(object: u64, offset: u64, data: &[u8]) {
    each_shared_page(object, offset, data.len(), |frame, at, range| {
        let _ = memory::write_frame_at(frame, at, &data[range]);
    });
}

/// Calls `f(frame, offset in frame, range of the caller's buffer)` for
/// each shared page of `object` overlapping `[offset, offset + len)`.
fn each_shared_page(
    object: u64,
    offset: u64,
    len: usize,
    mut f: impl FnMut(Frame, usize, core::ops::Range<usize>),
) {
    let Some(end) = offset.checked_add(len as u64) else {
        return;
    };
    let pages = SHARED_PAGES.lock();
    let first = offset & !(PAGE - 1);
    for (&(_, page), &frame) in pages.range((object, first)..(object, end)) {
        let from = page.max(offset);
        let to = (page + PAGE).min(end);
        f(
            frame,
            (from - page) as usize,
            (from - offset) as usize..(to - offset) as usize,
        );
    }
}

/// The file `object` now ends at `len` (ftruncate(2)): its shared pages
/// wholly past the end leave the cache, and the bytes past the end in the
/// page that holds it become zero, as the file's own bytes do ("the
/// extended part reads as null bytes" if it grows again). A mapping that
/// already has a dropped page keeps its frame until unmapped; Linux would
/// unmap it, so that a later access gets SIGBUS (ADR 0021).
pub fn shared_truncate(object: u64, len: u64) {
    let mut pages = SHARED_PAGES.lock();
    let keep_to = len.next_multiple_of(PAGE);
    let gone: alloc::vec::Vec<u64> = pages
        .range((object, keep_to)..=(object, u64::MAX))
        .map(|(&(_, page), _)| page)
        .collect();
    for page in gone {
        if let Some(frame) = pages.remove(&(object, page)) {
            let _ = memory::release(frame);
        }
    }
    if !len.is_multiple_of(PAGE)
        && let Some(&frame) = pages.get(&(object, len & !(PAGE - 1)))
    {
        let at = (len % PAGE) as usize;
        let zeros = [0u8; PAGE as usize];
        let _ = memory::write_frame_at(frame, at, &zeros[at..]);
    }
}

/// Drops every shared page of `object` (the file is gone).
pub fn shared_forget(object: u64) {
    shared_truncate(object, 0);
}

/// Shared pages held in the cache (tests).
pub fn shared_pages() -> usize {
    SHARED_PAGES.lock().len()
}

/// The cached frame of `object`'s page at `offset`, made on first use
/// from the file's bytes (zero past its end). None if the page starts at
/// or past the end of the file, or memory runs out.
fn shared_frame(object: u64, offset: u64) -> Option<Frame> {
    if let Some(&frame) = SHARED_PAGES.lock().get(&(object, offset)) {
        return Some(frame);
    }
    // Read the file before taking a frame (a page past the end costs
    // nothing), without holding the cache lock.
    let mut contents = [0u8; 4096];
    let reader = (*FILE_READER.lock())?;
    let filled = reader(object, offset, &mut contents)?.min(contents.len());
    let frame = memory::allocate_zeroed_user()?;
    if filled > 0 && memory::fill_frame(frame, &contents[..filled]).is_err() {
        let _ = memory::release(frame);
        return None;
    }
    SHARED_PAGES.lock().insert((object, offset), frame);
    Some(frame)
}

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
    account: Account,
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
    /// Never reused, unlike the table frames (audit 2, A4).
    id: u64,
    inner: IrqMutex<Inner>,
}

/// Source of `AddressSpace::id`. 64 bits never wrap in practice.
static NEXT_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

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
        LIVE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(Arc::new(AddressSpace {
            root,
            user_root,
            id: NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            inner: IrqMutex::new(Inner {
                layout: Layout::new(),
                parked: BTreeMap::new(),
                account: Account {
                    frames: 0,
                    budget: None,
                },
            }),
        }))
    }

    /// An identifier no other address space, past or future, has. The
    /// table addresses are not one: a freed table frame can be handed to
    /// the next address space.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Charges this space to `budget` from now on, starting with the frames
    /// it already holds (what the loader populated). Refused, with nothing
    /// changed, if they do not fit, or if a budget is already attached.
    pub fn attach_budget(&self, budget: Arc<Budget>) -> Result<(), AsError> {
        let mut inner = self.inner.lock();
        if inner.account.budget.is_some() || !budget.try_charge(inner.account.frames) {
            return Err(AsError::OutOfMemory);
        }
        inner.account.budget = Some(budget);
        Ok(())
    }

    /// Frames charged to this space (see `Account`).
    pub fn charged_frames(&self) -> usize {
        self.inner.lock().account.frames
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
        self.map_backed(placement, length, prot, None)
    }

    /// Adds a private mapping of a file (mmap with a descriptor, P3-T7).
    /// Pages are read from the file through the installed `FileReader`
    /// when first touched, into private frames.
    pub fn map_file(
        &self,
        placement: Placement,
        length: u64,
        prot: Prot,
        backing: Backing,
    ) -> Result<u64, AsError> {
        self.map_backed(placement, length, prot, Some(backing))
    }

    fn map_backed(
        &self,
        placement: Placement,
        length: u64,
        prot: Prot,
        backing: Option<Backing>,
    ) -> Result<u64, AsError> {
        let mut inner = self.inner.lock();
        let (start, replaced) = inner.layout.map_backed(placement, length, prot, backing)?;
        for (from, to) in replaced {
            self.unmap_pages(&mut inner, from, to);
        }
        let changes = inner.layout.take_object_changes();
        drop(inner);
        report_objects(changes);
        Ok(start)
    }

    /// Removes a range (munmap) and frees its pages.
    pub fn unmap(&self, start: u64, length: u64) -> Result<(), AsError> {
        let mut inner = self.inner.lock();
        for (from, to) in inner.layout.unmap(start, length)? {
            self.unmap_pages(&mut inner, from, to);
        }
        let changes = inner.layout.take_object_changes();
        drop(inner);
        report_objects(changes);
        Ok(())
    }

    /// Changes protection (mprotect). Pages already present get the new
    /// rights; copy-on-write pages stay read-only until written.
    pub fn protect(&self, start: u64, length: u64, prot: Prot) -> Result<(), AsError> {
        let mut inner = self.inner.lock();
        let none = prot == Prot::NONE;
        // Only present pages and parked frames are visited, never every
        // page of the range: a range can be terabytes (a reservation).
        for (from, to) in inner.layout.protect(start, length, prot)? {
            // A shared file page is writable whoever else maps it; a
            // private one only if no one else does (copy-on-write).
            let file_shared = inner
                .layout
                .find(from)
                .and_then(|v| v.backing)
                .is_some_and(|b| b.shared);
            let mut at = from;
            while let Some(page) =
                paging::next_present_small(&mut DirectMapTables, self.root, at, to)
            {
                at = page + PAGE;
                if none {
                    // Take the frame out of the page tables entirely.
                    if let Some(phys) = paging::unmap_small(&mut DirectMapTables, self.root, page) {
                        cpu::invalidate_page(page);
                        inner.parked.insert(page, Frame::containing(phys));
                    }
                } else if let Some(t) = paging::translate(&mut DirectMapTables, self.root, page) {
                    let exclusive =
                        file_shared || memory::references(Frame::containing(t.phys)) == 1;
                    let _ = paging::replace_small(
                        &mut DirectMapTables,
                        self.root,
                        page,
                        t.phys,
                        user_flags(prot, exclusive),
                    );
                    cpu::invalidate_page(page);
                }
            }
            if none {
                continue;
            }
            // Parked PROT_NONE frames in the range get mapped again.
            let parked: alloc::vec::Vec<u64> = inner
                .parked
                .range(from..to)
                .map(|(&page, _)| page)
                .collect();
            for page in parked {
                let Some(frame) = inner.parked.remove(&page) else {
                    continue;
                };
                let exclusive = file_shared || memory::references(frame) == 1;
                let mapped = paging::map(
                    &mut UserTables(DirectMapTables, &mut inner.account),
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
            }
        }
        self.sync_user_view();
        Ok(())
    }

    /// Frees every page in `[from, to)`. Visits only present pages and
    /// parked frames (the range can be terabytes; found by the fuzzer).
    fn unmap_pages(&self, inner: &mut Inner, from: u64, to: u64) {
        let mut at = from;
        while let Some(page) = paging::next_present_small(&mut DirectMapTables, self.root, at, to) {
            at = page + PAGE;
            if let Some(phys) = paging::unmap_small(&mut DirectMapTables, self.root, page) {
                cpu::invalidate_page(page);
                let _ = memory::release(Frame::containing(phys));
                inner.account.uncharge(1);
            }
        }
        let parked: alloc::vec::Vec<u64> = inner
            .parked
            .range(from..to)
            .map(|(&page, _)| page)
            .collect();
        for page in parked {
            if let Some(frame) = inner.parked.remove(&page) {
                let _ = memory::release(frame);
                inner.account.uncharge(1);
            }
        }
    }

    /// Resolves a fault at `address`; returns whether the access can now
    /// be retried.
    fn resolve_fault(&self, address: u64, error_code: u64) -> bool {
        let mut inner = self.inner.lock();
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
            FaultAction::DemandZero(prot) => self.populate(&mut inner, page, prot, None),
            FaultAction::FromFile {
                prot,
                object,
                offset,
            } => self.populate(&mut inner, page, prot, Some((object, offset))),
            FaultAction::Shared {
                prot,
                object,
                offset,
            } => self.map_shared(&mut inner, page, prot, object, offset),
            FaultAction::CopyOnWrite(prot) => {
                let Some(old) = paging::translate(&mut DirectMapTables, self.root, page) else {
                    return false;
                };
                let old_frame = Frame::containing(old.phys);
                let target = if memory::references(old_frame) == 1 {
                    // Last user: take the page over.
                    old_frame
                } else {
                    let Some(copy) = memory::allocate_zeroed_user() else {
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

    /// Maps a fresh page at `page`: zeroed, or holding the file's bytes from
    /// `file` = (object, offset). Charged to the account first: over the
    /// compartment's memory limit the fault cannot be resolved, as when
    /// memory runs out (a user access ends the thread, a kernel copy
    /// returns EFAULT). A file page that starts at or past the end of the
    /// file cannot be resolved either: Linux sends SIGBUS there (mmap(2)),
    /// and until signals arrive (P3-T6) the fault ends the thread.
    fn populate(&self, inner: &mut Inner, page: u64, prot: Prot, file: Option<(u64, u64)>) -> bool {
        // Read the file before taking a frame: a page past the end costs
        // nothing.
        let mut contents = [0u8; 4096];
        let filled = match file {
            None => 0,
            Some((object, offset)) => {
                let reader = *FILE_READER.lock();
                match reader.and_then(|read| read(object, offset, &mut contents)) {
                    Some(n) => n.min(contents.len()),
                    None => return false,
                }
            }
        };
        if !inner.account.charge(1) {
            return false;
        }
        let Some(frame) = memory::allocate_zeroed_user() else {
            inner.account.uncharge(1);
            return false;
        };
        if filled > 0 && memory::fill_frame(frame, &contents[..filled]).is_err() {
            let _ = memory::release(frame);
            inner.account.uncharge(1);
            return false;
        }
        let mapped = paging::map(
            &mut UserTables(DirectMapTables, &mut inner.account),
            self.root,
            page,
            frame.address(),
            PageSize::Small,
            user_flags(prot, true),
        );
        if mapped.is_err() {
            let _ = memory::release(frame);
            inner.account.uncharge(1);
        }
        self.sync_user_view();
        // AlreadyMapped means another path mapped it first: retry.
        matches!(mapped, Ok(()) | Err(paging::MapError::AlreadyMapped))
    }

    /// Maps the shared frame of `object` at `offset` at `page` (ADR 0021),
    /// or, if the page is present (a write to it while it was mapped
    /// read-only), gives it the VMA's rights: a shared page is never
    /// copied. Charged one frame, as any present page.
    fn map_shared(
        &self,
        inner: &mut Inner,
        page: u64,
        prot: Prot,
        object: u64,
        offset: u64,
    ) -> bool {
        if let Some(t) = paging::translate(&mut DirectMapTables, self.root, page) {
            let replaced = paging::replace_small(
                &mut DirectMapTables,
                self.root,
                page,
                t.phys,
                user_flags(prot, true),
            );
            cpu::invalidate_page(page);
            return replaced.is_ok();
        }
        let Some(frame) = shared_frame(object, offset) else {
            return false;
        };
        if !inner.account.charge(1) {
            return false;
        }
        if memory::retain(frame).is_err() {
            inner.account.uncharge(1);
            return false;
        }
        let mapped = paging::map(
            &mut UserTables(DirectMapTables, &mut inner.account),
            self.root,
            page,
            frame.address(),
            PageSize::Small,
            user_flags(prot, true),
        );
        if mapped.is_err() {
            let _ = memory::release(frame);
            inner.account.uncharge(1);
        }
        self.sync_user_view();
        matches!(mapped, Ok(()) | Err(paging::MapError::AlreadyMapped))
    }

    /// A copy of this address space in which every present page is shared
    /// copy-on-write (for fork), except pages of shared file mappings,
    /// which both copies keep mapping with their rights (fork(2): "the
    /// child inherits ... memory mappings"; MAP_SHARED ones stay shared). Both copies lose write access to shared
    /// pages until they write.
    pub fn duplicate(&self) -> Result<Arc<AddressSpace>, AsError> {
        let child = AddressSpace::new()?;
        let inner = self.inner.lock();
        let mut child_inner = child.inner.lock();
        // The child gets the layout only once every page is copied: if the
        // copy fails, the child is dropped with an empty layout, so it
        // reports no file it never reported mapping.
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
            if !child_inner.account.charge(1) {
                return Err(AsError::OutOfMemory);
            }
            if memory::retain(frame).is_err() {
                child_inner.account.uncharge(1);
                return Err(AsError::OutOfMemory);
            }
            let file_shared = vma.backing.is_some_and(|b| b.shared);
            let shared = user_flags(vma.prot, file_shared);
            if paging::map(
                &mut UserTables(DirectMapTables, &mut child_inner.account),
                child.root,
                virt,
                phys,
                PageSize::Small,
                shared,
            )
            .is_err()
            {
                // Give back the reference taken above (audit 2, A7.3).
                let _ = memory::release(frame);
                child_inner.account.uncharge(1);
                return Err(AsError::OutOfMemory);
            }
            if !file_shared {
                let _ = paging::replace_small(&mut DirectMapTables, self.root, virt, phys, shared);
                cpu::invalidate_page(virt);
            }
        }
        // Parked (PROT_NONE) pages are shared the same way: the child
        // parks the same frame, and whichever side raises the protection
        // first sees a shared frame and gets it read-only (copy on write).
        for (&page, &frame) in &inner.parked {
            if !child_inner.account.charge(1) {
                return Err(AsError::OutOfMemory);
            }
            if memory::retain(frame).is_err() {
                child_inner.account.uncharge(1);
                return Err(AsError::OutOfMemory);
            }
            child_inner.parked.insert(page, frame);
        }
        child_inner.layout = inner.layout.clone();
        // The copy maps the same files.
        let objects: alloc::vec::Vec<(u64, bool)> = child_inner
            .layout
            .objects()
            .map(|object| (object, true))
            .collect();
        drop(child_inner);
        drop(inner);
        report_objects(objects);
        child.sync_user_view();
        Ok(child)
    }

    /// Whether a mapping covers `address` (whatever its protection): a
    /// fault there is an access error, SEGV_ACCERR, and elsewhere a
    /// missing mapping, SEGV_MAPERR (Linux `arch/x86/mm/fault.c`,
    /// bad_area and access_error).
    pub fn is_mapped(&self, address: u64) -> bool {
        self.inner.lock().layout.find(address).is_some()
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

/// Address spaces alive right now (leak checks).
static LIVE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn live_address_spaces() -> u64 {
    LIVE.load(core::sync::atomic::Ordering::Relaxed)
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed);
        // Every file it maps is no longer mapped by it.
        let objects: alloc::vec::Vec<(u64, bool)> = self
            .inner
            .lock()
            .layout
            .objects()
            .map(|object| (object, false))
            .collect();
        report_objects(objects);
        let mut inner = self.inner.lock();
        for (_, frame) in core::mem::take(&mut inner.parked) {
            let _ = memory::release(frame);
        }
        // Everything the space held is freed below: give it all back.
        let frames = inner.account.frames;
        inner.account.uncharge(frames);
        drop(inner);
        // Each frame is freed as the walk reaches it; nothing is collected,
        // so tearing down a large process allocates nothing (audit 3, C2).
        paging::clear_user_half(&mut DirectMapTables, self.root, |item| {
            let frame = match item {
                paging::Cleared::Leaf(phys) => Frame::containing(phys),
                paging::Cleared::Table(table) => table,
            };
            let _ = memory::release(frame);
        });
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
