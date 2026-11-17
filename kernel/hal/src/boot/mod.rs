//! Safe view of what the bootloader handed over.
//!
//! Everything here reads structures that Limine placed in
//! bootloader-reclaimable memory. The bootloader is part of the verified
//! boot chain (SR-27), but firmware-derived numbers still pass through it,
//! so counts and sizes are capped and combined with checked arithmetic
//! before they are used (SR-19).
//!
//! Lifetime rule for the whole kernel: memory-map regions of kind
//! [`RegionKind::BootloaderReclaimable`] must not be reused while any
//! reference obtained from this module is alive. Nothing reclaims them yet.

pub mod limine;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::drivers::framebuffer::PixelLayout;

/// Upper bound on list lengths accepted from the bootloader. Real memory
/// maps have a few hundred entries at most; a larger count means the
/// response is corrupt and is treated as absent.
const MAX_LIST_ENTRIES: u64 = 4096;

/// Upper bound on the length of a bootloader string.
const MAX_STRING_LEN: usize = 4096;

/// Result of the base-revision handshake ("Base Revisions" in PROTOCOL.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseRevision {
    /// Revision the kernel asked for.
    pub requested: u64,
    /// Whether the bootloader honours the requested revision.
    pub supported: bool,
    /// Revision the bootloader actually applied, when it reports one.
    pub loaded: Option<u64>,
}

/// Reports how the bootloader answered the base-revision request.
pub fn base_revision() -> BaseRevision {
    BaseRevision {
        requested: limine::BASE_REVISION,
        supported: limine::BASE_REVISION_TAG.is_supported(),
        loaded: limine::BASE_REVISION_TAG.loaded_revision(),
    }
}

/// Virtual address at which physical address 0 is mapped (the higher-half
/// direct map), if the bootloader reported it.
pub fn hhdm_offset() -> Option<u64> {
    limine::HHDM.response().map(|r| r.offset)
}

/// Where the kernel image was loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelAddress {
    /// Physical address of the start of the image.
    pub physical_base: u64,
    /// Virtual address of the start of the image.
    pub virtual_base: u64,
}

/// Load addresses of the kernel image.
pub fn kernel_address() -> Option<KernelAddress> {
    limine::EXECUTABLE_ADDRESS
        .response()
        .map(|r| KernelAddress {
            physical_base: r.physical_base,
            virtual_base: r.virtual_base,
        })
}

/// Reads a NUL-terminated bootloader string, bounded by [`MAX_STRING_LEN`].
/// Returns `""` for a null pointer, a missing terminator, or invalid UTF-8.
///
/// # Safety
///
/// `ptr` must be null or point to memory that is readable and immutable
/// for `'static` up to and including the first NUL byte or
/// [`MAX_STRING_LEN`] bytes, whichever comes first.
unsafe fn bootloader_str(ptr: *const u8) -> &'static str {
    if ptr.is_null() {
        return "";
    }
    let mut len = 0;
    // SAFETY: each byte read is within the range the caller vouched for:
    // the loop stops at the first NUL or at MAX_STRING_LEN.
    while len < MAX_STRING_LEN && unsafe { ptr.add(len).read() } != 0 {
        len += 1;
    }
    if len == MAX_STRING_LEN {
        return "";
    }
    // SAFETY: the `len` bytes before the terminator were just read
    // successfully and stay valid and unchanged for `'static` per the
    // caller's contract.
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len) };
    core::str::from_utf8(bytes).unwrap_or("")
}

/// The kernel command line from `limine.conf` (`cmdline:`), or `""`.
pub fn cmdline() -> &'static str {
    match limine::CMDLINE.response() {
        // SAFETY: "Executable Command Line Feature": `cmdline` is a
        // 0-terminated string in bootloader-reclaimable memory, which is
        // immutable after handoff and kept for the kernel's lifetime.
        Some(response) => unsafe { bootloader_str(response.cmdline) },
        None => "",
    }
}

/// Kind of a physical memory region ("Memory Map Feature", `type` values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    /// Free RAM.
    Usable,
    /// Reserved by firmware or hardware; never touched.
    Reserved,
    /// ACPI tables; reclaimable once they have been parsed.
    AcpiReclaimable,
    /// ACPI non-volatile storage.
    AcpiNvs,
    /// Faulty RAM.
    BadMemory,
    /// Bootloader data still referenced by the kernel (see module docs).
    BootloaderReclaimable,
    /// The kernel image and boot modules.
    ExecutableAndModules,
    /// A memory-mapped framebuffer.
    Framebuffer,
    /// Reserved, but mapped in the HHDM (ACPI/SMBIOS/EFI runtime data).
    ReservedMapped,
    /// A type value this kernel does not know. Treated as reserved
    /// (fail closed, SR-10).
    Unknown(u64),
}

impl RegionKind {
    fn from_raw(kind: u64) -> Self {
        match kind {
            0 => Self::Usable,
            1 => Self::Reserved,
            2 => Self::AcpiReclaimable,
            3 => Self::AcpiNvs,
            4 => Self::BadMemory,
            5 => Self::BootloaderReclaimable,
            6 => Self::ExecutableAndModules,
            7 => Self::Framebuffer,
            8 => Self::ReservedMapped,
            other => Self::Unknown(other),
        }
    }
}

/// One entry of the physical memory map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    /// Physical base address.
    pub base: u64,
    /// Length in bytes.
    pub length: u64,
    /// What the region holds.
    pub kind: RegionKind,
}

/// Returns the bootloader's array of `count` pointers as a slice, or an
/// empty slice if the array is absent or implausibly long.
///
/// # Safety
///
/// If `array` is non-null it must point to `count` consecutive, initialised
/// `*const T` values that are immutable for `'static`.
unsafe fn pointer_array<T>(array: *const *const T, count: u64) -> &'static [*const T] {
    if array.is_null() || count > MAX_LIST_ENTRIES {
        return &[];
    }
    // SAFETY: non-null, and `count` elements are valid per the caller's
    // contract; `count <= MAX_LIST_ENTRIES` fits in usize and keeps the
    // slice far below `isize::MAX` bytes.
    unsafe { core::slice::from_raw_parts(array, count as usize) }
}

/// Iterates over the physical memory map, sorted by base address
/// (the protocol guarantees the order).
pub fn memory_map() -> impl Iterator<Item = MemoryRegion> {
    let entries = match limine::MEMMAP.response() {
        // SAFETY: "Memory Map Feature": `entries` points to `entry_count`
        // pointers in bootloader-reclaimable memory.
        Some(response) => unsafe { pointer_array(response.entries, response.entry_count) },
        None => &[],
    };
    entries.iter().filter_map(|&entry| {
        // SAFETY: each non-null element points to a `limine_memmap_entry`
        // in bootloader-reclaimable memory, immutable after handoff.
        let entry = unsafe { entry.as_ref() }?;
        Some(MemoryRegion {
            base: entry.base,
            length: entry.length,
            kind: RegionKind::from_raw(entry.kind),
        })
    })
}

/// A file the bootloader loaded alongside the kernel (the initramfs).
#[derive(Clone, Copy, Debug)]
pub struct Module {
    /// File contents.
    pub data: &'static [u8],
    /// Path on the boot volume, with a leading slash.
    pub path: &'static str,
    /// The `module_string` given in `limine.conf`, or `""`.
    pub string: &'static str,
}

/// Iterates over the boot modules in `limine.conf` order.
pub fn modules() -> impl Iterator<Item = Module> {
    let files = match limine::MODULES.response() {
        // SAFETY: "Module Feature": `modules` points to `module_count`
        // pointers in bootloader-reclaimable memory.
        Some(response) => unsafe { pointer_array(response.modules, response.module_count) },
        None => &[],
    };
    files.iter().filter_map(|&file| {
        // SAFETY: each non-null element points to a `limine_file`.
        let file = unsafe { file.as_ref() }?;
        if file.address.is_null() || file.size > isize::MAX as u64 {
            return None;
        }
        // SAFETY: "File Structure": `address`/`size` describe the loaded
        // file, which owns every 4 KiB page it covers; it lies in an
        // executable-and-modules region that the kernel never frees or
        // writes. The size was checked to fit a slice length.
        let data = unsafe { core::slice::from_raw_parts(file.address, file.size as usize) };
        Some(Module {
            data,
            // SAFETY: `path` and `string` are bootloader strings.
            path: unsafe { bootloader_str(file.path) },
            // SAFETY: as above.
            string: unsafe { bootloader_str(file.string) },
        })
    })
}

/// Length of the ACPI 1.0 Root System Description Pointer structure
/// (ACPI specification, "Root System Description Pointer (RSDP) Structure").
pub const RSDP_V1_LEN: usize = 20;

/// The first 20 bytes of the ACPI RSDP, if the firmware provides ACPI.
///
/// Only valid under base revision 4 or later, where the address is virtual
/// and the table is guaranteed to be mapped; otherwise returns `None`.
pub fn rsdp() -> Option<&'static [u8; RSDP_V1_LEN]> {
    let revision = base_revision();
    if !revision.supported || revision.loaded.unwrap_or(revision.requested) < 4 {
        return None;
    }
    let address = limine::RSDP.response()?.address;
    // SAFETY: under base revision >= 4 ("RSDP Feature", "Base Revision 4")
    // a non-null address is an HHDM pointer to the RSDP, which is mapped
    // within an ACPI or reserved-mapped region and is at least 20 bytes
    // long in every ACPI version. Firmware tables are not modified after
    // boot. `[u8; 20]` has alignment 1.
    unsafe { address.cast::<[u8; RSDP_V1_LEN]>().as_ref() }
}

/// The boot framebuffer: its pixel memory and its layout.
pub struct BootFramebuffer {
    /// Pixel memory, exactly as long as the layout requires.
    pub pixels: &'static mut [u8],
    /// Geometry and pixel format.
    pub layout: PixelLayout,
}

static FRAMEBUFFER_TAKEN: AtomicBool = AtomicBool::new(false);

/// Hands out the first framebuffer exactly once.
///
/// Returns `None` if there is no usable framebuffer or it was already
/// taken. Single ownership is what makes the `&'static mut` sound.
pub fn take_framebuffer() -> Option<BootFramebuffer> {
    let response = limine::FRAMEBUFFER.response()?;
    // SAFETY: "Framebuffer Feature": `framebuffers` points to
    // `framebuffer_count` pointers in bootloader-reclaimable memory.
    let list = unsafe { pointer_array(response.framebuffers, response.framebuffer_count) };
    // SAFETY: a non-null element points to a `limine_framebuffer`.
    let fb = unsafe { list.first()?.as_ref() }?;
    if fb.address.is_null() || fb.memory_model != limine::FRAMEBUFFER_RGB || fb.bpp % 8 != 0 {
        return None;
    }
    let layout = PixelLayout {
        width: usize::try_from(fb.width).ok()?,
        height: usize::try_from(fb.height).ok()?,
        pitch: usize::try_from(fb.pitch).ok()?,
        bytes_per_pixel: usize::from(fb.bpp / 8),
        red_shift: fb.red_mask_shift,
        red_size: fb.red_mask_size,
        green_shift: fb.green_mask_shift,
        green_size: fb.green_mask_size,
        blue_shift: fb.blue_mask_shift,
        blue_size: fb.blue_mask_size,
    };
    let len = layout.required_len()?;
    if len > isize::MAX as usize {
        return None;
    }
    if FRAMEBUFFER_TAKEN.swap(true, Ordering::AcqRel) {
        return None;
    }
    // SAFETY: the bootloader mapped the framebuffer at `address` for at
    // least `pitch * height` bytes ("Memory Layout at Entry" maps
    // framebuffer regions; `required_len` is no larger than that). The
    // mapping is writable, lives for the kernel's lifetime, and aliases no
    // Rust object. The `FRAMEBUFFER_TAKEN` swap above guarantees this is
    // the only mutable reference ever created to it.
    let pixels = unsafe { core::slice::from_raw_parts_mut(fb.address, len) };
    Some(BootFramebuffer { pixels, layout })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_kinds_follow_the_protocol_numbering() {
        assert_eq!(RegionKind::from_raw(0), RegionKind::Usable);
        assert_eq!(RegionKind::from_raw(5), RegionKind::BootloaderReclaimable);
        assert_eq!(RegionKind::from_raw(8), RegionKind::ReservedMapped);
        assert_eq!(RegionKind::from_raw(9), RegionKind::Unknown(9));
    }

    #[test]
    fn bootloader_strings_are_bounded_and_validated() {
        // SAFETY: (all four calls) each pointer is null or refers to a
        // static byte string that is readable up to its NUL terminator or
        // for at least MAX_STRING_LEN bytes.
        unsafe {
            assert_eq!(bootloader_str(core::ptr::null()), "");
            assert_eq!(bootloader_str(c"test=0".as_ptr().cast()), "test=0");
            assert_eq!(bootloader_str(c"\xff\xfe".as_ptr().cast()), "");
            static UNTERMINATED: [u8; MAX_STRING_LEN] = [b'a'; MAX_STRING_LEN];
            assert_eq!(bootloader_str(UNTERMINATED.as_ptr()), "");
        }
    }

    #[test]
    fn pointer_arrays_reject_null_and_oversized_counts() {
        let item = 7u32;
        let array = [&raw const item];
        // SAFETY: `array` holds one valid pointer; the other two calls are
        // rejected before any dereference.
        unsafe {
            assert_eq!(pointer_array::<u32>(core::ptr::null(), 1).len(), 0);
            assert_eq!(pointer_array(array.as_ptr(), MAX_LIST_ENTRIES + 1).len(), 0);
        }
    }

    #[test]
    fn host_has_no_boot_information() {
        assert_eq!(hhdm_offset(), None);
        assert_eq!(cmdline(), "");
        assert_eq!(memory_map().count(), 0);
        assert_eq!(modules().count(), 0);
        assert!(rsdp().is_none());
        assert!(take_framebuffer().is_none());
    }
}
