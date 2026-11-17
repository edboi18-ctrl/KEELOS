//! Raw Limine boot protocol structures and the kernel's request block.
//!
//! Written for this project (ADR 0002) from the protocol specification:
//! Limine boot protocol, `PROTOCOL.md` (https://codeberg.org/Limine/limine-protocol),
//! base revision 6. Section names are cited next to each item. Every
//! structure is `#[repr(C)]` and mirrors the C definition field for field.
//!
//! How the protocol works ("Features"): the kernel image contains request
//! structures, each starting with a 4-word magic ID. Before entering the
//! kernel the bootloader scans the loaded image between the start and end
//! markers, and for each request it recognises it stores a pointer to a
//! response structure into the request's `response` field. A request the
//! bootloader does not serve keeps its null `response`.

use core::cell::UnsafeCell;

/// "Features / Request": the two ID words shared by every request.
const COMMON_MAGIC: [u64; 2] = [0xc7b1dd30df4c8b88, 0x0a82e883a194f07b];

/// Highest base revision this kernel understands ("Base Revisions").
pub const BASE_REVISION: u64 = 6;

/// A request header as laid out by "Features / Request":
/// `uint64_t id[4]; uint64_t revision; struct response *response;`.
#[repr(C)]
pub struct Request<R: 'static> {
    id: [u64; 4],
    revision: u64,
    /// Written by the bootloader before kernel entry, never afterwards.
    response: UnsafeCell<*const R>,
}

// SAFETY: the only writer of `response` is the bootloader, which finishes
// before the kernel's first instruction runs. From then on the cell is
// read-only, so sharing references across threads is sound.
unsafe impl<R> Sync for Request<R> {}

impl<R> Request<R> {
    const fn new(id: [u64; 2]) -> Self {
        Self {
            id: [COMMON_MAGIC[0], COMMON_MAGIC[1], id[0], id[1]],
            revision: 0,
            response: UnsafeCell::new(core::ptr::null()),
        }
    }

    /// The bootloader's response, if it provided one.
    pub fn response(&self) -> Option<&'static R> {
        // SAFETY: `self.response` is a valid, aligned cell inside a static.
        // The read is volatile because the bootloader changed the value
        // behind the compiler's back; the initialiser must not be assumed.
        let ptr = unsafe { self.response.get().read_volatile() };
        // SAFETY: a non-null response pointer was written by the verified
        // bootloader and, per "General Notes", points (through the HHDM) at
        // a response structure in bootloader-reclaimable memory, which the
        // kernel never frees or remaps while these references exist. The
        // structure is immutable after handoff, hence `&'static`.
        unsafe { ptr.as_ref() }
    }
}

/// "Base Revisions": `{ 0xf9562b2d5c95a6c8, 0x6a7b384944536bdc, N }`.
#[repr(C)]
pub struct BaseRevisionTag(UnsafeCell<[u64; 3]>);

// SAFETY: as for `Request`: written only by the bootloader before entry.
unsafe impl Sync for BaseRevisionTag {}

impl BaseRevisionTag {
    const MAGIC_1: u64 = 0x6a7b384944536bdc;

    const fn new(revision: u64) -> Self {
        Self(UnsafeCell::new([
            0xf9562b2d5c95a6c8,
            Self::MAGIC_1,
            revision,
        ]))
    }

    fn word(&self, index: usize) -> u64 {
        debug_assert!(index < 3);
        // SAFETY: `index < 3` at both call sites, so the pointer stays
        // inside the 3-word array; the cell is valid and aligned. Volatile
        // for the same reason as in `Request::response`.
        unsafe { self.0.get().cast::<u64>().add(index).read_volatile() }
    }

    /// `LIMINE_BASE_REVISION_SUPPORTED`: the bootloader sets the third word
    /// to 0 when it honours the requested revision.
    pub fn is_supported(&self) -> bool {
        self.word(2) == 0
    }

    /// `LIMINE_LOADED_BASE_REVISION`: the revision actually used, which
    /// bootloaders supporting revision 3 or later store in the second word.
    pub fn loaded_revision(&self) -> Option<u64> {
        let word = self.word(1);
        (word != Self::MAGIC_1).then_some(word)
    }
}

// ---- Response structures (section "Feature List") -----------------------

/// "Executable Command Line Feature".
#[repr(C)]
pub struct CmdlineResponse {
    pub revision: u64,
    pub cmdline: *const u8,
}

/// "HHDM (Higher Half Direct Map) Feature".
#[repr(C)]
pub struct HhdmResponse {
    pub revision: u64,
    pub offset: u64,
}

/// "Framebuffer Feature": response.
#[repr(C)]
pub struct FramebufferResponse {
    pub revision: u64,
    pub framebuffer_count: u64,
    pub framebuffers: *const *const Framebuffer,
}

/// "Framebuffer Feature": `struct limine_framebuffer`. Only the fields of
/// response revision 0 are declared; later revisions append fields, and
/// the kernel reads this structure only through a pointer.
#[repr(C)]
pub struct Framebuffer {
    pub address: *mut u8,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
    pub unused: [u8; 7],
    pub edid_size: u64,
    pub edid: *const u8,
}

/// `LIMINE_FRAMEBUFFER_RGB`.
pub const FRAMEBUFFER_RGB: u8 = 1;

/// "Memory Map Feature": response.
#[repr(C)]
pub struct MemmapResponse {
    pub revision: u64,
    pub entry_count: u64,
    pub entries: *const *const MemmapEntry,
}

/// "Memory Map Feature": `struct limine_memmap_entry`.
#[repr(C)]
pub struct MemmapEntry {
    pub base: u64,
    pub length: u64,
    pub kind: u64,
}

/// "Module Feature": response.
#[repr(C)]
pub struct ModuleResponse {
    pub revision: u64,
    pub module_count: u64,
    pub modules: *const *const File,
}

/// "File Structure": the leading fields of `struct limine_file`. The
/// media, TFTP and UUID fields that follow are not used by Keel and are
/// not declared; the structure is only ever read through a pointer.
#[repr(C)]
pub struct File {
    pub revision: u64,
    pub address: *const u8,
    pub size: u64,
    pub path: *const u8,
    pub string: *const u8,
}

/// "RSDP Feature". Under base revision 4 or later `address` is virtual
/// (HHDM); it is physical under base revision 3 only.
#[repr(C)]
pub struct RsdpResponse {
    pub revision: u64,
    pub address: *const u8,
}

/// "Executable Address Feature".
#[repr(C)]
pub struct ExecutableAddressResponse {
    pub revision: u64,
    pub physical_base: u64,
    pub virtual_base: u64,
}

// ---- The request block ---------------------------------------------------
//
// The linker script (kernel/keel-kernel/linker.ld) places these three
// sections consecutively, in this order, inside the writable data segment:
//   .limine_requests_start, .limine_requests, .limine_requests_end
// "Requests Delimiters": under base revision 2 or later the bootloader only
// honours requests located between the start and the end marker. All items
// are 8-byte aligned because they consist of `u64` and pointer fields.
// `#[used]` keeps each static even where Rust code never names it.

#[used]
#[unsafe(link_section = ".limine_requests_start")]
static REQUESTS_START_MARKER: [u64; 4] = [
    0xf6b8f4b39de7d1ae,
    0xfab91a6940fcb9cf,
    0x785c6ed015d3e316,
    0x181e920a7852b9d9,
];

#[used]
#[unsafe(link_section = ".limine_requests")]
pub static BASE_REVISION_TAG: BaseRevisionTag = BaseRevisionTag::new(BASE_REVISION);

#[used]
#[unsafe(link_section = ".limine_requests")]
pub static CMDLINE: Request<CmdlineResponse> =
    Request::new([0x4b161536e598651e, 0xb390ad4a2f1f303a]);

#[used]
#[unsafe(link_section = ".limine_requests")]
pub static HHDM: Request<HhdmResponse> = Request::new([0x48dcf1cb8ad2b852, 0x63984e959a98244b]);

#[used]
#[unsafe(link_section = ".limine_requests")]
pub static FRAMEBUFFER: Request<FramebufferResponse> =
    Request::new([0x9d5827dcd881dd75, 0xa3148604f6fab11b]);

#[used]
#[unsafe(link_section = ".limine_requests")]
pub static MEMMAP: Request<MemmapResponse> = Request::new([0x67cf3d9d378a806f, 0xe304acdfc50c3c62]);

#[used]
#[unsafe(link_section = ".limine_requests")]
pub static MODULES: Request<ModuleResponse> =
    Request::new([0x3e7e279702be32af, 0xca1c4f3bd1280cee]);

#[used]
#[unsafe(link_section = ".limine_requests")]
pub static RSDP: Request<RsdpResponse> = Request::new([0xc5e77b6b397e7b43, 0x27637845accdcf3c]);

#[used]
#[unsafe(link_section = ".limine_requests")]
pub static EXECUTABLE_ADDRESS: Request<ExecutableAddressResponse> =
    Request::new([0x71ba76863cc55f63, 0xb2644a48c516a487]);

#[used]
#[unsafe(link_section = ".limine_requests_end")]
static REQUESTS_END_MARKER: [u64; 2] = [0xadc0e0531bb10d03, 0x9572709f31764c62];

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    /// Layout checks against the C definitions in PROTOCOL.md.
    #[test]
    fn structures_match_the_protocol_layout() {
        assert_eq!(size_of::<Request<HhdmResponse>>(), 48);
        assert_eq!(offset_of!(Request<HhdmResponse>, revision), 32);
        assert_eq!(offset_of!(Request<HhdmResponse>, response), 40);

        assert_eq!(offset_of!(Framebuffer, pitch), 24);
        assert_eq!(offset_of!(Framebuffer, bpp), 32);
        assert_eq!(offset_of!(Framebuffer, memory_model), 34);
        assert_eq!(offset_of!(Framebuffer, blue_mask_shift), 40);
        assert_eq!(offset_of!(Framebuffer, edid_size), 48);
        assert_eq!(size_of::<Framebuffer>(), 64);

        assert_eq!(size_of::<MemmapEntry>(), 24);
        assert_eq!(offset_of!(File, size), 16);
        assert_eq!(offset_of!(File, string), 32);
        assert_eq!(size_of::<ExecutableAddressResponse>(), 24);
    }

    /// On the host nothing fills in responses, so every request is empty
    /// and the base revision tag still holds its initial value.
    #[test]
    fn unanswered_requests_read_as_none() {
        assert!(HHDM.response().is_none());
        assert!(MEMMAP.response().is_none());
        assert!(!BASE_REVISION_TAG.is_supported());
        assert_eq!(BASE_REVISION_TAG.loaded_revision(), None);
    }
}
