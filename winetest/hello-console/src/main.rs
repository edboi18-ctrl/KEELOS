//! Phase 2 test executable: a Windows x64 console program with no C
//! runtime that imports only `GetStdHandle`, `WriteFile` and `ExitProcess`
//! from kernel32.dll. It prints one line and exits with status 0. The same
//! file runs on Windows and, through `peldr`, on Keel.
//!
//! With `kind = "raw-dylib"` the compiler generates the import library
//! itself, so no Windows SDK import library is needed (the Rust Reference,
//! "External blocks", `dylib` versus `raw-dylib`).
#![no_std]
#![no_main]

use core::ffi::c_void;
use core::ptr;

/// STD_OUTPUT_HANDLE, (DWORD)-11 (Microsoft: GetStdHandle).
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;

/// The line, in two parts reached through a table of pointers. Pointers
/// stored in data are absolute addresses, so the linker emits
/// IMAGE_REL_BASED_DIR64 base relocations for them: loaded anywhere but
/// its preferred base, the program prints the right line only if its
/// loader applied them (`peldr --relocate` tests that).
static PARTS: [&[u8]; 2] = [b"Hello from a Windows executable", b" on Keel\r\n"];
const MESSAGE_LEN: usize = 41;

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn GetStdHandle(std_handle: u32) -> *mut c_void;
    fn WriteFile(
        file: *mut c_void,
        buffer: *const u8,
        bytes_to_write: u32,
        bytes_written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn ExitProcess(exit_code: u32) -> !;
}

/// Entry point (`/ENTRY:mainCRTStartup`): there is no C runtime to call
/// `main`. Exit status 0 when the whole line was written, 1 otherwise.
#[unsafe(no_mangle)]
pub extern "system" fn mainCRTStartup() -> ! {
    let mut total = 0usize;
    // SAFETY: kernel32 functions with their documented signatures. Each
    // buffer is a static byte string of the length passed; `written` is a
    // valid u32 for each call; no OVERLAPPED is used (null), as for a
    // synchronous console or pipe handle.
    unsafe {
        let out = GetStdHandle(STD_OUTPUT_HANDLE);
        // black_box: keep the table in memory, so its pointers are read
        // (and must have been relocated) at run time.
        for part in core::hint::black_box(&PARTS) {
            let mut written: u32 = 0;
            let ok = WriteFile(
                out,
                part.as_ptr(),
                part.len() as u32,
                &mut written,
                ptr::null_mut(),
            );
            if ok != 0 {
                total += written as usize;
            }
        }
        ExitProcess(if total == MESSAGE_LEN { 0 } else { 1 })
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: as above; ExitProcess never returns.
    unsafe { ExitProcess(101) }
}
