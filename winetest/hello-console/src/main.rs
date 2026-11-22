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

const MESSAGE: &[u8] = b"Hello from a Windows executable on Keel\r\n";

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
    let mut written: u32 = 0;
    // SAFETY: kernel32 functions with their documented signatures. The
    // buffer is a static byte string of the length passed; `written` is a
    // valid u32 for the call; no OVERLAPPED is used (null), as for a
    // synchronous console or pipe handle.
    unsafe {
        let out = GetStdHandle(STD_OUTPUT_HANDLE);
        let ok = WriteFile(
            out,
            MESSAGE.as_ptr(),
            MESSAGE.len() as u32,
            &mut written,
            ptr::null_mut(),
        );
        let status = if ok != 0 && written as usize == MESSAGE.len() {
            0
        } else {
            1
        };
        ExitProcess(status)
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // SAFETY: as above; ExitProcess never returns.
    unsafe { ExitProcess(101) }
}
