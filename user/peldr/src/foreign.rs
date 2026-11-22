//! The only part of `peldr` that may use `unsafe` (ADR 0013): the
//! kernel32 stubs the loaded program calls, and the call into it.
//!
//! Calling convention. The program calls the stubs, and is called, with
//! the Windows x64 convention: integer arguments in RCX, RDX, R8, R9, then
//! the stack, with 32 bytes of shadow space the caller allocates, and a
//! different set of callee-saved registers from System V (RSI and RDI are
//! callee-saved on Windows). Declaring the functions `extern "win64"` makes
//! the compiler follow it on both sides (the Rust Reference, "External
//! blocks": "`win64`: the Windows x64 ABI"), so no assembly is needed.
//!
//! Stub behaviour (spec section 9) and signatures (Microsoft Learn,
//! kernel32: `GetStdHandle`, `WriteFile`, `WriteConsoleA`, `ExitProcess`):
//! - `GetStdHandle(DWORD) -> HANDLE`: STD_INPUT_HANDLE (-10),
//!   STD_OUTPUT_HANDLE (-11) and STD_ERROR_HANDLE (-12) become fake
//!   handles 0x100, 0x101 and 0x102 that encode fds 0, 1 and 2; anything
//!   else is INVALID_HANDLE_VALUE (-1).
//! - `WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) -> BOOL` and
//!   `WriteConsoleA(HANDLE, const VOID*, DWORD, LPDWORD, LPVOID) -> BOOL`:
//!   write(2) to the fd, store the count, TRUE if everything was written.
//! - `ExitProcess(UINT) -> !`: exit_group(2).

use keel_rt::syscall3;

const SYS_WRITE: u64 = 1;

/// (DWORD)-10, -11, -12.
const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
/// Fake handles: `HANDLE_BASE + fd` for fds 0 to 2.
const HANDLE_BASE: u64 = 0x100;
/// INVALID_HANDLE_VALUE, (HANDLE)-1.
const INVALID_HANDLE_VALUE: u64 = u64::MAX;

extern "win64" fn get_std_handle(which: u32) -> u64 {
    match which {
        STD_INPUT_HANDLE => HANDLE_BASE,
        STD_OUTPUT_HANDLE => HANDLE_BASE + 1,
        STD_ERROR_HANDLE => HANDLE_BASE + 2,
        _ => INVALID_HANDLE_VALUE,
    }
}

/// write(2)s `len` bytes from the program's `buffer` to the handle's fd and
/// stores the count at `written` (if not null). Returns TRUE (1) only if
/// everything was written.
fn write_handle(handle: u64, buffer: u64, len: u32, written: u64) -> i32 {
    if !(HANDLE_BASE..HANDLE_BASE + 3).contains(&handle) {
        return 0;
    }
    let fd = handle - HANDLE_BASE;
    let len = u64::from(len);
    let mut done = 0u64;
    while done < len {
        // SAFETY: write(2) only reads the program's buffer, and the kernel
        // checks that range itself (a bad pointer is EFAULT); nothing in
        // this process is written.
        let r = unsafe { syscall3(SYS_WRITE, fd, buffer.wrapping_add(done), len - done) };
        if r <= 0 {
            break;
        }
        done += r as u64;
    }
    if written != 0 {
        // SAFETY: the program passed `written` as the address of its DWORD
        // for the count, which is the function's contract. A program that
        // passes a bad pointer can only harm itself: the write faults and
        // the kernel ends this process, or it lands in memory of this
        // process, which the program could already write anywhere (it runs
        // with this process's rights; ADR 0013).
        unsafe { (written as *mut u32).write_unaligned(done as u32) };
    }
    i32::from(done == len)
}

extern "win64" fn write_file(
    handle: u64,
    buffer: u64,
    len: u32,
    written: u64,
    _overlapped: u64,
) -> i32 {
    write_handle(handle, buffer, len, written)
}

extern "win64" fn write_console_a(
    handle: u64,
    buffer: u64,
    len: u32,
    written: u64,
    _reserved: u64,
) -> i32 {
    write_handle(handle, buffer, len, written)
}

extern "win64" fn exit_process(code: u32) -> ! {
    keel_rt::exit(code as i32)
}

/// The stub for `dll!name`, if there is one. DLL names compare without
/// case, as Windows does; function names exactly.
pub fn resolve(dll: &[u8], name: &[u8]) -> Option<u64> {
    if !dll.eq_ignore_ascii_case(b"kernel32.dll") {
        return None;
    }
    let address = match name {
        b"GetStdHandle" => get_std_handle as extern "win64" fn(u32) -> u64 as usize,
        b"WriteFile" => write_file as extern "win64" fn(u64, u64, u32, u64, u64) -> i32 as usize,
        b"WriteConsoleA" => {
            write_console_a as extern "win64" fn(u64, u64, u32, u64, u64) -> i32 as usize
        }
        b"ExitProcess" => exit_process as extern "win64" fn(u32) -> ! as usize,
        _ => return None,
    };
    Some(address as u64)
}

/// Calls the program's entry point and returns its result, which Windows
/// takes as the exit code if the entry point returns.
pub fn call_entry(address: u64) -> u32 {
    // SAFETY: `address` is the image's AddressOfEntryPoint, which the
    // parser checked lies in an executable section, mapped by the loader
    // and made read+execute. A function pointer and a u64 have the same
    // size on x86-64. Running the program is the point of peldr: from here
    // it controls this process, which is ring 3 and can harm only itself
    // (ADR 0013).
    let entry: extern "win64" fn() -> u32 = unsafe { core::mem::transmute(address) };
    entry()
}
