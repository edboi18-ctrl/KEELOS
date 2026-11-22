//! Minimal runtime for Keel's own user programs: process entry, the
//! initial stack, and raw Linux system calls (ADR 0006).
//!
//! This is the one user-space crate allowed to contain `unsafe` and
//! assembly. Programs built on it run unchanged on Linux and on Keel: they
//! use only the Linux x86-64 system-call ABI (`man 2 syscall`: number in
//! RAX, arguments in RDI, RSI, RDX, R10, R8, R9, result in RAX, RCX and
//! R11 clobbered).
//!
//! A program provides `fn main(&Startup) -> i32` and registers it with
//! [`main!`]. The return value becomes the exit status.
#![no_std]

use core::arch::{asm, global_asm};
use core::ffi::CStr;

/// Linux x86-64 system-call numbers (`arch/x86/entry/syscalls/syscall_64.tbl`
/// at v6.12).
pub const SYS_WRITE: u64 = 1;
pub const SYS_EXIT: u64 = 60;
pub const SYS_EXIT_GROUP: u64 = 231;

/// Auxiliary vector types (psABI 1.0 Figure 3.11; Linux
/// `include/uapi/linux/auxvec.h`).
pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_ENTRY: u64 = 9;
pub const AT_RANDOM: u64 = 25;
pub const AT_EXECFN: u64 = 31;

// Assembly reasoning (spec section 1, rule 4)
//
// _start: the ELF entry point (lld's default entry symbol).
//   Entry state (psABI 1.0 section 3.4.1, "Stack State"): RSP points at
//   argc and is 16-byte aligned; RDX holds a function pointer to register
//   with atexit, or 0; RBP is unspecified and user code should zero it to
//   mark the deepest frame. Other registers are unspecified.
//   1. xor ebp, ebp: zero RBP (writing EBP zero-extends into RBP, SDM
//      Vol. 1 section 3.4.1.1).
//   2. RDI := RSP (initial stack pointer), RSI := RDX (atexit pointer),
//      then pushfq; pop rdx: RDX := RFLAGS at entry. The push and pop
//      cancel, so RSP is unchanged; they use the 8 bytes below the initial
//      RSP, which the psABI leaves undefined.
//   3. and rsp, -16: align even if the loader got it wrong (the program
//      checks RDI itself), then `call`, after which the callee sees RSP
//      = 8 mod 16, as the SysV ABI requires at function entry (psABI
//      section 3.2.2).
//   4. keel_rt_start never returns; ud2 traps if it ever did.
//   Exit state: none (does not return).
global_asm!(
    r#"
    .pushsection .text._start, "ax", @progbits
    .global _start
    .type _start, @function
    _start:
        xor ebp, ebp
        mov rdi, rsp
        mov rsi, rdx
        pushfq
        pop rdx
        and rsp, -16
        call {start}
        ud2
    .size _start, . - _start
    .popsection
    "#,
    start = sym keel_rt_start,
);

unsafe extern "C" {
    fn _start();
}

unsafe extern "Rust" {
    /// Defined by [`main!`] in the program.
    fn keel_rt_main(startup: &Startup) -> i32;
}

/// What the program found at entry.
pub struct Startup {
    /// RSP at `_start`.
    pub initial_sp: u64,
    /// RDX at `_start` (the atexit pointer).
    pub initial_rdx: u64,
    /// RFLAGS at `_start`.
    pub initial_rflags: u64,
    argc: usize,
    argv: *const *const u8,
    envp: *const *const u8,
    auxv: *const [u64; 2],
}

/// One ELF64 program header, as AT_PHDR points to (`Elf64_Phdr`, Linux
/// `include/uapi/linux/elf.h`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

extern "C" fn keel_rt_start(sp: *const u64, rdx: u64, rflags: u64) -> ! {
    // SAFETY: the loader placed argc at `sp`, followed by argv and its
    // NULL, envp and its NULL, then the auxiliary vector (psABI Figure
    // 3.9). As in any C runtime, the process trusts its own initial stack.
    let startup = unsafe {
        let argc = *sp as usize;
        let argv = sp.add(1) as *const *const u8;
        let envp = argv.add(argc + 1);
        let mut end = envp;
        while !(*end).is_null() {
            end = end.add(1);
        }
        Startup {
            initial_sp: sp as u64,
            initial_rdx: rdx,
            initial_rflags: rflags,
            argc,
            argv,
            envp,
            auxv: end.add(1) as *const [u64; 2],
        }
    };
    // SAFETY: `keel_rt_main` is the function defined by `main!`, with the
    // signature declared above.
    let status = unsafe { keel_rt_main(&startup) };
    exit(status)
}

/// Reads a NUL-terminated string from the initial stack.
///
/// # Safety
/// `p` must point to a NUL-terminated string that lives for the whole run.
unsafe fn c_str(p: *const u8) -> &'static [u8] {
    // SAFETY: the caller's contract.
    unsafe { CStr::from_ptr(p.cast()).to_bytes() }
}

impl Startup {
    /// argc.
    pub fn argc(&self) -> usize {
        self.argc
    }

    /// Whether argv[argc] is the NULL pointer the psABI requires.
    pub fn argv_terminated(&self) -> bool {
        // SAFETY: the slot after the last argument is part of the vector.
        unsafe { (*self.argv.add(self.argc)).is_null() }
    }

    /// The arguments.
    pub fn args(&self) -> impl Iterator<Item = &'static [u8]> + '_ {
        // SAFETY: argv holds argc pointers to strings on the initial stack.
        (0..self.argc).map(|i| unsafe { c_str(*self.argv.add(i)) })
    }

    /// The environment strings.
    pub fn env(&self) -> impl Iterator<Item = &'static [u8]> + '_ {
        let mut p = self.envp;
        core::iter::from_fn(move || {
            // SAFETY: envp is NULL-terminated (found in keel_rt_start);
            // each entry points to a string on the initial stack.
            unsafe {
                if (*p).is_null() {
                    None
                } else {
                    let s = c_str(*p);
                    p = p.add(1);
                    Some(s)
                }
            }
        })
    }

    /// The value of auxiliary entry `kind`, if present.
    pub fn aux(&self, kind: u64) -> Option<u64> {
        let mut p = self.auxv;
        loop {
            // SAFETY: the vector ends with an AT_NULL entry.
            let [k, v] = unsafe { *p };
            if k == AT_NULL {
                return None;
            }
            if k == kind {
                return Some(v);
            }
            // SAFETY: not past AT_NULL yet.
            p = unsafe { p.add(1) };
        }
    }

    /// The 16 bytes AT_RANDOM points to.
    pub fn random(&self) -> Option<[u8; 16]> {
        let address = self.aux(AT_RANDOM).filter(|&a| a != 0)?;
        // SAFETY: AT_RANDOM points to 16 bytes on the initial stack.
        Some(unsafe { *(address as *const [u8; 16]) })
    }

    /// The string AT_EXECFN points to.
    pub fn execfn(&self) -> Option<&'static [u8]> {
        let address = self.aux(AT_EXECFN).filter(|&a| a != 0)?;
        // SAFETY: AT_EXECFN points to a NUL-terminated path on the stack.
        Some(unsafe { c_str(address as *const u8) })
    }

    /// The program-header table AT_PHDR points to, if its entry size is
    /// the ELF64 one.
    pub fn program_headers(&self) -> Option<&'static [ProgramHeader]> {
        let address = self.aux(AT_PHDR).filter(|&a| a != 0)?;
        let count = self.aux(AT_PHNUM)? as usize;
        if self.aux(AT_PHENT)? != size_of::<ProgramHeader>() as u64 {
            return None;
        }
        // SAFETY: AT_PHDR/AT_PHNUM describe the loaded table (psABI
        // section 3.4.3), which stays mapped for the life of the program.
        Some(unsafe { core::slice::from_raw_parts(address as *const ProgramHeader, count) })
    }
}

/// The program's entry address (`_start`), to compare with AT_ENTRY.
pub fn entry_address() -> u64 {
    _start as *const () as usize as u64
}

/// write(2).
pub fn write(fd: i32, bytes: &[u8]) -> i64 {
    // SAFETY: the kernel reads at most `bytes.len()` bytes from a valid
    // buffer.
    unsafe {
        syscall3(
            SYS_WRITE,
            fd as u64,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    }
}

/// exit_group(2), falling back to exit(2).
pub fn exit(status: i32) -> ! {
    // SAFETY: neither call touches memory; they end the process.
    unsafe {
        syscall3(SYS_EXIT_GROUP, status as u64, 0, 0);
        loop {
            syscall3(SYS_EXIT, status as u64, 0, 0);
        }
    }
}

/// A raw system call with up to three arguments.
///
/// # Safety
/// The arguments must be valid for the call: any pointer must point to
/// memory the kernel may read or write as that call defines.
pub unsafe fn syscall3(number: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let result: u64;
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: RAX = number, RDI/RSI/RDX = arguments.
    // Instruction: `syscall` enters the kernel, which returns with the
    //   result in RAX and RCX/R11 clobbered (`man 2 syscall`; SDM Vol. 2B
    //   "SYSCALL": RCX and R11 receive RIP and RFLAGS).
    // Exit state: RAX = result; RCX, R11 clobbered; other registers kept.
    //   The kernel does not use the user stack, so `nostack` holds. Flags
    //   may change, so `preserves_flags` is not claimed.
    // SAFETY: the caller's contract; the instruction itself only enters
    // the kernel.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result as i64
}

/// A raw system call with up to six arguments.
///
/// # Safety
/// As [`syscall3`].
pub unsafe fn syscall6(number: u64, a: [u64; 6]) -> i64 {
    let result: u64;
    // Assembly reasoning (spec section 1, rule 4)
    // Entry state: RAX = number; RDI, RSI, RDX, R10, R8, R9 = arguments
    //   (`man 2 syscall`: the fourth argument goes in R10, not RCX, because
    //   SYSCALL overwrites RCX).
    // Instruction and exit state: as in `syscall3`.
    // SAFETY: the caller's contract.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") a[0],
            in("rsi") a[1],
            in("rdx") a[2],
            in("r10") a[3],
            in("r8") a[4],
            in("r9") a[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result as i64
}

pub mod fuzz;
pub mod sys;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    write(2, b"keel-rt: panic\n");
    exit(101)
}

/// Registers the program's main function: `keel_rt::main!(main);` with
/// `fn main(startup: &keel_rt::Startup) -> i32`.
#[macro_export]
macro_rules! main {
    ($function:path) => {
        #[unsafe(export_name = "keel_rt_main")]
        fn __keel_rt_main(startup: &$crate::Startup) -> i32 {
            $function(startup)
        }
    };
}
