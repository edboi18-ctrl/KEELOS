//! Tiny user-mode test programs (P1-T10 and P1 security acceptance).
//!
//! They are assembled by LLVM into a read-only, non-executable kernel data
//! section; the kernel never runs them. A test copies one into a user page,
//! makes the page read+execute, and starts a user thread there. System
//! call numbers follow the Linux x86-64 table (60 = exit). These threads
//! have no process, so every other call returns -ENOSYS, which is what
//! the programs use to see a result come back in RAX.
//!
//! Each program is position-independent and ends in a system call or a
//! deliberate fault; `ud2` after the last instruction catches a fall-through.

use core::arch::global_asm;

global_asm!(
    r#"
    .pushsection .rodata.keel_user_programs, "a", @progbits

    // A result comes back in RAX and an argument reaches the kernel:
    // exit(syscall(500) + 80) -> status 42.
    //   mov eax, 500: a 32-bit write zero-extends into RAX (Intel SDM
    //     Vol. 1, 3.4.1.1), so RAX = 500, a number inside the 512-entry
    //     table with no handler: the result is -ENOSYS (-38).
    //   lea edi, [rax + 80]: the 64-bit sum -38 + 80 = 42, low 32 bits
    //     kept (SDM Vol. 2A, LEA, address size 64, operand size 32), and
    //     the write to EDI zero-extends: RDI = 42, exit's status.
    .global keel_user_syscall_result, keel_user_syscall_result_end
    keel_user_syscall_result:
        mov eax, 500
        syscall
        lea edi, [rax + 80]
        mov eax, 60
        syscall
        ud2
    keel_user_syscall_result_end:

    // Callee-saved registers survive a system call; RAX holds the result.
    .global keel_user_regs, keel_user_regs_end
    keel_user_regs:
        mov rbx, 0x1111
        mov rbp, 0x2222
        mov r12, 0x3333
        mov r13, 0x4444
        mov r14, 0x5555
        mov r15, 0x6666
        // The result is -ENOSYS: cmp r64, imm32 sign-extends the
        // immediate (SDM Vol. 2A, CMP REX.W 81 /7 id), so -38 compares
        // as 0xffff_ffff_ffff_ffda.
        mov eax, 500
        syscall
        cmp rax, -38
        jne 2f
        cmp rbx, 0x1111
        jne 2f
        cmp rbp, 0x2222
        jne 2f
        cmp r12, 0x3333
        jne 2f
        cmp r13, 0x4444
        jne 2f
        cmp r14, 0x5555
        jne 2f
        cmp r15, 0x6666
        jne 2f
        xor edi, edi
        mov eax, 60
        syscall
    2:
        mov edi, 1
        mov eax, 60
        syscall
        ud2
    keel_user_regs_end:

    // An unknown system call returns -ENOSYS: exit(-rax) -> status 38.
    .global keel_user_enosys, keel_user_enosys_end
    keel_user_enosys:
        mov eax, 9999
        syscall
        neg rax
        mov rdi, rax
        mov eax, 60
        syscall
        ud2
    keel_user_enosys_end:

    // CLI at CPL 3 with IOPL 0 raises #GP.
    .global keel_user_cli, keel_user_cli_end
    keel_user_cli:
        cli
        ud2
    keel_user_cli_end:

    // Port I/O from user mode raises #GP (SR-9).
    .global keel_user_port_io, keel_user_port_io_end
    keel_user_port_io:
        in al, 0x60
        ud2
    keel_user_port_io_end:

    // Read one byte at the address the kernel passes in RDI. Used to probe
    // kernel memory: with page-table isolation anything outside the entry
    // trampoline is absent from the user view (#PF with P = 0).
    .global keel_user_read_address, keel_user_read_address_end
    keel_user_read_address:
        mov al, byte ptr [rdi]
        ud2
    keel_user_read_address_end:

    // Set RFLAGS.AC (allowed at CPL 3), then fault. The kernel must still
    // handle the fault with AC = 0, or SMAP would be off in the handler.
    .global keel_user_set_ac, keel_user_set_ac_end
    keel_user_set_ac:
        pushfq
        or dword ptr [rsp], 0x40000
        popfq
        ud2
    keel_user_set_ac_end:

    // Write to its own (read+execute) code page: #PF, P = 1, W = 1.
    .global keel_user_write_code, keel_user_write_code_end
    keel_user_write_code:
        lea rax, [rip]
        mov byte ptr [rax], 0x90
        ud2
    keel_user_write_code_end:

    // Put a RET on the stack and call it: #PF with I/D = 1 (stack is NX).
    .global keel_user_exec_stack, keel_user_exec_stack_end
    keel_user_exec_stack:
        sub rsp, 64
        mov byte ptr [rsp], 0xC3
        mov rax, rsp
        call rax
        ud2
    keel_user_exec_stack_end:

    // SGDT at CPL 3: #GP when CR4.UMIP = 1; otherwise exit(0).
    .global keel_user_sgdt, keel_user_sgdt_end
    keel_user_sgdt:
        sub rsp, 16
        sgdt [rsp]
        xor edi, edi
        mov eax, 60
        syscall
        ud2
    keel_user_sgdt_end:

    .popsection
    "#
);

macro_rules! programs {
    ($($name:ident: $start:ident, $end:ident;)*) => {
        unsafe extern "C" {
            $( static $start: u8; static $end: u8; )*
        }

        /// A test program.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[allow(non_camel_case_types)]
        pub enum Program { $($name,)* }

        impl Program {
            /// The program's machine code.
            pub fn code(self) -> &'static [u8] {
                let (start, end) = match self {
                    $( Program::$name => (&raw const $start as usize, &raw const $end as usize), )*
                };
                // SAFETY: start and end delimit one program in the
                // read-only `.rodata.keel_user_programs` section, which is
                // never written and lives as long as the kernel.
                unsafe { core::slice::from_raw_parts(start as *const u8, end - start) }
            }
        }
    };
}

programs! {
    SyscallResult: keel_user_syscall_result, keel_user_syscall_result_end;
    Registers: keel_user_regs, keel_user_regs_end;
    UnknownSyscall: keel_user_enosys, keel_user_enosys_end;
    Cli: keel_user_cli, keel_user_cli_end;
    PortIo: keel_user_port_io, keel_user_port_io_end;
    ReadAddress: keel_user_read_address, keel_user_read_address_end;
    SetAc: keel_user_set_ac, keel_user_set_ac_end;
    WriteCode: keel_user_write_code, keel_user_write_code_end;
    ExecStack: keel_user_exec_stack, keel_user_exec_stack_end;
    Sgdt: keel_user_sgdt, keel_user_sgdt_end;
}
