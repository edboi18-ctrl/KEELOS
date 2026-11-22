/*
 * Keel kernel link layout.
 *
 * References:
 *  - Limine boot protocol, PROTOCOL.md, "Memory Layout at Entry": the
 *    executable must be linked at or above 0xffffffff80000000, and a
 *    position-independent executable may be relocated by the bootloader.
 *  - PROTOCOL.md, "Requests Delimiters": requests are honoured only
 *    between the start and end markers.
 *  - System V ABI, generic part, "Program Header" (PT_LOAD, PT_DYNAMIC
 *    and the PF_X=1 / PF_W=2 / PF_R=4 segment flag bits).
 *
 * The kernel is a static position-independent executable (the default for
 * the x86_64-unknown-none target), so Limine can slide it for KASLR
 * (SR-16, enabled in Phase 1). Limine applies the R_X86_64_RELATIVE
 * relocations it finds through PT_DYNAMIC before entering the kernel.
 *
 * W^X (SR-12): four page-aligned PT_LOAD segments, none of which is both
 * writable and executable. Limine maps each with its segment permissions;
 * the kernel then builds its own tables, in which RELRO is read-only.
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    text    PT_LOAD    FLAGS(5);  /* PF_R | PF_X */
    rodata  PT_LOAD    FLAGS(4);  /* PF_R        */
    relro   PT_LOAD    FLAGS(6);  /* PF_R | PF_W until relocated */
    data    PT_LOAD    FLAGS(6);  /* PF_R | PF_W */
    dynamic PT_DYNAMIC FLAGS(6);
}

SECTIONS
{
    . = 0xffffffff80000000;
    __kernel_start = .;

    /*
     * Entry trampoline (SR-14). Exception and (later) syscall entry code
     * and the data the processor reads while entering the kernel (GDT,
     * IDT, TSS, IST stacks) are grouped into their own page-aligned ranges
     * so that page-table isolation can map exactly these pages into user
     * page tables and nothing else from the kernel image.
     */
    .text : {
        __entry_text_start = .;
        KEEP(*(.text.keel_entry))
        . = ALIGN(4096);
        __entry_text_end = .;
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __rodata_start = .;

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    /* Dynamic-linking metadata the bootloader reads to relocate the image. */
    .dynsym   : { *(.dynsym) }   :rodata
    .gnu.hash : { *(.gnu.hash) } :rodata
    .hash     : { *(.hash) }     :rodata
    .dynstr   : { *(.dynstr) }   :rodata
    .rela.dyn : { *(.rela.dyn .rela.*) } :rodata

    /*
     * RELRO (P1-S6): data that only the bootloader's relocations write
     * (vtables, pointer constants, the GOT). Its own page-aligned
     * segment, writable in the file so Limine can relocate it, and mapped
     * read-only, no-execute by the kernel's page tables, which treat
     * everything from __rodata_start to __data_start as read-only.
     */
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __relro_start = .;
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) } :relro
    .got         : { *(.got .got.*) }                 :relro
    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __relro_end = .;

    __data_start = .;

    .data : {
        __entry_data_start = .;
        KEEP(*(.data.keel_entry))
        . = ALIGN(4096);
        __entry_data_end = .;
        *(.data .data.*)

        /* Limine request block: markers must enclose every request. */
        . = ALIGN(8);
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :data

    .dynamic : { *(.dynamic) } :data :dynamic

    .bss : {
        . = ALIGN(4096);
        __entry_bss_start = .;
        *(.bss.keel_entry)
        . = ALIGN(4096);
        __entry_bss_end = .;
        *(.bss .bss.*)
        *(COMMON)
    } :data

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    __kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
        *(.comment)
        *(.interp)
    }
}
