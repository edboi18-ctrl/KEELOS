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
 * W^X (SR-12): three page-aligned PT_LOAD segments, none of which is both
 * writable and executable. Limine maps each with its segment permissions.
 */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    text    PT_LOAD    FLAGS(5);  /* PF_R | PF_X */
    rodata  PT_LOAD    FLAGS(4);  /* PF_R        */
    data    PT_LOAD    FLAGS(6);  /* PF_R | PF_W */
    dynamic PT_DYNAMIC FLAGS(6);
}

SECTIONS
{
    . = 0xffffffff80000000;
    __kernel_start = .;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    /* Dynamic-linking metadata the bootloader reads to relocate the image. */
    .dynsym   : { *(.dynsym) }   :rodata
    .gnu.hash : { *(.gnu.hash) } :rodata
    .hash     : { *(.hash) }     :rodata
    .dynstr   : { *(.dynstr) }   :rodata
    .rela.dyn : { *(.rela.dyn .rela.*) } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data .data.*)

        /* Limine request block: markers must enclose every request. */
        . = ALIGN(8);
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :data

    /* Pointers the bootloader relocates; they stay writable for now. */
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) } :data
    .got         : { *(.got .got.*) }                 :data

    .dynamic : { *(.dynamic) } :data :dynamic

    .bss : {
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
