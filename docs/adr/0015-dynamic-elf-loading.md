# ADR 0015: Loading dynamically linked programs

Status: accepted (Phase 3, P3-T2).

## Context

Wine and its tools, built on Alpine, are dynamically linked against musl.
Each program names its dynamic linker in `PT_INTERP`,
`/lib/ld-musl-x86_64.so.1`, which is also musl's libc. Until now the
parser refused `PT_INTERP`.

## Decision

1. **The parser accepts one `PT_INTERP`.** It applies Linux's checks
   from `load_elf_binary` (`fs/binfmt_elf.c` at v6.12, lines 876 to 891):
   the contents must be between 2 and `PATH_MAX` bytes and end in NUL,
   else `ENOEXEC`. Keel is stricter than Linux, in line with SR-10 (fail
   closed):
   - a NUL before the end is refused, where Linux would use the path up
     to the first NUL;
   - a second `PT_INTERP` is refused, where Linux uses the first.
2. **The interpreter must be position-independent and name no
   interpreter of its own.** Linux also accepts an `ET_EXEC` interpreter
   (`load_elf_interp`, lines 644 to 645) and ignores a `PT_INTERP` in
   it. A fixed-address interpreter could overlap the program, and musl's
   is `ET_DYN`.
3. **Placement follows Linux.** The program goes near `DYN_BASE` with
   its random bias. The interpreter goes into the mmap area: its whole
   span is reserved `PROT_NONE` where the allocator chooses, below the
   randomized mmap base, and its segments replace their parts. The gaps
   between segments stay reserved and inaccessible; Linux unmaps them.
   The process starts at the interpreter's entry.
4. **The auxiliary vector is what Linux's `create_elf_tables` writes,**
   minus entries without a Keel counterpart:
   - `AT_HWCAP` is CPUID leaf 1 EDX (`ELF_HWCAP`, `asm/elf.h`).
   - `AT_PAGESZ` and `AT_CLKTCK` (100, `USER_HZ`).
   - `AT_PHDR`, `AT_PHENT` and `AT_PHNUM` describe the program.
   - `AT_BASE` is the interpreter's load address; `AT_ENTRY` is the
     program's entry.
   - `AT_UID`, `AT_EUID`, `AT_GID` and `AT_EGID` are 0, since Keel has
     no users (SR-6), so `AT_SECURE` is 0.
   - `AT_RANDOM` and `AT_EXECFN` are added by the stack builder.
   - Left out: `AT_SYSINFO_EHDR` (no vDSO), `AT_HWCAP2`, `AT_PLATFORM`,
     `AT_MINSIGSTKSZ` and the rseq entries. musl 1.2.6's
     `__init_libc` reads none of them.
5. **The interpreter is found in the process's own tree.**
   `exec::load_in(root, ...)` resolves the path beneath `root`, the
   compartment's root (ADR 0014). A confined program cannot get a
   dynamic linker from outside its compartment. `exec::load` uses the
   filesystem root, for the kernel's own programs. The interpreter must
   be a regular file, else `EACCES`, as execve(2) gives for "a script
   interpreter is not a regular file".

## Evidence

- Host tests (`keel_core::elf`): the path is read; each of Linux's rules
  and each stricter rule refuses a crafted file.
- `exec.dynamic_musl` (phase 3): `fixtures/musl-dynamic` runs and
  prints its line, which `cargo xtask test` checks on serial. The
  interpreter is placed in the mmap area. No unimplemented system call is
  logged.
  - With `AT_BASE` reported as 0, the dynamic linker faults and the test
    fails. Running the program without its interpreter cannot print at
    all: its call to `printf` is never bound.
- `exec.interpreter_in_root`:
  - a compartment without `/lib` cannot load the program (`ENOENT`);
  - one whose "dynamic linker" is a static executable is refused
    (`BadInterpreter`);
  - one with a copy of the dynamic linker runs it.
  - Looking the interpreter up from `/` instead makes the test fail.
- Under Linux, `host.musl-dynamic` runs the same pair as
  `ld-musl-x86_64.so.1 hello` and gets the same line.

## Consequences

- A musl program that needs only libc runs now. musl's `load_library`
  treats every `libc.*` name as itself (`ldso/dynlink.c` lines 1070 to
  1093), so no file is mapped.
- Other shared libraries need file-backed `mmap` (P3-T7), which Wine
  needs too.
