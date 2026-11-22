# hello-console (Phase 2 test executable)

A Windows x64 console program with no C runtime (`src/main.rs`). It
imports only `GetStdHandle`, `WriteFile` and `ExitProcess` from
kernel32.dll, prints

    Hello from a Windows executable on Keel

followed by CR LF, and exits with status 0. `peldr` runs it on Keel and
on Linux; it also runs unmodified on Windows.

## Build

With the repository's pinned toolchain (`rust-toolchain.toml`):

    .\build.ps1        # Windows PowerShell
    ./build.sh         # Linux or WSL

The scripts run

    rustup target add x86_64-pc-windows-msvc
    cargo build --release --target x86_64-pc-windows-msvc

with `RUSTFLAGS` set to

    -Clinker=rust-lld -Clinker-flavor=lld-link -Clink-arg=/NODEFAULTLIB
    -Clink-arg=/ENTRY:mainCRTStartup -Clink-arg=/SUBSYSTEM:CONSOLE
    -Clink-arg=/Brepro -Clink-arg=/DEBUG:NONE

With `raw-dylib` the compiler generates the import library itself (the
Rust Reference, "External blocks"), so no Windows SDK is needed;
`rust-lld` ships with the toolchain.
`/Brepro` makes the output reproducible (no timestamp).

## Reference build

`hello.exe` (2560 bytes) is the reference build, SHA-256 in
`hello.sha256`. Built in the Linux CI-like container with Rust 1.100.0;
a clean rebuild gave the same hash. `cargo xtask` checks the hash before
putting the file in a test image.

Layout (from `llvm-objdump -p`): PE32+, image base 0x140000000, entry
RVA 0x1000, sections `.text`, `.rdata`, `.pdata`, an empty base
relocation directory (all code is RIP-relative), subsystem Windows CUI.

## Running on Windows

    .\hello.exe
    echo $LASTEXITCODE     # 0
