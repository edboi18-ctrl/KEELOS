# Builds hello.exe on Windows (PowerShell) with the repository's pinned
# Rust toolchain and its bundled rust-lld (lld-link mode): no Windows SDK
# or MSVC needed. Its SHA-256 must equal hello.sha256.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
rustup target add x86_64-pc-windows-msvc
$env:RUSTFLAGS = '-Clinker=rust-lld -Clinker-flavor=lld-link -Clink-arg=/NODEFAULTLIB -Clink-arg=/ENTRY:mainCRTStartup -Clink-arg=/SUBSYSTEM:CONSOLE -Clink-arg=/Brepro -Clink-arg=/DEBUG:NONE'
cargo build --release --target x86_64-pc-windows-msvc
Get-FileHash -Algorithm SHA256 target\x86_64-pc-windows-msvc\release\hello-console.exe
Get-Content hello.sha256
