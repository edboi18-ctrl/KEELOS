#!/bin/sh
# Builds hello.exe with the repository's pinned Rust toolchain and its
# bundled rust-lld (lld-link mode): no Windows SDK or MSVC needed.
# Output: target/x86_64-pc-windows-msvc/release/hello-console.exe; its
# SHA-256 must equal hello.sha256.
set -eu
cd "$(dirname "$0")"
rustup target add x86_64-pc-windows-msvc
RUSTFLAGS='-Clinker=rust-lld -Clinker-flavor=lld-link -Clink-arg=/NODEFAULTLIB -Clink-arg=/ENTRY:mainCRTStartup -Clink-arg=/SUBSYSTEM:CONSOLE -Clink-arg=/Brepro -Clink-arg=/DEBUG:NONE' \
    cargo build --release --target x86_64-pc-windows-msvc
sha256sum target/x86_64-pc-windows-msvc/release/hello-console.exe
cat hello.sha256
