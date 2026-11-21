//! Passes the kernel linker script to the linker.

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let script = std::path::Path::new(&dir).join("linker.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rustc-link-arg-bins=--script={}", script.display());
    // 4 KiB pages: keeps segment alignment (and the image) small.
    println!("cargo:rustc-link-arg-bins=-zmax-page-size=0x1000");
}
