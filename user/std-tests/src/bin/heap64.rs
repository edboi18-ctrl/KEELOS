//! Phase 1 acceptance item 2: a Rust x86_64-unknown-linux-musl static
//! binary that allocates 64 MB on the heap, touches every page, and prints
//! a checksum. Its output must be identical on Linux and on Keel.

#![forbid(unsafe_code)]

const SIZE: usize = 64 << 20;
const PAGE: usize = 4096;

fn main() {
    let mut heap: Vec<u8> = vec![0; SIZE];
    // Write a pattern into every page, then fold the whole buffer into
    // a checksum (FNV-1a, 64-bit): any page that read back wrong would
    // change it.
    for (index, page) in heap.chunks_mut(PAGE).enumerate() {
        let value = (index % 251) as u8;
        page[0] = value;
        page[PAGE / 2] = value.wrapping_mul(3);
        page[PAGE - 1] = value ^ 0x5a;
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in &heap {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    println!(
        "heap64: {} bytes in {} pages, checksum {hash:#018x}",
        heap.len(),
        SIZE / PAGE
    );
}
