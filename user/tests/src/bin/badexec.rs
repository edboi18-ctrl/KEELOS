//! Phase 2 audit item 5: hostile executables. `badexec SEED COUNT` builds
//! a small valid ELF executable, then COUNT times writes a randomly
//! damaged copy to /hostile and has a forked child execve it. Most are
//! refused (ENOEXEC and the like); some load and run. The kernel must stay
//! up and give everything back; the kernel's test runs this in a
//! compartment with limits and checks that.
//!
//! The base file: an ELF header and two program headers in a read-only
//! first page, and an executable second page of NOPs ending in exit(0),
//! so a damaged entry point that still lands in it just exits. Damage:
//! one to four of random bytes in the headers, boundary values in header
//! fields, random bytes anywhere, and truncation. Prints a summary line.
//! Keel only (it writes /hostile at the root of its tree).
#![no_std]
#![no_main]

use keel_rt::Startup;
use keel_rt::sys::{self, AT_FDCWD, O_CREAT, O_WRONLY};

const SIZE: usize = 0x2000;
const BASE: u64 = 0x40_0000;
const WNOHANG: u32 = 1;
/// O_TRUNC (Linux x86-64).
const O_TRUNC: u64 = 0o1000;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64* (Vigna, "An experimental exploration of Marsaglia's
        // xorshift generators, scrambled", 2016).
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn put(file: &mut [u8], at: usize, bytes: &[u8]) {
    file[at..at + bytes.len()].copy_from_slice(bytes);
}

/// The valid base executable (System V gABI ELF64 layout; Linux elf.h).
fn base() -> [u8; SIZE] {
    let mut f = [0u8; SIZE];
    put(&mut f, 0, &[0x7f, b'E', b'L', b'F', 2, 1, 1]);
    put(&mut f, 16, &2u16.to_le_bytes()); // ET_EXEC
    put(&mut f, 18, &62u16.to_le_bytes()); // EM_X86_64
    put(&mut f, 20, &1u32.to_le_bytes());
    put(&mut f, 24, &(BASE + 0x1000).to_le_bytes()); // e_entry
    put(&mut f, 32, &64u64.to_le_bytes()); // e_phoff
    put(&mut f, 52, &64u16.to_le_bytes()); // e_ehsize
    put(&mut f, 54, &56u16.to_le_bytes()); // e_phentsize
    put(&mut f, 56, &2u16.to_le_bytes()); // e_phnum
    // PT_LOAD, R: the headers. PT_LOAD, R+X: the code.
    for (i, (flags, offset)) in [(4u32, 0u64), (5, 0x1000)].into_iter().enumerate() {
        let at = 64 + i * 56;
        put(&mut f, at, &1u32.to_le_bytes());
        put(&mut f, at + 4, &flags.to_le_bytes());
        put(&mut f, at + 8, &offset.to_le_bytes());
        put(&mut f, at + 16, &(BASE + offset).to_le_bytes());
        put(&mut f, at + 24, &(BASE + offset).to_le_bytes());
        put(&mut f, at + 32, &0x1000u64.to_le_bytes());
        put(&mut f, at + 40, &0x1000u64.to_le_bytes());
        put(&mut f, at + 48, &0x1000u64.to_le_bytes());
    }
    // NOPs, then mov eax, 60; xor edi, edi; syscall (exit(0)).
    f[0x1000..SIZE].fill(0x90);
    put(
        &mut f,
        SIZE - 9,
        &[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05],
    );
    f
}

/// Damages `file`; returns its new length.
fn damage(file: &mut [u8; SIZE], rng: &mut Rng) -> usize {
    const HEADERS: u64 = 64 + 2 * 56;
    const VALUES: [u64; 8] = [
        0,
        1,
        0xff,
        0x7fff_ffff,
        0xffff_ffff,
        0x8000_0000_0000,
        u64::MAX,
        0x1000,
    ];
    let mut len = SIZE;
    for _ in 0..=rng.below(4) {
        match rng.below(8) {
            0..=3 => file[rng.below(HEADERS) as usize] = rng.next() as u8,
            4 | 5 => {
                let at = (rng.below(HEADERS - 8) & !7) as usize;
                let value = VALUES[rng.below(VALUES.len() as u64) as usize];
                put(file, at, &value.to_le_bytes());
            }
            6 => file[rng.below(SIZE as u64) as usize] = rng.next() as u8,
            _ => len = rng.below(SIZE as u64) as usize,
        }
    }
    len
}

fn write_file(bytes: &[u8]) -> bool {
    let fd = sys::openat(AT_FDCWD, c"/hostile", O_WRONLY | O_CREAT | O_TRUNC, 0o755);
    if fd < 0 {
        return false;
    }
    let ok = bytes.is_empty() || sys::write(fd as i32, bytes) == bytes.len() as i64;
    sys::close(fd as i32);
    ok
}

/// Runs /hostile in a child; returns its wait status, or None if it was
/// still running after about 3 s (left running; not waited for).
fn run_child() -> Option<i32> {
    let pid = sys::fork();
    if pid == 0 {
        let error = sys::execve(c"/hostile", Some(&[c"hostile"]), &[]);
        // Refused: exit with the errno (1 to 133), so the parent can tell.
        keel_rt::exit((-error).clamp(1, 255) as i32 + 100);
    }
    if pid < 0 {
        return Some(-1);
    }
    let mut status = 0;
    for _ in 0..300 {
        if sys::wait4(pid as i32, &mut status, WNOHANG) == pid {
            return Some(status);
        }
        let mut ignored = [[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]];
        sys::poll(&mut ignored, 10);
    }
    None
}

fn number(text: Option<&[u8]>) -> Option<u64> {
    let text = text.filter(|t| !t.is_empty())?;
    text.iter().try_fold(0u64, |n, &c| {
        c.is_ascii_digit()
            .then(|| n.checked_mul(10)?.checked_add(u64::from(c - b'0')))
            .flatten()
    })
}

fn main(startup: &Startup) -> i32 {
    let (Some(seed), Some(count)) = (number(startup.args().nth(1)), number(startup.args().nth(2)))
    else {
        return 20;
    };
    // The undamaged file runs and exits 0: otherwise this test proves
    // nothing.
    let good = base();
    if !write_file(&good) || run_child() != Some(0) {
        return 1;
    }
    let mut rng = Rng(seed | 1);
    let (mut refused, mut ran, mut faulted, mut stuck) = (0u64, 0u64, 0u64, 0u64);
    for _ in 0..count {
        let mut file = good;
        let len = damage(&mut file, &mut rng);
        if !write_file(&file[..len]) {
            return 2;
        }
        match run_child() {
            Some(-1) => return 3, // fork failed
            Some(status) if status & 0x7f != 0 => faulted += 1,
            Some(status) if status >> 8 > 100 => refused += 1,
            Some(_) => ran += 1,
            None => stuck += 1,
        }
        if stuck > 2 {
            break;
        }
    }
    sys::write_number(b"badexec: refused ", refused, b"");
    sys::write_number(b", ran ", ran, b"");
    sys::write_number(b", faulted ", faulted, b"");
    sys::write_number(b", stuck ", stuck, b"\n");
    i32::from(stuck != 0) * 4
}

keel_rt::main!(main);
