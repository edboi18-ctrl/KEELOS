//! Linux x86-64 constants and the byte layout of structures copied to user
//! space. Every structure is built in a zeroed buffer, so padding never
//! carries kernel bytes (SR-18).
//!
//! Sources (Linux v6.12): `include/uapi/asm-generic/fcntl.h` (O_*,
//! AT_FDCWD), `include/uapi/asm-generic/mman-common.h`, `mman.h` and
//! `include/uapi/linux/mman.h` (PROT_*, MAP_*), `arch/x86/include/uapi/asm/
//! prctl.h` (ARCH_*), `arch/x86/include/uapi/asm/stat.h` (struct stat,
//! x86-64 branch), `include/linux/kdev_t.h` (`new_encode_dev`),
//! `include/uapi/linux/time.h` (CLOCK_*),
//! `include/uapi/linux/random.h` (GRND_*), `include/uapi/linux/uio.h`
//! (UIO_MAXIOV), `include/linux/fs.h` (MAX_RW_COUNT).

use keel_core::vfs::Stat;

// open(2) flags.
pub const O_ACCMODE: u64 = 0o3;
pub const O_RDONLY: u64 = 0o0;
pub const O_WRONLY: u64 = 0o1;
pub const O_RDWR: u64 = 0o2;
pub const O_CREAT: u64 = 0o100;
pub const O_EXCL: u64 = 0o200;
pub const O_NOCTTY: u64 = 0o400;
pub const O_TRUNC: u64 = 0o1000;
pub const O_APPEND: u64 = 0o2000;
pub const O_NONBLOCK: u64 = 0o4000;
pub const O_LARGEFILE: u64 = 0o100000;
pub const O_DIRECTORY: u64 = 0o200000;
pub const O_NOFOLLOW: u64 = 0o400000;
pub const O_CLOEXEC: u64 = 0o2000000;
/// Every flag Keel accepts; any other bit is EINVAL (SR-10). Not
/// accepted yet: O_DSYNC, O_SYNC, O_DIRECT, O_NOATIME, O_PATH, O_TMPFILE.
pub const O_KNOWN: u64 = O_ACCMODE
    | O_CREAT
    | O_EXCL
    | O_NOCTTY
    | O_TRUNC
    | O_APPEND
    | O_NONBLOCK
    | O_LARGEFILE
    | O_DIRECTORY
    | O_NOFOLLOW
    | O_CLOEXEC;
pub const AT_FDCWD: i32 = -100;

// mmap(2).
pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;
pub const MAP_SHARED: u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
/// MAP_SHARED with unknown flags refused (`include/uapi/linux/mman.h`).
pub const MAP_SHARED_VALIDATE: u64 = 0x03;
pub const MAP_TYPE: u64 = 0x0f;
pub const MAP_FIXED: u64 = 0x10;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_DENYWRITE: u64 = 0x0800;
pub const MAP_EXECUTABLE: u64 = 0x1000;
pub const MAP_NORESERVE: u64 = 0x4000;
pub const MAP_POPULATE: u64 = 0x8000;
pub const MAP_NONBLOCK: u64 = 0x01_0000;
pub const MAP_STACK: u64 = 0x02_0000;
pub const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
/// Flags accepted besides the type. DENYWRITE and EXECUTABLE are ignored
/// by Linux too; NORESERVE is the only behaviour Keel has (no overcommit
/// accounting); POPULATE, NONBLOCK and STACK are hints. Not accepted:
/// GROWSDOWN, LOCKED, HUGETLB, SYNC, 32BIT, UNINITIALIZED, DROPPABLE.
pub const MAP_KNOWN: u64 = MAP_TYPE
    | MAP_FIXED
    | MAP_ANONYMOUS
    | MAP_DENYWRITE
    | MAP_EXECUTABLE
    | MAP_NORESERVE
    | MAP_POPULATE
    | MAP_NONBLOCK
    | MAP_STACK
    | MAP_FIXED_NOREPLACE;

// arch_prctl(2).
pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;

// ioctl(2) on terminals.
pub const TCGETS: u32 = 0x5401;
pub const TIOCGWINSZ: u32 = 0x5413;

// clock_gettime(2).
pub const CLOCK_REALTIME: u64 = 0;
pub const CLOCK_MONOTONIC: u64 = 1;
pub const CLOCK_MONOTONIC_RAW: u64 = 4;
pub const CLOCK_REALTIME_COARSE: u64 = 5;
pub const CLOCK_MONOTONIC_COARSE: u64 = 6;
pub const CLOCK_BOOTTIME: u64 = 7;

// getrandom(2).
pub const GRND_NONBLOCK: u64 = 0x1;
pub const GRND_RANDOM: u64 = 0x2;
pub const GRND_INSECURE: u64 = 0x4;

/// Most iovecs per call.
pub const UIO_MAXIOV: u64 = 1024;
/// Largest single read or write: `INT_MAX & PAGE_MASK`.
pub const MAX_RW_COUNT: u64 = 0x7fff_f000;

/// `new_encode_dev`: minor low byte, major, then the high minor bits.
pub fn encode_dev(major: u32, minor: u32) -> u64 {
    u64::from((minor & 0xff) | (major << 8) | ((minor & !0xff) << 12))
}

/// Device number reported as `st_dev` for every tmpfs node. Keel has one
/// filesystem; 0:1 is an arbitrary choice with major 0, the major Linux
/// uses for filesystems without a block device (`devices.txt`, "0
/// Unnamed devices").
pub const TMPFS_DEV: (u32, u32) = (0, 1);

/// `struct stat` for x86-64: 144 bytes. Offsets: st_dev 0, st_ino 8,
/// st_nlink 16, st_mode 24, st_uid 28, st_gid 32, __pad0 36, st_rdev 40,
/// st_size 48, st_blksize 56, st_blocks 64, st_atime 72, st_atime_nsec 80,
/// st_mtime 88, st_mtime_nsec 96, st_ctime 104, st_ctime_nsec 112, unused
/// 120..144 (`arch/x86/include/uapi/asm/stat.h`). st_blocks counts 512-byte
/// blocks of whole pages for a regular file, as tmpfs allocates them
/// (`BLOCKS_PER_PAGE`, `mm/shmem.c`), and 0 for anything else.
pub fn stat_bytes(stat: &Stat) -> [u8; 144] {
    stat_bytes_on(stat, TMPFS_DEV)
}

/// Device number reported for procfs nodes: another anonymous device
/// (major 0), as procfs is its own superblock on Linux. 0:2 is arbitrary.
pub const PROCFS_DEV: (u32, u32) = (0, 2);

/// [`stat_bytes`] for a node on device `dev`.
pub fn stat_bytes_on(stat: &Stat, dev: (u32, u32)) -> [u8; 144] {
    let mut out = [0u8; 144];
    let put = |out: &mut [u8; 144], at: usize, value: u64| {
        out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(&mut out, 0, encode_dev(dev.0, dev.1));
    put(&mut out, 8, stat.ino + 1); // inode 0 is "none" to most tools
    put(&mut out, 16, u64::from(stat.nlink));
    out[24..28].copy_from_slice(&stat.mode.to_le_bytes());
    // uid and gid 0: stored and reported only (SR-6).
    put(&mut out, 40, encode_dev(stat.rdev.0, stat.rdev.1));
    put(&mut out, 48, stat.size);
    put(&mut out, 56, 4096);
    let blocks = if stat.mode & keel_core::vfs::S_IFMT == keel_core::vfs::S_IFREG {
        stat.size.div_ceil(4096) * 8
    } else {
        0
    };
    put(&mut out, 64, blocks);
    for (at, t) in [(72, stat.atime), (88, stat.mtime), (104, stat.ctime)] {
        put(&mut out, at, t.sec as u64);
        put(&mut out, at + 8, u64::from(t.nsec));
    }
    out
}

/// `struct timespec`: seconds, nanoseconds.
pub fn timespec_bytes(nanos: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&(nanos / 1_000_000_000).to_le_bytes());
    out[8..].copy_from_slice(&(nanos % 1_000_000_000).to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_numbers_encode_like_linux() {
        // /dev/null 1:3 -> 0x103; a minor above 255 uses the high bits.
        assert_eq!(encode_dev(1, 3), 0x103);
        assert_eq!(encode_dev(5, 1), 0x501);
        assert_eq!(encode_dev(8, 0x1_23), 0x10_0823);
    }

    #[test]
    fn stat_layout() {
        let s = Stat {
            ino: 6,
            mode: 0o100644,
            size: 1025,
            nlink: 1,
            rdev: (1, 9),
            atime: keel_core::vfs::Timespec { sec: 11, nsec: 12 },
            mtime: keel_core::vfs::Timespec { sec: 13, nsec: 14 },
            ctime: keel_core::vfs::Timespec { sec: 15, nsec: 16 },
        };
        let b = stat_bytes(&s);
        let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        assert_eq!(u64_at(8), 7);
        assert_eq!(u64_at(16), 1);
        assert_eq!(u32::from_le_bytes(b[24..28].try_into().unwrap()), 0o100644);
        assert_eq!(u64_at(40), 0x109);
        assert_eq!(u64_at(48), 1025);
        assert_eq!(u64_at(56), 4096);
        assert_eq!(u64_at(64), 8, "one whole page");
        assert!(b[28..40].iter().all(|&x| x == 0), "uid, gid, padding");
        let times: alloc::vec::Vec<u64> = (0..6).map(|i| u64_at(72 + i * 8)).collect();
        assert_eq!(times, [11, 12, 13, 14, 15, 16]);
        assert!(b[120..].iter().all(|&x| x == 0), "unused");
    }

    #[test]
    fn timespec() {
        let t = timespec_bytes(3_000_000_007);
        assert_eq!(u64::from_le_bytes(t[..8].try_into().unwrap()), 3);
        assert_eq!(u64::from_le_bytes(t[8..].try_into().unwrap()), 7);
    }
}
