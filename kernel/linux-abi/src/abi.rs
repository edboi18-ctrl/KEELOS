//! Linux x86-64 constants and the byte layout of structures copied to user
//! space. Every structure is built in a zeroed buffer, so padding never
//! carries kernel bytes (SR-18).
//!
//! Sources (Linux v6.12): `include/uapi/asm-generic/fcntl.h` (O_*,
//! AT_FDCWD), `include/uapi/asm-generic/mman-common.h`, `mman.h` and
//! `include/uapi/linux/mman.h` (PROT_*, MAP_*), `arch/x86/include/uapi/asm/
//! prctl.h` (ARCH_*), `arch/x86/include/uapi/asm/stat.h` (struct stat,
//! x86-64 branch), `include/linux/kdev_t.h` (`new_encode_dev`),
//! `include/uapi/asm-generic/ioctls.h` and `termbits.h` (TCGETS,
//! TIOCGWINSZ, struct termios, NCCS 19), `drivers/tty/tty_io.c`
//! (`tty_std_termios`) and `include/linux/termios_internal.h`
//! (`INIT_C_CC`), `include/uapi/linux/time.h` (CLOCK_*),
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
/// st_size 48, st_blksize 56, st_blocks 64, times 72..120, unused 120..144.
/// Times are 0 until Keel has a real-time clock.
pub fn stat_bytes(stat: &Stat) -> [u8; 144] {
    let mut out = [0u8; 144];
    let put = |out: &mut [u8; 144], at: usize, value: u64| {
        out[at..at + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(&mut out, 0, encode_dev(TMPFS_DEV.0, TMPFS_DEV.1));
    put(&mut out, 8, u64::from(stat.ino) + 1); // inode 0 is "none" to most tools
    put(&mut out, 16, u64::from(stat.nlink));
    out[24..28].copy_from_slice(&stat.mode.to_le_bytes());
    // uid and gid 0: stored and reported only (SR-6).
    put(&mut out, 40, encode_dev(stat.rdev.0, stat.rdev.1));
    put(&mut out, 48, stat.size);
    put(&mut out, 56, 4096);
    put(&mut out, 64, stat.size.div_ceil(512));
    out
}

/// `struct timespec`: seconds, nanoseconds.
pub fn timespec_bytes(nanos: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&(nanos / 1_000_000_000).to_le_bytes());
    out[8..].copy_from_slice(&(nanos % 1_000_000_000).to_le_bytes());
    out
}

/// `struct termios` (36 bytes: four u32 flag words, c_line, c_cc[19])
/// with Linux's `tty_std_termios` values: iflag ICRNL|IXON, oflag
/// OPOST|ONLCR, cflag B38400|CS8|CREAD|HUPCL, lflag ISIG|ICANON|ECHO|
/// ECHOE|ECHOK|ECHOCTL|ECHOKE|IEXTEN, and `INIT_C_CC`.
pub fn std_termios_bytes() -> [u8; 36] {
    const ICRNL: u32 = 0x100;
    const IXON: u32 = 0x400;
    const OPOST: u32 = 0x01;
    const ONLCR: u32 = 0x04;
    const B38400: u32 = 0x0f;
    const CS8: u32 = 0x30;
    const CREAD: u32 = 0x80;
    const HUPCL: u32 = 0x400;
    const ISIG: u32 = 0x1;
    const ICANON: u32 = 0x2;
    const ECHO: u32 = 0x8;
    const ECHOE: u32 = 0x10;
    const ECHOK: u32 = 0x20;
    const ECHOCTL: u32 = 0x200;
    const ECHOKE: u32 = 0x800;
    const IEXTEN: u32 = 0x8000;
    let ctrl = |c: u8| c - 0x40;
    let mut out = [0u8; 36];
    let flags = [
        ICRNL | IXON,
        OPOST | ONLCR,
        B38400 | CS8 | CREAD | HUPCL,
        ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
    ];
    for (i, f) in flags.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&f.to_le_bytes());
    }
    // out[16] = c_line 0 (N_TTY). c_cc starts at 17; indices are VINTR 0,
    // VQUIT 1, VERASE 2, VKILL 3, VEOF 4, VMIN 6, VSTART 8, VSTOP 9,
    // VSUSP 10, VREPRINT 12, VDISCARD 13, VWERASE 14, VLNEXT 15.
    let cc = &mut out[17..36];
    cc[0] = ctrl(b'C');
    cc[1] = ctrl(b'\\');
    cc[2] = 0o177;
    cc[3] = ctrl(b'U');
    cc[4] = ctrl(b'D');
    cc[6] = 1;
    cc[8] = ctrl(b'Q');
    cc[9] = ctrl(b'S');
    cc[10] = ctrl(b'Z');
    cc[12] = ctrl(b'R');
    cc[13] = ctrl(b'O');
    cc[14] = ctrl(b'W');
    cc[15] = ctrl(b'V');
    out
}

/// `struct winsize`: rows, columns, then two unused pixel sizes (u16).
pub fn winsize_bytes(rows: u16, cols: u16) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..2].copy_from_slice(&rows.to_le_bytes());
    out[2..4].copy_from_slice(&cols.to_le_bytes());
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
        };
        let b = stat_bytes(&s);
        let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
        assert_eq!(u64_at(8), 7);
        assert_eq!(u64_at(16), 1);
        assert_eq!(u32::from_le_bytes(b[24..28].try_into().unwrap()), 0o100644);
        assert_eq!(u64_at(40), 0x109);
        assert_eq!(u64_at(48), 1025);
        assert_eq!(u64_at(56), 4096);
        assert_eq!(u64_at(64), 3);
        assert!(b[28..40].iter().all(|&x| x == 0), "uid, gid, padding");
        assert!(b[72..].iter().all(|&x| x == 0), "times and unused");
    }

    #[test]
    fn termios_matches_tty_std_termios() {
        let t = std_termios_bytes();
        let word = |i: usize| u32::from_le_bytes(t[i * 4..i * 4 + 4].try_into().unwrap());
        assert_eq!(word(0), 0x500);
        assert_eq!(word(1), 0x5);
        assert_eq!(word(2), 0x4bf);
        assert_eq!(word(3), 0x8a3b);
        assert_eq!(t[16], 0);
        assert_eq!(&t[17..22], &[3, 0x1c, 0x7f, 0x15, 4]);
        assert_eq!(t[17 + 6], 1, "VMIN");
    }

    #[test]
    fn timespec_and_winsize() {
        let t = timespec_bytes(3_000_000_007);
        assert_eq!(u64::from_le_bytes(t[..8].try_into().unwrap()), 3);
        assert_eq!(u64::from_le_bytes(t[8..].try_into().unwrap()), 7);
        assert_eq!(winsize_bytes(25, 80), [25, 0, 80, 0, 0, 0, 0, 0]);
    }
}
