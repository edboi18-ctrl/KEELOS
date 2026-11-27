//! Allowlist profiles (P3-S3, ADR 0041; SR-7, SR-10): which system calls
//! a compartment's processes may make, which operations of the
//! multiplexer calls (`clone`, `fcntl`, `prctl`, `madvise`, `ioctl`), and
//! which ioctl requests on each kind of object. A compartment has one
//! profile, fixed when it is made.
//!
//! The never-implemented calls (spec section 7, "Linux-ABI surface
//! policy") are in no profile; [`NEVER`] lists them and the tests below
//! hold every profile to that. System-call numbers are x86-64's, checked
//! against Linux v6.12 `arch/x86/entry/syscalls/syscall_64.tbl`.

/// How many system-call numbers a profile covers (the dispatch table's
/// size; numbers above it are not Linux calls Keel knows).
pub const CALLS: usize = 512;

/// The never-implemented calls, by number and name. In no profile, and
/// refused before any profile is consulted.
pub const NEVER: &[(u64, &str)] = &[
    // Cross-process inspection and control.
    (101, "ptrace"),
    (310, "process_vm_readv"),
    (311, "process_vm_writev"),
    (312, "kcmp"),
    (438, "pidfd_getfd"),
    // Large, historically bug-prone surfaces.
    (425, "io_uring_setup"),
    (426, "io_uring_enter"),
    (427, "io_uring_register"),
    (321, "bpf"),
    (323, "userfaultfd"),
    (298, "perf_event_open"),
    // Namespaces and mounts, including the new mount API (`open_tree` to
    // `mount_setattr`), which mounts as `mount` does.
    (272, "unshare"),
    (308, "setns"),
    (165, "mount"),
    (166, "umount2"),
    (155, "pivot_root"),
    (161, "chroot"),
    (428, "open_tree"),
    (429, "move_mount"),
    (430, "fsopen"),
    (431, "fsconfig"),
    (432, "fsmount"),
    (433, "fspick"),
    (442, "mount_setattr"),
    // Kernel code loading and machine control.
    (175, "init_module"),
    (313, "finit_module"),
    (176, "delete_module"),
    (246, "kexec_load"),
    (320, "kexec_file_load"),
    (169, "reboot"),
    (167, "swapon"),
    (172, "iopl"),
    (173, "ioperm"),
    // Global state, or lookups that bypass path-based confinement.
    (250, "keyctl"),
    (248, "add_key"),
    (249, "request_key"),
    (304, "open_by_handle_at"),
    (303, "name_to_handle_at"),
    (179, "quotactl"),
    (443, "quotactl_fd"),
    (163, "acct"),
    (103, "syslog"),
    // 32-bit segments.
    (154, "modify_ldt"),
];

/// `clone` flags that make a namespace (`include/uapi/linux/sched.h`):
/// CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC,
/// CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET. Never allowed. (CLONE_NEWTIME,
/// 0x80, exists only for `clone3` and `unshare`: in `clone`'s flags that
/// bit is part of the exit signal.)
pub const CLONE_NEW: u64 =
    0x0002_0000 | 0x0200_0000 | 0x0400_0000 | 0x0800_0000 | 0x1000_0000 | 0x2000_0000 | 0x4000_0000;

/// The system-call numbers that are mechanism, not surface: every profile
/// has them. `exit` and `exit_group` end a program, `rt_sigreturn` ends a
/// signal handler, and `restart_syscall` (219) is what the kernel itself
/// has a program call to resume an interrupted sleep (ADR 0033).
pub const ALWAYS: &[u64] = &[60, 231, 15, 219];

/// Operations of one multiplexer call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ops {
    /// Whatever the call itself accepts.
    Any,
    /// Only these values of the operation argument.
    Only(&'static [u64]),
}

impl Ops {
    pub fn allows(self, op: u64) -> bool {
        match self {
            Ops::Any => true,
            Ops::Only(ops) => ops.contains(&op),
        }
    }

    /// Whether everything this allows, `ceiling` allows.
    pub fn within(self, ceiling: Ops) -> bool {
        match (self, ceiling) {
            (_, Ops::Any) => true,
            (Ops::Any, Ops::Only(_)) => false,
            (Ops::Only(ops), Ops::Only(_)) => ops.iter().all(|op| ceiling.allows(*op)),
        }
    }
}

/// What kind of object an ioctl is made on: ioctl allowlists are per
/// device type (SR-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// A terminal: the console, a pty side, `/dev/tty`.
    Terminal,
    /// A regular file.
    File,
    Directory,
    /// A pipe or FIFO end.
    Pipe,
    Socket,
    /// Anything else: other devices, eventfds, epoll and the rest.
    Other,
}

/// ioctl requests a profile allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ioctls {
    /// Whatever each object answers.
    Any,
    /// Only these (class, request) pairs.
    Only(&'static [(Class, u32)]),
}

impl Ioctls {
    pub fn allows(self, class: Class, request: u32) -> bool {
        match self {
            Ioctls::Any => true,
            Ioctls::Only(pairs) => pairs.contains(&(class, request)),
        }
    }

    pub fn within(self, ceiling: Ioctls) -> bool {
        match (self, ceiling) {
            (_, Ioctls::Any) => true,
            (Ioctls::Any, Ioctls::Only(_)) => false,
            (Ioctls::Only(pairs), Ioctls::Only(_)) => {
                pairs.iter().all(|(c, r)| ceiling.allows(*c, *r))
            }
        }
    }
}

/// A system-call number set, one bit per number below [`CALLS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Calls([u64; CALLS / 64]);

impl Calls {
    /// Every number except the never-implemented ones.
    const fn all_but_never() -> Calls {
        let mut bits = [u64::MAX; CALLS / 64];
        let mut i = 0;
        while i < NEVER.len() {
            let n = NEVER[i].0 as usize;
            bits[n / 64] &= !(1 << (n % 64));
            i += 1;
        }
        Calls(bits)
    }

    /// `numbers` and [`ALWAYS`].
    const fn of(numbers: &[(u64, &str)]) -> Calls {
        let mut bits = [0u64; CALLS / 64];
        let mut i = 0;
        while i < numbers.len() {
            let n = numbers[i].0 as usize;
            bits[n / 64] |= 1 << (n % 64);
            i += 1;
        }
        let mut i = 0;
        while i < ALWAYS.len() {
            let n = ALWAYS[i] as usize;
            bits[n / 64] |= 1 << (n % 64);
            i += 1;
        }
        Calls(bits)
    }

    pub fn contains(&self, number: u64) -> bool {
        (number as usize) < CALLS && self.0[number as usize / 64] & (1 << (number % 64)) != 0
    }

    fn within(&self, ceiling: &Calls) -> bool {
        self.0
            .iter()
            .zip(ceiling.0.iter())
            .all(|(a, c)| a & !c == 0)
    }
}

/// A compartment's allowlists.
#[derive(Debug, PartialEq, Eq)]
pub struct Profile {
    /// Its name in a manifest.
    pub name: &'static str,
    /// Its number in the native interface (ADR 0040, the limits
    /// structure).
    pub id: u32,
    pub calls: Calls,
    /// `clone`'s whole flags argument, exit signal included.
    pub clone: Ops,
    /// `fcntl`'s command.
    pub fcntl: Ops,
    /// `prctl`'s option.
    pub prctl: Ops,
    /// `madvise`'s advice.
    pub madvise: Ops,
    pub ioctl: Ioctls,
}

/// Why a call was refused, which fixes its error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    /// The call is not in the profile (or never implemented): ENOSYS, as
    /// Linux answers a number it has no call for (`sys_ni_syscall`).
    Call,
    /// An operation of `clone`, `fcntl`, `prctl` or `madvise` the profile
    /// does not allow: EINVAL, what each answers for an operation it does
    /// not know (clone(2), fcntl(2), prctl(2), madvise(2)).
    Operation,
}

impl Profile {
    /// Whether `number` with `args` may be made. ioctl requests are
    /// checked by [`Profile::allows_ioctl`] once the object is known.
    pub fn check(&self, number: u64, args: &[u64; 6]) -> Result<(), Denied> {
        if is_never(number) || !self.calls.contains(number) {
            return Err(Denied::Call);
        }
        let allowed = match number {
            56 => args[0] & CLONE_NEW == 0 && self.clone.allows(args[0]),
            72 => self.fcntl.allows(args[1] & 0xffff_ffff),
            157 => self.prctl.allows(args[0] & 0xffff_ffff),
            28 => self.madvise.allows(args[2] & 0xffff_ffff),
            _ => true,
        };
        if allowed {
            Ok(())
        } else {
            Err(Denied::Operation)
        }
    }

    pub fn allows_ioctl(&self, class: Class, request: u32) -> bool {
        self.ioctl.allows(class, request)
    }

    /// Whether everything this profile allows, `ceiling` allows (a
    /// factory's ceiling, ADR 0040).
    pub fn within(&self, ceiling: &Profile) -> bool {
        self.calls.within(&ceiling.calls)
            && self.clone.within(ceiling.clone)
            && self.fcntl.within(ceiling.fcntl)
            && self.prctl.within(ceiling.prctl)
            && self.madvise.within(ceiling.madvise)
            && self.ioctl.within(ceiling.ioctl)
    }
}

pub fn is_never(number: u64) -> bool {
    NEVER.iter().any(|(n, _)| *n == number)
}

/// Every call and operation Keel implements: the system compartment, and
/// compartments the kernel makes for its own tests and programs. Only the
/// never-implemented calls and namespace flags are refused here; the
/// calls themselves refuse what they do not implement (SR-10).
pub static FULL: Profile = Profile {
    name: "full",
    id: 1,
    calls: Calls::all_but_never(),
    clone: Ops::Any,
    fcntl: Ops::Any,
    prctl: Ops::Any,
    madvise: Ops::Any,
    ioctl: Ioctls::Any,
};

/// The system calls of the Wine trace (`docs/syscall-inventory.md`,
/// `wine cmd /c echo hello`), less `userfaultfd` (never implemented: Wine
/// probes it and goes on without it), plus `clock_gettime`, which the
/// trace could not show: musl reads the clock through the vDSO on Linux,
/// and Keel has none, so musl makes the call (the inventory's note).
pub const WINE_TRACE: &[(u64, &str)] = &[
    (59, "execve"),
    (158, "arch_prctl"),
    (218, "set_tid_address"),
    (12, "brk"),
    (9, "mmap"),
    (10, "mprotect"),
    (89, "readlink"),
    (2, "open"),
    (72, "fcntl"),
    (5, "fstat"),
    (0, "read"),
    (3, "close"),
    (14, "rt_sigprocmask"),
    (324, "membarrier"),
    (13, "rt_sigaction"),
    (102, "getuid"),
    (8, "lseek"),
    (11, "munmap"),
    (157, "prctl"),
    (302, "prlimit64"),
    (80, "chdir"),
    (4, "stat"),
    (83, "mkdir"),
    (6, "lstat"),
    (293, "pipe2"),
    (56, "clone"),
    (53, "socketpair"),
    (48, "shutdown"),
    (7, "poll"),
    (22, "pipe"),
    (57, "fork"),
    (112, "setsid"),
    (87, "unlink"),
    (41, "socket"),
    (49, "bind"),
    (90, "chmod"),
    (50, "listen"),
    (291, "epoll_create1"),
    (233, "epoll_ctl"),
    (33, "dup2"),
    (1, "write"),
    (231, "exit_group"),
    (61, "wait4"),
    (54, "setsockopt"),
    (42, "connect"),
    (81, "fchdir"),
    (138, "fstatfs"),
    (17, "pread64"),
    (328, "pwritev2"),
    (77, "ftruncate"),
    (39, "getpid"),
    (141, "setpriority"),
    (281, "epoll_pwait"),
    (43, "accept"),
    (46, "sendmsg"),
    (47, "recvmsg"),
    (131, "sigaltstack"),
    (186, "gettid"),
    (204, "sched_getaffinity"),
    (20, "writev"),
    (95, "umask"),
    (79, "getcwd"),
    (99, "sysinfo"),
    (32, "dup"),
    (16, "ioctl"),
    (203, "sched_setaffinity"),
    (63, "uname"),
    (217, "getdents64"),
    (191, "getxattr"),
    (193, "fgetxattr"),
    (229, "clock_getres"),
    (19, "readv"),
    (98, "getrusage"),
    (24, "sched_yield"),
    (23, "select"),
    (257, "openat"),
    (318, "getrandom"),
    (202, "futex"),
    (21, "access"),
    (60, "exit"),
    (44, "sendto"),
    (45, "recvfrom"),
    (62, "kill"),
    (234, "tgkill"),
    (15, "rt_sigreturn"),
    (82, "rename"),
    (228, "clock_gettime"),
];

/// The default profile (SR-7: "the set Wine was observed to need"): the
/// calls of [`WINE_TRACE`], and of the multiplexers only the operations
/// the trace shows.
pub static DEFAULT: Profile = Profile {
    name: "default",
    id: 0,
    calls: Calls::of(WINE_TRACE),
    // musl's pthread_create (CLONE_VM | CLONE_FS | CLONE_FILES |
    // CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
    // CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED, no exit
    // signal) and posix_spawn (CLONE_VM | CLONE_VFORK | SIGCHLD): the two
    // combinations traced.
    clone: Ops::Only(&[0x007d_0f00, 0x4111]),
    // F_SETFD, F_GETFL, F_SETFL, F_SETLK.
    fcntl: Ops::Only(&[2, 3, 4, 6]),
    // PR_SET_NAME and PR_SET_PTRACER (Keel answers the second EINVAL:
    // it has no ptrace to permit).
    prctl: Ops::Only(&[15, 0x5961_6d61]),
    // Not traced.
    madvise: Ops::Only(&[]),
    // TIOCGWINSZ on a terminal; FS_IOC_GETFLAGS and
    // VFAT_IOCTL_READDIR_BOTH on files and directories (both answered
    // ENOTTY by Keel's tmpfs, as by a Linux filesystem without them). The
    // traced SIOCGIF* requests were made on AF_INET sockets, which Keel
    // does not have.
    ioctl: Ioctls::Only(&[
        (Class::Terminal, 0x5413),
        (Class::File, 0x8008_6601),
        (Class::Directory, 0x8008_6601),
        (Class::File, 0x8230_7201),
        (Class::Directory, 0x8230_7201),
    ]),
};

/// Every profile, by id.
pub static PROFILES: [&Profile; 2] = [&DEFAULT, &FULL];

/// The profile with this id, if there is one.
pub fn by_id(id: u32) -> Option<&'static Profile> {
    PROFILES.iter().copied().find(|p| p.id == id)
}

/// The profile with this manifest name.
pub fn by_name(name: &[u8]) -> Option<&'static Profile> {
    PROFILES.iter().copied().find(|p| p.name.as_bytes() == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_profile_has_a_never_implemented_call() {
        for p in PROFILES {
            for (n, name) in NEVER {
                assert!(!p.calls.contains(*n), "{} has {name}", p.name);
                assert_eq!(p.check(*n, &[0; 6]), Err(Denied::Call), "{name}");
            }
        }
    }

    #[test]
    fn keel_rt_has_the_same_never_list() {
        // user/keel-rt's copy, which profileprobe calls (ADR 0041).
        let rt = include_str!("../../../user/keel-rt/src/sys.rs");
        let head = "pub const NEVER_IMPLEMENTED: &[u64] = &[";
        let body = &rt[rt.find(head).unwrap() + head.len()..];
        let body = &body[..body.find("];").unwrap()];
        let theirs: alloc::vec::Vec<u64> = body
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().unwrap())
            .collect();
        let ours: alloc::vec::Vec<u64> = NEVER.iter().map(|(n, _)| *n).collect();
        assert_eq!(theirs, ours);
    }

    #[test]
    fn never_list_is_unique_and_in_range() {
        for (i, (n, name)) in NEVER.iter().enumerate() {
            assert!((*n as usize) < CALLS, "{name}");
            assert!(NEVER[..i].iter().all(|(m, _)| m != n), "{name} twice");
        }
    }

    #[test]
    fn namespace_flags_are_refused_in_every_profile() {
        for p in PROFILES {
            for bit in 0..64 {
                let flag = 1u64 << bit;
                if flag & CLONE_NEW != 0 {
                    assert_eq!(p.check(56, &[flag, 0, 0, 0, 0, 0]), Err(Denied::Operation));
                    assert_eq!(
                        p.check(56, &[0x007d_0f00 | flag, 0, 0, 0, 0, 0]),
                        Err(Denied::Operation)
                    );
                }
            }
        }
    }

    #[test]
    fn every_profile_has_the_mechanism_calls() {
        for p in PROFILES {
            for n in ALWAYS {
                assert!(p.calls.contains(*n), "{} lacks {n}", p.name);
            }
        }
    }

    #[test]
    fn the_default_is_the_trace() {
        // Exactly the trace's calls and the mechanism ones.
        let traced = |n: u64| WINE_TRACE.iter().any(|(m, _)| *m == n) || ALWAYS.contains(&n);
        for n in 0..CALLS as u64 {
            assert_eq!(DEFAULT.calls.contains(n), traced(n), "{n}");
        }
        // Each traced name once, the inventory's 87 less userfaultfd,
        // plus clock_gettime.
        assert_eq!(WINE_TRACE.len(), 87);
        for (i, (n, _)) in WINE_TRACE.iter().enumerate() {
            assert!(WINE_TRACE[..i].iter().all(|(m, _)| m != n));
        }
        let inventory = include_str!("../../../docs/syscall-inventory.md");
        let table = &inventory[inventory.find("## System calls").unwrap()
            ..inventory.find("## `clone` flag combinations").unwrap()];
        let traced_names: alloc::vec::Vec<&str> = table
            .lines()
            .filter(|l| l.starts_with("| ") && l[2..].starts_with(|c: char| c.is_ascii_digit()))
            .filter_map(|l| l.split('`').nth(1))
            .collect();
        assert_eq!(traced_names.len(), 87);
        for (_, name) in WINE_TRACE {
            assert!(
                traced_names.contains(name) || *name == "clock_gettime",
                "{name} is not in the trace"
            );
        }
        for name in &traced_names {
            assert!(
                WINE_TRACE.iter().any(|(_, n)| n == name) || *name == "userfaultfd",
                "{name} from the trace is missing"
            );
        }
    }

    #[test]
    fn default_operations() {
        let d = &DEFAULT;
        // musl's thread and posix_spawn flags; fork-style clone is not.
        assert_eq!(d.check(56, &[0x007d_0f00, 0, 0, 0, 0, 0]), Ok(()));
        assert_eq!(d.check(56, &[0x4111, 0, 0, 0, 0, 0]), Ok(()));
        assert_eq!(d.check(56, &[17, 0, 0, 0, 0, 0]), Err(Denied::Operation));
        assert_eq!(d.check(72, &[0, 3, 0, 0, 0, 0]), Ok(()));
        assert_eq!(d.check(72, &[0, 1, 0, 0, 0, 0]), Err(Denied::Operation));
        // The command is an int: upper bits are not part of it.
        assert_eq!(d.check(72, &[0, (1 << 32) | 3, 0, 0, 0, 0]), Ok(()));
        assert_eq!(d.check(157, &[15, 0, 0, 0, 0, 0]), Ok(()));
        assert_eq!(d.check(157, &[16, 0, 0, 0, 0, 0]), Err(Denied::Operation));
        // madvise is not traced at all.
        assert_eq!(d.check(28, &[0, 0, 4, 0, 0, 0]), Err(Denied::Call));
        assert_eq!(d.check(110, &[0; 6]), Err(Denied::Call));
        assert!(d.allows_ioctl(Class::Terminal, 0x5413));
        assert!(!d.allows_ioctl(Class::Terminal, 0x5401));
        assert!(!d.allows_ioctl(Class::Pipe, 0x541b));
        assert!(!d.allows_ioctl(Class::File, 0x5413));
    }

    #[test]
    fn full_allows_what_is_not_never() {
        let f = &FULL;
        assert_eq!(f.check(110, &[0; 6]), Ok(()));
        assert_eq!(f.check(56, &[17, 0, 0, 0, 0, 0]), Ok(()));
        assert_eq!(f.check(72, &[0, 1, 0, 0, 0, 0]), Ok(()));
        assert_eq!(f.check(28, &[0, 0, 4, 0, 0, 0]), Ok(()));
        assert!(f.allows_ioctl(Class::Pipe, 0x541b));
        assert_eq!(f.check(CALLS as u64, &[0; 6]), Err(Denied::Call));
    }

    #[test]
    fn ceilings() {
        assert!(DEFAULT.within(&FULL));
        assert!(DEFAULT.within(&DEFAULT));
        assert!(FULL.within(&FULL));
        assert!(!FULL.within(&DEFAULT));
        assert!(Ops::Only(&[1]).within(Ops::Only(&[1, 2])));
        assert!(!Ops::Only(&[3]).within(Ops::Only(&[1, 2])));
        assert!(!Ops::Any.within(Ops::Only(&[1])));
        assert!(Ops::Only(&[]).within(Ops::Only(&[])));
    }

    #[test]
    fn lookups() {
        assert_eq!(by_id(0), Some(&DEFAULT));
        assert_eq!(by_id(1), Some(&FULL));
        assert_eq!(by_id(2), None);
        assert_eq!(by_name(b"default"), Some(&DEFAULT));
        assert_eq!(by_name(b"full"), Some(&FULL));
        assert_eq!(by_name(b"wine-gui"), None);
    }
}
