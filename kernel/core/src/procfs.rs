//! The procfs subset Keel provides (P3-T9, ADR 0024), as pure data and
//! tested on the host: path parsing, `/proc/cpuinfo` from CPUID, and
//! `/proc/net/dev`, the directory listings and `/proc/<pid>/stat`.
//! `keel-linux-abi` answers lookups with it.
//!
//! The Wine traces use these (`docs/syscall-inventory.md`): `/proc`
//! itself, `/proc/self` and `/proc/<pid>` (readlink), their `exe` links,
//! `/proc/<pid>/task/<tid>/comm` (thread names), `/proc/cpuinfo` and
//! `/proc/net/dev`. Beyond the traces (ADR 0037), what `ps` and `pidof`
//! read: the directories listed, `/proc/<pid>/stat` and
//! `/proc/<pid>/cmdline`. Formats are Linux v6.12's
//! (`arch/x86/kernel/cpu/proc.c`, `fs/proc/base.c`, `fs/proc/root.c`,
//! `fs/proc/generic.c`, `fs/proc/array.c`, `fs/proc/self.c`,
//! `fs/proc/thread_self.c`, `net/core/net-procfs.c`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// A procfs node a path can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    /// `/proc`.
    Root,
    /// `/proc/self`: a symbolic link to the caller's PID.
    SelfLink,
    /// `/proc/thread-self`: a link to `<pid>/task/<tid>` of the caller.
    ThreadSelf,
    /// `/proc/<pid>`.
    Pid(u32),
    /// `/proc/<pid>/exe`: a link to the program.
    Exe(u32),
    /// `/proc/<pid>/comm`: the thread group leader's name.
    Comm(u32),
    /// `/proc/<pid>/cmdline`: the process's argv.
    Cmdline(u32),
    /// `/proc/<pid>/stat`: its status line.
    Stat(u32),
    /// `/proc/<pid>/task`.
    Tasks(u32),
    /// `/proc/<pid>/task/<tid>`.
    Task(u32, u32),
    /// `/proc/<pid>/task/<tid>/comm`.
    TaskComm(u32, u32),
    /// `/proc/cpuinfo`.
    CpuInfo,
    /// `/proc/net`: on Linux a link to `self/net`; here a directory.
    Net,
    /// `/proc/net/dev`.
    NetDev,
}

impl Node {
    /// Whether it is a directory, a symbolic link, or a regular file.
    pub fn kind(self) -> Kind {
        match self {
            Node::Root | Node::Pid(_) | Node::Tasks(_) | Node::Task(..) | Node::Net => {
                Kind::Directory
            }
            Node::SelfLink | Node::ThreadSelf | Node::Exe(_) => Kind::Symlink,
            Node::Comm(_)
            | Node::Cmdline(_)
            | Node::Stat(_)
            | Node::TaskComm(..)
            | Node::CpuInfo
            | Node::NetDev => Kind::File,
        }
    }

    /// Permission bits, as procfs gives them: directories 0555, links
    /// 0777, `comm` 0644 (S_IRUGO|S_IWUSR), the rest 0444.
    pub fn permissions(self) -> u32 {
        match self {
            Node::Comm(_) | Node::TaskComm(..) => 0o644,
            n if n.kind() == Kind::Directory => 0o555,
            n if n.kind() == Kind::Symlink => 0o777,
            _ => 0o444,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Directory,
    Symlink,
    File,
}

/// Where a path inside `/proc` leads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// A procfs node.
    Node(Node),
    /// A link out of procfs to follow in the real tree (an `exe` link
    /// followed): the path to look up instead.
    Elsewhere(Vec<u8>),
    /// Nothing there (ENOENT).
    Missing,
}

/// What a lookup needs to know about the caller and its compartment.
pub trait View {
    /// The caller's PID and TID (as getpid and gettid give them).
    fn me(&self) -> (u32, u32);
    /// Whether `pid` is a process in the caller's compartment.
    fn has_pid(&self, pid: u32) -> bool;
    /// Whether `tid` is a thread of process `pid`.
    fn has_task(&self, pid: u32, tid: u32) -> bool;
    /// The program's path of process `pid` (what `exe` reads as).
    fn exe(&self, pid: u32) -> Option<Vec<u8>>;
    /// The PIDs of the caller's compartment, in increasing order.
    fn pids(&self) -> Vec<u32>;
    /// The TIDs of process `pid`, its first thread first.
    fn tasks(&self, pid: u32) -> Vec<u32>;
}

/// A number as procfs reads one in a path: decimal digits only, no sign,
/// no leading zero (`name_to_int`, `fs/proc/util.c`).
fn number(name: &[u8]) -> Option<u32> {
    if name.is_empty() || name.len() > 10 || (name.len() > 1 && name[0] == b'0') {
        return None;
    }
    if !name.iter().all(u8::is_ascii_digit) {
        return None;
    }
    core::str::from_utf8(name).ok()?.parse().ok()
}

/// The target a procfs link reads as (readlink): `self` the caller's PID,
/// `thread-self` `<pid>/task/<tid>`, `exe` the program's path.
pub fn link_target(node: Node, view: &dyn View) -> Option<Vec<u8>> {
    let (pid, tid) = view.me();
    match node {
        Node::SelfLink => Some(format!("{pid}").into_bytes()),
        Node::ThreadSelf => Some(format!("{pid}/task/{tid}").into_bytes()),
        Node::Exe(p) => view.exe(p),
        _ => None,
    }
}

/// Resolves `rest`, the components after `/proc` (`.` and empty ones
/// already dropped by the caller, `..` not allowed: the caller resolves
/// those itself). Links met before the last component are followed; the
/// last only if `follow_last`.
pub fn resolve(rest: &[&[u8]], follow_last: bool, view: &dyn View) -> Resolved {
    let mut at = Node::Root;
    let mut i = 0;
    while i < rest.len() {
        let name = rest[i];
        let next = match (at, name) {
            (Node::Root, b"self") => Node::SelfLink,
            (Node::Root, b"thread-self") => Node::ThreadSelf,
            (Node::Root, b"cpuinfo") => Node::CpuInfo,
            (Node::Root, b"net") => Node::Net,
            (Node::Root, n) => match number(n) {
                Some(pid) if view.has_pid(pid) => Node::Pid(pid),
                _ => return Resolved::Missing,
            },
            (Node::Net, b"dev") => Node::NetDev,
            (Node::Pid(p), b"exe") => Node::Exe(p),
            (Node::Pid(p), b"comm") => Node::Comm(p),
            (Node::Pid(p), b"cmdline") => Node::Cmdline(p),
            (Node::Pid(p), b"stat") => Node::Stat(p),
            (Node::Pid(p), b"task") => Node::Tasks(p),
            (Node::Tasks(p), n) => match number(n) {
                Some(tid) if view.has_task(p, tid) => Node::Task(p, tid),
                _ => return Resolved::Missing,
            },
            (Node::Task(p, t), b"comm") => Node::TaskComm(p, t),
            (Node::Task(p, t), b"exe") => {
                let _ = t;
                Node::Exe(p)
            }
            _ => return Resolved::Missing,
        };
        let last = i + 1 == rest.len();
        at = match next {
            Node::SelfLink | Node::ThreadSelf if !last || follow_last => {
                let (pid, tid) = view.me();
                if next == Node::SelfLink {
                    Node::Pid(pid)
                } else {
                    Node::Task(pid, tid)
                }
            }
            Node::Exe(p) if !last || follow_last => {
                let Some(path) = view.exe(p) else {
                    return Resolved::Missing;
                };
                if !last {
                    // exe is not a directory.
                    return Resolved::Missing;
                }
                return Resolved::Elsewhere(path);
            }
            n => n,
        };
        i += 1;
    }
    Resolved::Node(at)
}

/// `FIRST_PROCESS_ENTRY` (`include/linux/proc_fs.h`): where `/proc`'s
/// listing goes from its fixed entries to `self`, `thread-self` and the
/// PIDs (`proc_root_readdir`).
const FIRST_PROCESS_ENTRY: u64 = 256;
/// `TGID_OFFSET` (`fs/proc/base.c`): PID n is at position n + 258.
pub const TGID_OFFSET: u64 = FIRST_PROCESS_ENTRY + 2;
/// `PID_MAX_LIMIT` on 64-bit (`include/linux/threads.h`): the position
/// after the last PID is PID_MAX_LIMIT + TGID_OFFSET.
const PID_MAX_LIMIT: u64 = 4 * 1024 * 1024;

/// A directory entry: its position (what getdents64's d_off and lseek
/// take back to), its name, and its node; None for `..` of `/proc`,
/// which is in the real tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub pos: u64,
    pub name: Vec<u8>,
    pub node: Option<Node>,
}

/// The entries of directory `dir`, in order, and the position after the
/// last one. As Linux lists them:
/// - **`/proc`** (`proc_root_readdir`): `.` and `..`, the fixed entries
///   in `proc_readdir_de`'s order (shorter names first, then by byte),
///   then from position 256 `self` and `thread-self`, then each PID at
///   PID + 258 (`proc_pid_readdir`), increasing; the end is
///   PID_MAX_LIMIT + 258;
/// - **`/proc/<pid>`** (`proc_pident_readdir`): `.`, `..`, then its
///   entries in `tgid_base_stuff`'s order, the ones Keel has; the task
///   directories in `tid_base_stuff`'s;
/// - **`/proc/<pid>/task`** (`proc_task_readdir`): `.`, `..`, then the
///   threads, the first one first.
///
/// Positions other than `/proc`'s are indices; the end is one past the
/// last.
pub fn list(dir: Node, view: &dyn View) -> (Vec<Entry>, u64) {
    let mut out = Vec::new();
    let mut put = |pos: u64, name: &[u8], node: Option<Node>| {
        out.push(Entry {
            pos,
            name: name.to_vec(),
            node,
        });
    };
    let parent = match dir {
        Node::Root => None,
        Node::Pid(_) | Node::Net => Some(Node::Root),
        Node::Tasks(p) => Some(Node::Pid(p)),
        Node::Task(p, _) => Some(Node::Tasks(p)),
        _ => return (out, 0),
    };
    put(0, b".", Some(dir));
    put(1, b"..", parent);
    let fixed: Vec<(&[u8], Node)> = match dir {
        Node::Root => alloc::vec![(&b"net"[..], Node::Net), (b"cpuinfo", Node::CpuInfo)],
        Node::Net => alloc::vec![(&b"dev"[..], Node::NetDev)],
        Node::Pid(p) => alloc::vec![
            (&b"task"[..], Node::Tasks(p)),
            (b"comm", Node::Comm(p)),
            (b"cmdline", Node::Cmdline(p)),
            (b"stat", Node::Stat(p)),
            (b"exe", Node::Exe(p)),
        ],
        Node::Task(p, t) => {
            alloc::vec![(&b"comm"[..], Node::TaskComm(p, t)), (b"exe", Node::Exe(p))]
        }
        _ => Vec::new(),
    };
    let mut pos = 2;
    for (name, node) in fixed {
        put(pos, name, Some(node));
        pos += 1;
    }
    match dir {
        Node::Root => {
            put(FIRST_PROCESS_ENTRY, b"self", Some(Node::SelfLink));
            put(
                FIRST_PROCESS_ENTRY + 1,
                b"thread-self",
                Some(Node::ThreadSelf),
            );
            for pid in view.pids() {
                put(
                    u64::from(pid) + TGID_OFFSET,
                    format!("{pid}").as_bytes(),
                    Some(Node::Pid(pid)),
                );
            }
            (out, PID_MAX_LIMIT + TGID_OFFSET)
        }
        Node::Tasks(p) => {
            for tid in view.tasks(p) {
                put(pos, format!("{tid}").as_bytes(), Some(Node::Task(p, tid)));
                pos += 1;
            }
            (out, pos)
        }
        _ => (out, pos),
    }
}

/// The path of a procfs directory, for lookups relative to it.
pub fn path_of(dir: Node) -> Option<String> {
    match dir {
        Node::Root => Some(String::from("/proc")),
        Node::Net => Some(String::from("/proc/net")),
        Node::Pid(p) => Some(format!("/proc/{p}")),
        Node::Tasks(p) => Some(format!("/proc/{p}/task")),
        Node::Task(p, t) => Some(format!("/proc/{p}/task/{t}")),
        _ => None,
    }
}

/// What `/proc/<pid>/stat` shows of a process (`do_task_stat` with
/// `whole`, `fs/proc/array.c`). Fields Keel does not keep are not here
/// and read as 0: fault counts, CPU times, the code and data bounds, the
/// argument and environment bounds, wchan's address, the CPU, real-time
/// priority and policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatInfo {
    pub pid: u32,
    /// The thread group leader's name.
    pub comm: Vec<u8>,
    /// R, S, T or Z.
    pub state: u8,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    /// The controlling terminal's device number (`new_encode_dev`), 0
    /// for none.
    pub tty_nr: u32,
    /// The terminal's foreground group, -1 without one.
    pub tpgid: i64,
    pub num_threads: u32,
    /// Clock ticks (USER_HZ 100) from boot to the process's start.
    pub start_time: u64,
    /// The address space's size in bytes and resident pages.
    pub vsize: u64,
    pub rss: u64,
    pub start_stack: u64,
    pub start_brk: u64,
    /// Signal sets as bit masks (signal n at bit n - 1).
    pub pending: u64,
    pub blocked: u64,
    pub ignored: u64,
    pub caught: u64,
    /// 1 if single-threaded and not running (`!task_is_running`).
    pub wchan: u64,
    pub exit_signal: i32,
    /// The wait status, for a zombie; else 0.
    pub exit_code: i32,
}

/// RLIMIT_RSS's soft limit: RLIM_INFINITY (`INIT_RLIMITS`).
const RLIM_INFINITY: u64 = u64::MAX;

/// `/proc/<pid>/stat`: the 52 fields of `do_task_stat`, in its order,
/// separated by spaces, with a newline. The obsolete signal fields keep
/// only signals 1-31 (`& 0x7fffffff`).
pub fn stat_line(s: &StatInfo) -> Vec<u8> {
    let low = |v: u64| v & 0x7fff_ffff;
    let mut out = format!("{} (", s.pid).into_bytes();
    out.extend_from_slice(&s.comm);
    out.extend_from_slice(b") ");
    out.push(s.state);
    let fields: [i128; 49] = [
        s.ppid.into(),
        s.pgid.into(),
        s.sid.into(),
        s.tty_nr.into(),
        s.tpgid.into(),
        0,  // flags
        0,  // min_flt
        0,  // cmin_flt
        0,  // maj_flt
        0,  // cmaj_flt
        0,  // utime
        0,  // stime
        0,  // cutime
        0,  // cstime
        20, // priority: task_prio, 120 - MAX_RT_PRIO
        0,  // nice
        s.num_threads.into(),
        0, // itrealvalue
        s.start_time.into(),
        s.vsize.into(),
        s.rss.into(),
        RLIM_INFINITY.into(),
        0, // start_code
        0, // end_code
        s.start_stack.into(),
        0, // esp
        0, // eip
        low(s.pending).into(),
        low(s.blocked).into(),
        low(s.ignored).into(),
        low(s.caught).into(),
        s.wchan.into(),
        0, // nswap
        0, // cnswap
        s.exit_signal.into(),
        0, // processor
        0, // rt_priority
        0, // policy
        0, // delayacct_blkio_ticks
        0, // guest_time
        0, // cguest_time
        0, // start_data
        0, // end_data
        s.start_brk.into(),
        0, // arg_start
        0, // arg_end
        0, // env_start
        0, // env_end
        s.exit_code.into(),
    ];
    for f in fields {
        out.extend_from_slice(format!(" {f}").as_bytes());
    }
    out.push(b'\n');
    out
}

/// `/proc/net/dev` with no network interfaces: the two header lines of
/// `dev_seq_show` (`net/core/net-procfs.c`). Keel has no network yet.
pub const NET_DEV: &str = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n";

/// The `power management` names of CPUID 0x80000007 EDX bits
/// (`x86_power_flags`, `arch/x86/kernel/cpu/powerflags.c`); an empty name
/// is not shown.
const POWER_FLAGS: [&str; 13] = [
    "ts",
    "fid",
    "vid",
    "ttp",
    "tm",
    "stc",
    "100mhzsteps",
    "hwpstate",
    "",
    "cpb",
    "eff_freq_ro",
    "proc_feedback",
    "acc_power",
];

// Generated from Linux v6.12 arch/x86/include/asm/cpufeatures.h by the rule of
// arch/x86/kernel/cpu/mkcapflags.sh (a flag is shown under the quoted name
// in its comment, lower-cased; none, or "", hides it), for the words that
// are one CPUID register each. Do not edit by hand.
pub const CPU_FLAGS: &[(u8, u8, &str)] = &[
    (0, 0, "fpu"),
    (0, 1, "vme"),
    (0, 2, "de"),
    (0, 3, "pse"),
    (0, 4, "tsc"),
    (0, 5, "msr"),
    (0, 6, "pae"),
    (0, 7, "mce"),
    (0, 8, "cx8"),
    (0, 9, "apic"),
    (0, 11, "sep"),
    (0, 12, "mtrr"),
    (0, 13, "pge"),
    (0, 14, "mca"),
    (0, 15, "cmov"),
    (0, 16, "pat"),
    (0, 17, "pse36"),
    (0, 18, "pn"),
    (0, 19, "clflush"),
    (0, 21, "dts"),
    (0, 22, "acpi"),
    (0, 23, "mmx"),
    (0, 24, "fxsr"),
    (0, 25, "sse"),
    (0, 26, "sse2"),
    (0, 27, "ss"),
    (0, 28, "ht"),
    (0, 29, "tm"),
    (0, 30, "ia64"),
    (0, 31, "pbe"),
    (1, 11, "syscall"),
    (1, 19, "mp"),
    (1, 20, "nx"),
    (1, 22, "mmxext"),
    (1, 25, "fxsr_opt"),
    (1, 26, "pdpe1gb"),
    (1, 27, "rdtscp"),
    (1, 29, "lm"),
    (1, 30, "3dnowext"),
    (1, 31, "3dnow"),
    (4, 0, "pni"),
    (4, 1, "pclmulqdq"),
    (4, 2, "dtes64"),
    (4, 3, "monitor"),
    (4, 4, "ds_cpl"),
    (4, 5, "vmx"),
    (4, 6, "smx"),
    (4, 7, "est"),
    (4, 8, "tm2"),
    (4, 9, "ssse3"),
    (4, 10, "cid"),
    (4, 11, "sdbg"),
    (4, 12, "fma"),
    (4, 13, "cx16"),
    (4, 14, "xtpr"),
    (4, 15, "pdcm"),
    (4, 17, "pcid"),
    (4, 18, "dca"),
    (4, 19, "sse4_1"),
    (4, 20, "sse4_2"),
    (4, 21, "x2apic"),
    (4, 22, "movbe"),
    (4, 23, "popcnt"),
    (4, 24, "tsc_deadline_timer"),
    (4, 25, "aes"),
    (4, 26, "xsave"),
    (4, 28, "avx"),
    (4, 29, "f16c"),
    (4, 30, "rdrand"),
    (4, 31, "hypervisor"),
    (6, 0, "lahf_lm"),
    (6, 1, "cmp_legacy"),
    (6, 2, "svm"),
    (6, 3, "extapic"),
    (6, 4, "cr8_legacy"),
    (6, 5, "abm"),
    (6, 6, "sse4a"),
    (6, 7, "misalignsse"),
    (6, 8, "3dnowprefetch"),
    (6, 9, "osvw"),
    (6, 10, "ibs"),
    (6, 11, "xop"),
    (6, 12, "skinit"),
    (6, 13, "wdt"),
    (6, 15, "lwp"),
    (6, 16, "fma4"),
    (6, 17, "tce"),
    (6, 19, "nodeid_msr"),
    (6, 21, "tbm"),
    (6, 22, "topoext"),
    (6, 23, "perfctr_core"),
    (6, 24, "perfctr_nb"),
    (6, 26, "bpext"),
    (6, 27, "ptsc"),
    (6, 28, "perfctr_llc"),
    (6, 29, "mwaitx"),
    (9, 0, "fsgsbase"),
    (9, 1, "tsc_adjust"),
    (9, 2, "sgx"),
    (9, 3, "bmi1"),
    (9, 4, "hle"),
    (9, 5, "avx2"),
    (9, 7, "smep"),
    (9, 8, "bmi2"),
    (9, 9, "erms"),
    (9, 10, "invpcid"),
    (9, 11, "rtm"),
    (9, 12, "cqm"),
    (9, 14, "mpx"),
    (9, 15, "rdt_a"),
    (9, 16, "avx512f"),
    (9, 17, "avx512dq"),
    (9, 18, "rdseed"),
    (9, 19, "adx"),
    (9, 20, "smap"),
    (9, 21, "avx512ifma"),
    (9, 23, "clflushopt"),
    (9, 24, "clwb"),
    (9, 25, "intel_pt"),
    (9, 26, "avx512pf"),
    (9, 27, "avx512er"),
    (9, 28, "avx512cd"),
    (9, 29, "sha_ni"),
    (9, 30, "avx512bw"),
    (9, 31, "avx512vl"),
    (10, 0, "xsaveopt"),
    (10, 1, "xsavec"),
    (10, 2, "xgetbv1"),
    (10, 3, "xsaves"),
    (12, 4, "avx_vnni"),
    (12, 5, "avx512_bf16"),
    (12, 17, "fred"),
    (12, 26, "lam"),
    (13, 0, "clzero"),
    (13, 1, "irperf"),
    (13, 2, "xsaveerptr"),
    (13, 4, "rdpru"),
    (13, 9, "wbnoinvd"),
    (13, 23, "amd_ppin"),
    (13, 25, "virt_ssbd"),
    (13, 27, "cppc"),
    (13, 31, "brs"),
    (14, 0, "dtherm"),
    (14, 1, "ida"),
    (14, 2, "arat"),
    (14, 4, "pln"),
    (14, 6, "pts"),
    (14, 7, "hwp"),
    (14, 8, "hwp_notify"),
    (14, 9, "hwp_act_window"),
    (14, 10, "hwp_epp"),
    (14, 11, "hwp_pkg_req"),
    (14, 19, "hfi"),
    (16, 1, "avx512vbmi"),
    (16, 2, "umip"),
    (16, 3, "pku"),
    (16, 4, "ospke"),
    (16, 5, "waitpkg"),
    (16, 6, "avx512_vbmi2"),
    (16, 8, "gfni"),
    (16, 9, "vaes"),
    (16, 10, "vpclmulqdq"),
    (16, 11, "avx512_vnni"),
    (16, 12, "avx512_bitalg"),
    (16, 13, "tme"),
    (16, 14, "avx512_vpopcntdq"),
    (16, 16, "la57"),
    (16, 22, "rdpid"),
    (16, 24, "bus_lock_detect"),
    (16, 25, "cldemote"),
    (16, 27, "movdiri"),
    (16, 28, "movdir64b"),
    (16, 29, "enqcmd"),
    (16, 30, "sgx_lc"),
    (17, 0, "overflow_recov"),
    (17, 1, "succor"),
    (17, 3, "smca"),
    (18, 2, "avx512_4vnniw"),
    (18, 3, "avx512_4fmaps"),
    (18, 4, "fsrm"),
    (18, 8, "avx512_vp2intersect"),
    (18, 10, "md_clear"),
    (18, 14, "serialize"),
    (18, 16, "tsxldtrk"),
    (18, 18, "pconfig"),
    (18, 19, "arch_lbr"),
    (18, 20, "ibt"),
    (18, 22, "amx_bf16"),
    (18, 23, "avx512_fp16"),
    (18, 24, "amx_tile"),
    (18, 25, "amx_int8"),
    (18, 28, "flush_l1d"),
    (18, 29, "arch_capabilities"),
];
/// The CPUID leaf, subleaf and register (0 EAX, 1 EBX, 2 ECX, 3 EDX) of each word.
pub const CPU_WORDS: &[(u8, u32, u32, u8)] = &[
    (0, 0x1, 0, 3),
    (1, 0x80000001, 0, 3),
    (4, 0x1, 0, 2),
    (6, 0x80000001, 0, 2),
    (9, 0x7, 0, 1),
    (10, 0xd, 1, 0),
    (12, 0x7, 1, 0),
    (13, 0x80000008, 0, 1),
    (14, 0x6, 0, 0),
    (16, 0x7, 0, 2),
    (17, 0x80000007, 0, 1),
    (18, 0x7, 0, 3),
];

/// `/proc/cpuinfo` for `cpus` processors, as `show_cpuinfo`
/// (`arch/x86/kernel/cpu/proc.c`) prints each, from `cpuid(leaf,
/// subleaf)` and the TSC frequency in kHz:
/// - vendor, family, model and stepping from leaves 0 and 1
///   (`x86_family`, `x86_model`, `x86_stepping`, `arch/x86/lib/cpu.c`);
///   the model name from 0x80000002-4 with surrounding spaces trimmed
///   (`get_model_name`);
/// - `cpu MHz` from the TSC; `bogomips` as Linux computes it from a
///   loops-per-jiffy equal to the TSC's cycles per jiffy: twice the MHz;
/// - the core lines for one package of `cpus` cores;
/// - `flags` from the CPUID words of `CPU_FLAGS`, in Linux's order.
///
/// Not shown, where Linux would show them: `microcode` (an MSR),
/// `cache size` (from cache leaves Keel does not decode), the flags Linux
/// synthesizes (constant_tsc, nopl, ...), and the `bugs` list Linux
/// derives from its mitigations. ADR 0024.
pub fn cpuinfo(
    cpuid: &dyn Fn(u32, u32) -> (u32, u32, u32, u32),
    tsc_khz: u64,
    cpus: u32,
) -> String {
    let (max_leaf, b, c, d) = cpuid(0, 0);
    let mut vendor = Vec::new();
    for r in [b, d, c] {
        vendor.extend_from_slice(&r.to_le_bytes());
    }
    let vendor = String::from_utf8_lossy(&vendor).into_owned();
    let (sig, misc, _, edx1) = cpuid(1, 0);
    let mut family = (sig >> 8) & 0xf;
    if family == 0xf {
        family += (sig >> 20) & 0xff;
    }
    let mut model = (sig >> 4) & 0xf;
    if family >= 6 {
        model += ((sig >> 16) & 0xf) << 4;
    }
    let stepping = sig & 0xf;
    let (max_ext, ..) = cpuid(0x8000_0000, 0);
    let name = if max_ext >= 0x8000_0004 {
        let mut raw = Vec::new();
        for leaf in 0x8000_0002..=0x8000_0004 {
            let (a, b, c, d) = cpuid(leaf, 0);
            for r in [a, b, c, d] {
                raw.extend_from_slice(&r.to_le_bytes());
            }
        }
        let end = raw.iter().position(|&x| x == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).trim().into()
    } else {
        String::from("unknown")
    };
    let clflush = ((misc >> 8) & 0xff) * 8;
    let (phys, virt) = if max_ext >= 0x8000_0008 {
        let (a, ..) = cpuid(0x8000_0008, 0);
        (a & 0xff, (a >> 8) & 0xff)
    } else {
        (36, 48)
    };
    let power = if max_ext >= 0x8000_0007 {
        cpuid(0x8000_0007, 0).3
    } else {
        0
    };
    let mut flags = String::new();
    let word = |w: u8| -> u32 {
        CPU_WORDS
            .iter()
            .find(|&&(n, ..)| n == w)
            .map_or(0, |&(_, leaf, sub, reg)| {
                let supported = if leaf >= 0x8000_0000 {
                    max_ext
                } else {
                    max_leaf
                };
                if leaf > supported {
                    return 0;
                }
                let r = cpuid(leaf, sub);
                [r.0, r.1, r.2, r.3][reg as usize]
            })
    };
    for &(w, bit, flag) in CPU_FLAGS {
        if word(w) & (1 << bit) != 0 {
            flags.push(' ');
            flags.push_str(flag);
        }
    }
    let mut pm = String::new();
    for (i, n) in POWER_FLAGS.iter().enumerate() {
        if power & (1 << i) != 0 && !n.is_empty() {
            pm.push(' ');
            pm.push_str(n);
        }
    }
    for i in POWER_FLAGS.len()..32 {
        if power & (1 << i) != 0 {
            pm.push_str(&format!(" [{i}]"));
        }
    }
    let mhz = (tsc_khz / 1000, tsc_khz % 1000);
    // loops_per_jiffy = tsc_khz * 1000 / HZ; bogomips = lpj / (500000 /
    // HZ), with lpj / (5000 / HZ) % 100 as the hundredths: 2 * tsc_khz /
    // 1000, and 2 * tsc_khz / 10 % 100.
    let bogo = (2 * tsc_khz / 1000, (2 * tsc_khz / 10) % 100);
    let mut out = String::new();
    for cpu in 0..cpus {
        out.push_str(&format!(
            "processor\t: {cpu}\nvendor_id\t: {vendor}\ncpu family\t: {family}\nmodel\t\t: {model}\nmodel name\t: {name}\nstepping\t: {stepping}\n"
        ));
        if edx1 & (1 << 4) != 0 {
            out.push_str(&format!("cpu MHz\t\t: {}.{:03}\n", mhz.0, mhz.1));
        }
        out.push_str(&format!(
            "physical id\t: 0\nsiblings\t: {cpus}\ncore id\t\t: {cpu}\ncpu cores\t: {cpus}\napicid\t\t: {cpu}\ninitial apicid\t: {cpu}\n"
        ));
        out.push_str(&format!(
            "fpu\t\t: yes\nfpu_exception\t: yes\ncpuid level\t: {max_leaf}\nwp\t\t: yes\n"
        ));
        out.push_str(&format!(
            "flags\t\t:{flags}\nbugs\t\t:\nbogomips\t: {}.{:02}\n",
            bogo.0, bogo.1
        ));
        out.push_str(&format!(
            "clflush size\t: {clflush}\ncache_alignment\t: {clflush}\naddress sizes\t: {phys} bits physical, {virt} bits virtual\npower management:{pm}\n\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct V;
    impl View for V {
        fn me(&self) -> (u32, u32) {
            (7, 9)
        }
        fn has_pid(&self, pid: u32) -> bool {
            pid == 7 || pid == 3
        }
        fn has_task(&self, pid: u32, tid: u32) -> bool {
            (pid, tid) == (7, 7) || (pid, tid) == (7, 9) || (pid, tid) == (3, 3)
        }
        fn exe(&self, pid: u32) -> Option<Vec<u8>> {
            Some(format!("/bin/p{pid}").into_bytes())
        }
        fn pids(&self) -> Vec<u32> {
            alloc::vec![3, 7]
        }
        fn tasks(&self, pid: u32) -> Vec<u32> {
            if pid == 7 {
                alloc::vec![7, 9]
            } else {
                alloc::vec![3]
            }
        }
    }

    fn r(path: &[&[u8]], follow: bool) -> Resolved {
        resolve(path, follow, &V)
    }

    #[test]
    fn paths_resolve_as_procfs() {
        assert_eq!(r(&[], true), Resolved::Node(Node::Root));
        assert_eq!(r(&[b"self"], false), Resolved::Node(Node::SelfLink));
        assert_eq!(r(&[b"self"], true), Resolved::Node(Node::Pid(7)));
        assert_eq!(r(&[b"self", b"exe"], false), Resolved::Node(Node::Exe(7)));
        assert_eq!(
            r(&[b"self", b"exe"], true),
            Resolved::Elsewhere(b"/bin/p7".to_vec())
        );
        assert_eq!(
            r(&[b"3", b"task", b"3", b"comm"], true),
            Resolved::Node(Node::TaskComm(3, 3))
        );
        assert_eq!(
            r(&[b"thread-self", b"comm"], true),
            Resolved::Node(Node::TaskComm(7, 9))
        );
        assert_eq!(r(&[b"net", b"dev"], true), Resolved::Node(Node::NetDev));
        // Another compartment's PIDs, a thread of another process, and
        // non-numbers do not exist.
        assert_eq!(r(&[b"8"], true), Resolved::Missing);
        assert_eq!(r(&[b"3", b"task", b"9"], true), Resolved::Missing);
        assert_eq!(r(&[b"07"], true), Resolved::Missing);
        assert_eq!(r(&[b"+7"], true), Resolved::Missing);
        assert_eq!(r(&[b"self", b"exe", b"x"], true), Resolved::Missing);
        assert_eq!(r(&[b"cpuinfo", b"x"], true), Resolved::Missing);
        assert_eq!(link_target(Node::SelfLink, &V), Some(b"7".to_vec()));
        assert_eq!(
            link_target(Node::ThreadSelf, &V),
            Some(b"7/task/9".to_vec())
        );
        assert_eq!(
            (Node::Root.permissions(), Node::TaskComm(1, 1).permissions()),
            (0o555, 0o644)
        );
        assert_eq!(
            (Node::Exe(1).permissions(), Node::CpuInfo.permissions()),
            (0o777, 0o444)
        );
    }

    fn names(dir: Node) -> Vec<(u64, String, Option<Node>)> {
        let (entries, _) = list(dir, &V);
        entries
            .into_iter()
            .map(|e| (e.pos, String::from_utf8(e.name).unwrap(), e.node))
            .collect()
    }

    #[test]
    fn directories_list_as_procfs() {
        let s = |n: &str| String::from(n);
        assert_eq!(
            names(Node::Root),
            alloc::vec![
                (0, s("."), Some(Node::Root)),
                (1, s(".."), None),
                (2, s("net"), Some(Node::Net)),
                (3, s("cpuinfo"), Some(Node::CpuInfo)),
                (256, s("self"), Some(Node::SelfLink)),
                (257, s("thread-self"), Some(Node::ThreadSelf)),
                (261, s("3"), Some(Node::Pid(3))),
                (265, s("7"), Some(Node::Pid(7))),
            ]
        );
        assert_eq!(list(Node::Root, &V).1, 4 * 1024 * 1024 + 258);
        let pid: Vec<String> = names(Node::Pid(7)).into_iter().map(|e| e.1).collect();
        assert_eq!(pid, [".", "..", "task", "comm", "cmdline", "stat", "exe"]);
        assert_eq!(
            names(Node::Tasks(7)),
            alloc::vec![
                (0, s("."), Some(Node::Tasks(7))),
                (1, s(".."), Some(Node::Pid(7))),
                (2, s("7"), Some(Node::Task(7, 7))),
                (3, s("9"), Some(Node::Task(7, 9))),
            ]
        );
        assert_eq!(list(Node::Tasks(7), &V).1, 4);
        let task: Vec<String> = names(Node::Task(7, 9)).into_iter().map(|e| e.1).collect();
        assert_eq!(task, [".", "..", "comm", "exe"]);
        assert_eq!(names(Node::Net)[2], (2, s("dev"), Some(Node::NetDev)));
        assert!(list(Node::Stat(7), &V).0.is_empty());
        assert_eq!(r(&[b"7", b"stat"], true), Resolved::Node(Node::Stat(7)));
        assert_eq!(
            r(&[b"7", b"cmdline"], true),
            Resolved::Node(Node::Cmdline(7))
        );
        assert_eq!(path_of(Node::Task(7, 9)).as_deref(), Some("/proc/7/task/9"));
        assert_eq!(path_of(Node::Stat(7)), None);
    }

    #[test]
    fn stat_line_is_do_task_stats() {
        let info = StatInfo {
            pid: 12,
            comm: b"a) (b".to_vec(),
            state: b'S',
            ppid: 1,
            pgid: 12,
            sid: 5,
            tty_nr: 34816,
            tpgid: 12,
            num_threads: 2,
            start_time: 345,
            vsize: 8192,
            rss: 2,
            start_stack: 0x7ff0,
            start_brk: 0x5000,
            pending: 1 << 31 | 1 << 9,
            blocked: 2,
            ignored: 4,
            caught: 8,
            wchan: 0,
            exit_signal: 17,
            exit_code: 0,
        };
        let line = String::from_utf8(stat_line(&info)).unwrap();
        assert_eq!(
            line,
            "12 (a) (b) S 1 12 5 34816 12 0 0 0 0 0 0 0 0 0 20 0 2 0 345 8192 2 18446744073709551615 0 0 32752 0 0 512 2 4 8 0 0 0 17 0 0 0 0 0 0 0 0 20480 0 0 0 0 0\n"
        );
        assert_eq!(line.split(' ').count(), 53); // 52 fields, the name in two
    }

    #[test]
    fn cpuinfo_reads_cpuid_as_linux() {
        // A family 6 model 0x9e CPU (extended model 9), stepping 10.
        let cpuid = |leaf: u32, _sub: u32| -> (u32, u32, u32, u32) {
            let s = |t: &[u8; 16]| {
                let w = |i: usize| u32::from_le_bytes(t[i * 4..i * 4 + 4].try_into().unwrap());
                (w(0), w(1), w(2), w(3))
            };
            match leaf {
                0 => (
                    0x16,
                    u32::from_le_bytes(*b"Genu"),
                    u32::from_le_bytes(*b"ntel"),
                    u32::from_le_bytes(*b"ineI"),
                ),
                1 => (0x0009_06ea, 8 << 8, 1 | (1 << 31), 1 | (1 << 4) | (1 << 26)),
                0x8000_0000 => (0x8000_0008, 0, 0, 0),
                0x8000_0001 => (0, 0, 0, 1 << 29),
                0x8000_0002 => s(b"  Test CPU Model"),
                0x8000_0003 => s(b" 9000  \0\0\0\0\0\0\0\0\0"),
                0x8000_0004 => s(&[0; 16]),
                0x8000_0007 => (0, 0, 0, 1 | (1 << 8)),
                0x8000_0008 => (0x3027, 0, 0, 0),
                _ => (0, 0, 0, 0),
            }
        };
        let text = cpuinfo(&cpuid, 2_904_000, 1);
        assert!(text.starts_with("processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 158\nmodel name\t: Test CPU Model 9000\nstepping\t: 10\ncpu MHz\t\t: 2904.000\n"));
        assert!(
            text.contains("\nflags\t\t: fpu tsc sse2 lm pni hypervisor\n"),
            "{text}"
        );
        assert!(text.contains("\nbogomips\t: 5808.00\n"));
        assert!(text.contains("\nclflush size\t: 64\ncache_alignment\t: 64\naddress sizes\t: 39 bits physical, 48 bits virtual\npower management: ts\n\n"));
        assert_eq!(text.matches("processor\t:").count(), 1);
    }
}
