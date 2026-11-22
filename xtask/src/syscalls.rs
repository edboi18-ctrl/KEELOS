//! `cargo xtask syscalls`: turn an `strace -f` trace of Wine into
//! `docs/syscalls.md`, the system-call inventory Phase 3 is planned from
//! (spec section 10, "Method: trace first, then implement", step 3).
//!
//! The inventory lists every system call the trace shows, in order of
//! first appearance (the order Phase 3 implements them in), with its call
//! and error counts, the distinct flag combinations seen for `mmap`,
//! `clone`, `clone3`, `futex`, `fcntl`, `ioctl`, `socket` and `prctl`,
//! every path opened, every program executed and every signal delivered.
//!
//! The "Keel status" and "Test" columns are kept by hand. Regenerating
//! keeps what the existing file says for each call.
//!
//! The parser follows strace's output format, strace(1) "DESCRIPTION": one
//! line per call, `name(args) = result`, prefixed with the thread ID under
//! `-f`; a call another thread interrupts is split into
//! `name(args <unfinished ...>` and `<... name resumed>args) = result`;
//! signals are `--- SIGNAME {...} ---` and exits `+++ exited with N +++`.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::Path;

use crate::util::{self, Result};

/// One completed call, with its unfinished and resumed halves joined.
#[derive(Debug, PartialEq)]
struct Call {
    name: String,
    args: Vec<String>,
    /// The text after ` = `: `0`, `-1 ENOENT (No such file or directory)`,
    /// `0x7f0000000000`, or `?` for a call that never returned.
    result: String,
}

impl Call {
    /// The error name when the call failed, for example `ENOENT`.
    fn error(&self) -> Option<&str> {
        let rest = self.result.strip_prefix("-1 ")?;
        rest.split_whitespace().next()
    }
}

/// What one line of the trace is.
#[derive(Debug, PartialEq)]
enum Line {
    Call(Call),
    Signal(String),
    Other,
}

/// Splits off strace's `-f` thread-ID prefix, if there is one.
fn split_pid(line: &str) -> (Option<&str>, &str) {
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0 && line[digits..].starts_with([' ', '\t']) {
        (Some(&line[..digits]), line[digits..].trim_start())
    } else {
        (None, line)
    }
}

/// Splits an argument list at top-level commas: not inside a string,
/// brackets, braces or parentheses.
fn split_args(text: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut start = 0;
    for (i, c) in text.char_indices() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                args.push(text[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = text[start..].trim();
    if !last.is_empty() {
        args.push(last.to_string());
    }
    args
}

/// Parses `name(args) = result` (both halves of a split call already
/// joined).
fn parse_call(text: &str) -> Option<Call> {
    let open = text.find('(')?;
    let name = &text[..open];
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    // The result follows the last ") = ". Arguments can contain " = "
    // inside strings, but strace prints the result last.
    let close = text.rfind(") = ")?;
    if close < open {
        return None;
    }
    Some(Call {
        name: name.to_string(),
        args: split_args(&text[open + 1..close]),
        result: text[close + 4..].trim().to_string(),
    })
}

/// Reads the trace line by line, joining split calls per thread.
struct Parser {
    pending: HashMap<String, String>,
}

impl Parser {
    fn new() -> Self {
        Parser {
            pending: HashMap::new(),
        }
    }

    fn line(&mut self, raw: &str) -> Line {
        let (pid, text) = split_pid(raw.trim_end());
        let pid = pid.unwrap_or("").to_string();
        if let Some(signal) = text.strip_prefix("--- ") {
            let name = signal.split_whitespace().next().unwrap_or("");
            return Line::Signal(name.to_string());
        }
        if text.starts_with("+++") {
            return Line::Other;
        }
        if let Some(head) = text.strip_suffix(" <unfinished ...>") {
            self.pending.insert(pid, head.to_string());
            return Line::Other;
        }
        if let Some(rest) = text.strip_prefix("<... ") {
            let Some(at) = rest.find(" resumed>") else {
                return Line::Other;
            };
            let tail = &rest[at + " resumed>".len()..];
            let Some(head) = self.pending.remove(&pid) else {
                return Line::Other;
            };
            return parse_call(&format!("{head}{tail}")).map_or(Line::Other, Line::Call);
        }
        parse_call(text).map_or(Line::Other, Line::Call)
    }
}

/// Everything the inventory reports.
#[derive(Default)]
struct Inventory {
    /// Call name to (first appearance, calls, errors), in first-appearance
    /// order by the first field.
    calls: HashMap<String, (usize, u64, u64)>,
    /// Call name to flag combination to count.
    flags: BTreeMap<&'static str, BTreeMap<String, u64>>,
    /// Path opened to (opens, failures, an error seen).
    opened: BTreeMap<String, (u64, u64, String)>,
    executed: BTreeMap<String, String>,
    signals: BTreeMap<String, u64>,
}

/// The calls whose flag combinations the spec asks for, and which
/// argument holds them.
fn flag_key(call: &Call) -> Option<(&'static str, String)> {
    let arg = |i: usize| call.args.get(i).cloned().unwrap_or_default();
    let named = |prefix: &str| {
        call.args
            .iter()
            .find_map(|a| a.strip_prefix(prefix).map(str::to_string))
            .unwrap_or_default()
    };
    Some(match call.name.as_str() {
        // mmap(addr, length, prot, flags, fd, offset)
        "mmap" => {
            let backing = if arg(4) == "-1" { "anonymous" } else { "file" };
            ("mmap", format!("{}, {}, {backing}", arg(2), arg(3)))
        }
        // clone(child_stack=..., flags=..., ...): strace names the arguments.
        "clone" => ("clone", named("flags=")),
        // clone3({flags=..., ...}, size)
        "clone3" => {
            let inner = arg(0);
            let inner = inner.trim_start_matches('{').trim_end_matches('}');
            let flags = split_args(inner)
                .into_iter()
                .find_map(|a| a.strip_prefix("flags=").map(str::to_string))
                .unwrap_or_default();
            ("clone3", flags)
        }
        // futex(uaddr, op, ...)
        "futex" => ("futex", arg(1)),
        // fcntl(fd, cmd, arg): the argument matters for the set commands.
        "fcntl" => {
            let cmd = arg(1);
            if cmd.starts_with("F_SET") && !cmd.starts_with("F_SETLK") {
                ("fcntl", format!("{cmd}, {}", arg(2)))
            } else {
                ("fcntl", cmd)
            }
        }
        // ioctl(fd, request, ...)
        "ioctl" => ("ioctl", arg(1)),
        // socket(domain, type, protocol)
        "socket" => ("socket", call.args.join(", ")),
        // prctl(option, ...)
        "prctl" => ("prctl", arg(0)),
        _ => return None,
    })
}

/// The path argument of an open, if this is one: open(path, ...),
/// openat(dirfd, path, ...), openat2(dirfd, path, ...).
fn opened_path(call: &Call) -> Option<&str> {
    let index = match call.name.as_str() {
        "open" | "creat" => 0,
        "openat" | "openat2" => 1,
        _ => return None,
    };
    let path = call.args.get(index)?;
    // strace quotes paths, printed in full whatever `-s` says.
    Some(path.strip_prefix('"')?.strip_suffix('"').unwrap_or(path))
}

impl Inventory {
    fn add(&mut self, call: &Call) {
        let order = self.calls.len();
        let entry = self.calls.entry(call.name.clone()).or_insert((order, 0, 0));
        entry.1 += 1;
        if call.error().is_some() {
            entry.2 += 1;
        }
        if let Some((name, key)) = flag_key(call) {
            *self.flags.entry(name).or_default().entry(key).or_default() += 1;
        }
        if let Some(path) = opened_path(call) {
            let entry = self.opened.entry(path.to_string()).or_default();
            entry.0 += 1;
            if let Some(error) = call.error() {
                entry.1 += 1;
                entry.2 = error.to_string();
            }
        }
        if call.name == "execve" || call.name == "execveat" {
            let index = usize::from(call.name == "execveat");
            if let Some(path) = call.args.get(index) {
                let outcome = call.error().unwrap_or("ok").to_string();
                self.executed.insert(path.clone(), outcome);
            }
        }
    }

    fn in_order(&self) -> Vec<(&str, u64, u64)> {
        let mut rows: Vec<_> = self
            .calls
            .iter()
            .map(|(name, &(order, calls, errors))| (order, name.as_str(), calls, errors))
            .collect();
        rows.sort();
        rows.into_iter().map(|(_, n, c, e)| (n, c, e)).collect()
    }
}

/// Reads `strace -c` output: `% time  seconds  usecs/call  calls  errors
/// syscall`, where the errors column is empty for calls that never
/// failed. Returns name to (calls, errors).
fn parse_counts(text: &str) -> BTreeMap<String, (u64, u64)> {
    let mut counts = BTreeMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (calls, errors) = match fields.len() {
            5 => (fields[3], "0"),
            6 => (fields[3], fields[4]),
            _ => continue,
        };
        let name = fields[fields.len() - 1];
        if name == "total" || name == "syscall" {
            continue;
        }
        if let (Ok(calls), Ok(errors)) = (calls.parse(), errors.parse()) {
            counts.insert(name.to_string(), (calls, errors));
        }
    }
    counts
}

/// The hand-kept status and test columns of an existing inventory, by
/// call name.
fn kept_columns(existing: &str) -> HashMap<String, (String, String)> {
    let mut kept = HashMap::new();
    for line in existing.lines() {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        // | # | `name` | calls | errors | -c calls | status | test |
        if cells.len() == 9 && cells[1].parse::<usize>().is_ok() {
            let name = cells[2].trim_matches('`').to_string();
            kept.insert(name, (cells[6].to_string(), cells[7].to_string()));
        }
    }
    kept
}

fn escape(cell: &str) -> String {
    cell.replace('|', "\\|")
}

fn render(
    inventory: &Inventory,
    counts: &BTreeMap<String, (u64, u64)>,
    kept: &HashMap<String, (String, String)>,
    source: &str,
) -> String {
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(w, "# System-call inventory");
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "Generated by `cargo xtask syscalls` from {source} (spec section 10, \
         \"trace first\"). Regenerating keeps the Keel status and Test \
         columns; edit those by hand. Status is missing, partial or complete."
    );
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "Calls and Errors are from the `strace -f` trace; `-c` calls is the \
         separate `strace -f -c` run (blank when that run did not see the call)."
    );
    let _ = writeln!(w);
    let _ = writeln!(w, "## System calls, in order of first appearance");
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "| # | System call | Calls | Errors | `-c` calls | Keel status | Test |"
    );
    let _ = writeln!(w, "| --- | --- | --- | --- | --- | --- | --- |");
    for (i, (name, calls, errors)) in inventory.in_order().into_iter().enumerate() {
        let c_calls = counts.get(name).map_or(String::new(), |c| c.0.to_string());
        let (status, test) = kept
            .get(name)
            .cloned()
            .unwrap_or_else(|| ("missing".to_string(), String::new()));
        let _ = writeln!(
            w,
            "| {} | `{name}` | {calls} | {errors} | {c_calls} | {status} | {test} |",
            i + 1
        );
    }
    let missed: Vec<_> = counts
        .keys()
        .filter(|name| !inventory.calls.contains_key(*name))
        .collect();
    if !missed.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(
            w,
            "Seen only in the `-c` run: {}.",
            missed
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for (name, combos) in &inventory.flags {
        let _ = writeln!(w);
        let _ = writeln!(w, "## `{name}` flag combinations");
        let _ = writeln!(w);
        let _ = writeln!(w, "| Arguments | Calls |");
        let _ = writeln!(w, "| --- | --- |");
        for (combo, n) in combos {
            let _ = writeln!(w, "| `{}` | {n} |", escape(combo));
        }
    }
    let _ = writeln!(w);
    let _ = writeln!(w, "## Paths opened");
    let _ = writeln!(w);
    let _ = writeln!(w, "| Path | Opens | Failed | Error |");
    let _ = writeln!(w, "| --- | --- | --- | --- |");
    for (path, (opens, failed, error)) in &inventory.opened {
        let _ = writeln!(w, "| `{}` | {opens} | {failed} | {error} |", escape(path));
    }
    let _ = writeln!(w);
    let _ = writeln!(w, "## Programs executed");
    let _ = writeln!(w);
    let _ = writeln!(w, "| Path | Outcome |");
    let _ = writeln!(w, "| --- | --- |");
    for (path, outcome) in &inventory.executed {
        let _ = writeln!(w, "| `{}` | {outcome} |", escape(path));
    }
    let _ = writeln!(w);
    let _ = writeln!(w, "## Signals delivered");
    let _ = writeln!(w);
    let _ = writeln!(w, "| Signal | Times |");
    let _ = writeln!(w, "| --- | --- |");
    for (signal, n) in &inventory.signals {
        let _ = writeln!(w, "| `{signal}` | {n} |");
    }
    out
}

fn inventory_of(trace: &str) -> Inventory {
    let mut parser = Parser::new();
    let mut inventory = Inventory::default();
    for raw in trace.lines() {
        match parser.line(raw) {
            Line::Call(call) => inventory.add(&call),
            Line::Signal(name) => *inventory.signals.entry(name).or_default() += 1,
            Line::Other => {}
        }
    }
    inventory
}

/// Writes `out` from the trace (and the `-c` counts, if given).
pub fn syscalls(trace: &Path, counts: Option<&Path>, out: &Path, source: &str) -> Result<()> {
    let text = String::from_utf8_lossy(&util::read(trace)?).into_owned();
    let inventory = inventory_of(&text);
    if inventory.calls.is_empty() {
        return Err(format!("{} holds no system calls", trace.display()).into());
    }
    let counts = match counts {
        Some(path) => parse_counts(&String::from_utf8_lossy(&util::read(path)?)),
        None => BTreeMap::new(),
    };
    let kept = match std::fs::read_to_string(out) {
        Ok(existing) => kept_columns(&existing),
        Err(_) => HashMap::new(),
    };
    util::write(out, render(&inventory, &counts, &kept, source).as_bytes())?;
    println!(
        "xtask: syscalls: {} distinct calls, {} paths opened -> {}",
        inventory.calls.len(),
        inventory.opened.len(),
        out.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_unfinished_and_resumed_calls_per_thread() {
        let trace = "\
100   read(3,  <unfinished ...>
101   openat(AT_FDCWD, \"/a, b\", O_RDONLY) = -1 ENOENT (No such file or directory)
100   <... read resumed>\"x\", 1) = 1
100   --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_TKILL} ---
100   +++ exited with 0 +++
";
        let inventory = inventory_of(trace);
        assert_eq!(inventory.in_order(), vec![("openat", 1, 1), ("read", 1, 0)]);
        assert_eq!(inventory.opened["/a, b"], (1, 1, "ENOENT".to_string()));
        assert_eq!(inventory.signals["SIGUSR1"], 1);
    }

    #[test]
    fn reads_trace_without_thread_ids() {
        let call = Parser::new().line("brk(NULL) = 0x5555");
        assert!(matches!(call, Line::Call(Call { ref name, .. }) if name == "brk"));
    }

    #[test]
    fn records_the_flags_the_spec_asks_for() {
        let trace = "\
1 mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f00
1 mmap(NULL, 8192, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f10
1 clone(child_stack=0x7f, flags=CLONE_VM|CLONE_FS|CLONE_THREAD, parent_tid=[2]) = 2
1 clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD, stack=0x1}, 88) = 3
1 fcntl(3, F_SETFD, FD_CLOEXEC) = 0
1 fcntl(3, F_SETLK, {l_type=F_WRLCK, l_whence=SEEK_SET, l_start=0, l_len=0}) = 0
";
        let flags = inventory_of(trace).flags;
        assert_eq!(
            flags["mmap"].keys().collect::<Vec<_>>(),
            vec![
                "PROT_READ, MAP_PRIVATE, file",
                "PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, anonymous"
            ]
        );
        assert!(flags["clone"].contains_key("CLONE_VM|CLONE_FS|CLONE_THREAD"));
        assert!(flags["clone3"].contains_key("CLONE_VM|CLONE_VFORK"));
        assert!(flags["fcntl"].contains_key("F_SETFD, FD_CLOEXEC"));
        assert!(flags["fcntl"].contains_key("F_SETLK"));
    }

    #[test]
    fn reads_strace_c_tables() {
        let text = "\
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 40.00    0.000400          10        40        12 openat
 10.00    0.000100           5        20           mmap
------ ----------- ----------- --------- --------- ----------------
100.00    0.001000          16        60        12 total
";
        let counts = parse_counts(text);
        assert_eq!(counts["openat"], (40, 12));
        assert_eq!(counts["mmap"], (20, 0));
        assert!(!counts.contains_key("total"));
    }

    #[test]
    fn regenerating_keeps_the_hand_kept_columns() {
        let inventory = inventory_of("1 read(0, \"\", 1) = 0\n1 getpid() = 1\n");
        let mut kept = HashMap::new();
        kept.insert(
            "read".to_string(),
            ("complete".to_string(), "`fs.read`".to_string()),
        );
        let first = render(&inventory, &BTreeMap::new(), &kept, "a test");
        let again = render(
            &inventory,
            &BTreeMap::new(),
            &kept_columns(&first),
            "a test",
        );
        assert_eq!(first, again);
        assert!(first.contains("| 1 | `read` | 1 | 0 |  | complete | `fs.read` |"));
        assert!(first.contains("| 2 | `getpid` | 1 | 0 |  | missing |  |"));
    }
}
