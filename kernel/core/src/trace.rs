//! The debug-tracing options of the kernel command line (spec section
//! 15, "Debugging toolkit"; ADR 0043). Only a kernel built with the
//! `debug-tracing` feature reads them (SR-21); this is the parser, kept
//! here so it is tested on the host.

pub const SYSCALLS: u8 = 1;
pub const FAULTS: u8 = 2;
pub const SIGNALS: u8 = 4;
pub const SCHED: u8 = 8;

/// The trace flags and PID filter `cmdline` asks for, and the words it
/// did not understand.
pub fn parse(cmdline: &str) -> (u8, u32, alloc::vec::Vec<&str>) {
    let (mut flags, mut pid, mut unknown) = (0, 0, alloc::vec::Vec::new());
    for word in cmdline.split_ascii_whitespace() {
        if let Some(list) = word.strip_prefix("trace=") {
            for what in list.split(',') {
                match what {
                    "syscalls" => flags |= SYSCALLS,
                    "faults" => flags |= FAULTS,
                    "signals" => flags |= SIGNALS,
                    "sched" => flags |= SCHED,
                    _ => unknown.push(what),
                }
            }
        } else if let Some(n) = word.strip_prefix("trace.pid=") {
            match n.parse::<u32>() {
                Ok(n) if n > 0 => pid = n,
                _ => unknown.push(word),
            }
        }
    }
    (flags, pid, unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_parsed_and_unknown_ones_reported() {
        assert_eq!(parse(""), (0, 0, alloc::vec![]));
        assert_eq!(parse("test=3 trace=syscalls"), (SYSCALLS, 0, alloc::vec![]));
        assert_eq!(
            parse("trace=faults,signals,sched trace.pid=7"),
            (FAULTS | SIGNALS | SCHED, 7, alloc::vec![])
        );
        assert_eq!(
            parse("trace=syscalls,everything trace.pid=0"),
            (SYSCALLS, 0, alloc::vec!["everything", "trace.pid=0"])
        );
    }
}
