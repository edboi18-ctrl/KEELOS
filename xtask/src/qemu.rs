//! Running the boot tree in QEMU: `cargo xtask run` and `cargo xtask test`
//! (P0-T6).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::build::{self, BootMode};
use crate::util::{self, Result};

/// QEMU exit status for a passing run: the kernel writes 0x10 to the
/// isa-debug-exit port and QEMU exits with `(0x10 << 1) | 1`
/// (QEMU `hw/misc/debugexit.c`).
const EXIT_SUCCESS: i32 = 33;

/// A phase with in-guest tests.
pub struct Phase {
    pub number: u32,
    /// Whether the phase's acceptance tests are all implemented. Only then
    /// must the run print the `KEEL P<n> OK` marker.
    pub complete: bool,
    /// Extra boots, each testing one behaviour that ends the kernel.
    pub scenarios: &'static [&'static str],
}

/// Every phase with tests. `cargo xtask test` runs them all, so work on an
/// unfinished phase is regression-tested in CI as it lands.
pub const PHASES: &[Phase] = &[
    Phase {
        number: 0,
        complete: true,
        scenarios: &[],
    },
    Phase {
        number: 1,
        complete: false,
        scenarios: &["double_fault"],
    },
];

/// First line of the kernel's panic output (`keel-kernel/src/main.rs`).
const PANIC_BANNER: &str = "*** KEEL KERNEL PANIC ***";

/// Serial lines printed when a test run fails (spec section 15).
const TAIL_LINES: usize = 200;

fn find_in_path(names: &[&str]) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
        .find(|candidate| candidate.is_file())
}

/// Locates `qemu-system-x86_64`: `KEEL_QEMU`, then PATH, then the default
/// install directory of the Windows installer.
fn find_qemu() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("KEEL_QEMU") {
        return Ok(path.into());
    }
    if let Some(path) = find_in_path(&["qemu-system-x86_64", "qemu-system-x86_64.exe"]) {
        return Ok(path);
    }
    let windows_default = Path::new(r"C:\Program Files\qemu\qemu-system-x86_64.exe");
    if windows_default.is_file() {
        return Ok(windows_default.to_path_buf());
    }
    Err(
        "qemu-system-x86_64 not found. Install QEMU and put it on PATH, \
         or set KEEL_QEMU to the full path of the executable."
            .into(),
    )
}

/// Locates the UEFI firmware code image: `KEEL_OVMF_CODE`, then the places
/// QEMU and common Linux distributions install it.
fn find_ovmf(qemu: &Path) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("KEEL_OVMF_CODE") {
        return Ok(path.into());
    }
    let mut candidates = Vec::new();
    if let Some(dir) = qemu.parent() {
        // The Windows installer puts firmware in `share\` next to the
        // executable; Unix installs use `<prefix>/share/qemu/`.
        candidates.push(dir.join("share").join("edk2-x86_64-code.fd"));
        candidates.push(dir.join("../share/qemu/edk2-x86_64-code.fd"));
    }
    for path in [
        "/usr/share/OVMF/OVMF_CODE_4M.fd",     // Debian, Ubuntu
        "/usr/share/OVMF/OVMF_CODE.fd",        // older Debian, Ubuntu
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",   // Fedora
        "/usr/share/edk2/x64/OVMF_CODE.4m.fd", // Arch
        "/usr/share/qemu/edk2-x86_64-code.fd",
    ] {
        candidates.push(PathBuf::from(path));
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            "UEFI firmware (OVMF/edk2 code image) not found. \
             Set KEEL_OVMF_CODE to the path of edk2-x86_64-code.fd or OVMF_CODE.fd."
                .into()
        })
}

/// Options that differ between interactive and test runs.
pub struct RunOptions {
    /// Hardware accelerator for `-accel` (for example `kvm` or `whpx`).
    pub accel: Option<String>,
    /// Start paused with a GDB stub on TCP port 1234.
    pub gdb: bool,
}

/// The disk QEMU boots from.
enum BootDisk<'a> {
    /// A directory exposed as a virtual FAT drive (the `target/esp` tree).
    Directory(&'a Path),
    /// A raw disk image file. Opened with `snapshot=on`, so it is never
    /// modified.
    Image(&'a Path),
}

/// The QEMU command line from spec section 4, "QEMU baseline invocation".
fn base_command(disk: BootDisk, options: &RunOptions) -> Result<Command> {
    let qemu = find_qemu()?;
    let ovmf = find_ovmf(&qemu)?;
    let root = util::workspace_root();
    let drive = match disk {
        BootDisk::Directory(esp) => {
            // A relative path keeps drive-letter colons out of the `fat:` spec.
            let esp = esp.strip_prefix(&root).unwrap_or(esp);
            // Read-only, so neither the firmware (which saves NvVars to
            // the ESP) nor a QEMU killed mid-write can change the build
            // output. QEMU's emulated SATA disk refuses read-only media,
            // so the tree is attached as a virtio disk, which OVMF boots.
            format!(
                "if=virtio,format=raw,readonly=on,file=fat:{}",
                esp.display()
            )
        }
        BootDisk::Image(image) => format!("format=raw,snapshot=on,file={}", image.display()),
    };

    let mut command = Command::new(qemu);
    command.current_dir(&root);
    command.args(["-machine", "q35", "-m", "4G", "-smp", "1"]);
    match &options.accel {
        // `-cpu host` needs an accelerator; `max` is the TCG equivalent.
        Some(accel) => command.args(["-accel", accel, "-cpu", "host"]),
        None => command.args(["-cpu", "max"]),
    };
    command.arg("-drive").arg(format!(
        "if=pflash,format=raw,readonly=on,file={}",
        ovmf.display()
    ));
    command.arg("-drive").arg(drive);
    command.args(["-serial", "stdio", "-no-reboot"]);
    command.args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
    if options.gdb {
        command.args(["-s", "-S"]);
    }
    Ok(command)
}

/// `cargo xtask run`: build, then boot interactively with serial on stdio.
pub fn run(options: &RunOptions) -> Result<()> {
    let esp = build::build(BootMode::Normal)?;
    let mut command = base_command(BootDisk::Directory(&esp), options)?;
    command.arg("-no-shutdown");
    if options.gdb {
        println!("xtask: QEMU is paused. Attach with:");
        println!(
            "  gdb target/x86_64-unknown-none/release/keel-kernel -ex \"target remote :1234\""
        );
    }
    let status = command.status()?;
    println!("xtask: QEMU exited with {status}");
    Ok(())
}

/// What a test run's serial log says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TestReport {
    pub passed: Vec<String>,
    pub failed: Vec<String>,
    /// `(passed, failed)` from the `TEST SUMMARY` line.
    pub summary: Option<(u32, u32)>,
    pub panicked: bool,
}

/// Parses the in-guest runner's fixed-format lines (spec section 15):
/// `TEST <name> PASS|FAIL <detail>` and
/// `TEST SUMMARY passed=<n> failed=<m>`. Everything else is ignored.
pub fn parse_report<'a>(lines: impl IntoIterator<Item = &'a str>) -> TestReport {
    let mut report = TestReport::default();
    for line in lines {
        let line = line.trim_end();
        if line.contains(PANIC_BANNER) {
            report.panicked = true;
        }
        let Some(rest) = line.strip_prefix("TEST ") else {
            continue;
        };
        let mut words = rest.split(' ');
        match (words.next(), words.next()) {
            (Some("SUMMARY"), Some(passed)) => {
                let failed = words.next();
                let number =
                    |field: Option<&str>, key: &str| field?.strip_prefix(key)?.parse::<u32>().ok();
                if let (Some(p), Some(f)) =
                    (number(Some(passed), "passed="), number(failed, "failed="))
                {
                    report.summary = Some((p, f));
                }
            }
            (Some(name), Some("PASS")) => report.passed.push(name.to_string()),
            (Some(name), Some("FAIL")) => {
                report
                    .failed
                    .push(line["TEST ".len()..].replacen(&format!("{name} FAIL"), name, 1))
            }
            _ => {}
        }
    }
    report
}

/// Decides whether a phase passed, given everything the run produced.
pub fn verdict(
    marker: Option<&str>,
    lines: &[String],
    exit_code: Option<i32>,
) -> std::result::Result<(), String> {
    let report = parse_report(lines.iter().map(String::as_str));
    if report.panicked {
        return Err("the kernel panicked".into());
    }
    if !report.failed.is_empty() {
        return Err(format!("failed tests: {}", report.failed.join("; ")));
    }
    let Some((passed, failed)) = report.summary else {
        return Err("no TEST SUMMARY line: the in-guest runner did not finish".into());
    };
    if failed != 0 || passed as usize != report.passed.len() || passed == 0 {
        return Err(format!(
            "summary (passed={passed} failed={failed}) does not match the {} PASS lines seen",
            report.passed.len()
        ));
    }
    if let Some(marker) = marker
        && !lines.iter().any(|line| line.trim_end() == marker)
    {
        return Err(format!(
            "acceptance marker \"{marker}\" not found on serial"
        ));
    }
    if exit_code != Some(EXIT_SUCCESS) {
        return Err(format!(
            "QEMU exit status {exit_code:?}, expected {EXIT_SUCCESS}"
        ));
    }
    Ok(())
}

/// Removes ANSI CSI escape sequences (`ESC [ parameters final-byte`,
/// ECMA-48 section 5.4) from a serial line. Firmware and Limine position
/// every character with them, which would otherwise hide their messages
/// from substring checks.
pub fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            // Parameter and intermediate bytes are 0x20..=0x3F; the
            // sequence ends at the first final byte, 0x40..=0x7E.
            for c in chars.by_ref() {
                if ('\u{40}'..='\u{7e}').contains(&c) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Serial output as the reader thread reports it.
enum SerialEvent {
    /// A complete line (or the last, unterminated one at end of output).
    Line(String),
    /// The current line so far; more may follow.
    Partial(String),
}

/// What a headless boot produced.
struct Capture {
    lines: Vec<String>,
    exit_code: Option<i32>,
    timed_out: bool,
}

/// Boots `esp` headless and collects serial lines until QEMU exits, the
/// timeout expires, or `stop` returns true for a line. QEMU is always
/// killed before this returns, so nothing is left running.
fn boot_headless(
    disk: BootDisk,
    options: &RunOptions,
    timeout: Duration,
    stop: impl Fn(&str) -> bool,
) -> Result<Capture> {
    let mut command = base_command(disk, options)?;
    command.args(["-display", "none", "-monitor", "none"]);
    command.stdin(Stdio::null()).stdout(Stdio::piped());

    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("stdout was piped");
    // The reader sends each finished line, and also a snapshot of the
    // unfinished line after every read. Firmware and Limine can print a
    // message and then wait for a key without ever ending the line, and
    // the stop predicate must still see it.
    let (sender, receiver) = mpsc::channel::<SerialEvent>();
    let reader = std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut pending = Vec::new();
        let mut chunk = [0u8; 4096];
        let clean = |bytes: &[u8]| {
            strip_ansi(&String::from_utf8_lossy(bytes))
                .trim_end()
                .to_string()
        };
        loop {
            let read = match stdout.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            pending.extend_from_slice(&chunk[..read]);
            while let Some(end) = pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = pending.drain(..=end).collect();
                if sender.send(SerialEvent::Line(clean(&line))).is_err() {
                    return;
                }
            }
            if !pending.is_empty() && sender.send(SerialEvent::Partial(clean(&pending))).is_err() {
                return;
            }
        }
        if !pending.is_empty() {
            let _ = sender.send(SerialEvent::Line(clean(&pending)));
        }
    });

    let deadline = Instant::now() + timeout;
    let mut capture = Capture {
        lines: Vec::new(),
        exit_code: None,
        timed_out: false,
    };
    let mut stopped = false;
    loop {
        while let Ok(event) = receiver.try_recv() {
            match event {
                SerialEvent::Line(line) => {
                    stopped |= stop(&line);
                    capture.lines.push(line);
                }
                SerialEvent::Partial(text) => stopped |= stop(&text),
            }
        }
        if stopped {
            break;
        }
        if let Some(status) = child.try_wait()? {
            capture.exit_code = status.code();
            break;
        }
        if Instant::now() >= deadline {
            capture.timed_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // A hang is a failure, and a stopped run is finished: either way make
    // sure QEMU is gone. Killing an already-exited child is harmless.
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    // After the kill the reader hits end-of-file and sends what was left
    // of an unfinished line as a final `Line`.
    capture
        .lines
        .extend(receiver.try_iter().filter_map(|event| match event {
            SerialEvent::Line(line) => Some(line),
            SerialEvent::Partial(_) => None,
        }));
    Ok(capture)
}

fn print_tail(lines: &[String]) {
    let start = lines.len().saturating_sub(TAIL_LINES);
    println!("xtask: last {} serial lines:", lines.len() - start);
    for line in &lines[start..] {
        println!("  | {line}");
    }
}

/// Boots one phase's self-tests, or one of its scenarios, headless and
/// judges the result.
fn test_boot(
    phase: &Phase,
    scenario: Option<&'static str>,
    options: &RunOptions,
    timeout: Duration,
) -> Result<()> {
    let number = phase.number;
    match scenario {
        None => println!("xtask: ---- phase {number} ----"),
        Some(name) => println!("xtask: ---- phase {number}, scenario {name} ----"),
    }
    let esp = build::build(BootMode::Test(number, scenario))?;
    let capture = boot_headless(BootDisk::Directory(&esp), options, timeout, |_| false)?;
    // Scenarios end in a deliberate fault, so only the main boot of a
    // complete phase prints the acceptance marker.
    let marker = (phase.complete && scenario.is_none()).then(|| format!("KEEL P{number} OK"));
    let result = if capture.timed_out {
        Err(format!("timed out after {} s", timeout.as_secs()))
    } else {
        verdict(marker.as_deref(), &capture.lines, capture.exit_code)
    };
    match result {
        Ok(()) => {
            for line in capture.lines.iter().filter(|l| l.starts_with("TEST ")) {
                println!("  {line}");
            }
            Ok(())
        }
        Err(reason) => {
            print_tail(&capture.lines);
            Err(format!("phase {number} FAILED: {reason}").into())
        }
    }
}

/// Text Limine prints when a file does not match its pinned hash
/// (Limine 12.9.6, `common/lib/uri.c`, `uri_hash_mismatch`).
const LIMINE_HASH_PANIC: &str = "does not match";

/// Judges a boot of a tampered image: it passes only if Limine reported
/// the hash mismatch and the kernel never produced a line of output.
pub fn tamper_verdict(lines: &[String]) -> std::result::Result<(), String> {
    if lines.iter().any(|line| line.starts_with("Keel ")) {
        return Err("the kernel booted from a tampered image".into());
    }
    if !lines
        .iter()
        .any(|line| line.contains("PANIC") && line.contains(LIMINE_HASH_PANIC))
    {
        return Err("Limine did not report a hash mismatch".into());
    }
    Ok(())
}

/// SR-27 negative test: flip one byte of the kernel, then of the
/// initramfs, and check that the bootloader refuses each image.
fn test_tampered_boot(options: &RunOptions, timeout: Duration) -> Result<()> {
    let tree = build::build_tree(BootMode::Test(0, None))?;
    for (name, target) in [
        ("sr27.tamper.kernel", build::KERNEL_PATH),
        ("sr27.tamper.initramfs", build::INITRAMFS_PATH),
    ] {
        let esp = util::workspace_root().join("target").join("esp-tampered");
        if esp.exists() {
            std::fs::remove_dir_all(&esp)?;
        }
        for (path, data) in &tree.files {
            let mut data = data.clone();
            if *path == target {
                let middle = data.len() / 2;
                data[middle] ^= 0x01;
            }
            if *path == build::CONFIG_PATH {
                // Make Limine report its panic on the serial port, which
                // is the only output this headless test can read.
                let conf = String::from_utf8(data)?;
                data = conf
                    .replacen("timeout: 0\n", "timeout: 0\nserial: yes\n", 1)
                    .into_bytes();
            }
            util::write(&esp.join(path), &data)?;
        }
        let capture = boot_headless(BootDisk::Directory(&esp), options, timeout, |line| {
            line.contains(LIMINE_HASH_PANIC) || line.starts_with("Keel ")
        })?;
        match tamper_verdict(&capture.lines) {
            Ok(()) => println!("  TEST {name} PASS bootloader refused the altered file"),
            Err(reason) => {
                print_tail(&capture.lines);
                return Err(format!("TEST {name} FAIL {reason}").into());
            }
        }
    }
    Ok(())
}

/// Boots a raw disk image headless and succeeds once a serial line starts
/// with `marker`. Fails on a kernel panic, on QEMU exiting first, or after
/// the default timeout.
pub fn boot_image_until(image: &Path, options: &RunOptions, marker: &str) -> Result<()> {
    if !image.is_file() {
        return Err(format!("{} is not a file", image.display()).into());
    }
    let image = image.canonicalize()?;
    let timeout = Duration::from_secs(180);
    let capture = boot_headless(BootDisk::Image(&image), options, timeout, |line| {
        line.starts_with(marker) || line.contains(PANIC_BANNER)
    })?;
    let reached = capture.lines.iter().any(|line| line.starts_with(marker));
    let panicked = capture.lines.iter().any(|line| line.contains(PANIC_BANNER));
    if reached && !panicked {
        for line in capture.lines.iter().filter(|l| l.starts_with("boot: ")) {
            println!("  {line}");
        }
        println!("xtask: image booted: \"{marker}\" seen on serial");
        Ok(())
    } else {
        print_tail(&capture.lines);
        Err(format!("image did not reach \"{marker}\"").into())
    }
}

/// `cargo xtask test [--phase N]`.
pub fn test(phase: Option<u32>, options: &RunOptions, timeout: Duration) -> Result<()> {
    let selected: Vec<&Phase> = match phase {
        None => PHASES.iter().collect(),
        Some(n) => match PHASES.iter().find(|p| p.number == n) {
            Some(p) => vec![p],
            None => {
                let available: Vec<u32> = PHASES.iter().map(|p| p.number).collect();
                return Err(
                    format!("phase {n} has no tests yet (available: {available:?})").into(),
                );
            }
        },
    };
    for phase in selected {
        test_boot(phase, None, options, timeout)?;
        for &scenario in phase.scenarios {
            test_boot(phase, Some(scenario), options, timeout)?;
        }
        if phase.number == 0 {
            test_tampered_boot(options, timeout)?;
        }
        if phase.complete {
            println!("xtask: phase {} PASSED", phase.number);
        } else {
            println!(
                "xtask: phase {} tests PASSED (phase in progress; acceptance not yet complete)",
                phase.number
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(text: &str) -> Vec<String> {
        text.lines().map(str::to_string).collect()
    }

    const P0: Option<&str> = Some("KEEL P0 OK");

    #[test]
    fn in_progress_phases_need_no_marker() {
        let no_marker = GOOD.replace("KEEL P0 OK\n", "");
        assert_eq!(verdict(None, &lines(&no_marker), Some(33)), Ok(()));
        assert!(verdict(None, &lines(&no_marker), Some(35)).is_err());
    }

    const GOOD: &str = "Keel 0.0.0 booting\n\
        TEST boot.hhdm PASS HHDM offset is page-aligned\n\
        KEEL P0 OK\n\
        TEST fb.marker PASS framebuffer pixels show the marker\n\
        TEST SUMMARY passed=2 failed=0\n";

    #[test]
    fn accepts_a_clean_run() {
        assert_eq!(verdict(P0, &lines(GOOD), Some(33)), Ok(()));
    }

    #[test]
    fn rejects_wrong_exit_status_or_missing_marker() {
        assert!(verdict(P0, &lines(GOOD), Some(35)).is_err());
        assert!(verdict(P0, &lines(GOOD), None).is_err());
        assert!(verdict(Some("KEEL P1 OK"), &lines(GOOD), Some(33)).is_err());
        let no_marker = GOOD.replace("KEEL P0 OK\n", "");
        assert!(verdict(P0, &lines(&no_marker), Some(33)).is_err());
        // The marker must be a whole line, not a substring of another one.
        let embedded = GOOD.replace("KEEL P0 OK\n", "not KEEL P0 OK really\n");
        assert!(verdict(P0, &lines(&embedded), Some(33)).is_err());
    }

    #[test]
    fn rejects_failures_panics_and_inconsistent_summaries() {
        let failing = GOOD.replace("TEST boot.hhdm PASS", "TEST boot.hhdm FAIL");
        let error = verdict(P0, &lines(&failing), Some(33)).unwrap_err();
        assert!(error.contains("boot.hhdm"), "{error}");

        let panicked = format!("{GOOD}*** KEEL KERNEL PANIC ***\n");
        assert!(verdict(P0, &lines(&panicked), Some(33)).is_err());

        let no_summary = GOOD.replace("TEST SUMMARY passed=2 failed=0\n", "");
        assert!(verdict(P0, &lines(&no_summary), Some(33)).is_err());

        // A summary claiming more passes than PASS lines were seen.
        let inflated = GOOD.replace("passed=2", "passed=3");
        assert!(verdict(P0, &lines(&inflated), Some(33)).is_err());

        let empty = "KEEL P0 OK\nTEST SUMMARY passed=0 failed=0\n";
        assert!(verdict(P0, &lines(empty), Some(33)).is_err());
    }

    #[test]
    fn tamper_verdict_needs_a_refusal_and_a_silent_kernel() {
        let refused = lines("limine: Loading...PANIC: Blake2b hash for URI `x` does not match!");
        assert_eq!(tamper_verdict(&refused), Ok(()));
        assert!(tamper_verdict(&lines("limine: Loading executable")).is_err());
        assert!(tamper_verdict(&[]).is_err());
        let booted = lines("PANIC: hash does not match\nKeel 0.0.0 booting");
        assert!(tamper_verdict(&booted).is_err());
    }

    #[test]
    fn strips_cursor_positioning_sequences() {
        let raw = "\u{1b}[01;01HP\u{1b}[01;02HA\u{1b}[2J\u{1b}[=3hNIC";
        assert_eq!(strip_ansi(raw), "PANIC");
        assert_eq!(strip_ansi("plain [text]"), "plain [text]");
        assert_eq!(strip_ansi("cut off \u{1b}[12"), "cut off ");
    }

    #[test]
    fn parser_ignores_other_output() {
        let report = parse_report(["boot: TEST not a result", "TESTING", "TEST lonely"]);
        assert_eq!(report, TestReport::default());
    }
}
