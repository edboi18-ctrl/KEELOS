//! Compartment manifests (P3-S2, ADR 0040): the format keel-launch reads.
//!
//! A subset of TOML 1.0.0 (toml.io/en/v1.0.0): what it accepts is valid
//! TOML meaning the same, and some valid TOML it refuses.
//! - **Kept:** comments from `#` outside a string; `key = value` lines
//!   with bare keys (`A-Za-z0-9_-`); table headers (`[root]`), each
//!   once; array-table headers (`[[grant]]`, recognized and refused).
//!   Values: basic strings with the escapes `\\`, `\"`, `\n` and `\t`,
//!   control characters other than tab refused as TOML requires; decimal
//!   integers without a sign or leading zeros, at most 2^63 - 1 as TOML's
//!   signed 64 bits; `true` and `false`; arrays of strings on one line.
//! - **Refused though valid:** the other escapes (`\b`, `\f`, `\r`,
//!   `\u`, `\U`), literal and multi-line strings, signed, hex, octal,
//!   binary and float numbers, dates, arrays over several lines or with a
//!   trailing comma, inline tables, quoted and dotted keys.
//! - **Control characters** other than tab are refused anywhere, comments
//!   included, as TOML refuses them.
//!
//! Everything else fails closed (SR-10): an unknown table or key, a value
//! of the wrong type, a key or table given twice, a string over
//! [`MAX_STRING`], or a manifest over [`MAX_MANIFEST`]. Each error names
//! its line. Parsing allocates nothing: decoded strings go into the
//! manifest's own arena.
#![no_std]

/// The largest manifest accepted, in bytes.
pub const MAX_MANIFEST: usize = 64 * 1024;
/// The longest string value, decoded.
pub const MAX_STRING: usize = 4096;
/// Room for every decoded string together.
pub const ARENA: usize = 16 * 1024;
/// At most this many arguments, and as many environment strings.
pub const MAX_LIST: usize = 32;

/// A grantable device (ADR 0040), by its native-interface code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Device {
    Null = 1,
    Zero = 2,
    Urandom = 3,
    Tty = 4,
    Ptmx = 5,
}

impl Device {
    fn named(name: &[u8]) -> Option<Device> {
        Some(match name {
            b"null" => Device::Null,
            b"zero" => Device::Zero,
            b"urandom" => Device::Urandom,
            b"tty" => Device::Tty,
            b"ptmx" => Device::Ptmx,
            _ => return None,
        })
    }

    pub fn code(self) -> u64 {
        self as u64
    }
}

/// The compartment's limits, as the manifest gives them or by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub memory_mb: u64,
    pub processes: u32,
    pub handles: u32,
    pub tmpfs_mb: u64,
    pub tmpfs_nodes: u64,
}

impl Limits {
    /// ADR 0040's defaults.
    pub const DEFAULT: Limits = Limits {
        memory_mb: 256,
        processes: 64,
        handles: 1024,
        tmpfs_mb: 64,
        tmpfs_nodes: 4096,
    };
}

/// A parse error: the line (from 1; 0 for the whole manifest) and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub line: usize,
    pub what: &'static str,
}

#[derive(Clone, Copy, Debug, Default)]
struct Span {
    start: u16,
    len: u16,
}

/// A parsed manifest.
pub struct Manifest {
    arena: [u8; ARENA],
    used: usize,
    name: Option<Span>,
    exec: Option<Span>,
    args: [Span; MAX_LIST],
    nargs: usize,
    env: [Span; MAX_LIST],
    nenv: usize,
    devices: [Option<Device>; 5],
    root: Option<Span>,
    pub limits: Limits,
}

impl Manifest {
    fn text(&self, s: Span) -> &[u8] {
        &self.arena[s.start as usize..s.start as usize + s.len as usize]
    }

    /// The application's name.
    pub fn name(&self) -> &[u8] {
        self.name.map_or(&[], |s| self.text(s))
    }

    /// The program, an absolute path in the compartment.
    pub fn exec(&self) -> &[u8] {
        self.exec.map_or(&[], |s| self.text(s))
    }

    /// The directory that becomes the compartment's `/`.
    pub fn root(&self) -> &[u8] {
        self.root.map_or(&[], |s| self.text(s))
    }

    /// The arguments after argv[0].
    pub fn args(&self) -> impl Iterator<Item = &[u8]> {
        self.args[..self.nargs].iter().map(|&s| self.text(s))
    }

    /// The environment, `KEY=VALUE` each.
    pub fn env(&self) -> impl Iterator<Item = &[u8]> {
        self.env[..self.nenv].iter().map(|&s| self.text(s))
    }

    /// The devices to grant.
    pub fn devices(&self) -> impl Iterator<Item = Device> + '_ {
        self.devices.iter().filter_map(|d| *d)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Table {
    Top,
    Root,
    Display,
    Network,
    Limits,
}

/// What a line's value is, before it is stored.
enum Value<'a> {
    /// A string's raw bytes between its quotes, escapes not yet decoded.
    Str(&'a [u8]),
    Int(u64),
    Bool(bool),
    /// A string array's raw contents between its brackets.
    Array(&'a [u8]),
}

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// The line without its comment: the first `#` outside a string.
fn uncomment(line: &[u8]) -> &[u8] {
    let mut in_string = false;
    let mut i = 0;
    while i < line.len() {
        match line[i] {
            b'\\' if in_string => i += 1,
            b'"' => in_string = !in_string,
            b'#' if !in_string => return &line[..i],
            _ => {}
        }
        i += 1;
    }
    line
}

/// The raw bytes of a basic string starting at `s[0] == b'"'`, and the
/// rest after its closing quote.
fn string_at(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut i = 1;
    while i < s.len() {
        match s[i] {
            b'\\' => i += 2,
            b'"' => return Some((&s[1..i], &s[i + 1..])),
            _ => i += 1,
        }
    }
    None
}

fn parse_value(v: &[u8]) -> Option<Value<'_>> {
    match v.first()? {
        b'"' => {
            let (raw, rest) = string_at(v)?;
            trim(rest).is_empty().then_some(Value::Str(raw))
        }
        b'[' => {
            let inner = v.strip_prefix(b"[")?.strip_suffix(b"]")?;
            Some(Value::Array(inner))
        }
        b't' if v == b"true" => Some(Value::Bool(true)),
        b'f' if v == b"false" => Some(Value::Bool(false)),
        b'0'..=b'9' => {
            // No leading zeros but 0 itself (TOML), no sign, fits u64.
            if v.len() > 1 && v[0] == b'0' {
                return None;
            }
            let mut n: u64 = 0;
            for &d in v {
                if !d.is_ascii_digit() {
                    return None;
                }
                n = n.checked_mul(10)?.checked_add(u64::from(d - b'0'))?;
            }
            // TOML integers are signed 64-bit.
            (n <= i64::MAX as u64).then_some(Value::Int(n))
        }
        _ => None,
    }
}

struct Parser<'a> {
    m: Manifest,
    line: usize,
    /// Keys seen, as (table, key): a key given twice is an error.
    seen: [(u8, &'a [u8]); 48],
    nseen: usize,
    tables_seen: u8,
}

impl<'a> Parser<'a> {
    fn err(&self, what: &'static str) -> Error {
        Error {
            line: self.line,
            what,
        }
    }

    /// Decodes a basic string's escapes into the arena.
    fn store(&mut self, raw: &[u8]) -> Result<Span, Error> {
        let start = self.m.used;
        let mut i = 0;
        while i < raw.len() {
            let b = match raw[i] {
                b'\\' => {
                    i += 1;
                    match raw.get(i) {
                        Some(b'\\') => b'\\',
                        Some(b'"') => b'"',
                        Some(b'n') => b'\n',
                        Some(b't') => b'\t',
                        _ => return Err(self.err("unknown escape in a string")),
                    }
                }
                // TOML: control characters other than tab must be escaped.
                c if (c < 0x20 && c != b'\t') || c == 0x7f => {
                    return Err(self.err("control character in a string"));
                }
                c => c,
            };
            if self.m.used - start >= MAX_STRING {
                return Err(self.err("string too long"));
            }
            if self.m.used >= ARENA {
                return Err(self.err("strings too long together"));
            }
            self.m.arena[self.m.used] = b;
            self.m.used += 1;
            i += 1;
        }
        Ok(Span {
            start: start as u16,
            len: (self.m.used - start) as u16,
        })
    }

    /// The strings of an array's raw contents, each stored.
    fn strings(
        &mut self,
        mut inner: &[u8],
        out: &mut [Span],
        what: &'static str,
    ) -> Result<usize, Error> {
        let mut n = 0;
        inner = trim(inner);
        while !inner.is_empty() {
            if inner[0] != b'"' {
                return Err(self.err(what));
            }
            let (raw, rest) = string_at(inner).ok_or_else(|| self.err("unterminated string"))?;
            if n == out.len() {
                return Err(self.err("too many strings in an array"));
            }
            out[n] = self.store(raw)?;
            n += 1;
            inner = trim(rest);
            match inner.first() {
                None => {}
                Some(b',') => inner = trim(&inner[1..]),
                Some(_) => return Err(self.err(what)),
            }
        }
        Ok(n)
    }

    fn once(&mut self, table: Table, key: &'a [u8]) -> Result<(), Error> {
        let entry = (table as u8, key);
        if self.seen[..self.nseen].contains(&entry) {
            return Err(self.err("key given twice"));
        }
        if self.nseen == self.seen.len() {
            return Err(self.err("too many keys"));
        }
        self.seen[self.nseen] = entry;
        self.nseen += 1;
        Ok(())
    }

    fn assign(&mut self, table: Table, key: &'a [u8], value: Value<'_>) -> Result<(), Error> {
        self.once(table, key)?;
        let int = |v: &Value<'_>, lo: u64, hi: u64| match v {
            Value::Int(n) if (lo..=hi).contains(n) => Some(*n),
            _ => None,
        };
        match (table, key, value) {
            (Table::Top, b"name", Value::Str(raw)) => {
                let s = self.store(raw)?;
                let text = self.m.text(s);
                if text.is_empty()
                    || text.len() > 64
                    || !text
                        .iter()
                        .all(|&b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                {
                    return Err(self.err("name must be 1 to 64 letters, digits, '-', '_' or '.'"));
                }
                self.m.name = Some(s);
            }
            (Table::Top, b"exec", Value::Str(raw)) => {
                let s = self.store(raw)?;
                if self.m.text(s).first() != Some(&b'/') || self.m.text(s).contains(&0) {
                    return Err(self.err("exec must be an absolute path"));
                }
                self.m.exec = Some(s);
            }
            (Table::Top, b"args", Value::Array(inner)) => {
                let mut spans = [Span::default(); MAX_LIST];
                let n = self.strings(inner, &mut spans, "args must be an array of strings")?;
                self.m.args = spans;
                self.m.nargs = n;
                if self.m.args().any(|a| a.contains(&0)) {
                    return Err(self.err("an argument holds a NUL"));
                }
            }
            (Table::Top, b"env", Value::Array(inner)) => {
                let mut spans = [Span::default(); MAX_LIST];
                let n = self.strings(inner, &mut spans, "env must be an array of strings")?;
                self.m.env = spans;
                self.m.nenv = n;
                if self.m.env().any(|e| {
                    e.contains(&0) || e.iter().position(|&b| b == b'=').is_none_or(|i| i == 0)
                }) {
                    return Err(self.err("env entries must be KEY=VALUE"));
                }
            }
            (Table::Top, b"devices", Value::Array(inner)) => {
                let mut spans = [Span::default(); MAX_LIST];
                let n = self.strings(inner, &mut spans, "devices must be an array of strings")?;
                for (i, span) in spans[..n].iter().enumerate() {
                    let device = Device::named(self.m.text(*span)).ok_or_else(|| {
                        self.err("unknown device (null, zero, urandom, tty, ptmx)")
                    })?;
                    if self.m.devices.contains(&Some(device)) {
                        return Err(self.err("device listed twice"));
                    }
                    self.m.devices[i.min(4)] = Some(device);
                }
            }
            (Table::Top, b"profile", Value::Str(raw)) => {
                if raw != b"default" {
                    return Err(self.err("only the default profile exists until P3-S3"));
                }
            }
            (Table::Root, b"base", Value::Str(raw)) => {
                let s = self.store(raw)?;
                if self.m.text(s).first() != Some(&b'/') || self.m.text(s).contains(&0) {
                    return Err(self.err("root base must be an absolute path"));
                }
                self.m.root = Some(s);
            }
            (Table::Root, b"prefix" | b"writable", _) => {
                return Err(self.err("layered roots are not supported until P3-S5"));
            }
            (Table::Display, b"allowed", Value::Bool(false))
            | (Table::Network, b"allowed", Value::Bool(false)) => {}
            (Table::Display, b"allowed", Value::Bool(true)) => {
                return Err(self.err("no display until Phase 5"));
            }
            (Table::Network, b"allowed", Value::Bool(true)) => {
                return Err(self.err("no network"));
            }
            (Table::Display, b"max_surfaces", Value::Int(_)) => {}
            (Table::Limits, b"memory_mb", v) => {
                self.m.limits.memory_mb = int(&v, 1, 1 << 20)
                    .ok_or_else(|| self.err("memory_mb must be 1 to 1048576"))?;
            }
            (Table::Limits, b"processes", v) => {
                self.m.limits.processes =
                    int(&v, 1, 4096).ok_or_else(|| self.err("processes must be 1 to 4096"))? as u32;
            }
            (Table::Limits, b"handles", v) => {
                self.m.limits.handles =
                    int(&v, 3, 1024).ok_or_else(|| self.err("handles must be 3 to 1024"))? as u32;
            }
            (Table::Limits, b"tmpfs_mb", v) => {
                self.m.limits.tmpfs_mb =
                    int(&v, 0, 1 << 20).ok_or_else(|| self.err("tmpfs_mb must be 0 to 1048576"))?;
            }
            (Table::Limits, b"tmpfs_nodes", v) => {
                self.m.limits.tmpfs_nodes = int(&v, 0, 1 << 24)
                    .ok_or_else(|| self.err("tmpfs_nodes must be 0 to 16777216"))?;
            }
            (Table::Top, b"name" | b"exec" | b"args" | b"env" | b"devices" | b"profile", _)
            | (Table::Root, b"base", _)
            | (Table::Display | Table::Network, b"allowed", _)
            | (Table::Display, b"max_surfaces", _) => {
                return Err(self.err("value of the wrong type"));
            }
            _ => return Err(self.err("unknown key")),
        }
        Ok(())
    }
}

/// Parses `text`. Nothing is returned unless all of it is good.
pub fn parse(text: &[u8]) -> Result<Manifest, Error> {
    if text.len() > MAX_MANIFEST {
        return Err(Error {
            line: 0,
            what: "manifest too large",
        });
    }
    let mut p = Parser {
        m: Manifest {
            arena: [0; ARENA],
            used: 0,
            name: None,
            exec: None,
            args: [Span::default(); MAX_LIST],
            nargs: 0,
            env: [Span::default(); MAX_LIST],
            nenv: 0,
            devices: [None; 5],
            root: None,
            limits: Limits::DEFAULT,
        },
        line: 0,
        seen: [(0, &[]); 48],
        nseen: 0,
        tables_seen: 0,
    };
    let mut table = Table::Top;
    for raw_line in text.split(|&b| b == b'\n') {
        p.line += 1;
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        // TOML: no control character but tab anywhere, comments included.
        // (Inside a string an escaped one is written as its escape.)
        if raw_line
            .iter()
            .any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f)
        {
            return Err(p.err("control character"));
        }
        let line = trim(uncomment(raw_line));
        if line.is_empty() {
            continue;
        }
        if line.starts_with(b"[[") {
            return Err(p.err("[[grant]] needs mounts, not supported until P3-S5"));
        }
        if let Some(name) = line.strip_prefix(b"[").and_then(|l| l.strip_suffix(b"]")) {
            let (next, bit) = match trim(name) {
                b"root" => (Table::Root, 1),
                b"display" => (Table::Display, 2),
                b"network" => (Table::Network, 4),
                b"limits" => (Table::Limits, 8),
                _ => return Err(p.err("unknown table")),
            };
            if p.tables_seen & bit != 0 {
                return Err(p.err("table given twice"));
            }
            p.tables_seen |= bit;
            table = next;
            continue;
        }
        let eq = line
            .iter()
            .position(|&b| b == b'=')
            .ok_or_else(|| p.err("expected key = value"))?;
        let key = trim(&line[..eq]);
        if key.is_empty() || !key.iter().all(|&b| is_key_byte(b)) {
            return Err(p.err("bad key"));
        }
        let value = parse_value(trim(&line[eq + 1..])).ok_or_else(|| p.err("bad value"))?;
        p.assign(table, key, value)?;
    }
    p.line = 0;
    if p.m.name.is_none() {
        return Err(p.err("name is required"));
    }
    if p.m.exec.is_none() {
        return Err(p.err("exec is required"));
    }
    if p.m.root.is_none() {
        return Err(p.err("[root] base is required"));
    }
    Ok(p.m)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    const GOOD: &[u8] = br#"# A test application.
name = "hello-1.0"
exec = "/bin/hello"    # in the compartment
args = ["a b", "c\"d", ""]
env  = ["PATH=/bin", "X=1=2"]
devices = ["null", "ptmx"]
profile = "default"

[root]
base = "/apps/hello"

[display]
allowed = false
max_surfaces = 32

[network]
allowed = false

[limits]
memory_mb = 128
processes = 8
"#;

    #[test]
    fn a_good_manifest() {
        let m = parse(GOOD).unwrap();
        assert_eq!(m.name(), b"hello-1.0");
        assert_eq!(m.exec(), b"/bin/hello");
        assert_eq!(m.root(), b"/apps/hello");
        let args: std::vec::Vec<&[u8]> = m.args().collect();
        assert_eq!(args, [&b"a b"[..], b"c\"d", b""]);
        let env: std::vec::Vec<&[u8]> = m.env().collect();
        assert_eq!(env, [&b"PATH=/bin"[..], b"X=1=2"]);
        let devices: std::vec::Vec<Device> = m.devices().collect();
        assert_eq!(devices, [Device::Null, Device::Ptmx]);
        assert_eq!(
            m.limits,
            Limits {
                memory_mb: 128,
                processes: 8,
                ..Limits::DEFAULT
            }
        );
    }

    #[test]
    fn the_minimum_and_the_defaults() {
        let m = parse(b"name = \"x\"\nexec = \"/x\"\n[root]\nbase = \"/r\"\n").unwrap();
        assert_eq!(m.limits, Limits::DEFAULT);
        assert_eq!(m.args().count() + m.env().count() + m.devices().count(), 0);
    }

    fn fails(text: &str, line: usize, what: &str) {
        let e = parse(text.as_bytes())
            .err()
            .unwrap_or_else(|| panic!("accepted: {text}"));
        assert_eq!((e.line, e.what), (line, what), "{text}");
    }

    #[test]
    fn everything_else_fails_closed() {
        let base = "exec = \"/x\"\n[root]\nbase = \"/r\"\n";
        let with = |first: &str| std::format!("{first}\n{base}");
        fails(&with("name = \"x\"\nname = \"y\""), 2, "key given twice");
        fails(&with("nme = \"x\""), 1, "unknown key");
        fails(&with("name = 3"), 1, "value of the wrong type");
        fails(
            &with("name = \"a b\""),
            1,
            "name must be 1 to 64 letters, digits, '-', '_' or '.'",
        );
        fails(
            &with("name = \"x\"\nprofile = \"wine-gui\""),
            2,
            "only the default profile exists until P3-S3",
        );
        fails(
            &with("name = \"x\"\ndevices = [\"mem\"]"),
            2,
            "unknown device (null, zero, urandom, tty, ptmx)",
        );
        fails(
            &with("name = \"x\"\ndevices = [\"null\", \"null\"]"),
            2,
            "device listed twice",
        );
        fails(
            &with("name = \"x\"\nenv = [\"=x\"]"),
            2,
            "env entries must be KEY=VALUE",
        );
        fails(
            &with("name = \"x\"\nargs = [\"a\" \"b\"]"),
            2,
            "args must be an array of strings",
        );
        fails(&with("name = \"x\\q\""), 1, "unknown escape in a string");
        fails(&with("name = \"x"), 1, "bad value");
        fails(
            &with("name = \"x\"\n[[grant]]"),
            2,
            "[[grant]] needs mounts, not supported until P3-S5",
        );
        fails(
            &std::format!("name = \"x\"\n{base}[root]\n"),
            5,
            "table given twice",
        );
        fails(&with("name = \"x\"\n[nope]"), 2, "unknown table");
        fails(
            &with("name = \"x\"\n[root]\nprefix = \"p\""),
            3,
            "layered roots are not supported until P3-S5",
        );
        fails(
            &with("name = \"x\"\n[display]\nallowed = true"),
            3,
            "no display until Phase 5",
        );
        fails(
            &with("name = \"x\"\n[network]\nallowed = true"),
            3,
            "no network",
        );
        fails(
            &with("name = \"x\"\n[limits]\nprocesses = 0"),
            3,
            "processes must be 1 to 4096",
        );
        fails(
            &with("name = \"x\"\n[limits]\nmemory_mb = 018"),
            3,
            "bad value",
        );
        fails(
            &with("name = \"x\"\n[limits]\nmemory_mb = 99999999999999999999"),
            3,
            "bad value",
        );
        fails(&with("name = \"x\"\nexec2"), 2, "expected key = value");
        fails(
            &with("name = \"x\"\n[limits]\nmemory_mb = 9223372036854775808"),
            3,
            "bad value",
        );
        fails(&with("name = \"x\" # \x01"), 1, "control character");
        fails(&with("name = \"x\x7f\""), 1, "control character");
        fails(
            "name = \"x\"\n[root]\nbase = \"/r\"\n",
            0,
            "exec is required",
        );
        fails(
            "name = \"x\"\nexec = \"x\"\n",
            2,
            "exec must be an absolute path",
        );
        fails("exec = \"/x\"\n", 0, "name is required");
        let long = std::format!("name = \"x\"\nexec = \"/{}\"\n", "y".repeat(MAX_STRING));
        fails(&long, 2, "string too long");
        let big = std::vec![b'#'; MAX_MANIFEST + 1];
        assert_eq!(
            parse(&big).err().map(|e| e.what),
            Some("manifest too large")
        );
    }

    #[test]
    fn comments_end_lines_but_not_strings() {
        let m = parse(b"name = \"a#b\" # c\nexec = \"/x\"\n[root] # r\nbase = \"/r\"\r\n").err();
        // '#' is not allowed in a name, so this one fails on the name.
        assert_eq!(m.map(|e| e.line), Some(1));
        let m = parse(b"name = \"a\"\nexec = \"/x#y\" # c\n[root] # r\nbase = \"/r\"\r\n").unwrap();
        assert_eq!(m.exec(), b"/x#y");
    }
}
