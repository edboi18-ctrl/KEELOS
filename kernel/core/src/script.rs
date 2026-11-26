//! `#!` scripts (ADR 0036): the interpreter line, as Linux v6.12's
//! `load_script` (`fs/binfmt_script.c`) reads it.

use crate::errno::Errno;

/// An interpreter line: the interpreter's name and its optional argument.
pub type Line<'a> = (&'a [u8], Option<&'a [u8]>);

/// `load_script` (fs/binfmt_script.c, ADR 0036): None if `file` does not
/// start with `#!`; else its interpreter and optional argument, from the
/// first BINPRM_BUF_SIZE (256) bytes:
/// - the line ends at a newline; with none in those bytes, the
///   interpreter's name must still end (a space, tab or NUL) within
///   them, or the call is ENOEXEC (a truncated argument is fine);
/// - spaces and tabs before the name, and at the end, are skipped; no
///   name is ENOEXEC;
/// - the argument is everything after the name and the blanks that
///   follow it, as one string (inner blanks kept), or none.
pub fn interpreter(file: &[u8]) -> Option<Result<Line<'_>, Errno>> {
    const BINPRM_BUF_SIZE: usize = 256;
    if !file.starts_with(b"#!") {
        return None;
    }
    let buf = &file[..file.len().min(BINPRM_BUF_SIZE)];
    let blank = |c: u8| c == b' ' || c == b'\t';
    let terminator = |c: u8| blank(c) || c == 0;
    // i_end: the newline, or with none the buffer's end, once the name is
    // known to be whole.
    let mut end = match buf.iter().position(|&c| c == b'\n') {
        Some(newline) => newline,
        None => {
            let Some(first) = buf[2..].iter().position(|&c| !blank(c)).map(|i| i + 2) else {
                return Some(Err(Errno::ENOEXEC));
            };
            // Bytes past a short file read as NUL padding, as in Linux's
            // buffer.
            let whole = buf.len() < BINPRM_BUF_SIZE || buf[first..].iter().any(|&c| terminator(c));
            if !whole {
                return Some(Err(Errno::ENOEXEC));
            }
            // `i_end = buf_end`, the buffer's last byte, which the line
            // stops before; a shorter file's NUL padding ends it anyway.
            buf.len().min(BINPRM_BUF_SIZE - 1)
        }
    };
    while end > 2 && blank(buf[end - 1]) {
        end -= 1;
    }
    let line = &buf[..end];
    let Some(start) = line[2..].iter().position(|&c| !blank(c)).map(|i| i + 2) else {
        return Some(Err(Errno::ENOEXEC));
    };
    // The name stops at a blank or NUL (`next_terminator`); a NUL ends the
    // line there.
    let stop = line[start..]
        .iter()
        .position(|&c| terminator(c))
        .map_or(line.len(), |i| start + i);
    let name = &line[start..stop];
    let arg = if stop < line.len() && line[stop] != 0 {
        line[stop..]
            .iter()
            .position(|&c| !blank(c))
            .map(|i| &line[stop + i..])
            // An argument ends at a NUL, as the C string Linux passes.
            .map(|a| &a[..a.iter().position(|&c| c == 0).unwrap_or(a.len())])
            .filter(|a| !a.is_empty())
    } else {
        None
    };
    Some(Ok((name, arg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(file: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
        let (name, arg) = interpreter(file).unwrap().unwrap();
        (name.to_vec(), arg.map(<[u8]>::to_vec))
    }

    #[test]
    fn not_a_script() {
        assert!(interpreter(b"\x7fELF").is_none());
        assert!(interpreter(b"#").is_none());
        assert!(interpreter(b"").is_none());
    }

    #[test]
    fn name_and_argument() {
        assert_eq!(ok(b"#!/bin/sh\necho"), (b"/bin/sh".to_vec(), None));
        assert_eq!(ok(b"#! \t/bin/sh  \n"), (b"/bin/sh".to_vec(), None));
        assert_eq!(
            ok(b"#!/usr/bin/env  a b \t\n"),
            (b"/usr/bin/env".to_vec(), Some(b"a b".to_vec()))
        );
        // No newline: the file's end (NUL padding in Linux's buffer).
        assert_eq!(
            ok(b"#!/bin/sh -e"),
            (b"/bin/sh".to_vec(), Some(b"-e".to_vec()))
        );
        // A NUL ends the name, and the line.
        assert_eq!(ok(b"#!/bin/sh\0 -e\n"), (b"/bin/sh".to_vec(), None));
    }

    #[test]
    fn refusals() {
        for bad in [&b"#!\n"[..], b"#!   \n", b"#!", b"#!  "] {
            assert_eq!(interpreter(bad), Some(Err(Errno::ENOEXEC)), "{bad:?}");
        }
        // 256 bytes, no newline, the name never ending: truncated.
        let mut long = b"#!/".to_vec();
        long.resize(300, b'x');
        assert_eq!(interpreter(&long), Some(Err(Errno::ENOEXEC)));
        // The name ending in time is fine; the argument is cut before
        // the buffer's last byte.
        let mut cut = b"#!/bin/sh ".to_vec();
        cut.resize(300, b'a');
        let (name, arg) = ok(&cut);
        assert_eq!(name, b"/bin/sh");
        assert_eq!(arg.unwrap().len(), 255 - 10);
    }
}
