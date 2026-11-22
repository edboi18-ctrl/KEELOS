//! PC keyboard scancode set 1 to characters, US layout (P1-T14).
//!
//! Set 1 is what an i8042 controller delivers with translation on. Make
//! codes are from keycodemapdb `data/keymaps.csv` (the table QEMU builds
//! its scancode maps from, column "AT set1 keycode"; file SHA-256
//! 527727ef96d7103a8d7725a6ed9738812660b5a3f4aec086dd7b587b1ba9fcca,
//! read 2026-11-22). A release is the make code with bit 7 set, and
//! extended keys are prefixed with 0xE0 (QEMU `hw/input/ps2.c`, set 1
//! path: `if (!key->down) keycode |= 0x80`, and 0xE0 put before codes
//! with a high byte). Pause sends 0xE1 and two more codes per event.
//!
//! The output is what a terminal sends: Enter is CR (the line discipline
//! maps it to NL, ICRNL), Backspace is DEL (0x7F, the VERASE default),
//! Ctrl+letter is the letter's control code. Cursor and function keys are
//! ignored until the TTY layer emits escape sequences for them.

/// Unshifted and shifted characters for make codes 0x00-0x39 (0 = none).
const PLAIN: &[u8; 0x3a] =
    b"\0\x1b1234567890-=\x7f\tqwertyuiop[]\r\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
const SHIFTED: &[u8; 0x3a] =
    b"\0\x1b!@#$%^&*()_+\x7f\tQWERTYUIOP{}\r\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";

const LEFT_CTRL: u8 = 0x1d;
const LEFT_SHIFT: u8 = 0x2a;
const RIGHT_SHIFT: u8 = 0x36;
const LEFT_ALT: u8 = 0x38;
const CAPS_LOCK: u8 = 0x3a;
const KEYPAD_ENTER: u8 = 0x1c; // after 0xE0
const KEYPAD_SLASH: u8 = 0x35; // after 0xE0

#[derive(Clone, Debug, Default)]
pub struct Decoder {
    extended: bool,
    /// Bytes of a Pause (0xE1) sequence still to skip.
    skip: u8,
    shift_left: bool,
    shift_right: bool,
    ctrl_left: bool,
    ctrl_right: bool,
    alt: bool,
    caps_lock: bool,
}

impl Decoder {
    pub const fn new() -> Self {
        Decoder {
            extended: false,
            skip: 0,
            shift_left: false,
            shift_right: false,
            ctrl_left: false,
            ctrl_right: false,
            alt: false,
            caps_lock: false,
        }
    }

    /// Feeds one byte from the controller; returns a character if the byte
    /// completes a key press that produces one.
    pub fn feed(&mut self, byte: u8) -> Option<u8> {
        if self.skip > 0 {
            self.skip -= 1;
            return None;
        }
        match byte {
            0xE0 => {
                self.extended = true;
                return None;
            }
            0xE1 => {
                self.skip = 2;
                return None;
            }
            _ => {}
        }
        let extended = core::mem::take(&mut self.extended);
        let released = byte & 0x80 != 0;
        let code = byte & 0x7f;
        if extended {
            return match code {
                LEFT_CTRL => {
                    self.ctrl_right = !released;
                    None
                }
                LEFT_ALT => {
                    self.alt = !released;
                    None
                }
                KEYPAD_ENTER if !released => Some(b'\r'),
                KEYPAD_SLASH if !released => Some(b'/'),
                // Includes the fake shifts around Print Screen (E0 2A,
                // E0 AA), which must not change the shift state.
                _ => None,
            };
        }
        match code {
            LEFT_SHIFT => self.shift_left = !released,
            RIGHT_SHIFT => self.shift_right = !released,
            LEFT_CTRL => self.ctrl_left = !released,
            LEFT_ALT => self.alt = !released,
            CAPS_LOCK if !released => self.caps_lock = !self.caps_lock,
            _ => {}
        }
        if released {
            return None;
        }
        let index = usize::from(code);
        let shift = self.shift_left || self.shift_right;
        let plain = *PLAIN.get(index)?;
        let mut c = if shift { SHIFTED[index] } else { plain };
        if c == 0 {
            return None;
        }
        if self.caps_lock && plain.is_ascii_lowercase() {
            c = if shift {
                plain
            } else {
                plain.to_ascii_uppercase()
            };
        }
        if self.ctrl_left || self.ctrl_right {
            return match c {
                b'@'..=b'_' | b'a'..=b'z' => Some(c & 0x1f),
                b' ' | b'2' => Some(0), // Ctrl+Space, Ctrl+2: NUL
                _ => Some(c),
            };
        }
        Some(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(d: &mut Decoder, codes: &[u8]) -> alloc::vec::Vec<u8> {
        codes.iter().filter_map(|&b| d.feed(b)).collect()
    }

    #[test]
    fn letters_digits_and_releases() {
        let mut d = Decoder::new();
        // k, e, e, l with releases, then Enter.
        let keys = [0x25, 0xa5, 0x12, 0x92, 0x12, 0x92, 0x26, 0xa6, 0x1c, 0x9c];
        assert_eq!(press(&mut d, &keys), b"keel\r");
        assert_eq!(press(&mut d, &[0x02, 0x0b, 0x39, 0x0e, 0x0f]), b"10 \x7f\t");
    }

    #[test]
    fn shift_and_caps_lock() {
        let mut d = Decoder::new();
        assert_eq!(press(&mut d, &[0x2a, 0x1e, 0x02, 0xaa, 0x1e]), b"A!a");
        assert_eq!(press(&mut d, &[0x36, 0x28, 0x2b, 0xb6]), b"\"|");
        // Caps Lock affects letters only; Shift inverts it for letters.
        assert_eq!(press(&mut d, &[0x3a, 0xba, 0x1e, 0x02]), b"A1");
        assert_eq!(press(&mut d, &[0x2a, 0x1e, 0x02, 0xaa]), b"a!");
        assert_eq!(press(&mut d, &[0x3a, 0xba, 0x1e]), b"a");
    }

    #[test]
    fn control_keys() {
        let mut d = Decoder::new();
        // Ctrl+C, Ctrl+D, Ctrl+U; right Ctrl (E0 1D) works too.
        assert_eq!(press(&mut d, &[0x1d, 0x2e, 0x20, 0x16, 0x9d]), [3, 4, 0x15]);
        assert_eq!(
            press(&mut d, &[0xe0, 0x1d, 0x2e, 0xe0, 0x9d, 0x2e]),
            [3, b'c']
        );
    }

    #[test]
    fn extended_and_ignored_keys() {
        let mut d = Decoder::new();
        // Keypad Enter and slash; arrows (E0 48) produce nothing yet.
        assert_eq!(
            press(&mut d, &[0xe0, 0x1c, 0xe0, 0x9c, 0xe0, 0x35, 0xe0, 0x48]),
            b"\r/"
        );
        // Print Screen's fake shift must not leave Shift held.
        assert_eq!(press(&mut d, &[0xe0, 0x2a, 0xe0, 0x37, 0x1e]), b"a");
        // Pause (E1 1D 45 E1 9D C5) is skipped whole.
        assert_eq!(
            press(&mut d, &[0xe1, 0x1d, 0x45, 0xe1, 0x9d, 0xc5, 0x1e]),
            b"a"
        );
        // F1 and codes beyond the table produce nothing.
        assert_eq!(press(&mut d, &[0x3b, 0x58, 0x7f]), b"");
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut d = Decoder::new();
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..50_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let _ = d.feed(state as u8);
        }
    }
}
