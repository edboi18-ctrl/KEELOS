//! Text console on a linear framebuffer.
//!
//! All drawing is safe Rust over a byte slice, so the same code is unit
//! tested on the host against an ordinary `Vec<u8>`. The only `unsafe`
//! involved in the real console is the one-time construction of the slice
//! from the bootloader's framebuffer description, in [`crate::boot`].
//!
//! The font is the public-domain 8x8 IBM-style bitmap set from the
//! `font8x8` crate (`BASIC_LEGACY`: one `[u8; 8]` per ASCII code, one byte
//! per row, least-significant bit is the leftmost pixel). Each font pixel
//! is drawn as a 2x2 block so text is legible on high-resolution panels.

use core::fmt;

use font8x8::legacy::BASIC_LEGACY;

const FONT_SIZE: usize = 8;
const SCALE: usize = 2;
/// Width and height of one character cell in framebuffer pixels.
pub const CELL: usize = FONT_SIZE * SCALE;

/// Geometry and pixel format of a linear framebuffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelLayout {
    /// Visible width in pixels.
    pub width: usize,
    /// Visible height in pixels.
    pub height: usize,
    /// Bytes from the start of one row to the start of the next.
    pub pitch: usize,
    /// Bytes per pixel (3 or 4 are supported).
    pub bytes_per_pixel: usize,
    /// Bit position of the least-significant red bit within a pixel.
    pub red_shift: u8,
    /// Number of red bits (1 to 8).
    pub red_size: u8,
    /// Bit position of the least-significant green bit.
    pub green_shift: u8,
    /// Number of green bits (1 to 8).
    pub green_size: u8,
    /// Bit position of the least-significant blue bit.
    pub blue_shift: u8,
    /// Number of blue bits (1 to 8).
    pub blue_size: u8,
}

impl PixelLayout {
    /// Number of bytes a buffer must have to hold every visible pixel, or
    /// `None` if the description is inconsistent or unsupported.
    ///
    /// The values come from firmware, so every step uses checked
    /// arithmetic (SR-19, SR-20).
    pub fn required_len(&self) -> Option<usize> {
        if !(3..=4).contains(&self.bytes_per_pixel) || self.width == 0 || self.height == 0 {
            return None;
        }
        let row_bytes = self.width.checked_mul(self.bytes_per_pixel)?;
        if self.pitch < row_bytes {
            return None;
        }
        let pixel_bits = self.bytes_per_pixel * 8;
        for (shift, size) in [
            (self.red_shift, self.red_size),
            (self.green_shift, self.green_size),
            (self.blue_shift, self.blue_size),
        ] {
            if !(1..=8).contains(&size) || usize::from(shift) + usize::from(size) > pixel_bits {
                return None;
            }
        }
        self.pitch
            .checked_mul(self.height - 1)?
            .checked_add(row_bytes)
    }

    /// Encodes an 8-bit-per-channel colour into this layout's pixel value.
    fn encode(&self, red: u8, green: u8, blue: u8) -> u32 {
        let channel = |value: u8, shift: u8, size: u8| -> u32 {
            // `size` is 1..=8 (checked in `required_len`), so the shift
            // amounts below are in range.
            (u32::from(value) >> (8 - u32::from(size))) << u32::from(shift)
        };
        channel(red, self.red_shift, self.red_size)
            | channel(green, self.green_shift, self.green_size)
            | channel(blue, self.blue_shift, self.blue_size)
    }
}

/// A scrolling text console drawn into a framebuffer.
pub struct TextConsole<'a> {
    buf: &'a mut [u8],
    layout: PixelLayout,
    cols: usize,
    rows: usize,
    col: usize,
    row: usize,
    fg: u32,
    bg: u32,
}

impl<'a> TextConsole<'a> {
    /// Creates a console over `buf` and clears it.
    ///
    /// Returns `None` if the layout is unsupported, the buffer is too small
    /// for it, or the screen is smaller than one character cell.
    pub fn new(buf: &'a mut [u8], layout: PixelLayout) -> Option<Self> {
        let required = layout.required_len()?;
        if buf.len() < required {
            return None;
        }
        let cols = layout.width / CELL;
        let rows = layout.height / CELL;
        if cols == 0 || rows == 0 {
            return None;
        }
        let mut console = Self {
            buf,
            layout,
            cols,
            rows,
            col: 0,
            row: 0,
            fg: layout.encode(0xE6, 0xE6, 0xE6),
            bg: layout.encode(0x10, 0x18, 0x28),
        };
        console.clear();
        Some(console)
    }

    /// Text columns on screen.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Text rows on screen.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Current cursor position as `(column, row)`.
    pub fn cursor(&self) -> (usize, usize) {
        (self.col, self.row)
    }

    /// Fills the whole screen with the background colour and homes the cursor.
    pub fn clear(&mut self) {
        for y in 0..self.layout.height {
            self.fill_span(0, y, self.layout.width, self.bg);
        }
        self.col = 0;
        self.row = 0;
    }

    /// Byte range of pixel `(x, y)`. Callers keep `x < width`, `y < height`;
    /// `new` checked that every such pixel lies inside `buf`.
    fn pixel_range(&self, x: usize, y: usize) -> core::ops::Range<usize> {
        let start = y * self.layout.pitch + x * self.layout.bytes_per_pixel;
        start..start + self.layout.bytes_per_pixel
    }

    fn fill_span(&mut self, x: usize, y: usize, count: usize, value: u32) {
        let bytes = value.to_le_bytes();
        let bpp = self.layout.bytes_per_pixel;
        for i in 0..count {
            let range = self.pixel_range(x + i, y);
            self.buf[range].copy_from_slice(&bytes[..bpp]);
        }
    }

    fn read_pixel(&self, x: usize, y: usize) -> u32 {
        let mut bytes = [0u8; 4];
        let bpp = self.layout.bytes_per_pixel;
        bytes[..bpp].copy_from_slice(&self.buf[self.pixel_range(x, y)]);
        u32::from_le_bytes(bytes)
    }

    /// Bitmap for `ch`; anything outside printable ASCII is shown as `?`.
    fn glyph(ch: char) -> [u8; FONT_SIZE] {
        let code = if ch.is_ascii_graphic() || ch == ' ' {
            ch as usize
        } else {
            b'?' as usize
        };
        BASIC_LEGACY[code]
    }

    fn draw_glyph(&mut self, col: usize, row: usize, ch: char) {
        let glyph = Self::glyph(ch);
        for (gy, bits) in glyph.iter().enumerate() {
            for gx in 0..FONT_SIZE {
                let value = if bits & (1 << gx) != 0 {
                    self.fg
                } else {
                    self.bg
                };
                for dy in 0..SCALE {
                    self.fill_span(
                        col * CELL + gx * SCALE,
                        row * CELL + gy * SCALE + dy,
                        SCALE,
                        value,
                    );
                }
            }
        }
    }

    /// Whether the cell at `(col, row)` currently shows exactly the glyph
    /// for `ch` in the console colours. Used by the boot self-test to prove
    /// that text really reached the framebuffer.
    pub fn glyph_matches(&self, col: usize, row: usize, ch: char) -> bool {
        if col >= self.cols || row >= self.rows {
            return false;
        }
        let glyph = Self::glyph(ch);
        for (gy, bits) in glyph.iter().enumerate() {
            for gx in 0..FONT_SIZE {
                let expected = if bits & (1 << gx) != 0 {
                    self.fg
                } else {
                    self.bg
                };
                for dy in 0..SCALE {
                    for dx in 0..SCALE {
                        let x = col * CELL + gx * SCALE + dx;
                        let y = row * CELL + gy * SCALE + dy;
                        if self.read_pixel(x, y) != expected {
                            return false;
                        }
                    }
                }
            }
        }
        true
    }

    /// Whether `text` is displayed starting at `(col, row)` on one line.
    pub fn text_matches(&self, col: usize, row: usize, text: &str) -> bool {
        text.chars()
            .enumerate()
            .all(|(i, ch)| self.glyph_matches(col + i, row, ch))
    }

    fn newline(&mut self) {
        self.col = 0;
        if self.row + 1 < self.rows {
            self.row += 1;
        } else {
            self.scroll();
        }
    }

    /// Moves every text row up by one and blanks the last row.
    fn scroll(&mut self) {
        let row_bytes = CELL * self.layout.pitch;
        let text_pixel_rows = self.rows * CELL;
        // The last pixel row may be shorter than `pitch` in the buffer, so
        // the copied region ends at the last pixel actually present.
        let end = (text_pixel_rows * self.layout.pitch).min(self.buf.len());
        self.buf.copy_within(row_bytes..end, 0);
        for y in (text_pixel_rows - CELL)..text_pixel_rows {
            self.fill_span(0, y, self.layout.width, self.bg);
        }
    }

    /// Draws one character at the cursor and advances it.
    pub fn put_char(&mut self, ch: char) {
        match ch {
            '\n' => self.newline(),
            '\r' => self.col = 0,
            // Backspace moves left within the line (terminal behaviour;
            // the echo of an erased character is BS, space, BS).
            '\u{8}' => self.col = self.col.saturating_sub(1),
            _ => {
                if self.col >= self.cols {
                    self.newline();
                }
                self.draw_glyph(self.col, self.row, ch);
                self.col += 1;
            }
        }
    }
}

impl fmt::Write for TextConsole<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for ch in s.chars() {
            self.put_char(ch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    fn bgrx(width: usize, height: usize) -> PixelLayout {
        PixelLayout {
            width,
            height,
            pitch: width * 4 + 8, // deliberately padded rows
            bytes_per_pixel: 4,
            red_shift: 16,
            red_size: 8,
            green_shift: 8,
            green_size: 8,
            blue_shift: 0,
            blue_size: 8,
        }
    }

    fn buffer(layout: &PixelLayout) -> Vec<u8> {
        vec![0xAA; layout.required_len().unwrap()]
    }

    #[test]
    fn required_len_counts_last_row_without_padding() {
        let layout = bgrx(64, 32);
        assert_eq!(layout.required_len(), Some((64 * 4 + 8) * 31 + 64 * 4));
    }

    #[test]
    fn rejects_inconsistent_layouts() {
        let mut layout = bgrx(64, 32);
        layout.pitch = 10; // shorter than one row
        assert_eq!(layout.required_len(), None);

        let mut layout = bgrx(64, 32);
        layout.bytes_per_pixel = 2;
        assert_eq!(layout.required_len(), None);

        let mut layout = bgrx(64, 32);
        layout.red_shift = 28; // 28 + 8 bits does not fit in 32
        assert_eq!(layout.required_len(), None);

        let mut layout = bgrx(64, 32);
        layout.green_size = 0;
        assert_eq!(layout.required_len(), None);

        let mut layout = bgrx(64, 32);
        layout.width = usize::MAX;
        assert_eq!(layout.required_len(), None);
    }

    #[test]
    fn rejects_short_buffer_and_tiny_screen() {
        let layout = bgrx(64, 32);
        let mut short = vec![0u8; layout.required_len().unwrap() - 1];
        assert!(TextConsole::new(&mut short, layout).is_none());

        let tiny = bgrx(CELL - 1, CELL);
        let mut buf = buffer(&tiny);
        assert!(TextConsole::new(&mut buf, tiny).is_none());
    }

    #[test]
    fn encodes_channels_for_rgb565_style_masks() {
        let layout = PixelLayout {
            width: 16,
            height: 16,
            pitch: 48,
            bytes_per_pixel: 3,
            red_shift: 11,
            red_size: 5,
            green_shift: 5,
            green_size: 6,
            blue_shift: 0,
            blue_size: 5,
        };
        assert_eq!(layout.encode(0xFF, 0x00, 0x00), 0b11111 << 11);
        assert_eq!(layout.encode(0x00, 0xFF, 0x00), 0b111111 << 5);
        assert_eq!(layout.encode(0x00, 0x00, 0xFF), 0b11111);
    }

    #[test]
    fn draws_glyph_pixels_scaled() {
        let layout = bgrx(64, 32);
        let mut buf = buffer(&layout);
        let mut console = TextConsole::new(&mut buf, layout).unwrap();
        console.put_char('A');
        let (fg, bg) = (console.fg, console.bg);
        // font8x8 'A' row 0 is 0x0C: font pixels 2 and 3 are set.
        assert_eq!(BASIC_LEGACY[b'A' as usize][0], 0x0C);
        for x in 0..CELL {
            let expected = if (4..8).contains(&x) { fg } else { bg };
            assert_eq!(console.read_pixel(x, 0), expected, "x = {x}");
            assert_eq!(console.read_pixel(x, 1), expected, "x = {x}");
        }
        assert!(console.glyph_matches(0, 0, 'A'));
        assert!(!console.glyph_matches(0, 0, 'B'));
        assert!(console.glyph_matches(1, 0, ' '));
        assert_eq!(console.cursor(), (1, 0));
    }

    #[test]
    fn padding_bytes_are_never_written() {
        let layout = bgrx(32, 32);
        let mut buf = buffer(&layout);
        {
            let mut console = TextConsole::new(&mut buf, layout).unwrap();
            for _ in 0..20 {
                console.write_str("XXXXXXXX\n").unwrap();
            }
        }
        for y in 0..31 {
            let pad = y * layout.pitch + layout.width * 4;
            assert_eq!(&buf[pad..pad + 8], &[0xAA; 8], "row {y}");
        }
    }

    #[test]
    fn wraps_and_scrolls() {
        let layout = bgrx(4 * CELL, 2 * CELL); // 4 columns, 2 rows
        let mut buf = buffer(&layout);
        let mut console = TextConsole::new(&mut buf, layout).unwrap();
        console.write_str("abcdef").unwrap(); // wraps after 4 columns
        assert!(console.text_matches(0, 0, "abcd"));
        assert!(console.text_matches(0, 1, "ef"));
        console.write_str("\ngh").unwrap(); // scrolls
        assert!(console.text_matches(0, 0, "ef  "));
        assert!(console.text_matches(0, 1, "gh  "));
        assert_eq!(console.cursor(), (2, 1));
    }

    #[test]
    fn non_ascii_is_shown_as_question_mark() {
        let layout = bgrx(64, 32);
        let mut buf = buffer(&layout);
        let mut console = TextConsole::new(&mut buf, layout).unwrap();
        console.write_str("\u{e9}\u{7}").unwrap();
        assert!(console.text_matches(0, 0, "??"));
    }

    #[test]
    fn text_matches_out_of_range_is_false() {
        let layout = bgrx(64, 32);
        let mut buf = buffer(&layout);
        let console = TextConsole::new(&mut buf, layout).unwrap();
        assert!(!console.glyph_matches(4, 0, ' '));
        assert!(!console.glyph_matches(0, 2, ' '));
    }
}
