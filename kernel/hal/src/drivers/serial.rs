//! 16550 UART driver, used for COM1 at 115200 8N1: polled transmit, and
//! receive by interrupt once [`SerialPort::enable_rx_interrupt`] is called
//! (P3-T12).
//!
//! Register layout and the initialisation order follow the PC16550D
//! datasheet (Texas Instruments/National Semiconductor, "PC16550D Universal
//! Asynchronous Receiver/Transmitter with FIFOs", register summary table)
//! and the OSDev wiki article "Serial Ports".

use core::fmt;

use crate::arch::x86_64::port::{inb, outb};

/// I/O base of the first PC serial port.
pub const COM1_BASE: u16 = 0x3F8;
/// COM2: the second ISA serial port. Under QEMU, the second `-serial`
/// option is placed here (QEMU 8.2.2 `hw/char/serial-isa.c`,
/// `isa_serial_io`: 0x3f8, 0x2f8, 0x3e8, 0x2e8).
pub const COM2_BASE: u16 = 0x2F8;

// Register offsets from the base port (PC16550D register summary).
const REG_DATA: u16 = 0; // THR (write) / RBR (read); DLL when DLAB = 1
const REG_INT_ENABLE: u16 = 1; // IER; DLM when DLAB = 1
const REG_FIFO_CTRL: u16 = 2; // FCR (write)
const REG_LINE_CTRL: u16 = 3; // LCR
const REG_MODEM_CTRL: u16 = 4; // MCR
const REG_LINE_STATUS: u16 = 5; // LSR

const LCR_DLAB: u8 = 0x80; // divisor latch access bit
const LCR_8N1: u8 = 0x03; // 8 data bits, no parity, 1 stop bit
const FCR_ENABLE_CLEAR_14: u8 = 0xC7; // FIFOs on, both cleared, 14-byte trigger
const MCR_DTR_RTS: u8 = 0x03;
const MCR_OUT2: u8 = 0x08; // bit 3: OUT2, which gates the IRQ line on PCs
const MCR_LOOPBACK: u8 = 0x10; // bit 4: local loopback
const IER_RX_AVAILABLE: u8 = 0x01; // bit 0: received data available
const LSR_DATA_READY: u8 = 0x01;
const LSR_THR_EMPTY: u8 = 0x20; // bit 5: transmit holding register empty
const LSR_TX_EMPTY: u8 = 0x40; // bit 6: transmitter (THR and shift register) empty

/// The UART clock (1.8432 MHz) divided by 16 gives 115200 baud at divisor 1.
const DIVISOR_115200: u16 = 1;

/// How many status polls to wait for the transmitter before dropping a byte.
/// Bounded so that a missing or stuck UART can never hang the kernel.
const TX_SPIN_LIMIT: u32 = 100_000;

/// A polled 16550 UART.
pub struct SerialPort {
    base: u16,
    present: bool,
}

/// Nanoseconds to wait before each byte; 0 (the default) means none. Set
/// only by self-tests, to make the emulated UART as slow as a real one:
/// 115200 baud with 8N1 framing carries 10 bits per byte, 11,520 bytes a
/// second, about 86.8 µs each (audit 2, A3).
pub static TEST_BYTE_DELAY_NS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

impl SerialPort {
    /// Creates a handle for the UART at `base` without touching hardware.
    ///
    /// # Safety
    ///
    /// `base` must be the I/O base of a 16550-compatible UART (or of
    /// nothing at all), and the caller must not create a second handle
    /// that is used concurrently with this one.
    pub const unsafe fn new(base: u16) -> Self {
        Self {
            base,
            present: false,
        }
    }

    /// A handle for a UART that `init` already set up and found working,
    /// without touching it again (so its interrupt settings stay).
    ///
    /// # Safety
    ///
    /// As [`SerialPort::new`]; `init` must have returned true for `base`.
    pub const unsafe fn attached(base: u16) -> Self {
        Self {
            base,
            present: true,
        }
    }

    /// Programs 115200 8N1 with FIFOs and runs a loopback self-test.
    ///
    /// Returns whether a working UART answered. When it did not (the target
    /// machine's serial port is an optional add-in), all later writes are
    /// silently dropped.
    pub fn init(&mut self) -> bool {
        // SAFETY: by the contract of `new`, `base..base+8` is a UART or is
        // undecoded. Programming a UART's own registers cannot affect
        // memory safety.
        unsafe {
            outb(self.base + REG_INT_ENABLE, 0x00); // no UART interrupts
            outb(self.base + REG_LINE_CTRL, LCR_DLAB);
            outb(self.base + REG_DATA, DIVISOR_115200.to_le_bytes()[0]);
            outb(self.base + REG_INT_ENABLE, DIVISOR_115200.to_le_bytes()[1]);
            outb(self.base + REG_LINE_CTRL, LCR_8N1); // also clears DLAB
            outb(self.base + REG_FIFO_CTRL, FCR_ENABLE_CLEAR_14);

            // Loopback test: in loopback mode a transmitted byte comes
            // straight back on the receiver and never reaches the wire.
            outb(self.base + REG_MODEM_CTRL, MCR_LOOPBACK | MCR_DTR_RTS);
            outb(self.base + REG_DATA, 0xAE);
            let mut echoed = false;
            for _ in 0..TX_SPIN_LIMIT {
                if inb(self.base + REG_LINE_STATUS) & LSR_DATA_READY != 0 {
                    echoed = inb(self.base + REG_DATA) == 0xAE;
                    break;
                }
            }
            outb(self.base + REG_MODEM_CTRL, MCR_DTR_RTS);
            self.present = echoed;
        }
        self.present
    }

    /// Whether `init` found a working UART.
    pub fn is_present(&self) -> bool {
        self.present
    }

    /// Writes bytes as they are (no newline translation): terminal output,
    /// which the line discipline has already processed (ONLCR).
    pub fn write_raw(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b);
        }
    }

    /// Turns on the received-data interrupt (IER bit 0) and OUT2, which on
    /// a PC connects the UART's interrupt output to the interrupt
    /// controller (PC16550D datasheet, MCR bit 3 and IER bit 0; Linux
    /// `serial8250_do_startup` sets UART_MCR_OUT2 for the same reason).
    pub fn enable_rx_interrupt(&mut self) {
        if !self.present {
            return;
        }
        // SAFETY: as in `init`: programming our own UART's registers.
        unsafe {
            outb(self.base + REG_MODEM_CTRL, MCR_DTR_RTS | MCR_OUT2);
            outb(self.base + REG_INT_ENABLE, IER_RX_AVAILABLE);
        }
    }

    /// Takes received bytes into `buf` while the line status register
    /// says data is ready; returns how many. Reading RBR clears the
    /// received-data interrupt once the FIFO is below its trigger level.
    pub fn read_received(&mut self, buf: &mut [u8]) -> usize {
        if !self.present {
            return 0;
        }
        let mut n = 0;
        while n < buf.len() {
            // SAFETY: reading LSR has no side effect that matters; reading
            // RBR when DR is set takes one received byte.
            unsafe {
                if inb(self.base + REG_LINE_STATUS) & LSR_DATA_READY == 0 {
                    break;
                }
                buf[n] = inb(self.base + REG_DATA);
            }
            n += 1;
        }
        n
    }

    /// Sends `bytes` back to the receiver in loopback mode (MCR bit 4),
    /// where nothing reaches the wire, then leaves loopback. For
    /// self-tests: the bytes then arrive as received data, with its
    /// interrupt. Returns whether the transmitter emptied in time.
    pub fn loop_back(&mut self, bytes: &[u8]) -> bool {
        if !self.present {
            return false;
        }
        // SAFETY: as in `init`.
        unsafe {
            outb(
                self.base + REG_MODEM_CTRL,
                MCR_LOOPBACK | MCR_DTR_RTS | MCR_OUT2,
            )
        };
        for &b in bytes {
            self.write_byte(b);
        }
        let mut empty = false;
        for _ in 0..TX_SPIN_LIMIT {
            // SAFETY: as in `write_byte`.
            if unsafe { inb(self.base + REG_LINE_STATUS) } & LSR_TX_EMPTY != 0 {
                empty = true;
                break;
            }
        }
        // SAFETY: as in `init`.
        unsafe { outb(self.base + REG_MODEM_CTRL, MCR_DTR_RTS | MCR_OUT2) };
        empty
    }

    fn write_byte(&mut self, byte: u8) {
        if !self.present {
            return;
        }
        // Test knob: emulate a real UART's speed (QEMU's is instant).
        #[cfg(target_os = "none")]
        let delay = TEST_BYTE_DELAY_NS.load(core::sync::atomic::Ordering::Relaxed);
        #[cfg(target_os = "none")]
        if delay != 0 {
            crate::time::spin_ns(delay);
        }
        for _ in 0..TX_SPIN_LIMIT {
            // SAFETY: reading the line-status register of our own UART has
            // no side effect that matters here.
            if unsafe { inb(self.base + REG_LINE_STATUS) } & LSR_THR_EMPTY != 0 {
                // SAFETY: the transmitter is ready; writing THR sends a byte.
                unsafe { outb(self.base + REG_DATA, byte) };
                return;
            }
        }
        // Transmitter never became ready: drop the byte rather than hang.
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
        Ok(())
    }
}
