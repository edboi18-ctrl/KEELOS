//! i8042 PS/2 keyboard controller (P1-T14; QEMU and machines with a real
//! or emulated 8042).
//!
//! Registers, commands and bits from Linux `drivers/input/serio/
//! i8042-io.h` (data 0x60, status/command 0x64, keyboard IRQ 1) and
//! `include/linux/i8042.h` (status OBF 0x01, IBF 0x02, AUXDATA 0x20;
//! commands 0x20 read and 0x60 write the configuration byte, 0xAE enable
//! the keyboard port, 0xD2 "keyboard loop": the next data byte is returned
//! as if the keyboard sent it; configuration bits KBDINT 0x01, AUXINT
//! 0x02, KBDDIS 0x10, XLATE 0x40) at v6.12. QEMU implements 0xD2 by
//! queueing the byte as keyboard data (`hw/input/pckbd.c`,
//! KBD_CCMD_WRITE_OBUF), which the self-tests use to type.
//!
//! Translation (XLATE) is turned on, so the keyboard's set-2 codes reach
//! the kernel as set 1. Each received byte goes to the callback
//! registered with [`init`], in interrupt context.

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::arch::x86_64::port::{inb, outb};
use crate::interrupts;

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const COMMAND: u16 = 0x64;
const STR_OBF: u8 = 0x01;
const STR_IBF: u8 = 0x02;
const STR_AUXDATA: u8 = 0x20;
const CMD_READ_CTR: u8 = 0x20;
const CMD_WRITE_CTR: u8 = 0x60;
const CMD_KBD_ENABLE: u8 = 0xAE;
const CMD_KBD_LOOP: u8 = 0xD2;
const CTR_KBDINT: u8 = 0x01;
const CTR_AUXINT: u8 = 0x02;
const CTR_KBDDIS: u8 = 0x10;
const CTR_XLATE: u8 = 0x40;
const KEYBOARD_IRQ: u8 = 1;
/// Interrupt vector for the keyboard (the timer uses 0x20).
pub const KEYBOARD_VECTOR: u8 = 0x21;
/// Polls before giving up on the controller (each poll is one port read,
/// about a microsecond on ISA timing).
const TIMEOUT_POLLS: u32 = 100_000;
/// Most bytes taken from the controller per interrupt (its buffer holds
/// 16 on Linux's count, I8042_BUFFER_SIZE).
const DRAIN_MAX: u32 = 16;

/// Why the controller could not be set up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ps2Error {
    /// Status reads 0xFF: nothing decodes the ports.
    Absent,
    /// The controller did not accept a command or answer in time.
    Timeout,
    /// The interrupt could not be routed or the vector is taken.
    Interrupt,
}

static CALLBACK: AtomicUsize = AtomicUsize::new(0);

fn status() -> u8 {
    // SAFETY: reading the i8042 status register has no side effects.
    unsafe { inb(STATUS) }
}

fn wait_input_empty() -> Result<(), Ps2Error> {
    for _ in 0..TIMEOUT_POLLS {
        if status() & STR_IBF == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(Ps2Error::Timeout)
}

fn wait_output_full() -> Result<(), Ps2Error> {
    for _ in 0..TIMEOUT_POLLS {
        if status() & STR_OBF != 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(Ps2Error::Timeout)
}

fn command(byte: u8) -> Result<(), Ps2Error> {
    wait_input_empty()?;
    // SAFETY: the kernel owns the i8042; controller commands cannot touch
    // memory (it has no DMA).
    unsafe { outb(COMMAND, byte) };
    Ok(())
}

fn write_data(byte: u8) -> Result<(), Ps2Error> {
    wait_input_empty()?;
    // SAFETY: as `command`.
    unsafe { outb(DATA, byte) };
    Ok(())
}

fn read_data() -> Result<u8, Ps2Error> {
    wait_output_full()?;
    // SAFETY: reading the data port only consumes the byte.
    Ok(unsafe { inb(DATA) })
}

fn flush() {
    for _ in 0..DRAIN_MAX {
        if status() & STR_OBF == 0 {
            return;
        }
        // SAFETY: as `read_data`.
        let _ = unsafe { inb(DATA) };
    }
}

fn on_interrupt() {
    let callback = CALLBACK.load(Ordering::Acquire);
    for _ in 0..DRAIN_MAX {
        let s = status();
        if s & STR_OBF == 0 {
            break;
        }
        // SAFETY: as `read_data`; OBF is set, so a byte is waiting.
        let byte = unsafe { inb(DATA) };
        if s & STR_AUXDATA != 0 || callback == 0 {
            continue; // mouse data, or nobody listening yet
        }
        // SAFETY: the only non-zero value stored is a `fn(u8)` converted
        // to usize in `init`, so converting back gives that function.
        let callback: fn(u8) = unsafe { core::mem::transmute::<usize, fn(u8)>(callback) };
        callback(byte);
    }
}

/// Sets up the controller and the keyboard interrupt. `callback` is
/// called in interrupt context for each byte from the keyboard: it may
/// take `IrqMutex` locks and wake wait queues, but must not print (the
/// console locks are spinlocks a holder could have been interrupted in).
pub fn init(callback: fn(u8)) -> Result<(), Ps2Error> {
    if status() == 0xFF {
        return Err(Ps2Error::Absent);
    }
    flush();
    command(CMD_READ_CTR)?;
    let ctr = read_data()?;
    let ctr = (ctr | CTR_KBDINT | CTR_XLATE) & !(CTR_KBDDIS | CTR_AUXINT);
    command(CMD_WRITE_CTR)?;
    write_data(ctr)?;
    command(CMD_KBD_ENABLE)?;
    flush();
    CALLBACK.store(callback as usize, Ordering::Release);
    if !interrupts::set_handler(KEYBOARD_VECTOR, on_interrupt)
        || !interrupts::route_isa_irq(KEYBOARD_IRQ, KEYBOARD_VECTOR)
    {
        return Err(Ps2Error::Interrupt);
    }
    Ok(())
}

/// Makes the controller deliver `byte` as if the keyboard had sent it
/// (command 0xD2), raising the keyboard interrupt. For self-tests.
pub fn inject(byte: u8) -> Result<(), Ps2Error> {
    command(CMD_KBD_LOOP)?;
    write_data(byte)
}
