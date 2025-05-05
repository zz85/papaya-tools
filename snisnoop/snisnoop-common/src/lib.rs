#![no_std]

use core::mem;

#[repr(C)]
pub struct RawPacket {
    pub data: [u8; 1500],
    pub len: u32,
}

impl RawPacket {
    pub const LEN: usize = mem::size_of::<RawPacket>();
}
