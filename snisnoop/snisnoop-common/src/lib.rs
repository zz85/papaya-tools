#![no_std]

use core::mem;

#[derive(Debug)]
#[repr(C)]
pub struct RawPacket {
    pub data: [u8; 3000],
    pub len: u32,
}

impl RawPacket {
    pub const LEN: usize = mem::size_of::<RawPacket>();
}
