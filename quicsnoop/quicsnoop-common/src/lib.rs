#![no_std]

use core::mem;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct QuicPacket {
    /// Fix size allocation for packet data
    pub data: [u8; 3000],
    pub len: u32,
}

impl QuicPacket {
    pub const STRUCT_SIZE: usize = mem::size_of::<QuicPacket>();
}
