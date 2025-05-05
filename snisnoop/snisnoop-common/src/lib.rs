#![no_std]

use core::mem;

#[derive(Debug)]
#[repr(C)]
pub struct RawPacket {
    /// Fix size allocation for packet data
    pub data: [u8; 3000],
    /// Len of packet data written in
    pub len: u32,
    /// Process id
    pub tgid: u32,
}

impl RawPacket {
    pub const LEN: usize = mem::size_of::<RawPacket>();
}
