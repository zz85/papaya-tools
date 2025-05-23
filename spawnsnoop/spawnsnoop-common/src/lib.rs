#![no_std]

use core::mem;

pub const TASK_COMM_LEN: usize = 16;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SpawnInfo {
    pub pid: u32,
    pub command: [u8; TASK_COMM_LEN],
}

impl SpawnInfo {
    pub const STRUCT_SIZE: usize = mem::size_of::<SpawnInfo>();
}
