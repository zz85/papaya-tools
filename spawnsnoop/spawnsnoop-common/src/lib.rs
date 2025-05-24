#![no_std]

use core::mem;

pub const TASK_COMM_LEN: usize = 16;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SpawnInfo {
    pub pid: u32,
    pub command: [u8; TASK_COMM_LEN],
    pub event: Event,
}

impl SpawnInfo {
    pub const STRUCT_SIZE: usize = mem::size_of::<SpawnInfo>();
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub enum Event {
    Execve,
    ExecveDone,
    Exit,
    ExitDone,

    ProcessFork,
    ProcessExit,
}

/*
format:
field:unsigned short common_type;       offset:0;       size:2; signed:0;
field:unsigned char common_flags;       offset:2;       size:1; signed:0;
field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
field:int common_pid;   offset:4;       size:4; signed:1;
 */
