#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use spawnsnoop_common::SpawnInfo;

#[map]
static RINGBUF: RingBuf = RingBuf::with_byte_size(1000 * SpawnInfo::STRUCT_SIZE as u32, 0);

#[tracepoint]
pub fn spawnsnoop(ctx: TracePointContext) -> u32 {
    match try_spawnsnoop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_spawnsnoop(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sys_enter_execve called");

    send_to_ringbuf(ctx);

    Ok(0)
}

#[inline]
fn send_to_ringbuf(ctx: TracePointContext) -> bool {
    let Some(mut buf) = RINGBUF.reserve::<SpawnInfo>(0) else {
        return false;
    };

    let info = unsafe { buf.assume_init_mut() };

    info.pid = ctx.pid();
    if let Ok(cmd) = ctx.command() {
        info.command = cmd;
    }

    // usage of RingBufEntry requires us to submit or discard after reserving
    buf.submit(0);
    true
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
