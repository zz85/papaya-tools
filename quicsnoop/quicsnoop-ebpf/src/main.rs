#![no_std]
#![no_main]

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use aya_log_ebpf::info;
use quicsnoop_ebpf::parse_packet;

#[classifier]
pub fn quicsnoop(ctx: TcContext) -> i32 {
    match try_quicsnoop(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_quicsnoop(ctx: TcContext) -> Result<i32, i32> {
    // info!(&ctx, "received a packet");

    let _ = parse_packet(&ctx);
    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
