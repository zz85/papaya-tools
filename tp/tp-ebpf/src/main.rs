#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::__sk_buff, helpers::bpf_probe_read_kernel, macros::raw_tracepoint, programs::{
        sk_buff::{self, SkBuff},
        RawTracePointContext,
    }, EbpfContext
};
use aya_log_ebpf::info;
use network_types::eth::EthHdr;

#[raw_tracepoint(tracepoint = "net_dev_queue")]
pub fn tp(ctx: RawTracePointContext) -> i32 {
    match try_tp(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tp(ctx: RawTracePointContext) -> Result<i32, i32> {
    info!(&ctx, "tracepoint net_dev_queue called");

    // let g = ctx.gid()?;
    // ctx.tgid()
    // let pid = ctx.pid();

    // info!(&ctx, "PID {}", pid);

    // let cmd = ctx.command().map_err(|_e| 0)?;
    // let s = core::str::from_utf8(&cmd).unwrap();
    // info!(&ctx, "CMD {}", s);

    // let buf = unsafe {
    //     let ptr: *const *const __sk_buff = ctx.arg(0);
    //     // let skb = SkBuff::new(ptr as *mut _);
    //     // skb
    //     *ptr
    // };

    let buf = unsafe {
        let ptr: u8 = ctx.arg(0);
        &ptr
    };
    

    // unsafe {
    //     let buf = *bpf_probe_read_kernel(&buf ).map_err(|_e| 0)?;
    //     let len = buf.len;
    //     info!(&ctx, "test {}",  len);
    // }

    

    // 
    // info!(&ctx, "skb len {}", len );

    // let ethhdr: EthHdr = buf.load(0).map_err(|_| 0)?;

    info!(&ctx, "ok");

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
