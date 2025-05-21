#![no_std]
#![no_main]

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::classifier, programs::TcContext};
use aya_log_ebpf::{debug, info};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[classifier]
pub fn ipswap(ctx: TcContext) -> i32 {
    match try_ipswap(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ipswap(ctx: TcContext) -> Result<i32, i32> {
    debug!(&ctx, "received a packet");
    if let Ok(_) = parse_packet(ctx) {}
    Ok(TC_ACT_PIPE)
}

#[inline]
pub fn parse_packet(mut ctx: TcContext) -> Result<bool, i64> {
    let ethhdr: EthHdr = ctx.load(0)?;

    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let mut header = ctx.load::<Ipv4Hdr>(EthHdr::LEN)?;

            match header.proto {
                IpProto::Udp => {
                    let src = header.src_addr();
                    let dst = header.dst_addr();
                    let udp: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN)?;
                    let src_port = udp.source();
                    let dst_port = udp.dest();

                    if !(src_port == 12543 || dst_port == 12543) {
                        return Err(0);
                    }

                    info!(
                        &ctx,
                        "ipv4 src {}:{} -> {}:{} ", src, src_port, dst, dst_port,
                    );
                }
                _ => return Ok(false),
            };

            info!(&ctx, "Modifying packet");

            // Replaces the source IP address with something else
            header.src_addr[0] = 1;
            header.src_addr[1] = 1;
            header.src_addr[2] = 1;
            header.src_addr[3] = 1;

            ctx.store::<Ipv4Hdr>(EthHdr::LEN, &header, 0)?;
        }
        _ => return Ok(false),
    }

    Ok(true)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
