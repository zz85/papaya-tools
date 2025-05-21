#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[xdp]
pub fn ipipsnoop(ctx: XdpContext) -> u32 {
    match try_ipipsnoop(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct IpipEvent {
    outer_src: u32,
    outer_dst: u32,
    inner_src: u32,
    inner_dst: u32,
}

fn try_ipipsnoop(ctx: XdpContext) -> Result<u32, ()> {
    // Parse ethernet header
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Parse outer IP header
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => return Ok(xdp_action::XDP_PASS),
        IpProto::Udp => return Ok(xdp_action::XDP_PASS),
        IpProto::Ipv4 => {
            info!(&ctx, "received a IP in IP packet");
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    //

    info!(&ctx, "SRC IP: {:i}", source_addr);
    // Parse inner IP header
    let inner_ip = unsafe { ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };

    let inner_ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let inner_source_addr = u32::from_be_bytes(unsafe { (*inner_ipv4hdr).src_addr });

    let udp_source_port = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => return Ok(xdp_action::XDP_PASS),
        IpProto::Udp => {
            info!(&ctx, "received a inner UDP packet");
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            u16::from_be_bytes(unsafe { (*udphdr).source })
        }
        IpProto::Ipv4 => {
            info!(&ctx, "received a inner IP in IP packet");
            return Ok(xdp_action::XDP_PASS);
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    info!(
        &ctx,
        "INNER: SRC IP: {:i}, SRC PORT: {}", inner_source_addr, udp_source_port
    );

    // Create event
    // let event = IpipEvent {
    //     outer_src: u32::from_be_bytes(outer_ip.src_addr),
    //     outer_dst: u32::from_be_bytes(outer_ip.dst_addr),
    //     inner_src: u32::from_be_bytes(inner_ip.src_addr),
    //     inner_dst: u32::from_be_bytes(inner_ip.dst_addr),
    // };

    info!(&ctx, "received a IP in IP packet");
    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
