#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    cty::c_long,
    macros::{classifier, map},
    maps::{PerCpuArray},
    programs::TcContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
};
use snisnoop_common::RawPacket;

// will need >= Linux 5.8
// #[map]
// static DATA: RingBuf = RingBuf::with_byte_size(100 * RawPacket::LEN as u32, 0);
// #[map]
// pub static mut BUF: PerCpuArray<RawPacket> = PerCpuArray::with_max_entries(1100, 0);

#[classifier]
pub fn snisnoop(ctx: TcContext) -> i32 {
    match try_snisnoop(ctx) {
        Ok(ret) => ret,
        Err(ret) => -1,
    }
}

#[repr(C)]
pub struct Buf {
    pub buf: [u8; 128],
}
///
#[map]
pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
fn try_snisnoop(ctx: TcContext) -> Result<i32, c_long> {
    let uid = ctx.get_socket_uid();

    let ethhdr: EthHdr = ctx.load(0)?;

    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let header = ctx.load::<Ipv4Hdr>(EthHdr::LEN)?;

            match header.proto {
                IpProto::Tcp => {
                    let dst_addr = header.dst_addr();
                    let src_addr = header.src_addr();

                    let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN)?;
                    let src_port = u16::from_be(tcphdr.source);
                    let dst_port = u16::from_be(tcphdr.dest);

                    // warning: network_types doesn't seem to take into account
                    // ipv4 header options (should be doing header.total_len() - options..)
                    //  so this is going to work on best effort
                    // basis
                    //

                    // let mut buf: [u8; 1500] = [0; 1500];
                    // let size =
                    //     ctx.load_bytes(EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN, &mut buf)?;

                    if dst_port != 443 {
                        return Ok(TC_ACT_PIPE);
                    }

                    info!(
                        &ctx,
                        "ipv4 {}:{} -> {}:{}", src_addr, src_port, dst_addr, dst_port
                    );
                }
                _ => return Ok(TC_ACT_PIPE),
            };
        }
        EtherType::Ipv6 => {
            let header = ctx.load::<Ipv6Hdr>(EthHdr::LEN)?;

            let dst = header.dst_addr();
            let src = header.src_addr();
            match header.next_hdr {
                IpProto::Tcp => {
                    info!(&ctx, "ipv6 src {} -> {}", src, dst);
                    let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv6Hdr::LEN)?;
                }
                _ => return Ok(TC_ACT_PIPE),
            };
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    info!(&ctx, "received a packet {}", uid);

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
