#![no_std]

use aya_ebpf::macros::map;
use aya_ebpf::maps::RingBuf;
use aya_ebpf::programs::TcContext;
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    udp::UdpHdr,
};
use quicsnoop_common::QuicPacket;

const QUIC_LONG_PACKET_TYPE_MASK: u8 = 0x30;

#[map]
static DATA: RingBuf = RingBuf::with_byte_size(1000 * QuicPacket::LEN as u32, 0);

#[inline]
pub fn parse_packet(ctx: &TcContext) -> Result<bool, i64> {
    let ethhdr: EthHdr = ctx.load(0)?;

    match ethhdr.ether_type {
        EtherType::Ipv4 => {
            let header = ctx.load::<Ipv4Hdr>(EthHdr::LEN)?;

            match header.proto {
                IpProto::Udp => {
                    let src = header.src_addr();
                    let dst = header.dst_addr();
                    let udp: UdpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN)?;
                    let src_port = udp.source();
                    let dst_port = udp.dest();

                    let flag: u8 = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;

                    // TODO confirm calculation
                    let parse = flag & QUIC_LONG_PACKET_TYPE_MASK == 0;

                    info!(
                        ctx,
                        "ipv4 src {}:{} -> {}:{} flag: {}, parse: {}",
                        src,
                        src_port,
                        dst,
                        dst_port,
                        flag,
                        parse as u8
                    );

                    let ret = copy_data_to_userspace(ctx);

                    info!(ctx, "len {} - {}", ctx.len(), ret as u8);
                }
                _ => return Ok(false),
            };
        }
        EtherType::Ipv6 => {
            let header = ctx.load::<Ipv6Hdr>(EthHdr::LEN)?;

            match header.next_hdr {
                IpProto::Udp => {
                    let dst = header.dst_addr();
                    let src = header.src_addr();
                    let udp: UdpHdr = ctx.load(EthHdr::LEN + Ipv6Hdr::LEN)?;
                    let src_port = udp.source();
                    let dst_port = udp.dest();

                    let flag: u8 = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN)?;

                    info!(
                        ctx,
                        "ipv6 src {}:{} -> {}:{} flag: {}", src, src_port, dst, dst_port, flag
                    );

                    copy_data_to_userspace(ctx);
                }
                _ => return Ok(false),
            };
        }
        _ => return Ok(false),
    }

    Ok(true)
}

#[inline]
fn copy_data_to_userspace(ctx: &TcContext) -> bool {
    let Some(mut buf) = DATA.reserve::<QuicPacket>(0) else {
        return false;
    };

    let packet = unsafe { buf.assume_init_mut() };

    // let ebpf verifier know that there's at least a single byte in skbuff's data
    // which would be a requirement for bpf_skb_load_bytes() to work
    if ctx.len() < 2 {
        buf.discard(0);
        return false;
    }

    if let Ok(len) = ctx.load_bytes(0, &mut packet.data) {
        packet.len = len as u32;
    }

    // usage of RingBufEntry requires us to submit or discard after reserving
    buf.submit(0);
    true
}
