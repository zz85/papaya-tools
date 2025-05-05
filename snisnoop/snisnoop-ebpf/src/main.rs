#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    cty::c_long,
    helpers::r#gen::{bpf_get_current_task, bpf_skb_load_bytes},
    macros::{classifier, map},
    maps::{PerCpuArray, RingBuf},
    programs::{sk_buff::SkBuff, TcContext},
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
#[map]
static DATA: RingBuf = RingBuf::with_byte_size(100 * RawPacket::LEN as u32, 0);

#[map]
pub static mut BUF: PerCpuArray<[u8; 1024]> = PerCpuArray::with_max_entries(1, 0);

#[classifier]
#[inline]
pub fn snisnoop(ctx: TcContext) -> i32 {
    match try_snisnoop(ctx) {
        Ok(ret) => ret,
        Err(ret) => -1,
    }
}

#[inline]
pub fn load_bytes2(skb: &SkBuff, offset: usize, dst: &mut [u8]) -> Result<usize, c_long> {
    // let len = skb.len() as usize;
    let x = 1024;
    let ret = unsafe {
        bpf_skb_load_bytes(
            skb.skb as *const _,
            offset as u32,
            dst.as_mut_ptr() as *mut _,
            x as u32, // r4 (needs to be lower than allocated)
        )
    };
    if ret == 0 {
        Ok(4)
    } else {
        Err(ret)
    }
}

#[inline(always)]
fn try_snisnoop(ctx: TcContext) -> Result<i32, c_long> {
    // let uid = ctx.get_socket_uid();

    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(TC_ACT_PIPE)?;
        &mut *ptr
    };

    load_bytes2(&ctx.skb, 0, buf)?;
    // ctx.load_bytes(0,  buf).map_err(|e| 0)?;

    // if let Some(mut buf) = DATA.reserve::<RawPacket>(0) {
    //     let packet = unsafe {
    //         buf.assume_init_mut()
    //     };

    //     if let Ok(tmp) = ctx.load::<[u8; 256]>(0) {
    //         // packet.data[0..100].copy_from_slice(&tmp[..100]);
    //         packet.data[0] = tmp[0];
    //         packet.data[1] = tmp[1];
    //         packet.data[2] = tmp[2];
    //         packet.data[3] = tmp[3];
    //         packet.data[4] = tmp[4];
    //         packet.data[5] = tmp[5];
    //         packet.data[6] = tmp[6];
    //         packet.data[7] = tmp[7];
    //         packet.data[8] = tmp[8];
    //         packet.data[9] = tmp[9];
    //         packet.data[10] = tmp[10];
    //         packet.data[11] = tmp[11];
    //         packet.data[12] = tmp[12];
    //         packet.data[13] = tmp[13];
    //         packet.data[14] = tmp[14];
    //         packet.data[15] = tmp[15];
    //         packet.data[16] = tmp[16];
    //         packet.data[17] = tmp[17];
    //         packet.data[18] = tmp[18];
    //         packet.data[19] = tmp[19];
    //         packet.data[20] = tmp[20];
    //         packet.data[21] = tmp[21];
    //         packet.data[22] = tmp[22];
    //         packet.data[23] = tmp[23];
    //         packet.data[24] = tmp[24];
    //         packet.data[25] = tmp[25];
    //         packet.data[26] = tmp[26];
    //         packet.data[27] = tmp[27];
    //         packet.data[28] = tmp[28];
    //         packet.data[29] = tmp[29];
    //         packet.data[30] = tmp[30];
    //         packet.data[31] = tmp[31];
    //         packet.data[32] = tmp[32];
    //         packet.data[33] = tmp[33];
    //         packet.data[34] = tmp[34];
    //         packet.data[35] = tmp[35];
    //         packet.data[36] = tmp[36];

    //     }

    //     // if let Ok(_) = ctx.load_bytes(0,  &mut packet.data[..]) {
    //     //     packet.len = ctx.len() as u32;
    //     // }

    //     buf.submit(0);

    // }

    // ctx.load_bytes(0,  &mut buf)?;

    // unfortuantely, bpf_get_current_pid_tgid() only works in Linux 6.10
    // see https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
    // so we need to use bpf_get_current_task(), but we'll need the structs
    // from linux source <include/linux/sched.h>

    // let x = unsafe {
    //     bpf_get_current_task()
    // };
    // info!(
    //     &ctx, "task struct {}", x);

    // let ethhdr: EthHdr = ctx.load(0)?;

    // match ethhdr.ether_type {
    //     EtherType::Ipv4 => {
    //         let header = ctx.load::<Ipv4Hdr>(EthHdr::LEN)?;

    //         match header.proto {
    //             IpProto::Tcp => {
    //                 let dst_addr = header.dst_addr();
    //                 let src_addr = header.src_addr();

    //                 let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN)?;
    //                 let src_port = u16::from_be(tcphdr.source);
    //                 let dst_port = u16::from_be(tcphdr.dest);

    //                 // warning: network_types doesn't seem to take into account
    //                 // ipv4 header options (should be doing header.total_len() - options..)
    //                 //  so this is going to work on best effort
    //                 // basis
    //                 //

    //                 // let mut buf: [u8; 150] = [0; 150];
    //                 // ctx.load_bytes(EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN, &mut buf)?;
    //                 let size: [u8; 150] = ctx.load(0)?;

    //                 // EthHdr::LEN + Ipv4Hdr::LEN

    //                 // + TcpHdr::LEN)

    //                 if dst_port != 443 {
    //                     return Ok(TC_ACT_PIPE);
    //                 }

    //                 info!(
    //                     &ctx,
    //                     "ipv4 {}:{} -> {}:{}", src_addr, src_port, dst_addr, dst_port
    //                 );

    //                 // let a: u8 = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN + 0)?;
    //                 // let b: u8 = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN + 1)?;
    //                 // let c: u8 = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN + 2)?;
    //                 // let d: u8 = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN + 3)?;

    //                 let mut i = 0;
    //                 let i0 = u8::from_be(size[i]); i += 1;
    //                 let i1 = u8::from_be(size[i]); i += 1;
    //                 let i2 = u8::from_be(size[i]); i += 1;
    //                 let i3 = u8::from_be(size[i]); i += 1;
    //                 let i4 = u8::from_be(size[i]); i += 1;
    //                 let i5 = u8::from_be(size[i]); i += 1;
    //                 let i6 = u8::from_be(size[i]); i += 1;
    //                 let i7 = u8::from_be(size[i]); i += 1;
    //                 let i8 = u8::from_be(size[i]); i += 1;
    //                 let i9 = u8::from_be(size[i]); i += 1;

    //                 info!(&ctx, "{} {} {} {} {}", i0, i1, i2, i3, i4);
    //                 info!(&ctx, "{} {} {} {} {}", i5, i6, i7, i8, i9);

    //                 if let Some(mut buf) = DATA.reserve::<RawPacket>(0) {
    //                     unsafe {
    //                         let packet = buf.assume_init_mut();

    //                         // ctx.load_bytes(EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN, &mut packet.data)?;

    //                         packet.len = 1500;

    //                         buf.submit(0);
    //                     }
    //                 }
    //             }
    //             _ => return Ok(TC_ACT_PIPE),
    //         };
    //     }
    //     EtherType::Ipv6 => {
    //         let header = ctx.load::<Ipv6Hdr>(EthHdr::LEN)?;

    //         let dst = header.dst_addr();
    //         let src = header.src_addr();
    //         match header.next_hdr {
    //             IpProto::Tcp => {
    //                 info!(&ctx, "ipv6 src {} -> {}", src, dst);
    //                 let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv6Hdr::LEN)?;
    //             }
    //             _ => return Ok(TC_ACT_PIPE),
    //         };
    //     }
    //     _ => return Ok(TC_ACT_PIPE),
    // };

    info!(&ctx, "received a packet");

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
