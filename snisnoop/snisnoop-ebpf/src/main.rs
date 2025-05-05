#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    cty::c_long,
    helpers::r#gen::{bpf_get_current_task, bpf_skb_load_bytes},
    macros::{classifier, map},
    maps::RingBuf,
    programs::{sk_buff::SkBuff, TcContext},
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
};
use snisnoop_common::RawPacket;

// will require >= Linux 5.8
#[map]
static DATA: RingBuf = RingBuf::with_byte_size(100 * RawPacket::LEN as u32, 0);

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
    let lesser_len = dst.len().min(skb.len() as usize - offset);

    let x = dst.len();
    let ret = unsafe {
        bpf_skb_load_bytes(
            skb.skb as *const _,
            offset as u32,
            dst.as_mut_ptr() as *mut _,
            x as u32,
        )
    };
    if ret == 0 {
        Ok(lesser_len)
    } else {
        Err(ret)
    }
}

// we copy data to userspace so we have more flexibilty with packet parsing
#[inline]
fn copy_data_to_userspace(ctx: &TcContext) {
    if let Some(mut buf) = DATA.reserve::<RawPacket>(0) {
        let packet = unsafe { buf.assume_init_mut() };

        // fixme: ideally, we should be able to use ctx.load_bytes(0, &mut packet.data)
        // but ebpf verifier have just been erroring on that

        // usage of RingBufEntry requires us to submit or discard after reserving
        if let Ok(len) = load_bytes2(&ctx.skb, 0, &mut packet.data) {
            packet.len = len as u32;
            buf.submit(0);
        } else {
            buf.discard(0);
        }
    }
}

#[inline(always)]
fn try_snisnoop(ctx: TcContext) -> Result<i32, c_long> {
    // let uid = ctx.get_socket_uid();

    // todo: get associated process ID
    // unfortuantely, bpf_get_current_pid_tgid() only works in Linux 6.10
    // see https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
    // so we need to use bpf_get_current_task(), but we'll need the structs
    // from linux source <include/linux/sched.h>

    // let x = unsafe {
    //     bpf_get_current_task()
    // };
    // info!(
    //     &ctx, "task struct {}", x);

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
                    // so this is going to work on best effort
                    // basis

                    if dst_port != 443 {
                        return Ok(TC_ACT_PIPE);
                    }

                    info!(
                        &ctx,
                        "ipv4 {}:{} -> {}:{}", src_addr, src_port, dst_addr, dst_port
                    );

                    copy_data_to_userspace(&ctx);
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
