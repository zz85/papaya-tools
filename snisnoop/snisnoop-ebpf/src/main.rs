#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    cty::c_long,
    helpers::{bpf_get_current_task, bpf_probe_read_kernel, bpf_skb_load_bytes},
    macros::{classifier, map},
    maps::RingBuf,
    programs::{sk_buff::SkBuff, TcContext},
};
use aya_log_ebpf::debug;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
};
use snisnoop_common::RawPacket;
use vmlinux::task_struct;

mod vmlinux;

// will require >= Linux 5.8
#[map]
static DATA: RingBuf = RingBuf::with_byte_size(1000 * RawPacket::LEN as u32, 0);

#[classifier]
#[inline]
pub fn snisnoop(ctx: TcContext) -> i32 {
    match try_snisnoop(ctx) {
        Ok(ret) => ret,
        Err(ret) => -1,
    }
}

// Probably still buggy
#[inline]
pub fn load_bytes2(skb: &SkBuff, offset: usize, dst: &mut [u8]) -> Result<usize, c_long> {
    let buffer_len = dst.len();
    let sk_len = skb.len() as usize;
    let lesser_len = buffer_len.min(skb.len() as usize);
    // these checks doesn't help the verifier :(
    // if sk_len == 0 || sk_len >= buffer_len {
    //     return Err(0);
    // }

    let ret = unsafe {
        bpf_skb_load_bytes(
            skb.skb as *const _,
            offset as u32,
            dst.as_mut_ptr() as *mut _,
            buffer_len as u32,
        )
    };
    if ret == 0 {
        Ok(lesser_len)
    } else {
        Err(ret)
    }
}

#[inline]
fn get_process_id(ctx: &TcContext) -> Result<u32, i64> {
    // todo: get associated process ID
    // unfortuantely, bpf_get_current_pid_tgid() only works in Linux 6.10
    // see https://docs.ebpf.io/linux/helper-function/bpf_get_current_pid_tgid/
    // so we need to use bpf_get_current_task(), but we'll need the structs
    // from linux source <include/linux/sched.h>

    unsafe {
        let task = bpf_get_current_task() as *const task_struct;
        use core::ptr::addr_of;
        let tgid = bpf_probe_read_kernel(addr_of!((*task).tgid))?;

        Ok(tgid as u32)
    }
}

// we copy data to userspace so we have more flexibilty with packet parsing
#[inline]
fn copy_data_to_userspace(ctx: &TcContext) {
    if let Some(mut buf) = DATA.reserve::<RawPacket>(0) {
        let packet = unsafe { buf.assume_init_mut() };

        // fixme: ideally, we should be able to use ctx.load_bytes(0, &mut packet.data)
        // but ebpf verifier have just been erroring on that
        // example: https://github.com/iovisor/bcc/issues/3269

        // if let Ok(len) = load_bytes2(&ctx.skb, 0, &mut packet.data) {
        //     info!(ctx, "load_bytes2 ok len: {}", len);
        //     packet.len = ctx.len() as u32;
        //     buf.submit(0);
        // } else {
        //     info!(ctx, "load_bytes failed");
        //     buf.discard(0);
        // }

        // Looping statically and copying each byte seems to yield the best results
        for i in 0..packet.data.len() {
            if let Ok(v) = ctx.load::<u8>(i as usize) {
                packet.data[i] = v;
                packet.len = i as u32 + 1;
            } else {
                break;
            }
        }

        if let Ok(tgid) = get_process_id(ctx) {
            packet.tgid = tgid;
        }

        /*
        // This is rather strange - there's no errors, but after parsing tcp, payload seems to be filled with zeros
        unsafe {
            let len = packet.data.len().min(ctx.len() as usize);
            if let Ok(_) = aya_ebpf::helpers::bpf_probe_read_kernel_buf(
                ctx.data() as *const _,
                &mut packet.data[0..len],
            ) {
                // if let Ok(_) = aya_ebpf::helpers::bpf_probe_read_user_buf(ctx.data() as *const u8, &mut packet.data) {
                // if let Ok(_) = aya_ebpf::helpers::bpf_probe_read_buf(ctx.data() as *const u8, &mut packet.data[..len]) {
                packet.len = len as u32;
            }
        }*/

        // usage of RingBufEntry requires us to submit or discard after reserving
        if packet.len > 0 {
            buf.submit(0);
        } else {
            buf.discard(0);
        }
    }
}

#[inline(always)]
fn try_snisnoop(ctx: TcContext) -> Result<i32, c_long> {
    let len = ctx.len();
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

                    if dst_port != 443 {
                        return Ok(TC_ACT_PIPE);
                    }

                    // tls magic byte - this is a heutristics if without optional headers
                    // points to the TLS record header byte
                    // 0x16 - TLS handshake
                    // 0x17 - TLS application data
                    // 0x15 - TLS close notify
                    let _tls_record: u8 = u8::from_be(ctx.load(66)?);

                    // if tls_record != 0x16 {
                    //     return Ok(TC_ACT_PIPE);
                    // }

                    debug!(
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
                    let tcphdr: TcpHdr = ctx.load(EthHdr::LEN + Ipv6Hdr::LEN)?;

                    let src_port = u16::from_be(tcphdr.source);
                    let dst_port = u16::from_be(tcphdr.dest);

                    debug!(
                        &ctx,
                        "ipv6 src {}:{} -> {}:{}", src, src_port, dst, dst_port
                    );

                    // warning: network_types doesn't seem to take into account
                    // ipv4 header options (should be doing header.total_len() - options..)
                    // so this is going to work on best effort
                    // basis

                    // if dst_port != 443 {
                    //     return Ok(TC_ACT_PIPE);
                    // }

                    copy_data_to_userspace(&ctx);
                }
                _ => return Ok(TC_ACT_PIPE),
            };
        }
        _ => return Ok(TC_ACT_PIPE),
    };

    debug!(&ctx, "received a packet with len: {}", len);

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
