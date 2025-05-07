#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    cty::c_long,
    helpers::{bpf_get_current_task, bpf_probe_read_kernel},
    macros::{classifier, map},
    maps::RingBuf,
    programs::TcContext,
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

#[inline]
fn get_process_id() -> Result<u32, i64> {
    // get associated process ID
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

        // let ebpf verifier know that there's at least a single byte in skbuff's data
        // which would be a requirement for bpf_skb_load_bytes() to work
        if ctx.len() < 2 {
            buf.discard(0);
            return;
        }

        if let Ok(len) = ctx.load_bytes(0, &mut packet.data) {
            packet.len = len as u32;
        }

        if let Ok(tgid) = get_process_id() {
            packet.tgid = tgid;
        }

        // usage of RingBufEntry requires us to submit or discard after reserving
        buf.submit(0);
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
