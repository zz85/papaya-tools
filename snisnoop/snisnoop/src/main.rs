use aya::{
    maps::RingBuf,
    programs::{tc, SchedClassifier, TcAttachType},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use pktparse::{ethernet, ipv4, ipv6, tcp};
use snisnoop_common::RawPacket;
use tls_parser::{parse_tls_extensions, TlsExtension, TlsMessage, TlsMessageHandshake};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    interface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/snisnoop"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let Opt { interface } = opt;
    println!("Listening on interface {interface}...");

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&interface);

    let program: &mut SchedClassifier = ebpf.program_mut("snisnoop").unwrap().try_into()?;
    program.load()?;
    program.attach(&interface, TcAttachType::Egress)?;

    tokio::spawn(async move {
        let ring_buf = RingBuf::try_from(ebpf.map_mut("DATA").unwrap()).unwrap();
        use tokio::io::unix::AsyncFd;
        let mut fd = AsyncFd::new(ring_buf).unwrap();

        while let Ok(mut guard) = fd.readable_mut().await {
            match guard.try_io(|inner| {
                let ring_buf = inner.get_mut();
                while let Some(item) = ring_buf.next() {
                    let raw: &RawPacket = unsafe {
                        let ptr = item.as_ptr() as *const RawPacket;
                        &*ptr
                    };

                    let data = &raw.data[..raw.len as usize];

                    println!("User space received Raw packet with length: {}", raw.len);

                    if let Ok((remaining, eth_frame)) = ethernet::parse_ethernet_frame(data) {
                        println!("Parsed packet: {:?}", eth_frame);

                        if eth_frame.ethertype == ethernet::EtherType::IPv4 {
                            let (remaining, ip_headers) =
                                ipv4::parse_ipv4_header(remaining).unwrap();
                            println!("IPv4 packet {:?}", ip_headers);

                            let (remaining, tcp) = tcp::parse_tcp_header(remaining).unwrap();
                            println!("TCP packet {:?}", tcp);

                            println!("Remaining {:?}", &remaining[..10.min(remaining.len())]);

                            // if remaining[0] != 0x16 {
                            //     continue;
                            // }

                            if let Ok((_remaining, tls)) =
                                tls_parser::parse_tls_plaintext(remaining)
                            {
                                for msg in tls.msg {
                                    println!("TLS msg: {:?}", msg);

                                    let client_hello = match msg {
                                        TlsMessage::Handshake(
                                            TlsMessageHandshake::ClientHello(client_hello),
                                        ) => client_hello,
                                        _ => {
                                            continue;
                                        }
                                    };

                                    if let Ok((_, extensions)) = if let Some(ext) = client_hello.ext
                                    {
                                        parse_tls_extensions(ext)
                                    } else {
                                        continue;
                                    } {
                                        for ext in extensions {
                                            match ext {
                                                TlsExtension::SNI(sni) => {
                                                    for (_, b) in sni {
                                                        let sni = std::str::from_utf8(b)
                                                            .unwrap_or("")
                                                            .to_owned();
                                                        println!("SNI: {}", sni);
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                            }
                        } else if eth_frame.ethertype == ethernet::EtherType::IPv6 {
                            let (remaining, ip_headers) =
                                ipv6::parse_ipv6_header(remaining).unwrap();
                            println!("IPv6 packet {:?}", ip_headers);

                            let (remaining, tcp) = tcp::parse_tcp_header(remaining).unwrap();
                            println!("TCP packet {:?}", tcp);
                        } else {
                            println!("Unknown packet");
                        }

                        // if let Done(remaining, ipv4_packet) = ipv4::parse_ipv4_header(remaining) {
                        // }
                    };

                    // println!("Parsed packet: {:?}", parsed);

                    print!("Raw packet data:");
                    for x in &data[..100.min(data.len())] {
                        print!("{:02x} ", u8::from_be(*x));
                    }
                    println!(".");
                }
                Ok(())
            }) {
                Ok(_) => {
                    guard.clear_ready();
                    continue;
                }
                Err(_would_block) => continue,
            }
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
