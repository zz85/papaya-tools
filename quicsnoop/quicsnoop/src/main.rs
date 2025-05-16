use aya::{
    maps::RingBuf,
    programs::{tc, SchedClassifier, TcAttachType},
};
use clap::Parser;
use log::info;
#[rustfmt::skip]
use log::{debug, warn};
use crate::network::parse_ether;
use quicsnoop_common::QuicPacket;
use tokio::signal;

mod network;
mod quic;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,

    #[clap(short, long, default_value = "false")]
    egress: bool,
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
        "/quicsnoop"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let Opt { iface, egress } = opt;
    println!("Interface: {iface}, egress: {egress}");
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = ebpf.program_mut("quicsnoop").unwrap().try_into()?;
    program.load()?;

    let attach_type = if egress {
        TcAttachType::Egress
    } else {
        TcAttachType::Ingress
    };
    program.attach(&iface, attach_type)?;

    // Receive packets
    tokio::spawn(async move {
        let ring_buf = RingBuf::try_from(ebpf.map_mut("DATA").unwrap()).unwrap();
        use tokio::io::unix::AsyncFd;
        let mut fd = AsyncFd::new(ring_buf).unwrap();

        while let Ok(mut guard) = fd.readable_mut().await {
            match guard.try_io(|inner| {
                let ring_buf = inner.get_mut();
                while let Some(item) = ring_buf.next() {
                    let raw: &QuicPacket = unsafe {
                        let ptr = item.as_ptr() as *const QuicPacket;
                        &*ptr
                    };

                    let data = &raw.data[..raw.len as usize];

                    info!("User space received Raw packet with length: {}", raw.len);
                    if let Err(e) = parse_ether(data) {
                        debug!("Failed to parse packet: {}", e);
                    }
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
