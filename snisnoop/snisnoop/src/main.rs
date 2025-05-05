use aya::{
    maps::RingBuf,
    programs::{tc, SchedClassifier, TcAttachType},
};
use chrono::Local;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};

use tokio::signal;

use snisnoop_common::RawPacket;

mod network;
use network::handle_raw_packet;

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

    // todo: move this into a ring buf file
    tokio::spawn(async move {
        let ring_buf = RingBuf::try_from(ebpf.map_mut("DATA").unwrap()).unwrap();
        use tokio::io::unix::AsyncFd;
        let mut fd = AsyncFd::new(ring_buf).unwrap();

        // First print the header
        println!(
            "\n{:<12} {:<8} {:<22} {:<22} {:<30}",
            "TIME", "PID", "SOURCE", "DESTINATION", "SNI"
        );
        println!("{:-<94}", ""); // Adjusted separator line

        while let Ok(mut guard) = fd.readable_mut().await {
            match guard.try_io(|inner| {
                let ring_buf = inner.get_mut();
                while let Some(item) = ring_buf.next() {
                    let raw: &RawPacket = unsafe {
                        let ptr = item.as_ptr() as *const RawPacket;
                        &*ptr
                    };

                    let data = &raw.data[..raw.len as usize];

                    debug!("User space received Raw packet with length: {}", raw.len);
                    if let Some((src, source_port, dst, dest_port, sni)) = handle_raw_packet(data) {
                        let pid = raw.tgid;
                        // println!(
                        //     "\t{}:{} > {}:{}\t[{}]\tSNI: {}",
                        //     src, source_port, dst, dest_port, raw.tgid, sni_found
                        // );

                        println!(
                            "{:<12} {:<8} {:<22} {:<22} {:<30}",
                            Local::now().format("%H:%M:%S"),
                            pid,
                            format!("{}:{}", src, source_port),
                            format!("{}:{}", dst, dest_port),
                            sni
                        );
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
