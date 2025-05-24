use aya::{maps::RingBuf, programs::TracePoint};
#[rustfmt::skip]
use log::{debug, warn};
use spawnsnoop_common::SpawnInfo;
use tokio::signal;

mod ringbuf;
use ringbuf::{handle_ringbuf, RingBufEventHandler};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        "/spawnsnoop"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }
    let program: &mut TracePoint = ebpf.program_mut("trace_enter").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let program: &mut TracePoint = ebpf.program_mut("trace_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_execve")?;

    struct SpawnInfoHandler;

    impl RingBufEventHandler for SpawnInfoHandler {
        fn handle_event(&mut self, data: &[u8]) {
            let raw: &SpawnInfo = unsafe {
                let ptr = data.as_ptr() as *const SpawnInfo;
                &*ptr
            };

            let command = std::str::from_utf8(&raw.command).unwrap_or("");
            println!(
                "{} {}: {}",
                if raw.enter {
                    "New process"
                } else {
                    "Exit process: "
                },
                raw.pid,
                command
            );
        }
    }

    tokio::spawn(async move {
        let ring_buf = RingBuf::try_from(ebpf.map_mut("RINGBUF").unwrap()).unwrap();

        println!("Receiving...");
        println!("{:-<94}", "");

        handle_ringbuf(ring_buf, &mut SpawnInfoHandler).await;
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
