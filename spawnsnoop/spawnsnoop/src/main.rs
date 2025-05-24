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
    let program: &mut TracePoint = ebpf.program_mut("sys_enter_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_exit")?;

    let program: &mut TracePoint = ebpf.program_mut("trace_exit_execve").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_execve")?;

    let program: &mut TracePoint = ebpf.program_mut("sched_process_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exit")?;

    let program: &mut TracePoint = ebpf.program_mut("sched_process_fork").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_fork")?;

    let program: &mut TracePoint = ebpf.program_mut("sched_process_exec").unwrap().try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    /* Example timeline
    - sys_enter_execve  -> Start loading program
    - sys_exit_execve   -> Program loaded and started
    - [Program runs...] -> Program execution
    - sys_exit_exit     -> Program terminates
    - sched_process_exit
    */

    // Getting tracepoints
    // sudo ls /sys/kernel/debug/tracing/events/
    // sudo perf list | grep Tracepoint
    // cat /sys/kernel/debug/tracing/available_events
    // find /sys/kernel/debug/tracing/events -name format -exec cat {} \;
    // https://github.com/torvalds/linux/tree/5189dafa4cf950e675f02ee04b577dfbbad0d9b1/include/trace/events

    // List of IDs
    // sudo find /sys/kernel/debug/tracing/events -name format -exec cat {} \; | grep "ID:" -B 1

    // some references
    // https://ancat.github.io/kernel/2021/05/20/hooking-processes-and-threads.html

    // Other tracepoints
    // - acct_process
    // to compare against kprobes, see
    // - wake_up_new_task, clone, clone3, fork

    struct SpawnInfoHandler;

    impl RingBufEventHandler for SpawnInfoHandler {
        fn handle_event(&mut self, data: &[u8]) {
            let raw: &SpawnInfo = unsafe {
                let ptr = data.as_ptr() as *const SpawnInfo;
                &*ptr
            };

            let command = std::str::from_utf8(&raw.command).unwrap_or("");
            println!("{:?} {}: {}", raw.event, raw.pid, command);
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
