use aya::{maps::RingBuf, Ebpf};
use tokio::io::unix::AsyncFd;
use spawnsnoop_common::SpawnInfo;

pub fn spawn_ringbuf(ebpf: &mut Ebpf) {
    tokio::spawn(async move {
        let ring_buf = RingBuf::try_from(ebpf.map_mut("RINGBUF").unwrap()).unwrap();

        let mut fd = AsyncFd::new(ring_buf).unwrap();

        println!(
            "Receiving..."
        );
        println!("{:-<94}", ""); // Adjusted separator line

        while let Ok(mut guard) = fd.readable_mut().await {
            match guard.try_io(|inner| {
                let ring_buf = inner.get_mut();
                while let Some(item) = ring_buf.next() {
                    let raw: &SpawnInfo = unsafe {
                        let ptr = item.as_ptr() as *const SpawnInfo;
                        &*ptr
                    };

                    let command = std::str::from_utf8(&raw.command).unwrap_or("");
                    println!("New Process {}: {}", raw.pid, command);
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
}