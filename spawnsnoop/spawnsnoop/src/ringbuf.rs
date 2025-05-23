use std::borrow::Borrow;

use aya::maps::{MapData, RingBuf};
use tokio::io::unix::AsyncFd;

pub trait RingBufEventHandler {
    fn handle_event(&mut self, data: &[u8]);
}

pub async fn handle_ringbuf<T: Borrow<MapData>>(
    ring_buf: RingBuf<T>,
    handler: &mut impl RingBufEventHandler,
) {
    let mut async_fd = AsyncFd::new(ring_buf).unwrap();

    loop {
        let mut guard = async_fd.readable_mut().await.unwrap();
        let rb = guard.get_inner_mut();
        while let Some(read) = rb.next() {
            let data = unsafe { std::slice::from_raw_parts(read.as_ptr(), read.len()) };
            handler.handle_event(data);
        }
        guard.clear_ready();
    }
}
