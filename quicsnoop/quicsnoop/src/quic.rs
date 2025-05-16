use std::sync::{Arc, Mutex};

use log::{debug, info};
use quick_cache::sync::Cache;
use s2n_codec::DecoderBufferMut;
use s2n_quic_core::{
    connection::id::ConnectionInfo,
    crypto::InitialKey,
    frame::{Crypto, Frame, FrameMut},
    inet::SocketAddress,
    packet::ProtectedPacket,
};
use tls_parser::{
    parse_tls_extensions, parse_tls_message_handshake, TlsExtension, TlsMessage,
    TlsMessageHandshake,
};

// imported from https://github.com/zz85/packet_radar/commit/3bfd50ebe3b3e0a3077843ec40746dfcc7ec7053

use std::sync::LazyLock;
static QUIC_CACHE: LazyLock<Cache<Vec<u8>, Arc<Mutex<CryptoAssembler>>>> =
    LazyLock::new(|| Cache::new(50));

pub fn decode_quic_initial_packet(packet: &[u8]) -> Option<String> {
    let mut data = [0; 9000]; // jumbo frame just in case
    debug!("QUIC Packet len {}", packet.len());
    let decode_buffer = &mut data[..packet.len()];
    decode_buffer.copy_from_slice(packet);

    let payload = DecoderBufferMut::new(decode_buffer);
    let remote_address = SocketAddress::default();
    let connection_info = ConnectionInfo::new(&remote_address);

    // TODO: decryption for intial packet > #1 requires additional work

    let (packet, _remaining) = ProtectedPacket::decode(payload, &connection_info, &0).ok()?;

    let version = packet.version()?;

    // care only about initial packets
    let protected_packet = match packet {
        ProtectedPacket::Initial(packet) => packet,
        _ => {
            return None;
        }
    };

    let (initial_key, initial_header_key) = s2n_quic_crypto::initial::InitialKey::new_server(
        protected_packet.destination_connection_id(),
    );

    let initial_encrypted = protected_packet
        .unprotect(&initial_header_key, Default::default())
        .map_err(|e| {
            info!("cannot unprotect {e}");
        })
        .ok()?;

    let clear_initial = initial_encrypted
        .decrypt(&initial_key)
        .map_err(|err| {
            info!("cannot decrypt {err}");
            // just move on if we can't decrypt packet
        })
        .ok()?;

    let packet_number = clear_initial.packet_number;
    let dcid = clear_initial.destination_connection_id().to_vec();
    let scid = clear_initial.source_connection_id();

    debug!("QUIC Packet version {version}. #{packet_number}. scid {scid:02x?} -> dcid {dcid:02x?}");

    let mut payload = clear_initial.payload;

    let crypto = QUIC_CACHE
        .get_or_insert_with(&dcid, || {
            let crypto = CryptoAssembler::new();
            Ok::<_, std::io::Error>(Arc::new(Mutex::new(crypto)))
        })
        .unwrap();

    let mut crypto = crypto.lock().unwrap();

    // iterate frames from the QUIC packet
    while !payload.is_empty() {
        let Ok((frame, remaining)) = payload.decode::<FrameMut>() else {
            info!("Failed to decode QUIC frame – skipping packet");
            break;
        };

        if let Frame::Crypto(frame) = frame {
            // handle_crypto_frame
            crypto.add_frame(frame);
        }

        payload = remaining;
    }

    if !crypto.completed() {
        info!("QUIC Crypto incomplete");
        return None;
    }

    info!("QUIC Crypto completed. Parsing Client hello..");
    let (_, msg) = parse_tls_message_handshake(crypto.get_bytes())
        .map_err(|e| info!("Cannot parse {e:?}"))
        .ok()?;

    let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = msg else {
        return Err("No client hello").ok();
    };

    let (_, extensions) = parse_tls_extensions(client_hello.ext?).ok()?;

    // find the sni
    let sni = extensions
        .iter()
        .find_map(|ext| match ext {
            TlsExtension::SNI(sni) => sni.iter().find_map(|(_, b)| {
                let sni = std::str::from_utf8(b).map(|s| s.to_owned()).ok();
                sni
            }),
            _ => None,
        })
        .unwrap_or("<no sni>".to_string());

    info!("SNI: {sni}");

    // remove from cache
    drop(crypto);
    QUIC_CACHE.remove(&dcid);

    Some(sni)
}

/// we should probably use s2n_quic_core::buffer::Reassembler
/// as this is something simple, doesn't check duplicate bytes range
/// but could do for now
#[derive(Clone, Debug)]
struct CryptoAssembler {
    // up to 64k support
    crypto: [u8; 1 << 16],
    size: usize,
    recv: usize,
}

impl CryptoAssembler {
    fn new() -> Self {
        Self {
            crypto: [0u8; 1 << 16],
            size: 0,
            recv: 0,
        }
    }
    fn add_frame(&mut self, frame: Crypto<DecoderBufferMut>) {
        let slice = frame.data.as_less_safe_slice();
        let offset = frame.offset.as_u64() as usize;
        let to = offset + slice.len();

        debug!("received: {offset}..{to}");

        self.crypto[offset..to].copy_from_slice(slice);
        // let's expect the first 4 bytes to be together
        if offset == 0 && to > 2 {
            let target: u32 = ((self.crypto[1] as u32) << 16)
                + ((self.crypto[2] as u32) << 8)
                + self.crypto[3] as u32;
            self.size = target as usize + 4;
            debug!("matched 4 bytes {:x} - {target}", self.crypto[0]);
        }

        self.recv += slice.len();
    }

    fn get_bytes(&self) -> &[u8] {
        &self.crypto[..self.size]
    }

    fn completed(&self) -> bool {
        debug!("QUIC Crypto completed: {}/{}", self.recv, self.size);
        self.size > 0 && self.recv == self.size
    }
}
