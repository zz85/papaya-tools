use core::net::IpAddr;
use log::debug;
use pktparse::{ethernet, ipv4, ipv6, tcp};
use tls_parser::{parse_tls_extensions, TlsExtension, TlsMessage, TlsMessageHandshake};

/// Parses packet from the ethernet frame up to TLS layer,
/// extracting source and destination IPs+port,
/// along with the sni of initated TLS handshakes
pub fn handle_raw_packet(data: &[u8]) -> Option<(IpAddr, u16, IpAddr, u16, String)> {
    let (remaining, eth_frame) = ethernet::parse_ethernet_frame(data).ok()?;

    debug!("Parsed eth_frame: {:?}", eth_frame);

    // Get IP headers
    let (remaining, src, dst) = match eth_frame.ethertype {
        ethernet::EtherType::IPv4 => {
            let (remaining, ip_headers) = ipv4::parse_ipv4_header(remaining).ok()?;
            let src: IpAddr = ip_headers.source_addr.into();
            let dst: IpAddr = ip_headers.dest_addr.into();

            (remaining, src, dst)
        }
        ethernet::EtherType::IPv6 => {
            let (remaining, ip_headers) = ipv6::parse_ipv6_header(remaining).ok()?;

            let src: IpAddr = ip_headers.source_addr.into();
            let dst: IpAddr = ip_headers.dest_addr.into();
            (remaining, src, dst)
        }
        _ => {
            // could be Arp, Icmp etc
            return None;
        }
    };

    // Work on the TCP header
    let (remaining, tcp) = tcp::parse_tcp_header(remaining).ok()?;

    debug!("TCP packet {:?}", tcp);
    debug!("Remaining {:?}", &remaining[..10.min(remaining.len())]);

    // Short circuit to handshake TLS records only
    if remaining.is_empty() || remaining[0] != 0x16 {
        return None;
    }

    let sni_found = parse_tls_for_sni(remaining)?;

    debug!("Raw packet data:");
    for x in &data[..100.min(data.len())] {
        debug!("{:02x} ", u8::from_be(*x));
    }
    debug!(".");

    Some((src, tcp.source_port, dst, tcp.dest_port, sni_found))
}

/// Parses TLS record, extract the first client hello and SNI found
fn parse_tls_for_sni(bytes: &[u8]) -> Option<String> {
    let (_bytes, tls) = tls_parser::parse_tls_plaintext(bytes).ok()?;

    // find the client hello
    let (_, extensions) = tls.msg.iter().find_map(|msg| match msg {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) => {
            parse_tls_extensions(client_hello.ext?).ok()
        }
        _ => None,
    })?;

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

    Some(sni)
}
