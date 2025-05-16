use etherparse::SlicedPacket;

use crate::quic::decode_quic_initial_packet;

#[derive(Debug)]
pub struct QuicPacketInfo {
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub sni: String,
}

pub fn parse_ether(packet: &[u8]) -> Result<QuicPacketInfo, &str> {
    let ether = SlicedPacket::from_ethernet(packet).map_err(|_e| "cannot parse ethernet frame")?;
    let net = ether.net.ok_or("no net layer")?;

    if !net.is_ip() {
        return Err("not ip");
    }

    let transport = ether.transport.ok_or("no transport layer")?;
    let etherparse::TransportSlice::Udp(udp) = transport else {
        return Err("not udp");
    };

    let source_port = udp.source_port();
    let destination_port = udp.destination_port();

    let payload = udp.payload();
    let sni = decode_quic_initial_packet(payload).ok_or("unable to decode quic inital packet")?;

    let (source_ip, destination_ip) = if net.is_ipv4() {
        let ipv4 = net.ipv4_ref().ok_or("no ipv4")?;
        let destination = ipv4.header().destination_addr().to_string();
        let source = ipv4.header().source_addr().to_string();
        (source, destination)
    } else if net.is_ipv6() {
        let ipv6 = net.ipv6_ref().ok_or("no ipv6")?;
        let destination = ipv6.header().destination_addr().to_string();
        let source = ipv6.header().source_addr().to_string();
        (source, destination)
    } else {
        return Err("unsupported IP protocol");
    };

    log::info!(
        "{} {}:{} -> {}:{}. SNI: {}",
        if net.is_ipv4() { "IPv4" } else { "IPv6" },
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        sni
    );

    Ok(QuicPacketInfo {
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        sni: sni.to_string(),
    })
}
