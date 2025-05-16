use etherparse::SlicedPacket;

use crate::quic::decode_quic_initial_packet;

pub fn parse_ether(packet: &[u8]) -> Result<(), &str> {
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

    if net.is_ipv4() {
        let ipv4 = net.ipv4_ref().ok_or("no ipv4")?;
        let destination = ipv4.header().destination_addr();
        let source = ipv4.header().source_addr();
        println!(
            "IPv4 {}:{} -> {}:{}",
            source, source_port, destination, destination_port
        );
    } else if net.is_ipv6() {
        let ipv6 = net.ipv6_ref().ok_or("no ipv4")?;
        let destination = ipv6.header().destination_addr();
        let source = ipv6.header().source_addr();
        println!(
            "IPv6 {}:{} -> {}:{}",
            source, source_port, destination, destination_port
        );
    }

    // println!("UDP {:?}", udp.to_header());

    // println!("UDP payload {:?}", &payload[0..10]);
    // println!(
    //     "IP {:?}",
    //     &net.ip_payload_ref().ok_or("no ip payload")?.payload[0..12]
    // );

    // let ip_payload = ether.ip_payload().ok_or("ip")?;

    Ok(())
}
