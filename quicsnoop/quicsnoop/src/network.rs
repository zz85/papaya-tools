use etherparse::SlicedPacket;

use crate::quic::decode_quic_initial_packet;

pub fn parse_ether(packet: &[u8]) -> Result<(), &str> {
    let ether = SlicedPacket::from_ethernet(packet).map_err(|_e| "cannot parse ethernet frame")?;

    // println!("link: {:?}", ether.link); // mac address
    // println!("link_exts: {:?}", ether.link_exts); // vlan & macsec
    // println!("net: {:?}", ether.net); // ip & arp
    // println!("transport: {:?}", ether.transport); // udp

    let net = ether.net.ok_or("no net layer")?;

    if !net.is_ip() {
        return Err("not ip");
    }

    let transport = ether.transport.ok_or("no transport layer")?;
    let etherparse::TransportSlice::Udp(udp) = transport else {
        return Err("not udp");
    };

    if net.is_ipv4() {
        println!("IPv4");
        let ipv4 = net.ipv4_ref().ok_or("no ipv4")?;
        let destination = ipv4.header().destination_addr();
        let source = ipv4.header().source_addr();
        println!("IPv4 source: {}", source);
        println!("IPv4 destination: {}", destination);
    } else if net.is_ipv6() {
        println!("IPv6");
        let ipv6 = net.ipv6_ref().ok_or("no ipv4")?;
        let destination = ipv6.header().destination_addr();
        let source = ipv6.header().source_addr();
        println!("IPv6 source: {}", source);
        println!("IPv6 destination: {}", destination);
    }

    println!("UDP {:?}", udp.to_header());

    let source_port = udp.source_port();
    let destination_port = udp.destination_port();
    let length = udp.length();

    println!("UDP source port: {}", source_port);
    println!("UDP destination port: {}", destination_port);
    println!("UDP length: {}", length);

    let payload = udp.payload();

    println!("UDP payload {:?}", &payload[0..10]);

    println!(
        "IP {:?}",
        &net.ip_payload_ref().ok_or("no ip payload")?.payload[0..12]
    );

    let res = decode_quic_initial_packet(payload);

    println!("QUIC {:?}", res);

    // let ether_type = ether.payload_ether_type().ok_or("no ether type");

    // let ip_payload = ether.ip_payload().ok_or("ip")?;

    // let ether = ether
    //     .ether_payload()
    //     .ok_or("no payload in ethernet frame")?;

    // let ip = SlicedPacket::from_ip(ether.payload).map_err(|_e| "cannot parse IP frame")?;

    Ok(())
}
