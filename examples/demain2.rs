use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::Deserialize;
use std::env;
use std::fs;
use pnet::packet::tcp::TcpFlags;

#[derive(Deserialize, Debug)]
struct Settings {
    domains: Vec<String>,
}



fn handle_packet(ethernet: &EthernetPacket, domains: &[String]) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(header) = Ipv4Packet::new(ethernet.payload()) {
                match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp) = TcpPacket::new(header.payload()) {
                            if let Some(domain) = handle_tcp_packet(&tcp) {
                                if domains.iter().any(|d| domain.ends_with(d)) {
                                    println!("Intercepted DNS query for domain over TCP: {}", domain);
                                }
                            }
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp_packet) = UdpPacket::new(header.payload()) {
                            if is_dns_packet(&udp_packet) {
                                if let Some(domain_name) = extract_dns_query(&udp_packet) {
                                    if domains.iter().any(|d| domain_name.ends_with(d)) {
                                        println!("Intercepted DNS query for domain: {}", domain_name);
                                    }
                                }
                            }
                        }
                    }
                    _ => println!("Ignoring non TCP/UDP packet"),
                }
            }
        }
        _ => println!("Ignoring non IPv4 packet"),
    }
}

fn main() {
    let interface_name = env::args().nth(1).expect("Please provide an interface name");

    // 读取配置文件
    let config = fs::read_to_string("config.toml").expect("Failed to read config file");
    println!("Config file: {}", config);
    let settings: Settings = Settings {
        domains: vec!["hellobike.cn".to_string(), "hellobike.com".to_string()],
    }; //toml::from_str(&config).expect("Failed to parse config file");
    println!("settings file: {:?}", settings);
   // 获取网卡列表
   let interfaces = datalink::interfaces();
   let interface = interfaces
       .into_iter()
       .filter(|iface: &NetworkInterface| iface.name == interface_name) // 根据接口名称过滤网卡列表
       .next()
       .expect("Error getting interface"); // 如果找不到匹配的接口，打印错误消息并退出

   let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
       // 创建数据链路层通道，用于接收和发送数据包
       Ok(Ethernet(tx, rx)) => (tx, rx), // 如果通道类型是以太网通道，则将发送和接收通道分别赋值给_tx和rx
       Ok(_) => panic!("Unhandled channel type"), // 如果是其他类型的通道，抛出错误
       Err(e) => panic!(
           "An error occurred when creating the datalink channel: {}",
           e
       ), // 如果创建通道时发生错误，打印错误消息并退出
   };
    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(packet) = EthernetPacket::new(packet) {
                    handle_packet(&packet, &settings.domains);
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

fn handle_tcp_packet(tcp: &TcpPacket) -> Option<String> {
    if tcp.get_flags() & TcpFlags::ACK != 0 && tcp.get_flags() & TcpFlags::PSH != 0 {
        if is_dns_packet_tcp(&tcp) {
            if let Some(domain_name) = extract_dns_query_tcp(&tcp) {
                return Some(domain_name);
            }
        }
    }
    None
}

fn is_dns_packet_tcp(tcp_packet: &TcpPacket) -> bool {
    let source_port = tcp_packet.get_source();
    let destination_port = tcp_packet.get_destination();
    source_port == 53 || destination_port == 53
}

fn extract_dns_query_tcp(tcp_packet: &TcpPacket) -> Option<String> {
    let payload = tcp_packet.payload();
    if payload.len() < 2 {
        return None;
    }

    let dns_length = ((payload[0] as usize) << 8) | payload[1] as usize;
    if payload.len() < dns_length + 2 {
        return None;
    }

    let dns_payload = &payload[2..2 + dns_length];
    if dns_payload.len() < 12 {
        return None;
    }

    let mut pos = 12;
    let mut domain_name = String::new();
    while pos < dns_payload.len() {
        let len = dns_payload[pos] as usize;
        if len == 0 {
            break;
        }
        if pos + len + 1 > dns_payload.len() {
            return None;
        }

        let label = &dns_payload[pos + 1..pos + 1 + len];
        domain_name.push_str(&String::from_utf8_lossy(label));
        domain_name.push('.');

        pos += len + 1;
    }

    if domain_name.ends_with('.') {
        domain_name.pop();
    }

    Some(domain_name)
}
