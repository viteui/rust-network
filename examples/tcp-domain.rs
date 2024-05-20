use pnet::datalink::Channel::Ethernet; // 导入以太网通道
use pnet::datalink::{self, NetworkInterface}; // 导入datalink模块中的相关项
use pnet::packet::ethernet::{EtherTypes, EthernetPacket}; // 导入以太网数据包相关项
use pnet::packet::ip::IpNextHeaderProtocols; // 导入IP协议相关项
use pnet::packet::ipv4::Ipv4Packet; // 导入IPv4数据包相关项
use pnet::packet::tcp::TcpPacket; // 导入TCP数据包相关项
use pnet::packet::Packet; // 导入数据包trait
use pnet::packet::udp::UdpPacket;
use pnet::packet::tcp::TcpFlags;

use std::env; // 导入env模块

fn handle_packet(ethernet: &EthernetPacket) {
    // 对Ipv4的包按层解析
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            // 如果是IPv4数据包
            let header = Ipv4Packet::new(ethernet.payload()); // 解析IPv4头部
            if let Some(header) = header {
                if is_localhost(&header) {
                    println!("Intercepted localhost packet: {} -> {}", header.get_source(), header.get_destination());
                    return;
                }
                match header.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        // 如果是TCP协议
                        let tcp = TcpPacket::new(header.payload()); // 解析TCP头部
                        if let Some(tcp) = tcp {
                            if let Some(domain) = handle_tcp_packet(&tcp) {
                                println!("DNS query for domain over TCP: {}", domain);
                            }
                            // println!(
                            //     "Got a TCP packet {}:{} to {}:{}",
                            //     header.get_source(),
                            //     tcp.get_source(),
                            //     header.get_destination(),
                            //     tcp.get_destination(),
                            // );
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        let udp_packet = UdpPacket::new(header.payload());
                        if let Some(udp_packet) = udp_packet {
                            if is_dns_packet(&udp_packet) {
                                if let Some(domain_name) = extract_dns_query(&udp_packet) {
                                    println!("DNS query for domain: {}", domain_name);
                                }
                            }
                        }
                    }
                    _ => println!("Ignoring non TCP/UDP packet"), // 忽略其他非TCP/UDP协议
                }
            }
        }
        _ => println!("Ignoring non IPv4 packet"), // 忽略非IPv4数据包
    }
}

fn main() {
    let interface_name = env::args().nth(1).unwrap(); // 获取命令行参数中的接口名称

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
        // 获取收到的包
        match rx.next() {
            Ok(packet) => {
                let packet = EthernetPacket::new(packet).unwrap(); // 解析以太网数据包
                handle_packet(&packet); // 处理接收到的数据包
            }
            Err(e) => {
                panic!("An error occurred while reading: {}", e); // 如果读取数据包时发生错误，打印错误消息并退出
            }
        }
    }
}

// 检查是否为DNS数据包
fn is_dns_packet(udp_packet: &UdpPacket) -> bool {
    let source_port = udp_packet.get_source();
    let destination_port = udp_packet.get_destination();
    source_port == 53 || destination_port == 53
}

// 提取DNS请求中的域名
fn extract_dns_query(udp_packet: &UdpPacket) -> Option<String> {
    let payload = udp_packet.payload();
    if payload.len() < 12 {
        return None;
    }

    let mut pos = 12; // DNS头部长度
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

// 简化的处理TCP包，尝试找到可能的DNS数据（注意：这不完全准确处理TCP DNS流量）
fn handle_tcp_packet(tcp: &TcpPacket) -> Option<String> {
    // 确保TCP标志中有ACK和PSH，这可能表明是DNS响应的一部分，但实际检查更复杂
    if tcp.get_flags() & TcpFlags::ACK != 0 && tcp.get_flags() & TcpFlags::PSH != 0 {
        if is_dns_packet_tcp(&tcp) {
            if let Some(domain_name) = extract_dns_query_tcp(&tcp) {
                return Some(domain_name);
            }
        }
    }
    None
}

// 检查是否为DNS数据包
fn is_dns_packet_tcp(tcp_packet: &TcpPacket) -> bool {
    let source_port = tcp_packet.get_source();
    let destination_port = tcp_packet.get_destination();
    source_port == 53 || destination_port == 53
}

// 提取DNS请求中的域名
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

    let mut pos = 12; // DNS头部长度
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

// 检查是否为localhost或127.0.0.1的包
fn is_localhost(ipv4_packet: &Ipv4Packet) -> bool {
    let source = ipv4_packet.get_source();
    let destination = ipv4_packet.get_destination();
    println!("Source: {:?} ---> Destination: {:?}", source, destination);
    source.to_string() == "127.0.0.1" || destination.to_string() == "127.0.0.1"
}
