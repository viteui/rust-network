use std::net::Ipv4Addr; // 导入Ipv4Addr结构体
use pnet::datalink; // 导入datalink模块
use pnet::ipnetwork; // 导入ipnetwork模块

fn main() {
    let interfaces = datalink::interfaces(); // 获取所有网络接口信息

    for interface in interfaces {
        let ip: Vec<Ipv4Addr> = interface.ips.iter().map(|ip| match ip {
            ipnetwork::IpNetwork::V4(ref ipv4) => Ok(ipv4.ip()), // 提取IPv4地址
            _ => Err(""), // 其他类型的地址暂时忽略
        }).filter_map(Result::ok).collect(); // 过滤出成功匹配的IPv4地址，并收集到向量中

        #[cfg(unix)] // Unix系统条件编译
        if !ip.is_empty() && !interface.is_loopback() && interface.is_running() && interface.is_up() {
            println!("{}", interface.name); // 打印接口名称
        }

        #[cfg(not(unix))] // 非Unix系统条件编译
        if !ip.is_empty() && !interface.is_loopback() && interface.is_running() && interface.is_up() {
            println!("{}", interface.name); // 打印接口名称
        }
    }
}