//! 协议解析模块
//!
//! netHawk 的分层协议解析框架。每个子模块负责一层协议的解析，
//! 从链路层（Ethernet）到应用层（HTTP、DNS）。
//!
//! # 解析链
//!
//! ```text
//! EthernetFrame → ARPPacket              (EtherType 0x0806)
//! EthernetFrame → IPv4Packet / IPv6Packet (EtherType 0x0800 / 0x86DD)
//! IPv4Packet / IPv6Packet → ICMPPacket    (proto 1 / nh 58)
//! IPv4Packet / IPv6Packet → TCPSegment / UDPSegment → HTTPMessage / DNSRequest
//! ```
//!
//! # 统一结果类型
//!
//! [`ParseResult`] 枚举封装所有协议层的解析结果，供上层抓包管线统一消费。

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod ethernet;
pub mod http;
pub mod icmp;
pub mod ip;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use arp::ARPPacket;
pub use dhcp::DhcpPacket;
pub use dns::DNSRequest;
pub use ethernet::EthernetFrame;
pub use http::HTTPMessage;
pub use icmp::ICMPPacket;
pub use ip::{IPv4Packet, IPv6Packet};
pub use tcp::TCPSegment;
pub use tls::parse_client_hello;
pub use udp::UDPSegment;

/// 协议解析统一结果。
///
/// 将各层协议的解析结果封装为单一枚举，便于抓包管线跳过
/// 不关心的变体或按类型分派后续处理。
#[allow(dead_code, clippy::upper_case_acronyms)]
pub enum ParseResult<'a> {
    Ethernet(EthernetFrame<'a>),
    ARP(ARPPacket<'a>),
    IPv4(IPv4Packet<'a>),
    IPv6(IPv6Packet<'a>),
    ICMP(ICMPPacket<'a>),
    TCP(TCPSegment<'a>),
    UDP(UDPSegment<'a>),
    HTTP(HTTPMessage<'a>),
    DNS(DNSRequest),
    NotSupported,
    Unknown,
}

// ============================================================================
// 协议路由分发 — 按上层协议字段路由到下一层解析器
// ============================================================================

/// 从以太网帧分发到网络层（IPv4 / IPv6 / ARP）。
pub fn dispatch_from_ethernet<'a>(eth: &EthernetFrame<'a>) -> anyhow::Result<ParseResult<'a>> {
    match eth.ethernet_type {
        0x0800 => Ok(ParseResult::IPv4(IPv4Packet::parse(eth.payload)?)),
        0x86DD => Ok(ParseResult::IPv6(IPv6Packet::parse(eth.payload)?)),
        0x0806 => Ok(ParseResult::ARP(ARPPacket::parse(eth.payload)?)),
        _ => Ok(ParseResult::Unknown),
    }
}

/// 从 IPv4 分发到传输层（TCP / UDP / ICMP）。
pub fn dispatch_from_ipv4<'a>(ipv4: &IPv4Packet<'a>) -> anyhow::Result<ParseResult<'a>> {
    match ipv4.next_protocol {
        6 => Ok(ParseResult::TCP(TCPSegment::parse(ipv4.payload)?)),
        17 => Ok(ParseResult::UDP(UDPSegment::parse(ipv4.payload)?)),
        1 => Ok(ParseResult::ICMP(ICMPPacket::parse(ipv4.payload)?)),
        _ => Ok(ParseResult::Unknown),
    }
}

/// 从 IPv6 分发到传输层（TCP / UDP / ICMPv6）。
pub fn dispatch_from_ipv6<'a>(ipv6: &IPv6Packet<'a>) -> anyhow::Result<ParseResult<'a>> {
    match ipv6.next_header {
        6 => Ok(ParseResult::TCP(TCPSegment::parse(ipv6.payload)?)),
        17 => Ok(ParseResult::UDP(UDPSegment::parse(ipv6.payload)?)),
        58 => Ok(ParseResult::ICMP(ICMPPacket::parse(ipv6.payload)?)),
        _ => Ok(ParseResult::Unknown),
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// dispatch_from_ethernet 对未知 EtherType 返回 Unknown。
    #[test]
    fn dispatch_eth_unknown_ethertype() {
        let mut raw = [0u8; 20];
        raw[12..14].copy_from_slice(&[0x99, 0x99]);
        let eth = EthernetFrame::parse(&raw).unwrap();
        assert!(matches!(dispatch_from_ethernet(&eth).unwrap(), ParseResult::Unknown));
    }

    /// dispatch_from_ethernet 正确路由到 IPv4。
    #[test]
    fn dispatch_eth_to_ipv4() {
        let mut raw = vec![0u8; 34];
        raw[12..14].copy_from_slice(&[0x08, 0x00]);
        raw[14] = 0x45;
        raw[23] = 6;
        let eth = EthernetFrame::parse(&raw).unwrap();
        assert!(matches!(dispatch_from_ethernet(&eth).unwrap(), ParseResult::IPv4(_)));
    }

    /// dispatch_from_ipv4 正确路由到 TCP。
    #[test]
    fn dispatch_ipv4_to_tcp() {
        let mut raw = vec![0u8; 40]; // 20 IP + 20 TCP
        raw[0] = 0x45; raw[9] = 6;
        raw[32] = 0x50; // TCP data_offset=5 at payload[12]
        let ipv4 = IPv4Packet::parse(&raw).unwrap();
        assert!(matches!(dispatch_from_ipv4(&ipv4).unwrap(), ParseResult::TCP(_)));
    }

    /// dispatch_from_ipv4 正确路由到 UDP。
    #[test]
    fn dispatch_ipv4_to_udp() {
        let mut raw = vec![0u8; 28]; // 20 IP + 8 UDP
        raw[0] = 0x45; raw[9] = 17; // UDP
        raw[24..26].copy_from_slice(&8u16.to_be_bytes()); // UDP length
        let ipv4 = IPv4Packet::parse(&raw).unwrap();
        assert!(matches!(dispatch_from_ipv4(&ipv4).unwrap(), ParseResult::UDP(_)));
    }

    /// dispatch_from_ipv4 正确路由到 ICMP。
    #[test]
    fn dispatch_ipv4_to_icmp() {
        let mut raw = vec![0u8; 24]; // 20 IP + 4 ICMP
        raw[0] = 0x45; raw[9] = 1; // ICMP
        let ipv4 = IPv4Packet::parse(&raw).unwrap();
        assert!(matches!(dispatch_from_ipv4(&ipv4).unwrap(), ParseResult::ICMP(_)));
    }

    /// dispatch_from_ipv4 未知协议返回 Unknown。
    #[test]
    fn dispatch_ipv4_unknown_proto() {
        let mut raw = vec![0u8; 20];
        raw[0] = 0x45; raw[9] = 99; // 未知
        let ipv4 = IPv4Packet::parse(&raw).unwrap();
        assert!(matches!(dispatch_from_ipv4(&ipv4).unwrap(), ParseResult::Unknown));
    }

    /// dispatch_from_ipv6 正确路由到 TCP。
    #[test]
    fn dispatch_ipv6_to_tcp() {
        let mut raw = vec![0u8; 60]; // 40 IPv6 + 20 TCP
        raw[0] = 0x60; raw[6] = 6;
        raw[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload_len
        raw[52] = 0x50; // TCP data_offset=5 at payload[12]
        let ipv6 = IPv6Packet::parse(&raw).unwrap();
        assert!(matches!(dispatch_from_ipv6(&ipv6).unwrap(), ParseResult::TCP(_)));
    }

    /// dispatch_from_ipv6 正确路由到 UDP。
    #[test]
    fn dispatch_ipv6_to_udp() {
        let mut raw = vec![0u8; 48]; // 40 IPv6 + 8 UDP
        raw[0] = 0x60; raw[6] = 17;
        raw[4..6].copy_from_slice(&8u16.to_be_bytes()); // IPv6 payload len
        raw[44..46].copy_from_slice(&8u16.to_be_bytes()); // UDP length at payload[4]
        let ipv6 = IPv6Packet::parse(&raw).unwrap();
        assert!(matches!(dispatch_from_ipv6(&ipv6).unwrap(), ParseResult::UDP(_)));
    }

    /// dispatch_from_ipv6 未知 Next Header 返回 Unknown。
    #[test]
    fn dispatch_ipv6_unknown_nh() {
        let mut raw = vec![0u8; 40];
        raw[0] = 0x60; raw[6] = 99;
        let ipv6 = IPv6Packet::parse(&raw).unwrap();
        assert!(matches!(dispatch_from_ipv6(&ipv6).unwrap(), ParseResult::Unknown));
    }
}
