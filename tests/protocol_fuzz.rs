//! 协议解析模糊测试
//!
//! 使用 proptest 对每个协议解析器喂入随机字节，验证不会 panic。
//! 原则：解析器可以返回 Err，但绝不能 panic。

use proptest::prelude::*;
use nethawk::protocol::ethernet::EthernetFrame;
use nethawk::protocol::ip::{IPv4Packet, IPv6Packet};
use nethawk::protocol::tcp::TCPSegment;
use nethawk::protocol::udp::UDPSegment;
use nethawk::protocol::dns::DNSRequest;
use nethawk::protocol::http::HTTPMessage;

proptest! {
    // ======================================================================
    // 链路层
    // ======================================================================

    /// 以太网帧解析：任意字节输入不 panic。
    #[test]
    fn fuzz_ethernet(data in any::<Vec<u8>>()) {
        let _ = EthernetFrame::parse(&data);
    }

    // ======================================================================
    // 网络层
    // ======================================================================

    /// IPv4 解析：任意字节输入不 panic。
    #[test]
    fn fuzz_ipv4(data in any::<Vec<u8>>()) {
        let _ = IPv4Packet::parse(&data);
    }

    /// IPv6 解析：任意字节输入不 panic。
    #[test]
    fn fuzz_ipv6(data in any::<Vec<u8>>()) {
        let _ = IPv6Packet::parse(&data);
    }

    // ======================================================================
    // 传输层
    // ======================================================================

    /// TCP 解析：任意字节输入不 panic。
    #[test]
    fn fuzz_tcp(data in any::<Vec<u8>>()) {
        let _ = TCPSegment::parse(&data);
    }

    /// UDP 解析：任意字节输入不 panic。
    #[test]
    fn fuzz_udp(data in any::<Vec<u8>>()) {
        let _ = UDPSegment::parse(&data);
    }

    // ======================================================================
    // 应用层
    // ======================================================================

    /// DNS 解析：任意字节输入不 panic。
    #[test]
    fn fuzz_dns(data in any::<Vec<u8>>()) {
        let _ = DNSRequest::parse(&data);
    }

    /// HTTP 解析：任意字节输入不 panic。
    #[test]
    fn fuzz_http(data in any::<Vec<u8>>()) {
        let _ = HTTPMessage::parse(&data);
    }

    // ======================================================================
    // 格式化函数
    // ======================================================================

    /// MAC 地址格式化：任意 [u8;6] 输入不 panic。
    #[test]
    fn fuzz_format_mac(bytes in any::<[u8; 6]>()) {
        let _ = EthernetFrame::format_mac(&bytes);
    }

    /// IPv4 格式化：任意 [u8;4] 输入不 panic。
    #[test]
    fn fuzz_format_ipv4(bytes in any::<[u8; 4]>()) {
        let _ = IPv4Packet::format_ip(&bytes);
    }

    /// IPv6 格式化：任意 [u8;16] 输入不 panic。
    #[test]
    fn fuzz_format_ipv6(bytes in any::<[u8; 16]>()) {
        let _ = IPv6Packet::format_ip(&bytes);
    }
}
