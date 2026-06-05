//! 协议解析模块
//!
//! netHawk 的分层协议解析框架。每个子模块负责一层协议的解析，
//! 从链路层（Ethernet）到应用层（HTTP、DNS）。
//!
//! # 解析链
//!
//! ```text
//! EthernetFrame → IPv4Packet / IPv6Packet → TCPSegment / UDPSegment → HTTPMessage / DNSRequest
//! ```
//!
//! # 统一结果类型
//!
//! [`ParseResult`] 枚举封装所有协议层的解析结果，供上层抓包管线统一消费。

pub mod ethernet;
pub mod ip;
pub mod tcp;
pub mod udp;
pub mod http;
pub mod dns;

use ethernet::EthernetFrame;
use ip::{IPv4Packet, IPv6Packet};
use tcp::TCPSegment;
use udp::UDPSegment;
use http::HTTPMessage;
use dns::DNSRequest;

/// 协议解析统一结果。
///
/// 将各层协议的解析结果封装为单一枚举，便于抓包管线跳过
/// 不关心的变体或按类型分派后续处理。
pub enum ParseResult<'a> {
    /// 以太网帧。
    Ethernet(EthernetFrame<'a>),
    /// IPv4 数据包。
    IPv4(IPv4Packet<'a>),
    /// IPv6 数据包。
    IPv6(IPv6Packet<'a>),
    /// TCP 段。
    TCP(TCPSegment<'a>),
    /// UDP 数据报。
    UDP(UDPSegment<'a>),
    /// HTTP/1.x 报文（请求或响应）。
    HTTP(HTTPMessage<'a>),
    /// DNS 报文。
    DNS(DNSRequest),
}