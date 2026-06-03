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

pub enum ParseResult<'a> {
    Ethernet(EthernetFrame<'a>),
    IPv4(IPv4Packet<'a>),
    IPv6(IPv6Packet),
    TCP(TCPSegment<'a>),
    UDP(UDPSegment),
    HTTP(HTTPMessage),
    DNS(DNSRequest),
}