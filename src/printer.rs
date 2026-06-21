//! 数据包打印模块
//!
//! 提供十六进制 dump、逐包详细打印、单行摘要和 JSON 输出四种格式，
//! 供 capture/analyse 引擎共享使用。

use std::io::Write;

use crate::protocol::*;
use colored::Colorize;

/// 16 进制输出
pub fn hexdump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("  {:#06x}  ", i * 16);
        for (j, &byte) in chunk.iter().enumerate() {
            if j == 8 {
                print!(" ");
            }
            print!("{:02x} ", byte);
        }
        // 补齐不足 16 字节的行
        let pad = (16 - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
        print!("{:pad$}", "");
        print!(" ");
        for &byte in chunk {
            if byte.is_ascii_graphic() || byte == b' ' {
                print!("{}", byte as char);
            } else {
                print!(".");
            }
        }
        println!();
    }
}

// ============================================================================
// 数据包打印 — 顺序解析 → 逐层打印
// ============================================================================

/// 从原始字节顺序解析并打印各层协议信息。
///
/// 解析链：Ethernet → ARP / IP → ICMP / TCP / UDP。每层解析后立即打印摘要，
/// 再分发到下一层。解析失败时不 panic，打印错误信息并继续。
pub fn print_packet(raw: &[u8]) {
    // ── L2: 以太网 ──
    let eth = match EthernetFrame::parse(raw) {
        Ok(e) => e,
        Err(e) => {
            let line = format!("  [L2 解析失败] {}", e);
            eprintln!("{}", line.red());
            return;
        }
    };
    let ethline = format!(
        "  ETH  {} → {}  type={:#06x}",
        EthernetFrame::format_mac(&eth.src_mac),
        EthernetFrame::format_mac(&eth.dst_mac),
        eth.ethernet_type
    );
    println!("{}", ethline.cyan());

    // ── L2 → L3 ──
    let l3 = match dispatch_from_ethernet(&eth) {
        Ok(r) => r,
        Err(e) => {
            let line = format!("  [L3 分发失败] {}", e);
            eprintln!("{}", line.red());
            return;
        }
    };

    // ── L3: 网络层 ──
    match l3 {
        ParseResult::ARP(ref arp) => {
            let sender_ip = ARPPacket::format_ip(arp.sender_proto_addr);
            let target_ip = ARPPacket::format_ip(arp.target_proto_addr);
            let op = ARPPacket::operation_name(arp.operation);
            let line = format!("  ARP  {}  who-has {}  tell {}", op, target_ip, sender_ip);
            println!("{}", line.magenta());
            // ARP 不进入 L4 分发
        }
        ParseResult::IPv4(ref ipv4) => {
            let ipline = format!(
                "  IPv4 {} → {}  ttl={}  proto={}",
                IPv4Packet::format_ip(&ipv4.src_ip),
                IPv4Packet::format_ip(&ipv4.dst_ip),
                ipv4.ttl,
                ipv4.next_protocol
            );
            println!("{}", ipline.blue());
            match dispatch_from_ipv4(ipv4) {
                Ok(l4) => print_transport(&l4),
                Err(e) => {
                    let line = format!("  [L4 分发失败] {}", e);
                    eprintln!("{}", line.red());
                    return;
                }
            }
        }
        ParseResult::IPv6(ref ipv6) => {
            let ipline = format!(
                "  IPv6 {} → {}  hop={}  nh={}",
                IPv6Packet::format_ip(&ipv6.src_ip),
                IPv6Packet::format_ip(&ipv6.dst_ip),
                ipv6.hop_limit,
                ipv6.next_header
            );
            println!("{}", ipline.blue());
            match dispatch_from_ipv6(ipv6) {
                Ok(l4) => print_transport(&l4),
                Err(e) => {
                    let line = format!("  [L4 分发失败] {}", e);
                    eprintln!("{}", line.red());
                    return;
                }
            }
        }
        ParseResult::NotSupported => println!("{}", "  [L3] 不支持的上层协议".red()),
        ParseResult::Unknown => println!("{}", "  [L3] 未知 EtherType".red()),
        _ => {}
    }
    println!("\n");
    std::io::stdout().flush().ok();
}

/// 一行摘要输出（默认模式）。
///
/// 格式：`HH:MM:SS.uuuuuu  PROTO  src_ip:port → dst_ip:port  [FLAGS]  LENB`
pub fn print_one_liner(raw: &[u8], tv_sec: i64, tv_usec: i64) {
    let ts = format_timestamp(tv_sec, tv_usec);
    let len = raw.len();

    // L2
    let eth = match EthernetFrame::parse(raw) {
        Ok(e) => e,
        Err(_) => {
            println!("{}", "{ts}  ???  [L2 解析失败]  {len}B".red());
            return;
        }
    };

    // L2 → L3
    let l3 = match dispatch_from_ethernet(&eth) {
        Ok(r) => r,
        Err(_) => {
            println!("{}", "{ts}  ETH  [L3 分发失败]  {len}B".red());
            return;
        }
    };

    match l3 {
        ParseResult::ARP(ref arp) => {
            let sender_ip = ARPPacket::format_ip(arp.sender_proto_addr);
            let target_ip = ARPPacket::format_ip(arp.target_proto_addr);
            let op = ARPPacket::operation_name(arp.operation);
            let line = format!("{ts}  ARP  {op}  who-has {target_ip}  tell {sender_ip}  {len}B");
            println!("{}", line.magenta());
        }
        ParseResult::IPv4(ref ipv4) => {
            let src = IPv4Packet::format_ip(&ipv4.src_ip);
            let dst = IPv4Packet::format_ip(&ipv4.dst_ip);
            let proto = protocol_name(ipv4.next_protocol);
            match dispatch_from_ipv4(ipv4) {
                Ok(l4) => print_l4_one_liner(&ts, proto, &src, &dst, &l4, len),
                Err(_) => {
                    let line = format!("{}  {}  {} → {}  {}B", ts, proto, src, dst, len);
                    println!("{}", line.blue());
                }
            }
        }
        ParseResult::IPv6(ref ipv6) => {
            let src = IPv6Packet::format_ip(&ipv6.src_ip);
            let dst = IPv6Packet::format_ip(&ipv6.dst_ip);
            let proto = protocol_name(ipv6.next_header);
            match dispatch_from_ipv6(ipv6) {
                Ok(l4) => print_l4_one_liner(&ts, proto, &src, &dst, &l4, len),
                Err(_) => {
                    let line = format!("{ts}  {proto}  {src} → {dst}  {len}B");
                    println!("{}", line.blue());
                }
            }
        }
        ParseResult::NotSupported => {
            let line = format!("{ts}  ETH  [L3 不支持]  {len}B");
            println!("{}", line.red());
        }
        ParseResult::Unknown => {
            let line = format!("{ts}  ETH  type={:#06x}  {len}B", eth.ethernet_type);
            println!("{}", line.yellow());
        }
        _ => {}
    }
    std::io::stdout().flush().ok();
}

/// JSON 格式输出（需启用 `json` feature）。
///
/// 输出一条 JSON 行，包含时间戳、各层协议字段。
#[cfg(feature = "json")]
pub(crate) fn print_json(raw: &[u8], tv_sec: i64, tv_usec: i64) {
    use serde_json::json;

    let ts = format_timestamp(tv_sec, tv_usec);
    let mut obj = json!({
        "ts": ts,
        "len": raw.len(),
    });

    let eth = match EthernetFrame::parse(raw) {
        Ok(e) => e,
        Err(_) => {
            obj["error"] = json!("L2 parse failed");
            println!("{}", serde_json::to_string(&obj).unwrap());
            return;
        }
    };

    obj["eth"] = json!({
        "src_mac": EthernetFrame::format_mac(&eth.src_mac),
        "dst_mac": EthernetFrame::format_mac(&eth.dst_mac),
        "ethertype": format!("{:#06x}", eth.ethernet_type),
    });

    let l3 = match dispatch_from_ethernet(&eth) {
        Ok(r) => r,
        Err(e) => {
            obj["error"] = json!(format!("L3 dispatch failed: {e}"));
            println!("{}", serde_json::to_string(&obj).unwrap());
            return;
        }
    };

    match l3 {
        ParseResult::ARP(ref arp) => {
            obj["arp"] = json!({
                "operation": ARPPacket::operation_name(arp.operation),
                "sender_mac": ARPPacket::format_mac(arp.sender_hw_addr),
                "sender_ip": ARPPacket::format_ip(arp.sender_proto_addr),
                "target_mac": ARPPacket::format_mac(arp.target_hw_addr),
                "target_ip": ARPPacket::format_ip(arp.target_proto_addr),
            });
        }
        ParseResult::IPv4(ref ip) => {
            obj["ip"] = json!({
                "version": 4,
                "src": IPv4Packet::format_ip(&ip.src_ip),
                "dst": IPv4Packet::format_ip(&ip.dst_ip),
                "ttl": ip.ttl,
                "proto": ip.next_protocol,
            });
            if let Ok(l4) = dispatch_from_ipv4(ip) {
                add_l4_json(&mut obj, &l4);
            }
        }
        ParseResult::IPv6(ref ip) => {
            obj["ipv6"] = json!({
                "version": 6,
                "src": IPv6Packet::format_ip(&ip.src_ip),
                "dst": IPv6Packet::format_ip(&ip.dst_ip),
                "hop_limit": ip.hop_limit,
                "next_header": ip.next_header,
            });
            if let Ok(l4) = dispatch_from_ipv6(ip) {
                add_l4_json(&mut obj, &l4);
            }
        }
        _ => {}
    }

    println!("{}", serde_json::to_string(&obj).unwrap());
    std::io::stdout().flush().ok();
}

/// 向 JSON 对象中添加传输层字段。
#[cfg(feature = "json")]
fn add_l4_json(obj: &mut serde_json::Value, l4: &ParseResult<'_>) {
    use serde_json::json;
    match l4 {
        ParseResult::ICMP(icmp) => {
            let mut icmp_obj = json!({
                "type": icmp.icmp_type,
                "type_name": ICMPPacket::type_name(icmp.icmp_type),
                "code": icmp.code,
                "checksum": icmp.checksum,
            });
            if let Some(id) = icmp.identifier() {
                icmp_obj["id"] = json!(id);
            }
            if let Some(seq) = icmp.sequence() {
                icmp_obj["seq"] = json!(seq);
            }
            icmp_obj["payload_len"] = json!(icmp.payload.len());
            obj["icmp"] = icmp_obj;
        }
        ParseResult::TCP(tcp) => {
            obj["tcp"] = json!({
                "src_port": tcp.src_port,
                "dst_port": tcp.dst_port,
                "flags": format_tcp_flags(tcp.flags),
                "seq": tcp.seq,
            });
        }
        ParseResult::UDP(udp) => {
            obj["udp"] = json!({
                "src_port": udp.src_port,
                "dst_port": udp.dst_port,
                "len": udp.len,
            });
        }
        _ => {}
    }
}

/// 格式化 Unix 时间戳为 `HH:MM:SS.uuuuuu`。
fn format_timestamp(tv_sec: i64, tv_usec: i64) -> String {
    let secs_since_midnight = tv_sec.rem_euclid(86400);
    let h = secs_since_midnight / 3600;
    let m = (secs_since_midnight % 3600) / 60;
    let s = secs_since_midnight % 60;
    format!("{h:02}:{m:02}:{s:02}.{tv_usec:06}")
}

/// 协议号 → 缩写。
fn protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        58 => "ICMPv6",
        _ => "???",
    }
}

/// 打印传输层一行摘要（含 ICMP）。
fn print_l4_one_liner(
    ts: &str,
    proto: &str,
    src: &str,
    dst: &str,
    l4: &ParseResult<'_>,
    len: usize,
) {
    match l4 {
        ParseResult::ICMP(icmp) => {
            let tname = ICMPPacket::type_name(icmp.icmp_type);
            let extra = if let (Some(id), Some(seq)) = (icmp.identifier(), icmp.sequence()) {
                format!(" id={id} seq={seq}")
            } else {
                String::new()
            };
            let line = format!(
                "{ts}  {proto}  {src} → {dst}  {tname}  type={t} code={c}{extra}  {len}B",
                t = icmp.icmp_type,
                c = icmp.code,
            );
            println!("{}", line.magenta());
        }
        ParseResult::TCP(tcp) => {
            let line = format!(
                "{ts}  {proto}  {src}:{sp} → {dst}:{dp}  {flags}  {len}B",
                sp = tcp.src_port,
                dp = tcp.dst_port,
                flags = format_tcp_flags(tcp.flags),
            );
            println!("{}", line.green());
        }
        ParseResult::UDP(udp) => {
            let line = format!(
                "{ts}  {proto}  {src}:{sp} → {dst}:{dp}  {len}B",
                sp = udp.src_port,
                dp = udp.dst_port,
            );
            println!("{}", line.green());
        }
        ParseResult::NotSupported => {
            let line = format!("{ts}  {proto}  {src} → {dst}  [L4 不支持]  {len}B");
            println!("{}", line.red());
        }
        _ => {
            let line = format!("{ts}  {proto}  {src} → {dst}  {len}B");
            println!("{}", line.blue());
        }
    }
}

/// 打印传输层（TCP / UDP / ICMP）摘要。
fn print_transport(l4: &ParseResult<'_>) {
    match l4 {
        ParseResult::ICMP(icmp) => {
            let tname = ICMPPacket::type_name(icmp.icmp_type);
            let mut line = format!(
                "  ICMP  {}  type={}  code={}",
                tname, icmp.icmp_type, icmp.code,
            );
            if let (Some(id), Some(seq)) = (icmp.identifier(), icmp.sequence()) {
                line.push_str(&format!("  id={}  seq={}", id, seq));
            }
            line.push_str(&format!("  len={}", icmp.payload.len()));
            println!("{}", line.magenta());
        }
        ParseResult::TCP(tcp) => {
            let line = format!(
                "  TCP  :{} → :{}  {}  seq={}",
                tcp.src_port,
                tcp.dst_port,
                format_tcp_flags(tcp.flags),
                tcp.seq,
            );
            println!("{}", line.green());
        }
        ParseResult::UDP(udp) => {
            let line = format!(
                "  UDP  :{} → :{}  len={}",
                udp.src_port, udp.dst_port, udp.len
            );
            println!("{}", line.green());
        }
        ParseResult::NotSupported => println!("{}", "  [L4] 不支持的传输层协议".red()),
        ParseResult::Unknown => println!("{}", "  [L4] 未知协议号".yellow()),
        _ => {}
    }
}

/// 格式化 TCP 标志位为简写字符串（如 `[SYN]`、`[SYN,ACK]`）。
fn format_tcp_flags(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & 0x01 != 0 {
        parts.push("FIN");
    }
    if flags & 0x02 != 0 {
        parts.push("SYN");
    }
    if flags & 0x04 != 0 {
        parts.push("RST");
    }
    if flags & 0x08 != 0 {
        parts.push("PSH");
    }
    if flags & 0x10 != 0 {
        parts.push("ACK");
    }
    if flags & 0x20 != 0 {
        parts.push("URG");
    }
    if parts.is_empty() {
        "[NONE]".to_string()
    } else {
        format!("[{}]", parts.join(","))
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造最小 IPv4 ICMP Echo Request（14 eth + 20 ip + 8 icmp）。
    fn make_icmp_ping() -> Vec<u8> {
        let mut raw = vec![0u8; 42];
        raw[12..14].copy_from_slice(&[0x08, 0x00]); // EtherType IPv4
        raw[14] = 0x45; raw[23] = 1; // IPv4 → ICMP
        raw[34..36].copy_from_slice(&[0x08, 0x00]); // ICMP type=8, code=0
        raw
    }

    /// 构造最小 IPv4 TCP SYN（14 eth + 20 ip + 20 tcp）。
    fn make_tcp_syn() -> Vec<u8> {
        let mut raw = vec![0u8; 54];
        raw[12..14].copy_from_slice(&[0x08, 0x00]);
        raw[14] = 0x45; raw[23] = 6;
        raw[34] = 0x50; // data_offset=5 (20 bytes)
        raw[34 + 13] = 0x02; // SYN flag
        raw
    }

    /// hexdump 不 panic。
    #[test]
    fn hexdump_does_not_panic() {
        hexdump(&[0x00, 0x11, 0x22, 0xff]);
    }

    /// print_packet 不 panic。
    #[test]
    fn print_packet_does_not_panic() {
        print_packet(&make_icmp_ping());
        print_packet(&make_tcp_syn());
    }

    /// print_one_liner 不 panic。
    #[test]
    fn print_one_liner_does_not_panic() {
        let raw = make_icmp_ping();
        print_one_liner(&raw, 1000000, 500000);
    }

    /// 过短的原始数据不 panic。
    #[test]
    fn print_one_liner_short_raw() {
        // 畸形包不 panic
        print_one_liner(&[0u8; 10], 0, 0);
    }

    /// print_packet 短数据不 panic。
    #[test]
    fn print_packet_short_raw() {
        print_packet(&[0u8; 10]);
    }
}
