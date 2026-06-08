//! 捕获引擎模块
//!
//! 封装 pcap 数据包捕获逻辑，提供 [`CaptureEngine`] 结构体和相关方法
//!
//! # 用法
//!
//! ```no run
//! let mut engine = CaptureEngine::new(&args);
//! engine.run()?;
//! ```

use crate::protocol::*;
use crate::cli::CaptureArgs;
use pcap::Capture;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// 网络数据包捕获引擎
///
/// 封装 pcap 会话的创建、BPF 过滤器设置和抓包循环
pub struct CaptureEngine {
    /// 当前 pcap 会话的捕获套接字。
    cap: pcap::Capture<pcap::Active>,

    /// 设置最大抓包上限。
    limit: u64,

    /// 指定输出路径。
    output: Option<String>,

    /// 详细输出模式。
    verbose: bool,
}

impl CaptureEngine {
    /// 创建捕获引擎并初始化 pcap 会话。
    ///
    /// # 错误
    ///
    /// 网卡不存在或者权限不足时返回错误。
    pub fn new(args: &CaptureArgs) -> anyhow::Result<Self> {
        let mut cap = Capture::from_device(args.interface.as_str())?
            .promisc(true) // 混杂模式
            .snaplen(args.snaplen) // 快照长度
            .timeout(args.timeout) // 超时ms
            .open()?;
        // 启用 BPF 过滤器
        if let Some(ref f) = args.filter {
            cap.filter(f, true)?;
        }
        // 非阻塞模式：setnonblock 消耗 cap 并返回新的 cap，需在局部变量阶段调用
        let cap = cap.setnonblock()?;
        // 启用上限抓包计数
        let limit = args.count.unwrap_or(u64::MAX);
        Ok(Self {
            cap,
            limit,
            output: args.output.clone(),
            verbose: args.show_details,
        })
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        // 计数当前已抓获包数
        let mut captured = 0;
        let mut byte = 0;
        // pcap 文件保存路径
        // .as_deref() 将 Option<String> 转为 Option<&str>
        let mut writer = if let Some(path) = self.output.as_deref() {
            // Option<Result<Savefile, Error>>
            Some(self.cap.savefile(path)?)
        } else {
            None
        };

        let running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&running);
        // 设置 signal handler
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })?;

        // 抓包循环（非阻塞：无包时立即返回，每 50ms 检查一次 running）
        while running.load(Ordering::SeqCst) {
            match self.cap.next_packet() {
                Ok(packet) => {
                    if self.verbose {
                        print_packet(packet.data);
                    } else {
                        print_one_liner(packet.data, packet.header.ts.tv_sec as i64, packet.header.ts.tv_usec as i64);
                    }
                    // .as_mut() 拿到 Option 中的可变引用，不将其 move 出来。
                    if let Some(w) = writer.as_mut() {
                        w.write(&packet);
                    }

                    captured += 1;
                    byte += packet.data.len();
                    if captured >= self.limit {
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => {
                    // 非阻塞模式下无包可读，短暂休眠避免 CPU 空转，然后回头检查 running
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                Err(_) => break, // 真实错误，退出
            }
        }
        println!("共抓取了 {} 个数据包，{} 字节。", captured, byte);
        Ok(())
    }
}

// ============================================================================
// 协议分发函数 — 按上层协议字段路由到下一层解析器
// ============================================================================

/// 从以太网帧分发到网络层（IPv4 / IPv6 / ARP）。
fn dispatch_from_ethernet<'a>(eth: &EthernetFrame<'a>) -> anyhow::Result<ParseResult<'a>> {
    match eth.ethernet_type {
        0x0800 => Ok(ParseResult::IPv4(IPv4Packet::parse(eth.payload)?)),
        0x86DD => Ok(ParseResult::IPv6(IPv6Packet::parse(eth.payload)?)),
        0x0806 => Ok(ParseResult::NotSupported), // ARP
        _ => Ok(ParseResult::Unknown),
    }
}

/// 从 IPv4 分发到传输层（TCP / UDP / ICMP）。
fn dispatch_from_ipv4<'a>(ipv4: &IPv4Packet<'a>) -> anyhow::Result<ParseResult<'a>> {
    match ipv4.next_protocol {
        6 => Ok(ParseResult::TCP(TCPSegment::parse(ipv4.payload)?)),
        17 => Ok(ParseResult::UDP(UDPSegment::parse(ipv4.payload)?)),
        1 => Ok(ParseResult::NotSupported), // ICMP
        _ => Ok(ParseResult::Unknown),
    }
}

/// 从 IPv6 分发到传输层（TCP / UDP / ICMPv6）。
fn dispatch_from_ipv6<'a>(ipv6: &IPv6Packet<'a>) -> anyhow::Result<ParseResult<'a>> {
    match ipv6.next_header {
        6 => Ok(ParseResult::TCP(TCPSegment::parse(ipv6.payload)?)),
        17 => Ok(ParseResult::UDP(UDPSegment::parse(ipv6.payload)?)),
        58 => Ok(ParseResult::NotSupported), // ICMPv6
        _ => Ok(ParseResult::Unknown),
    }
}

// ============================================================================
// 数据包打印 — 顺序解析 → 逐层打印
// ============================================================================

/// 从原始字节顺序解析并打印各层协议信息。
///
/// 解析链：Ethernet → IP → TCP/UDP。每层解析后立即打印摘要，
/// 再分发到下一层。解析失败时不 panic，打印错误信息并继续。
fn print_packet(raw: &[u8]) {
    // ── L2: 以太网 ──
    let eth = match EthernetFrame::parse(raw) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("  [L2 解析失败] {}", e);
            return;
        }
    };
    println!(
        "  ETH  {} → {}  type={:#06x}",
        EthernetFrame::format_mac(&eth.src_mac),
        EthernetFrame::format_mac(&eth.dst_mac),
        eth.ethernet_type,
    );

    // ── L2 → L3 ──
    let l3 = match dispatch_from_ethernet(&eth) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [L3 分发失败] {}", e);
            return;
        }
    };

    // ── L3: 网络层 ──
    match l3 {
        ParseResult::IPv4(ref ipv4) => {
            println!(
                "  IPv4 {} → {}  ttl={}  proto={}",
                IPv4Packet::format_ip(&ipv4.src_ip),
                IPv4Packet::format_ip(&ipv4.dst_ip),
                ipv4.ttl,
                ipv4.next_protocol,
            );
            match dispatch_from_ipv4(ipv4) {
                Ok(l4) => print_transport(&l4),
                Err(e) => eprintln!("  [L4 分发失败] {}", e),
            }
        }
        ParseResult::IPv6(ref ipv6) => {
            println!(
                "  IPv6 {} → {}  hop={}  nh={}",
                IPv6Packet::format_ip(&ipv6.src_ip),
                IPv6Packet::format_ip(&ipv6.dst_ip),
                ipv6.hop_limit,
                ipv6.next_header,
            );
            match dispatch_from_ipv6(ipv6) {
                Ok(l4) => print_transport(&l4),
                Err(e) => eprintln!("  [L4 分发失败] {}", e),
            }
        }
        ParseResult::NotSupported => println!("  [L3] 不支持的上层协议"),
        ParseResult::Unknown => println!("  [L3] 未知 EtherType"),
        _ => {}
    }
    println!("\n");
}

/// 一行摘要输出（默认模式）。
///
/// 格式：`HH:MM:SS.uuuuuu  PROTO  src_ip:port → dst_ip:port  [FLAGS]  LENB`
fn print_one_liner(raw: &[u8], tv_sec: i64, tv_usec: i64) {
    let ts = format_timestamp(tv_sec, tv_usec);
    let len = raw.len();

    // L2
    let eth = match EthernetFrame::parse(raw) {
        Ok(e) => e,
        Err(_) => {
            println!("{ts}  ???  [L2 解析失败]  {len}B");
            return;
        }
    };

    // L2 → L3
    let l3 = match dispatch_from_ethernet(&eth) {
        Ok(r) => r,
        Err(_) => {
            println!("{ts}  ETH  [L3 分发失败]  {len}B");
            return;
        }
    };

    match l3 {
        ParseResult::IPv4(ref ipv4) => {
            let src = IPv4Packet::format_ip(&ipv4.src_ip);
            let dst = IPv4Packet::format_ip(&ipv4.dst_ip);
            let proto = protocol_name(ipv4.next_protocol);
            match dispatch_from_ipv4(ipv4) {
                Ok(l4) => print_l4_one_liner(&ts, proto, &src, &dst, &l4, len),
                Err(_) => println!("{ts}  {proto}  {src} → {dst}  {len}B"),
            }
        }
        ParseResult::IPv6(ref ipv6) => {
            let src = IPv6Packet::format_ip(&ipv6.src_ip);
            let dst = IPv6Packet::format_ip(&ipv6.dst_ip);
            let proto = protocol_name(ipv6.next_header);
            match dispatch_from_ipv6(ipv6) {
                Ok(l4) => print_l4_one_liner(&ts, proto, &src, &dst, &l4, len),
                Err(_) => println!("{ts}  {proto}  {src} → {dst}  {len}B"),
            }
        }
        ParseResult::NotSupported => println!("{ts}  ETH  [L3 不支持]  {len}B"),
        ParseResult::Unknown => println!("{ts}  ETH  type={:#06x}  {len}B", eth.ethernet_type),
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

/// 打印传输层一行摘要。
fn print_l4_one_liner(ts: &str, proto: &str, src: &str, dst: &str, l4: &ParseResult<'_>, len: usize) {
    match l4 {
        ParseResult::TCP(tcp) => {
            println!(
                "{ts}  {proto}  {src}:{sp} → {dst}:{dp}  {flags}  {len}B",
                sp = tcp.src_port,
                dp = tcp.dst_port,
                flags = format_tcp_flags(tcp.flags),
            );
        }
        ParseResult::UDP(udp) => {
            println!(
                "{ts}  {proto}  {src}:{sp} → {dst}:{dp}  {len}B",
                sp = udp.src_port,
                dp = udp.dst_port,
            );
        }
        ParseResult::NotSupported => println!("{ts}  {proto}  {src} → {dst}  [L4 不支持]  {len}B"),
        _ => println!("{ts}  {proto}  {src} → {dst}  {len}B"),
    }
}

/// 打印传输层（TCP / UDP）摘要。
fn print_transport(l4: &ParseResult<'_>) {
    match l4 {
        ParseResult::TCP(tcp) => {
            println!(
                "  TCP  :{} → :{}  {}  seq={}",
                tcp.src_port,
                tcp.dst_port,
                format_tcp_flags(tcp.flags),
                tcp.seq,
            );
        }
        ParseResult::UDP(udp) => {
            println!(
                "  UDP  :{} → :{}  len={}",
                udp.src_port, udp.dst_port, udp.len,
            );
        }
        ParseResult::NotSupported => println!("  [L4] 不支持的传输层协议"),
        ParseResult::Unknown => println!("  [L4] 未知协议号"),
        _ => {}
    }
}

/// 格式化 TCP 标志位为简写字符串（如 `[SYN]`、`[SYN,ACK]`）。
fn format_tcp_flags(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & 0x01 != 0 { parts.push("FIN"); }
    if flags & 0x02 != 0 { parts.push("SYN"); }
    if flags & 0x04 != 0 { parts.push("RST"); }
    if flags & 0x08 != 0 { parts.push("PSH"); }
    if flags & 0x10 != 0 { parts.push("ACK"); }
    if flags & 0x20 != 0 { parts.push("URG"); }
    if parts.is_empty() {
        "[NONE]".to_string()
    } else {
        format!("[{}]", parts.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CaptureArgs;

    /// 无效网卡名应返回 Err，而不是 panic。
    #[test]
    fn test_capture_engine_invalid_interface() {
        let args = CaptureArgs {
            interface: "nonexistent_iface_xyz".into(),
            count: Some(1),
            filter: None,
            output: None,
            snaplen: 65535,
            timeout: 1000,
            show_details: true,
        };
        assert!(CaptureEngine::new(&args).is_err());
    }
}
