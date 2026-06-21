//! 离线分析引擎模块
//!
//! 加载 pcap/pcapng 文件，对每个数据包执行分层协议解析，
//! 支持逐包打印、TLS/DHCP 深度检测、TCP 流跟踪与 HTTP 导出。

use std::collections::HashMap;
use std::io::Write;
use std::time::Instant;

use pcap::Capture;

use crate::cli::AnalyzeArgs;
#[cfg(feature = "json")]
use crate::printer::print_json;
#[allow(unused_imports)]
use crate::printer::{hexdump, print_one_liner, print_packet};
use crate::protocol::*;
use crate::tcp_stream::{FiveTuple, IpAddr as StreamIp, TcpState, TcpStreamTracker};

/// 离线分析引擎。
///
/// 持有分析模式标志（详细/hex/json/深度检测）和 TCP 流跟踪器，
/// 对 pcap 文件逐包解析并输出结果。
pub struct AnalyzeEngine {
    file: String,
    verbose: bool,
    dump: bool,
    #[cfg_attr(not(feature = "json"), allow(dead_code))]
    json: bool,
    follow_http: bool,
    tls: bool,
    dhcp: bool,
    export: bool,
}

impl AnalyzeEngine {
    /// 从 CLI 参数构造分析引擎。
    ///
    /// 将 `AnalyzeArgs` 的各标志映射到引擎内部字段。
    pub fn new(args: &AnalyzeArgs) -> anyhow::Result<Self> {
        Ok(Self {
            file: args.file.clone(),
            verbose: args.verbose_output,
            dump: args.hex,
            json: args.json_output,
            follow_http: args.follow_http,
            tls: args.tls,
            dhcp: args.dhcp,
            export: args.export,
        })
    }

    /// 运行离线分析。
    ///
    /// 打开 pcap 文件 → 逐包解析 → 按模式输出（默认逐行 / TLS / DHCP / HTTP 跟踪 / 导出）。
    #[allow(clippy::unnecessary_cast)] // tv_sec/tv_usec 类型因平台而异
    pub fn run(&self) -> anyhow::Result<()> {
        let mut cap = Capture::from_file(&self.file)?;
        let mut count = 0;
        let mut bytes = 0;
        let now = Instant::now();

        // TCP 流跟踪器（--follow-http / --export 时启用）
        let mut tracker = if self.follow_http || self.export {
            Some(TcpStreamTracker::new())
        } else {
            None
        };

        // HTTP 请求计数
        let mut http_requests: usize = 0;
        // 导出的文件句柄
        let mut export_files: HashMap<FiveTuple, std::fs::File> = HashMap::new();

        while let Ok(packet) = cap.next_packet() {
            count += 1;
            bytes += packet.data.len();

            // ── 基础打印 ──
            if !self.follow_http && !self.tls && !self.dhcp {
                // 默认模式：逐包打印
                #[cfg(feature = "json")]
                if self.json {
                    print_json(
                        packet.data,
                        packet.header.ts.tv_sec as i64,
                        packet.header.ts.tv_usec as i64,
                    );
                }

                #[cfg(feature = "json")]
                if !self.json {
                    if self.verbose {
                        print_packet(packet.data);
                    } else {
                        print_one_liner(
                            packet.data,
                            packet.header.ts.tv_sec as i64,
                            packet.header.ts.tv_usec as i64,
                        );
                    }
                }

                #[cfg(not(feature = "json"))]
                if self.verbose {
                    print_packet(packet.data);
                } else {
                    print_one_liner(
                        packet.data,
                        packet.header.ts.tv_sec as i64,
                        packet.header.ts.tv_usec as i64,
                    );
                }

                if self.dump {
                    hexdump(packet.data);
                }
            }

            // ── 协议深度分析 ──
            // 解析以太网帧
            let eth = match EthernetFrame::parse(packet.data) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // TLS ClientHello 检测 (在 TCP 内部)
            if self.tls {
                self.try_tls_detect(packet.data);
            }

            // DHCP 检测 (在 UDP 67/68 端口)
            if self.dhcp {
                self.try_dhcp_detect(packet.data);
            }

            // TCP 流跟踪
            if let Some(ref mut tracker) = tracker {
                self.feed_tracker(tracker, eth.payload, packet.data.len() as u64);
            }
        }

        // ── 后处理：HTTP 配对 + 导出 ──
        if let Some(ref tracker) = tracker {
            let all = tracker.all_streams();
            for (key, stream) in &all {
                if stream.state == TcpState::Closed
                    || (!stream.client_payload.is_empty() && !stream.server_payload.is_empty())
                {
                    let client_data = &stream.client_payload;
                    let server_data = &stream.server_payload;

                    // HTTP 请求统计
                    if self.follow_http && !client_data.is_empty() {
                        let requests = count_http_requests(client_data);
                        http_requests += requests;

                        if self.verbose {
                            let client_ip = key.client_ip().format();
                            let server_ip = key.server_ip().format();
                            println!("\n── TCP Stream {} → {} ──", client_ip, server_ip);
                            println!(
                                "  Packets: {}  Bytes: {}  State: {:?}",
                                stream.packet_count, stream.total_bytes, stream.state
                            );
                            println!(
                                "  Client→Server: {} bytes (≈{} HTTP requests)",
                                client_data.len(),
                                requests
                            );
                            println!("  Server→Client: {} bytes", server_data.len());
                        }
                    }

                    // 导出 HTTP 请求/响应体
                    if self.export && !client_data.is_empty() {
                        self.export_http_stream(key, client_data, server_data, &mut export_files);
                    }
                }
            }

            if self.follow_http {
                println!(
                    "\nTCP 流总数: {}  |  HTTP 请求: {}",
                    tracker.stream_count(),
                    http_requests
                );
            }
        }

        println!("本次分析耗时 {} μs。", now.elapsed().as_micros());
        println!("共分析了 {} 个数据包，{} 字节。", count, bytes);
        Ok(())
    }

    /// 尝试从 TCP 载荷中检测 TLS ClientHello。
    fn try_tls_detect(&self, raw: &[u8]) {
        let eth = match EthernetFrame::parse(raw) {
            Ok(e) => e,
            Err(_) => return,
        };
        let l3 = match dispatch_from_ethernet(&eth) {
            Ok(r) => r,
            Err(_) => return,
        };
        let ip_payload = match &l3 {
            ParseResult::IPv4(ipv4) => match dispatch_from_ipv4(ipv4) {
                Ok(ParseResult::TCP(tcp)) => {
                    if tcp.dst_port == 443 || tcp.src_port == 443 {
                        Some((
                            tcp.payload,
                            IPv4Packet::format_ip(&ipv4.src_ip),
                            IPv4Packet::format_ip(&ipv4.dst_ip),
                            tcp.src_port,
                            tcp.dst_port,
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            },
            ParseResult::IPv6(ipv6) => match dispatch_from_ipv6(ipv6) {
                Ok(ParseResult::TCP(tcp)) => {
                    if tcp.dst_port == 443 || tcp.src_port == 443 {
                        Some((
                            tcp.payload,
                            IPv6Packet::format_ip(&ipv6.src_ip),
                            IPv6Packet::format_ip(&ipv6.dst_ip),
                            tcp.src_port,
                            tcp.dst_port,
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            },
            _ => None,
        };

        if let Some((tcp_payload, src, dst, sp, dp)) = ip_payload
            && let Some(hello) = parse_client_hello(tcp_payload)
        {
            println!("\n── TLS ClientHello ──");
            println!("  {src}:{sp} → {dst}:{dp}");
            println!(
                "  Record Version: {}",
                tls::version_name(hello.record_version)
            );
            println!(
                "  Client Version: {}",
                tls::version_name(hello.client_version)
            );
            if let Some(ref sni) = hello.sni {
                println!("  SNI: {sni}");
            }
            if !hello.cipher_suites.is_empty() {
                println!("  Cipher Suites ({}):", hello.cipher_suites.len());
                for &cs in &hello.cipher_suites[..hello.cipher_suites.len().min(10)] {
                    println!("    - {:#06x}  {}", cs, tls::cipher_suite_name(cs));
                }
                if hello.cipher_suites.len() > 10 {
                    println!("    ... and {} more", hello.cipher_suites.len() - 10);
                }
            }
            if !hello.alpn.is_empty() {
                println!("  ALPN: {}", hello.alpn.join(", "));
            }
        }
    }

    /// 尝试从 UDP 载荷中检测 DHCP 报文。
    fn try_dhcp_detect(&self, raw: &[u8]) {
        let eth = match EthernetFrame::parse(raw) {
            Ok(e) => e,
            Err(_) => return,
        };
        let l3 = match dispatch_from_ethernet(&eth) {
            Ok(r) => r,
            Err(_) => return,
        };

        let dhcp_data = match &l3 {
            ParseResult::IPv4(ipv4) => match dispatch_from_ipv4(ipv4) {
                Ok(ParseResult::UDP(udp)) => {
                    if udp.src_port == 67
                        || udp.dst_port == 67
                        || udp.src_port == 68
                        || udp.dst_port == 68
                    {
                        Some((
                            udp.payload,
                            IPv4Packet::format_ip(&ipv4.src_ip),
                            IPv4Packet::format_ip(&ipv4.dst_ip),
                            udp.src_port,
                            udp.dst_port,
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            },
            _ => None,
        };

        if let Some((udp_payload, src, dst, sp, dp)) = dhcp_data
            && let Ok(dhcp) = DhcpPacket::parse(udp_payload)
        {
            let msg_type = dhcp
                .message_type()
                .map(|t| t.name().to_string())
                .unwrap_or_else(|| "???".to_string());
            println!("\n── DHCP ──");
            println!("  {src}:{sp} → {dst}:{dp}");
            println!("  Message: {msg_type}  (xid={:#010x})", dhcp.xid);
            println!(
                "  Client MAC: {}",
                dhcp::format_mac(&dhcp.chaddr[0..dhcp.hlen as usize])
            );
            if dhcp.yiaddr != [0, 0, 0, 0] {
                println!("  Assigned IP: {}", dhcp::format_ipv4(&dhcp.yiaddr));
            }
            if let Some(req_ip) = dhcp.requested_ip() {
                println!("  Requested IP: {}", dhcp::format_ipv4(&req_ip));
            }
            if let Some(srv_id) = dhcp.server_identifier() {
                println!("  DHCP Server: {}", dhcp::format_ipv4(&srv_id));
            }
            if self.verbose {
                println!("  Options ({}):", dhcp.options.len());
                for opt in &dhcp.options {
                    println!("    Option {} ({} bytes)", opt.code, opt.value.len());
                }
            }
        }
    }

    /// 将数据包喂入 TCP 流跟踪器。
    fn feed_tracker(&self, tracker: &mut TcpStreamTracker, ip_payload: &[u8], wire_len: u64) {
        let eth = match EthernetFrame::parse(ip_payload) {
            Ok(e) => e,
            Err(_) => return,
        };
        let l3 = match dispatch_from_ethernet(&eth) {
            Ok(r) => r,
            Err(_) => return,
        };

        match &l3 {
            ParseResult::IPv4(ipv4) => {
                if let Ok(ParseResult::TCP(tcp)) = dispatch_from_ipv4(ipv4) {
                    tracker.feed(
                        &StreamIp::v4(ipv4.src_ip),
                        &StreamIp::v4(ipv4.dst_ip),
                        tcp.src_port,
                        tcp.dst_port,
                        tcp.seq,
                        tcp.flags,
                        tcp.payload,
                        wire_len,
                    );
                }
            }
            ParseResult::IPv6(ipv6) => {
                if let Ok(ParseResult::TCP(tcp)) = dispatch_from_ipv6(ipv6) {
                    tracker.feed(
                        &StreamIp::v6(ipv6.src_ip),
                        &StreamIp::v6(ipv6.dst_ip),
                        tcp.src_port,
                        tcp.dst_port,
                        tcp.seq,
                        tcp.flags,
                        tcp.payload,
                        wire_len,
                    );
                }
            }
            _ => {}
        }
    }

    /// 导出 HTTP 请求/响应体到文件。
    fn export_http_stream(
        &self,
        key: &FiveTuple,
        client_data: &[u8],
        server_data: &[u8],
        files: &mut HashMap<FiveTuple, std::fs::File>,
    ) {
        let client_ip = key.client_ip().format();
        let server_ip = key.server_ip().format();
        let fname = format!("http_{}_{}.txt", client_ip, server_ip);

        match std::fs::File::create(&fname) {
            Ok(mut f) => {
                let _ = writeln!(f, "=== HTTP Stream Export ===");
                let _ = writeln!(f, "Client: {client_ip}");
                let _ = writeln!(f, "Server: {server_ip}");
                let _ = writeln!(f, "--- Request ---");

                // 提取请求部分
                if let Ok(req_str) = std::str::from_utf8(client_data) {
                    let _ = f.write_all(req_str.as_bytes());
                } else {
                    let _ = f.write_all(b"[binary data]");
                }
                let _ = writeln!(f, "\n--- Response ---");
                if let Ok(resp_str) = std::str::from_utf8(server_data) {
                    let _ = f.write_all(resp_str.as_bytes());
                } else {
                    let _ = f.write_all(b"[binary data]");
                }

                files.insert(key.clone(), f);
                println!("  已导出 HTTP 流到: {fname}");
            }
            Err(e) => {
                eprintln!("  导出失败 {fname}: {e}");
            }
        }
    }
}

/// 统计客户端数据中的 HTTP 请求数量（以 "GET " / "POST " / ... 开头行为准）。
fn count_http_requests(data: &[u8]) -> usize {
    if let Ok(text) = std::str::from_utf8(data) {
        text.lines()
            .filter(|line| {
                line.starts_with("GET ")
                    || line.starts_with("POST ")
                    || line.starts_with("PUT ")
                    || line.starts_with("DELETE ")
                    || line.starts_with("HEAD ")
                    || line.starts_with("OPTIONS ")
                    || line.starts_with("PATCH ")
                    || line.starts_with("CONNECT ")
            })
            .count()
    } else {
        0
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// 写入一个最小 pcap 文件。
    fn write_test_pcap(path: &str, packets: &[&[u8]]) {
        let mut f = std::fs::File::create(path).unwrap();
        let hdr: [u8; 24] = [
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0,
            0, 1, 0, 0, 0,
        ];
        f.write_all(&hdr).unwrap();
        let mut ts = 1_000_000u32;
        for &pkt in packets {
            let s = ts / 1_000_000;
            let u = ts % 1_000_000;
            let l = pkt.len() as u32;
            f.write_all(&s.to_le_bytes()).unwrap();
            f.write_all(&u.to_le_bytes()).unwrap();
            f.write_all(&l.to_le_bytes()).unwrap();
            f.write_all(&l.to_le_bytes()).unwrap();
            f.write_all(pkt).unwrap();
            ts += 1_000_000;
        }
    }

    fn make_icmp() -> Vec<u8> {
        let mut raw = vec![0u8; 42];
        raw[12..14].copy_from_slice(&[0x08, 0x00]);
        raw[14] = 0x45;
        raw[22] = 64;
        raw[23] = 1;
        raw[26..30].copy_from_slice(&[172, 24, 229, 162]);
        raw[30..34].copy_from_slice(&[8, 8, 8, 8]);
        raw[34..36].copy_from_slice(&[0x08, 0x00]);
        raw[38..40].copy_from_slice(&[0, 1]);
        raw[40..42].copy_from_slice(&[0, 1]);
        raw
    }

    /// AnalyzeEngine 默认模式正常运行。
    #[test]
    fn engine_runs_on_pcap() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_a.pcap");
        let ps = path.to_str().unwrap();
        let pkt = make_icmp();
        write_test_pcap(ps, &[&pkt]);
        let args = crate::cli::AnalyzeArgs {
            file: ps.to_string(),
            verbose_output: false,
            json_output: false,
            hex: false,
            follow_http: false,
            tls: false,
            dhcp: false,
            export: false,
        };
        let e = AnalyzeEngine::new(&args).unwrap();
        assert!(e.run().is_ok());
        let _ = std::fs::remove_file(&path);
    }

    /// AnalyzeEngine 详细模式正常运行。
    #[test]
    fn engine_verbose_mode() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_av.pcap");
        let ps = path.to_str().unwrap();
        write_test_pcap(ps, &[&make_icmp()]);
        let args = crate::cli::AnalyzeArgs {
            file: ps.to_string(),
            verbose_output: true,
            json_output: false,
            hex: false,
            follow_http: false,
            tls: false,
            dhcp: false,
            export: false,
        };
        assert!(AnalyzeEngine::new(&args).unwrap().run().is_ok());
        let _ = std::fs::remove_file(&path);
    }

    /// AnalyzeEngine --tls 模式不 panic。
    #[test]
    fn engine_tls_mode() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_atls.pcap");
        let ps = path.to_str().unwrap();
        write_test_pcap(ps, &[&make_icmp()]);
        let args = crate::cli::AnalyzeArgs {
            file: ps.to_string(),
            verbose_output: false,
            json_output: false,
            hex: false,
            follow_http: false,
            tls: true,
            dhcp: false,
            export: false,
        };
        assert!(AnalyzeEngine::new(&args).unwrap().run().is_ok());
        let _ = std::fs::remove_file(&path);
    }

    /// AnalyzeEngine --dhcp 模式不 panic。
    #[test]
    fn engine_dhcp_mode() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_adhcp.pcap");
        let ps = path.to_str().unwrap();
        write_test_pcap(ps, &[&make_icmp()]);
        let args = crate::cli::AnalyzeArgs {
            file: ps.to_string(),
            verbose_output: false,
            json_output: false,
            hex: false,
            follow_http: false,
            tls: false,
            dhcp: true,
            export: false,
        };
        assert!(AnalyzeEngine::new(&args).unwrap().run().is_ok());
        let _ = std::fs::remove_file(&path);
    }
}
