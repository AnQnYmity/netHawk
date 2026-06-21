//! 流量统计引擎模块
//!
//! 提供 [`StatEngine`] 结构体，支持两种模式：
//!
//! - **文件模式**（`-f`）：分析 pcap/pcapng 文件，统计全量数据后输出摘要。
//! - **实时模式**（`-i`）：监听网卡，按指定间隔输出增量统计。
//!
//! # 统计维度
//!
//! - 总包数 / 总字节数
//! - 按协议分布（IPv4 TCP/UDP/ICMP/其他、IPv6 TCP/UDP/ICMPv6/其他、ARP、未知）
//! - Top N 会话（五元组 + 包数/字节数）

use std::collections::{BinaryHeap, HashMap};
use std::time::{Duration, Instant};

use crate::cli::StatsArgs;
use crate::protocol::*;
use pcap::Capture;

// ============================================================================
// 统计引擎
// ============================================================================

/// 流量统计引擎。
///
/// 封装 pcap 会话（文件或实时接口）和统计累加逻辑，
/// 对外暴露 `run()` 方法按模式执行统计并输出报告。
pub struct StatEngine {
    /// 实时监听的网卡名（`-i`），与 `file` 互斥。
    interface: Option<String>,
    /// 离线 pcap 文件路径（`-f`），与 `interface` 互斥。
    file: Option<String>,
    /// 输出 Top N 会话数。
    top_n: usize,
    /// 统计刷新间隔（秒），仅实时模式生效。
    interval: u64,
}

impl StatEngine {
    /// 从 CLI 参数构造统计引擎。
    ///
    /// # 错误
    ///
    /// `interface` 和 `file` 均为 `None` 时返回错误。
    pub fn new(args: &StatsArgs) -> anyhow::Result<Self> {
        args.validate().map_err(anyhow::Error::msg)?;
        Ok(Self {
            interface: args.interface.clone(),
            file: args.file.clone(),
            top_n: args.top_n,
            interval: args.interval,
        })
    }

    /// 运行流量统计，根据参数自动选择文件模式或实时模式。
    pub fn run(&self) -> anyhow::Result<()> {
        if let Some(ref f) = self.file {
            self.run_file(f)
        } else if let Some(ref iface) = self.interface {
            self.run_live(iface)
        } else {
            anyhow::bail!("内部错误：interface 和 file 均为空（validate 应已拦截）");
        }
    }

    // -----------------------------------------------------------------------
    // 文件模式
    // -----------------------------------------------------------------------

    fn run_file(&self, path: &str) -> anyhow::Result<()> {
        let mut cap = Capture::from_file(path)?;
        let mut acc = StatAccumulator::new();
        let now = Instant::now();

        while let Ok(packet) = cap.next_packet() {
            acc.feed(packet.data, packet.header.len as u64);
        }

        let elapsed = now.elapsed();
        Self::print_report(&acc, self.top_n, path, elapsed);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // 实时模式
    // -----------------------------------------------------------------------

    fn run_live(&self, iface: &str) -> anyhow::Result<()> {
        let cap = Capture::from_device(iface)?
            .promisc(true)
            .snaplen(65535)
            .timeout(1000)
            .open()?;
        let mut cap = cap.setnonblock()?;

        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&running);
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })?;

        let interval = Duration::from_secs(self.interval);
        let mut tick = Instant::now();
        let mut acc = StatAccumulator::new();
        let mut round: u64 = 1;
        let mut last_reported: u64 = 0; // 上次输出时的累积包数

        println!(
            "实时流量统计 (接口: {iface}, 间隔: {}s, Top {})",
            self.interval, self.top_n
        );
        println!("按 Ctrl+C 退出\n");

        loop {
            if !running.load(Ordering::SeqCst) {
                break;
            }

            match cap.next_packet() {
                Ok(packet) => {
                    acc.feed(packet.data, packet.header.len as u64);
                }
                Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break, // 真实错误
            }

            // 间隔到了，输出累计统计
            if tick.elapsed() >= interval {
                Self::print_round_report(&acc, self.top_n, iface, round);
                last_reported = acc.total_packets;
                round += 1;
                tick = Instant::now();
            }
        }

        // 退出前：如果距上次输出后有新数据，输出最终累计
        if acc.total_packets > last_reported {
            Self::print_round_report(&acc, self.top_n, iface, round);
        }

        println!("\n统计已停止。");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // 报告输出
    // -----------------------------------------------------------------------

    /// 文件模式：全量统计报告。
    fn print_report(acc: &StatAccumulator, top_n: usize, source: &str, elapsed: Duration) {
        println!("\n══════════════════════════════════════════════════════");
        println!("  流量统计报告");
        println!("══════════════════════════════════════════════════════");
        println!("  数据源: {source}");
        println!("  分析耗时: {:.2} ms", elapsed.as_secs_f64() * 1000.0);
        Self::print_summary(acc, top_n);
    }

    /// 实时模式：累计统计报告（数据从启动开始持续累加）。
    fn print_round_report(acc: &StatAccumulator, top_n: usize, iface: &str, round: u64) {
        println!("\n── 第 {round} 轮 累计 ({iface}) ──");
        Self::print_summary(acc, top_n);
    }

    /// 共用的统计摘要输出。
    fn print_summary(acc: &StatAccumulator, top_n: usize) {
        println!(
            "  总包数: {}    总字节数: {}",
            acc.total_packets,
            format_bytes(acc.total_bytes)
        );

        // 协议分布
        println!("\n  ── 协议分布 ──");
        let total = acc.total_packets as f64;
        let protocols = [
            ("IPv4/TCP   ", acc.ipv4_tcp),
            ("IPv4/UDP   ", acc.ipv4_udp),
            ("IPv4/ICMP  ", acc.ipv4_icmp),
            ("IPv4/其他  ", acc.ipv4_other),
            ("IPv6/TCP   ", acc.ipv6_tcp),
            ("IPv6/UDP   ", acc.ipv6_udp),
            ("IPv6/ICMPv6", acc.ipv6_icmp6),
            ("IPv6/其他  ", acc.ipv6_other),
            ("ARP        ", acc.arp),
            ("其他       ", acc.other),
        ];

        for (label, (pkts, bytes)) in &protocols {
            if *pkts > 0 {
                let pct = *pkts as f64 / total * 100.0;
                println!(
                    "    {label}  {pkts:>6} 包 ({pct:>5.1}%)  {bytes_str}",
                    bytes_str = format_bytes(*bytes)
                );
            }
        }

        // Top N 会话
        if !acc.sessions.is_empty() {
            println!("\n  ── Top {top_n} 会话 ──");
            let top = acc.top_sessions(top_n);
            for (i, (key, rec)) in top.iter().enumerate() {
                let proto_str = match key.protocol {
                    6 => "TCP",
                    17 => "UDP",
                    1 => "ICMP",
                    58 => "ICMPv6",
                    ARP_PROTO => "ARP",
                    _ => "???",
                };
                let detail = match key.protocol {
                    1 | 58 => {
                        let itype = (key.src_port >> 8) as u8;
                        let icode = (key.src_port & 0xFF) as u8;
                        format!("type={itype}/code={icode}")
                    }
                    ARP_PROTO => {
                        let op = if key.src_port == 1 {
                            "who-has"
                        } else if key.src_port == 2 {
                            "is-at"
                        } else {
                            "op?"
                        };
                        let mac_tail = key.dst_port;
                        format!("{op} ..:{mac_tail:04x}")
                    }
                    _ => String::new(),
                };
                println!(
                    "    {:>2}. {} → {}  {proto_str}  {detail}  {} 包  {}",
                    i + 1,
                    key.src_ip,
                    key.dst_ip,
                    rec.packets,
                    format_bytes(rec.bytes),
                );
            }
        }
        println!();
    }
}

// ============================================================================
// 统计累加器
// ============================================================================

/// 单条会话记录。
#[derive(Clone, Debug)]
struct SessionRecord {
    packets: u64,
    bytes: u64,
}

/// 会话标识键。
///
/// 统一表示 TCP/UDP/ICMP/ARP 四种协议的会话：
/// - TCP (6) / UDP (17)：`src_port`/`dst_port` 为实际端口号
/// - ICMP (1) / ICMPv6 (58)：`src_port` 编码 `(type << 8) | code`
/// - ARP (255)：`src_port` 编码操作码 (1=request, 2=reply)
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct SessionKey {
    src_ip: String,
    dst_ip: String,
    /// 协议号：6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6, 255=ARP（合成）。
    protocol: u8,
    src_port: u16,
    dst_port: u16,
}

/// ARP 合成协议号（IP 协议号空间中无 ARP，使用 255 作为哨兵值）。
const ARP_PROTO: u8 = 255;

/// 将 ICMP type/code 编码到一个 u16 中（高 8 位 type，低 8 位 code）。
fn icmp_port(icmp_type: u8, icmp_code: u8) -> u16 {
    ((icmp_type as u16) << 8) | (icmp_code as u16)
}

/// 统计累加器，内部维护协议计数和会话映射。
struct StatAccumulator {
    total_packets: u64,
    total_bytes: u64,

    // 协议分布 (packets, bytes)
    ipv4_tcp: (u64, u64),
    ipv4_udp: (u64, u64),
    ipv4_icmp: (u64, u64),
    ipv4_other: (u64, u64),
    ipv6_tcp: (u64, u64),
    ipv6_udp: (u64, u64),
    ipv6_icmp6: (u64, u64),
    ipv6_other: (u64, u64),
    arp: (u64, u64),
    other: (u64, u64),

    sessions: HashMap<SessionKey, SessionRecord>,
}

impl StatAccumulator {
    fn new() -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            ipv4_tcp: (0, 0),
            ipv4_udp: (0, 0),
            ipv4_icmp: (0, 0),
            ipv4_other: (0, 0),
            ipv6_tcp: (0, 0),
            ipv6_udp: (0, 0),
            ipv6_icmp6: (0, 0),
            ipv6_other: (0, 0),
            arp: (0, 0),
            other: (0, 0),
            sessions: HashMap::new(),
        }
    }

    /// 清零所有计数，用于实时模式间隔重置（预留，未来按间隔重置时启用）。
    #[allow(dead_code)]
    fn reset(&mut self) {
        *self = Self::new();
    }

    /// 喂入一个原始数据包（以太网帧起始），累加协议和会话统计。
    fn feed(&mut self, raw: &[u8], wire_len: u64) {
        self.total_packets += 1;
        self.total_bytes += wire_len;

        let eth = match EthernetFrame::parse(raw) {
            Ok(e) => e,
            Err(_) => {
                self.other.0 += 1;
                self.other.1 += wire_len;
                return;
            }
        };

        match eth.ethernet_type {
            0x0800 => self.feed_ipv4(eth.payload, wire_len),
            0x86DD => self.feed_ipv6(eth.payload, wire_len),
            0x0806 => self.feed_arp(eth.payload, wire_len),
            _ => {
                self.other.0 += 1;
                self.other.1 += wire_len;
            }
        }
    }

    /// 处理 IPv4 载荷：解析 IP 头 → 按协议号分发到 TCP/UDP/ICMP/其他。
    fn feed_ipv4(&mut self, payload: &[u8], wire_len: u64) {
        let ipv4 = match IPv4Packet::parse(payload) {
            Ok(p) => p,
            Err(_) => {
                self.other.0 += 1;
                self.other.1 += wire_len;
                return;
            }
        };
        let src_ip = IPv4Packet::format_ip(&ipv4.src_ip);
        let dst_ip = IPv4Packet::format_ip(&ipv4.dst_ip);

        match ipv4.next_protocol {
            6 => {
                self.ipv4_tcp.0 += 1;
                self.ipv4_tcp.1 += wire_len;
                if let Ok(tcp) = TCPSegment::parse(ipv4.payload) {
                    self.upsert_session(src_ip, dst_ip, 6, tcp.src_port, tcp.dst_port, wire_len);
                }
            }
            17 => {
                self.ipv4_udp.0 += 1;
                self.ipv4_udp.1 += wire_len;
                if let Ok(udp) = UDPSegment::parse(ipv4.payload) {
                    self.upsert_session(src_ip, dst_ip, 17, udp.src_port, udp.dst_port, wire_len);
                }
            }
            1 => {
                self.ipv4_icmp.0 += 1;
                self.ipv4_icmp.1 += wire_len;
                if let Some((itype, icode)) = parse_icmp(ipv4.payload) {
                    self.upsert_session(src_ip, dst_ip, 1, icmp_port(itype, icode), 0, wire_len);
                }
            }
            _ => {
                self.ipv4_other.0 += 1;
                self.ipv4_other.1 += wire_len;
            }
        }
    }

    /// 处理 IPv6 载荷：解析 IP 头 → 按下一头部号分发到 TCP/UDP/ICMPv6/其他。
    fn feed_ipv6(&mut self, payload: &[u8], wire_len: u64) {
        let ipv6 = match IPv6Packet::parse(payload) {
            Ok(p) => p,
            Err(_) => {
                self.other.0 += 1;
                self.other.1 += wire_len;
                return;
            }
        };
        let src_ip = IPv6Packet::format_ip(&ipv6.src_ip);
        let dst_ip = IPv6Packet::format_ip(&ipv6.dst_ip);

        match ipv6.next_header {
            6 => {
                self.ipv6_tcp.0 += 1;
                self.ipv6_tcp.1 += wire_len;
                if let Ok(tcp) = TCPSegment::parse(ipv6.payload) {
                    self.upsert_session(src_ip, dst_ip, 6, tcp.src_port, tcp.dst_port, wire_len);
                }
            }
            17 => {
                self.ipv6_udp.0 += 1;
                self.ipv6_udp.1 += wire_len;
                if let Ok(udp) = UDPSegment::parse(ipv6.payload) {
                    self.upsert_session(src_ip, dst_ip, 17, udp.src_port, udp.dst_port, wire_len);
                }
            }
            58 => {
                self.ipv6_icmp6.0 += 1;
                self.ipv6_icmp6.1 += wire_len;
                if let Some((itype, icode)) = parse_icmp(ipv6.payload) {
                    self.upsert_session(src_ip, dst_ip, 58, icmp_port(itype, icode), 0, wire_len);
                }
            }
            _ => {
                self.ipv6_other.0 += 1;
                self.ipv6_other.1 += wire_len;
            }
        }
    }

    /// 处理 ARP 载荷：解析 ARP 字段 → 累加并插入会话。
    fn feed_arp(&mut self, payload: &[u8], wire_len: u64) {
        self.arp.0 += 1;
        self.arp.1 += wire_len;
        if let Some(arp_info) = parse_arp(payload) {
            let arp_src = IPv4Packet::format_ip(&arp_info.src_ip);
            let arp_dst = IPv4Packet::format_ip(&arp_info.dst_ip);
            let mac_hint = u16::from_be_bytes([arp_info.dst_mac[4], arp_info.dst_mac[5]]);
            self.upsert_session(
                arp_src,
                arp_dst,
                ARP_PROTO,
                arp_info.operation,
                mac_hint,
                wire_len,
            );
        }
    }

    /// 更新或插入一条会话记录。
    fn upsert_session(
        &mut self,
        src_ip: String,
        dst_ip: String,
        protocol: u8,
        src_port: u16,
        dst_port: u16,
        bytes: u64,
    ) {
        let key = SessionKey {
            src_ip,
            dst_ip,
            protocol,
            src_port,
            dst_port,
        };
        let entry = self.sessions.entry(key).or_insert(SessionRecord {
            packets: 0,
            bytes: 0,
        });
        entry.packets += 1;
        entry.bytes += bytes;
    }

    /// 返回按包数降序排列的 Top N 会话。
    fn top_sessions(&self, n: usize) -> Vec<(&SessionKey, &SessionRecord)> {
        // 最大堆：按 packets 降序，packets 相同时按 bytes 降序
        let mut heap = BinaryHeap::new();
        for (key, rec) in &self.sessions {
            heap.push(SessionHeapEntry {
                packets: rec.packets,
                bytes: rec.bytes,
                key,
                rec,
            });
        }
        let mut result = Vec::with_capacity(n.min(heap.len()));
        for _ in 0..n {
            if let Some(entry) = heap.pop() {
                result.push((entry.key, entry.rec));
            } else {
                break;
            }
        }
        result
    }
}

// ============================================================================
// BinaryHeap 辅助条目（按包数降序排列）
// ============================================================================

struct SessionHeapEntry<'a> {
    packets: u64,
    bytes: u64,
    key: &'a SessionKey,
    rec: &'a SessionRecord,
}

impl Eq for SessionHeapEntry<'_> {}

impl PartialEq for SessionHeapEntry<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.packets == other.packets && self.bytes == other.bytes
    }
}

impl PartialOrd for SessionHeapEntry<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SessionHeapEntry<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.packets
            .cmp(&other.packets)
            .then_with(|| self.bytes.cmp(&other.bytes))
    }
}

// ============================================================================
// 工具函数
// ============================================================================

/// 从 ICMP/ICMPv6 头部提取 type 和 code（需至少 8 字节）。
fn parse_icmp(raw: &[u8]) -> Option<(u8, u8)> {
    if raw.len() < 8 {
        return None;
    }
    Some((raw[0], raw[1]))
}

/// ARP 解析结果（仅支持 Ethernet/IPv4 场景）。
#[allow(dead_code)]
struct ArpInfo {
    #[allow(dead_code)]
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    operation: u16,
}

/// 从 ARP 包（28 字节 Ethernet/IPv4 格式）提取关键字段。
fn parse_arp(raw: &[u8]) -> Option<ArpInfo> {
    if raw.len() < 28 {
        return None;
    }
    let htype = u16::from_be_bytes([raw[0], raw[1]]);
    let ptype = u16::from_be_bytes([raw[2], raw[3]]);
    let hlen = raw[4];
    let plen = raw[5];
    // 仅支持 Ethernet (1) + IPv4 (0x0800)
    if htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4 {
        return None;
    }
    Some(ArpInfo {
        src_mac: raw[8..14].try_into().ok()?,
        src_ip: raw[14..18].try_into().ok()?,
        dst_mac: raw[18..24].try_into().ok()?,
        dst_ip: raw[24..28].try_into().ok()?,
        operation: u16::from_be_bytes([raw[6], raw[7]]),
    })
}

/// 人性化的字节数格式化。
fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let b = bytes as f64;
    if b >= GIB {
        format!("{:.2} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.2} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.2} KiB", b / KIB)
    } else {
        format!("{bytes} B")
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // format_bytes 测试
    // -----------------------------------------------------------------------

    /// format_bytes 小数值正确。
    #[test]
    fn test_format_bytes_small() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
    }

    /// format_bytes KiB 正确。
    #[test]
    fn test_format_bytes_kib() {
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1536), "1.50 KiB");
    }

    /// format_bytes MiB 正确。
    #[test]
    fn test_format_bytes_mib() {
        assert_eq!(format_bytes(1048576), "1.00 MiB");
        assert_eq!(format_bytes(2 * 1024 * 1024), "2.00 MiB");
    }

    /// format_bytes GiB 正确。
    #[test]
    fn test_format_bytes_gib() {
        assert_eq!(format_bytes(1073741824), "1.00 GiB");
    }

    // -----------------------------------------------------------------------
    // StatAccumulator 测试
    // -----------------------------------------------------------------------

    /// 构造一个最小合法 IPv4/TCP 数据包并喂入累加器。
    #[test]
    fn test_feed_ipv4_tcp() {
        let mut acc = StatAccumulator::new();
        let pkt = build_ipv4_tcp_packet();
        acc.feed(&pkt, pkt.len() as u64);

        assert_eq!(acc.total_packets, 1);
        assert_eq!(acc.total_bytes, pkt.len() as u64);
        assert_eq!(acc.ipv4_tcp.0, 1);
        assert_eq!(acc.ipv4_tcp.1, pkt.len() as u64);
        assert_eq!(acc.sessions.len(), 1);
    }

    /// 喂入两个相同会话的包，验证聚合。
    #[test]
    fn test_feed_same_session_aggregates() {
        let mut acc = StatAccumulator::new();
        let pkt = build_ipv4_tcp_packet();
        acc.feed(&pkt, pkt.len() as u64);
        acc.feed(&pkt, pkt.len() as u64);

        assert_eq!(acc.total_packets, 2);
        assert_eq!(acc.sessions.len(), 1);
        let (key, rec) = acc.sessions.iter().next().unwrap();
        assert_eq!(rec.packets, 2);
        assert_eq!(rec.bytes, 2 * pkt.len() as u64);
        assert_eq!(key.protocol, 6);
    }

    /// 构造一个最小合法 IPv4/UDP 数据包并验证。
    #[test]
    fn test_feed_ipv4_udp() {
        let mut acc = StatAccumulator::new();
        let pkt = build_ipv4_udp_packet();
        acc.feed(&pkt, pkt.len() as u64);

        assert_eq!(acc.total_packets, 1);
        assert_eq!(acc.ipv4_udp.0, 1);
        assert_eq!(acc.ipv4_udp.1, pkt.len() as u64);
        assert_eq!(acc.sessions.len(), 1);
    }

    /// ARP 请求包产生会话记录。
    #[test]
    fn test_feed_arp_with_session() {
        let mut acc = StatAccumulator::new();
        let pkt = build_arp_packet();
        acc.feed(&pkt, pkt.len() as u64);

        assert_eq!(acc.total_packets, 1);
        assert_eq!(acc.arp.0, 1);
        assert_eq!(acc.sessions.len(), 1);
        let (key, rec) = acc.sessions.iter().next().unwrap();
        assert_eq!(key.protocol, ARP_PROTO);
        assert_eq!(key.src_port, 1); // ARP request
        assert_eq!(rec.packets, 1);
    }

    /// IPv4/ICMP echo request 产生会话记录。
    #[test]
    fn test_feed_ipv4_icmp_with_session() {
        let mut acc = StatAccumulator::new();
        let pkt = build_ipv4_icmp_packet();
        acc.feed(&pkt, pkt.len() as u64);

        assert_eq!(acc.ipv4_icmp.0, 1);
        assert_eq!(acc.sessions.len(), 1);
        let (key, _rec) = acc.sessions.iter().next().unwrap();
        assert_eq!(key.protocol, 1);
        // type=8 (echo request), code=0 → port = 0x0800
        assert_eq!(key.src_port, 0x0800);
    }

    /// IPv6/TCP 包。
    #[test]
    fn test_feed_ipv6_tcp() {
        let mut acc = StatAccumulator::new();
        let pkt = build_ipv6_tcp_packet();
        acc.feed(&pkt, pkt.len() as u64);

        assert_eq!(acc.total_packets, 1);
        assert_eq!(acc.ipv6_tcp.0, 1);
        assert_eq!(acc.ipv6_tcp.1, pkt.len() as u64);
        assert_eq!(acc.sessions.len(), 1);
    }

    /// IPv6/ICMPv6 echo request 产生会话记录。
    #[test]
    fn test_feed_ipv6_icmp6_with_session() {
        let mut acc = StatAccumulator::new();
        let pkt = build_ipv6_icmp6_packet();
        acc.feed(&pkt, pkt.len() as u64);

        assert_eq!(acc.ipv6_icmp6.0, 1);
        assert_eq!(acc.sessions.len(), 1);
        let (key, _rec) = acc.sessions.iter().next().unwrap();
        assert_eq!(key.protocol, 58);
        // type=128 (echo request), code=0 → port = 0x8000
        assert_eq!(key.src_port, 0x8000);
    }

    /// 验证 reset() 清空所有计数。
    #[test]
    fn test_reset() {
        let mut acc = StatAccumulator::new();
        let pkt = build_ipv4_tcp_packet();
        acc.feed(&pkt, pkt.len() as u64);
        acc.reset();

        assert_eq!(acc.total_packets, 0);
        assert_eq!(acc.total_bytes, 0);
        assert_eq!(acc.ipv4_tcp.0, 0);
        assert_eq!(acc.sessions.len(), 0);
    }

    /// 验证 top_sessions 排序和截断。
    #[test]
    fn test_top_sessions_order_and_truncation() {
        let mut acc = StatAccumulator::new();

        // 手动插入 3 个会话
        acc.upsert_session("10.0.0.1".into(), "10.0.0.2".into(), 6, 443, 52831, 500);
        acc.upsert_session("10.0.0.1".into(), "10.0.0.2".into(), 6, 80, 41234, 500);
        // 第二个会话插入两次（包数更大）
        acc.upsert_session("10.0.0.1".into(), "10.0.0.3".into(), 6, 22, 50001, 200);
        acc.upsert_session("10.0.0.1".into(), "10.0.0.3".into(), 6, 22, 50001, 200);

        let top = acc.top_sessions(2);
        assert_eq!(top.len(), 2);
        // 第一个应该是包数最多的
        assert_eq!(top[0].0.dst_ip, "10.0.0.3");
        assert_eq!(top[0].1.packets, 2);
        // 第二个
        assert_eq!(top[1].0.dst_ip, "10.0.0.2");
        assert_eq!(top[1].1.packets, 1);
    }

    /// top_sessions 在 n > sessions 时返回全部。
    #[test]
    fn test_top_sessions_more_than_available() {
        let mut acc = StatAccumulator::new();
        acc.upsert_session("a".into(), "b".into(), 6, 1, 2, 100);
        let top = acc.top_sessions(10);
        assert_eq!(top.len(), 1);
    }

    /// 长度不足的垃圾数据被归入 "other"。
    #[test]
    fn test_feed_too_short() {
        let mut acc = StatAccumulator::new();
        acc.feed(&[0x00; 10], 10);
        assert_eq!(acc.total_packets, 1);
        assert_eq!(acc.other.0, 1);
        assert_eq!(acc.sessions.len(), 0);
    }

    /// print_summary 不 panic。
    #[test]
    fn test_print_summary_does_not_panic() {
        let mut acc = StatAccumulator::new();
        acc.feed(build_ipv4_tcp_packet().as_slice(), 54);
        acc.feed(build_ipv4_icmp_packet().as_slice(), 42);
        assert_eq!(acc.total_packets, 2);
        assert!(!acc.sessions.is_empty());
    }

    /// StatEngine 文件模式集成测试。
    #[test]
    fn stat_engine_file_mode() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_stat.pcap");
        let ps = path.to_str().unwrap();
        // 写入最小 pcap 文件
        let mut f = std::fs::File::create(ps).unwrap();
        let hdr: [u8; 24] = [
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0,
            0, 1, 0, 0, 0,
        ];
        f.write_all(&hdr).unwrap();
        let pkt = build_ipv4_tcp_packet();
        let l = pkt.len() as u32;
        f.write_all(&1u32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(&l.to_le_bytes()).unwrap();
        f.write_all(&l.to_le_bytes()).unwrap();
        f.write_all(&pkt).unwrap();
        drop(f);

        let args = crate::cli::StatsArgs {
            interface: None,
            file: Some(ps.to_string()),
            top_n: 5,
            interval: 1,
        };
        let engine = StatEngine::new(&args).unwrap();
        assert!(engine.run().is_ok());
        let _ = std::fs::remove_file(&path);
    }

    // -----------------------------------------------------------------------
    // 数据包构造辅助函数
    // -----------------------------------------------------------------------

    /// 构造一个最小合法 IPv4/TCP 以太网帧：
    /// ETH(14B) + IPv4(20B) + TCP(20B)
    fn build_ipv4_tcp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet II header (14 bytes)
        pkt.extend_from_slice(&[0x00; 6]); // dst MAC
        pkt.extend_from_slice(&[0x00; 6]); // src MAC
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType = IPv4

        // IPv4 header (20 bytes, no options, IHL=5)
        let ver_ihl: u8 = 0x45; // version=4, IHL=5
        pkt.push(ver_ihl);
        pkt.push(0x00); // DSCP/ECN
        // Total length = 20 (IP) + 20 (TCP)
        let total_len = 40u16;
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]); // Identification
        pkt.extend_from_slice(&[0x00, 0x00]); // Flags/Fragment
        pkt.push(64); // TTL
        pkt.push(6); // Protocol = TCP
        pkt.extend_from_slice(&[0x00, 0x00]); // Header checksum (zero for test)
        // src IP = 192.168.1.1
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        // dst IP = 10.0.0.1
        pkt.extend_from_slice(&[10, 0, 0, 1]);

        // TCP header (20 bytes, data_offset=5)
        pkt.extend_from_slice(&443u16.to_be_bytes()); // src port
        pkt.extend_from_slice(&52831u16.to_be_bytes()); // dst port
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // seq
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        pkt.push(0x50); // data_offset=5 (20 bytes), reserved
        pkt.push(0x00); // flags
        pkt.extend_from_slice(&[0x00, 0x00]); // window
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00]); // urgent
        pkt
    }

    /// 构造一个最小合法 IPv4/UDP 以太网帧。
    fn build_ipv4_udp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet II header
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());

        // IPv4 header
        pkt.push(0x45);
        pkt.push(0x00);
        let total_len = 28u16; // 20 (IP) + 8 (UDP)
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.push(64);
        pkt.push(17); // Protocol = UDP
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);

        // UDP header (8 bytes)
        pkt.extend_from_slice(&53u16.to_be_bytes()); // src port (DNS)
        pkt.extend_from_slice(&5353u16.to_be_bytes()); // dst port
        pkt.extend_from_slice(&8u16.to_be_bytes()); // length
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt
    }

    /// 构造一个最小合法 ARP 请求以太网帧（Ethernet/IPv4）。
    fn build_arp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        // Ethernet II header
        pkt.extend_from_slice(&[0xff; 6]); // dst MAC (broadcast)
        pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src MAC
        pkt.extend_from_slice(&0x0806u16.to_be_bytes()); // EtherType = ARP

        // ARP payload (28 bytes)
        pkt.extend_from_slice(&1u16.to_be_bytes()); // HTYPE = Ethernet
        pkt.extend_from_slice(&0x0800u16.to_be_bytes()); // PTYPE = IPv4
        pkt.push(6); // HLEN = 6
        pkt.push(4); // PLEN = 4
        pkt.extend_from_slice(&1u16.to_be_bytes()); // OPER = 1 (request)
        pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // SHA
        pkt.extend_from_slice(&[192, 168, 1, 1]); // SPA = 192.168.1.1
        pkt.extend_from_slice(&[0x00; 6]); // THA (zero in request)
        pkt.extend_from_slice(&[192, 168, 1, 254]); // TPA = 192.168.1.254
        pkt
    }

    /// 构造一个最小合法 IPv4/ICMP 以太网帧。
    fn build_ipv4_icmp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&0x0800u16.to_be_bytes());

        pkt.push(0x45);
        pkt.push(0x00);
        let total_len = 28u16; // 20 (IP) + 8 (ICMP)
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.push(64);
        pkt.push(1); // Protocol = ICMP
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&[10, 0, 0, 1]);

        // ICMP header (8 bytes): type=8 (echo request), code=0
        pkt.push(8); // type
        pkt.push(0); // code
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum (zero for test)
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // rest of header
        pkt
    }

    /// 构造一个最小合法 IPv6/TCP 以太网帧。
    fn build_ipv6_tcp_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&0x86DDu16.to_be_bytes()); // EtherType = IPv6

        // IPv6 header (40 bytes)
        let ver_tc_flow: u32 = 0x60000000; // version=6
        pkt.extend_from_slice(&ver_tc_flow.to_be_bytes());
        let payload_len = 20u16; // TCP 头
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.push(6); // Next header = TCP
        pkt.push(64); // Hop limit
        pkt.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]); // src
        pkt.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]); // dst

        // TCP header (20 bytes, data_offset=5)
        pkt.extend_from_slice(&443u16.to_be_bytes());
        pkt.extend_from_slice(&52831u16.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        pkt.push(0x50);
        pkt.push(0x00);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt
    }

    /// 构造一个最小合法 IPv6/ICMPv6 echo request 以太网帧。
    fn build_ipv6_icmp6_packet() -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&[0x00; 6]);
        pkt.extend_from_slice(&0x86DDu16.to_be_bytes());

        // IPv6 header (40 bytes)
        let ver_tc_flow: u32 = 0x60000000;
        pkt.extend_from_slice(&ver_tc_flow.to_be_bytes());
        let payload_len = 8u16; // ICMPv6 头
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.push(58); // Next header = ICMPv6
        pkt.push(64);
        pkt.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        pkt.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);

        // ICMPv6 header (8 bytes): type=128 (echo request), code=0
        pkt.push(128); // type
        pkt.push(0); // code
        pkt.extend_from_slice(&[0x00, 0x00]); // checksum
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // rest
        pkt
    }
}
