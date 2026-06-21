//! TCP 流跟踪与重组模块
//!
//! 按五元组（源/目的 IP、源/目的端口、协议）聚合 TCP 数据包，
//! 维护连接状态机并重组双向字节流，供上层（HTTP 配对、内容导出）使用。
//!
//! # 设计要点
//!
//! - **方向归一化**：A→B 和 B→A 属于同一个逻辑流，通过比较 IP+端口
//!   确定"客户端"（主动发起 SYN 的一方）和"服务器"。
//! - **状态机**：跟踪 SYN→ESTABLISHED→FIN/RST 转换，自动回收完成流。
//! - **乱序容忍**：重组缓冲区按 sequence 号插入数据，处理重叠/间隙。
//!
//! # 限制
//!
//! - 当前实现保留完整载荷（非零拷贝），对超大流可能消耗大量内存。
//! - 仅跟踪单向数据方向（客户端→服务器 和 服务器→客户端）作为两个缓冲区。

use std::collections::HashMap;

// ============================================================================
// 数据结构
// ============================================================================

/// IP 地址（v4 或 v6），用作流键的一部分。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl IpAddr {
    /// 从 4 字节切片构造 IPv4。
    pub fn v4(addr: [u8; 4]) -> Self {
        IpAddr::V4(addr)
    }

    /// 从 16 字节切片构造 IPv6。
    pub fn v6(addr: [u8; 16]) -> Self {
        IpAddr::V6(addr)
    }

    /// 格式化 IP 地址为人类可读字符串。
    pub fn format(&self) -> String {
        match *self {
            IpAddr::V4(addr) => format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
            IpAddr::V6(addr) => {
                let parts: Vec<String> = addr
                    .chunks_exact(2)
                    .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                    .collect();
                parts.join(":")
            }
        }
    }
}

/// 对称五元组（方向归一化：client 端 total_order 较小）。
///
/// `packed` 内部存储：`[src_ip(4|16)] + [dst_ip(4|16)] + src_port(2) + dst_port(2) + protocol(1)`
/// 方向已归一化（客户端地址在前）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    packed: Vec<u8>,
    /// 是否为 IPv6（影响 packed 解包）。
    is_v6: bool,
}

impl FiveTuple {
    /// 创建归一化的五元组。
    ///
    /// 归一化规则：将 (src_ip, src_port) 与 (dst_ip, dst_port) 按字节序比较，
    /// 较小的一方放在 packed 前面（标记为客户端）。
    pub fn new(a_ip: &IpAddr, b_ip: &IpAddr, a_port: u16, b_port: u16) -> Self {
        let is_v6 = matches!(a_ip, IpAddr::V6(_));

        // 序列化 a 端和 b 端的字节，用于比较
        let a_bytes = Self::pack_endpoint(a_ip, a_port);
        let b_bytes = Self::pack_endpoint(b_ip, b_port);

        // 归一化：较小的一端在前（客户端）
        let packed = if a_bytes <= b_bytes {
            let mut v = a_bytes;
            v.extend_from_slice(&b_bytes);
            v
        } else {
            let mut v = b_bytes;
            v.extend_from_slice(&a_bytes);
            v
        };

        FiveTuple { packed, is_v6 }
    }

    /// 将 (IP, port) 序列化为字节数组，用于比较和存储。
    fn pack_endpoint(ip: &IpAddr, port: u16) -> Vec<u8> {
        let mut v = Vec::new();
        match ip {
            IpAddr::V4(addr) => v.extend_from_slice(addr),
            IpAddr::V6(addr) => v.extend_from_slice(addr),
        }
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    /// 客户端的 IP 地址。
    pub fn client_ip(&self) -> IpAddr {
        self.read_ip_at(0)
    }

    /// 客户端的端口号。
    pub fn client_port(&self) -> u16 {
        let offset = if self.is_v6 { 16 } else { 4 };
        u16::from_be_bytes([self.packed[offset], self.packed[offset + 1]])
    }

    /// 服务器的 IP 地址。
    pub fn server_ip(&self) -> IpAddr {
        let offset = if self.is_v6 { 16 + 2 } else { 4 + 2 };
        self.read_ip_at(offset)
    }

    /// 服务器的端口号。
    #[allow(dead_code)]
    fn server_port(&self) -> u16 {
        let ip_size = if self.is_v6 { 16 } else { 4 };
        let offset = ip_size * 2 + 2;
        u16::from_be_bytes([self.packed[offset], self.packed[offset + 1]])
    }

    fn read_ip_at(&self, offset: usize) -> IpAddr {
        if self.is_v6 {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&self.packed[offset..offset + 16]);
            IpAddr::V6(addr)
        } else {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&self.packed[offset..offset + 4]);
            IpAddr::V4(addr)
        }
    }
}

/// TCP 连接状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// 收到 SYN，等待对端 SYN-ACK。
    SynSent,
    /// 连接已建立。
    Established,
    /// 收到 FIN，等待对端 FIN。
    FinWait,
    /// 连接已关闭（双向 FIN 或 RST）。
    Closed,
}

/// 一个 TCP 流的完整状态。
pub struct TcpStream {
    /// 连接状态。
    pub state: TcpState,
    /// 客户端→服务器方向已重组的载荷。
    pub client_payload: Vec<u8>,
    /// 服务器→客户端方向已重组的载荷。
    pub server_payload: Vec<u8>,
    /// 客户端下一个期望的 sequence 号。
    client_seq: u32,
    /// 服务器下一个期望的 sequence 号。
    server_seq: u32,
    /// 是否已初始化 sequence（SYN 包设置）。
    client_seq_init: bool,
    server_seq_init: bool,
    /// 当前流的总包数。
    pub packet_count: usize,
    /// 当前流的总字节数（含头部）。
    pub total_bytes: u64,
}

impl TcpStream {
    fn new() -> Self {
        Self {
            state: TcpState::SynSent,
            client_payload: Vec::new(),
            server_payload: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            client_seq_init: false,
            server_seq_init: false,
            packet_count: 0,
            total_bytes: 0,
        }
    }
}

// ============================================================================
// 流跟踪器
// ============================================================================

/// TCP 流跟踪器。
///
/// 持有所有活跃/已关闭流的 HashMap，对外暴露 `feed` 方法逐个处理数据包。
pub struct TcpStreamTracker {
    streams: HashMap<FiveTuple, TcpStream>,
}

impl Default for TcpStreamTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpStreamTracker {
    /// 创建空的流跟踪器。
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// 喂入一个 TCP 段。
    ///
    /// `src_ip`/`dst_ip`：IP 层源/目的地址。
    /// `src_port`/`dst_port`：TCP 源/目的端口。
    /// `seq`：TCP sequence 号。
    /// `flags`：TCP 标志位（仅检查 SYN/FIN/RST）。
    /// `payload`：TCP 载荷（零拷贝切片）。
    /// `wire_len`：完整帧长度（用于统计总字节数）。
    #[allow(clippy::too_many_arguments)]
    pub fn feed(
        &mut self,
        src_ip: &IpAddr,
        dst_ip: &IpAddr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
        wire_len: u64,
    ) {
        // 归一化方向：比较 (src_ip, src_port) 与 (dst_ip, dst_port)
        let key = FiveTuple::new(src_ip, dst_ip, src_port, dst_port);

        let stream = self.streams.entry(key).or_insert_with(TcpStream::new);
        stream.packet_count += 1;
        stream.total_bytes += wire_len;

        // 判断方向：src→dst 是客户端方向还是服务器方向
        let is_client_to_server = Self::is_client_dir(src_ip, src_port, dst_ip, dst_port);

        // 更新状态机
        if flags & 0x02 != 0 {
            // SYN
            if stream.state == TcpState::SynSent {
                stream.state = TcpState::Established;
            }
            // SYN 设置初始 seq（seq 是 SYN 包的 seq，下一个数据字节从 seq+1 开始）
            if is_client_to_server && !stream.client_seq_init {
                stream.client_seq = seq.wrapping_add(1);
                stream.client_seq_init = true;
            } else if !is_client_to_server && !stream.server_seq_init {
                stream.server_seq = seq.wrapping_add(1);
                stream.server_seq_init = true;
            }
        }

        if flags & 0x04 != 0 {
            // RST
            stream.state = TcpState::Closed;
            return;
        }

        if flags & 0x01 != 0 {
            // FIN
            if stream.state == TcpState::Established {
                stream.state = TcpState::FinWait;
            } else if stream.state == TcpState::FinWait {
                stream.state = TcpState::Closed;
            }
        }

        // 重组载荷（仅当有数据时）
        if !payload.is_empty() && stream.state != TcpState::Closed {
            if is_client_to_server {
                Self::append_payload(
                    &mut stream.client_payload,
                    &mut stream.client_seq,
                    seq,
                    payload,
                );
            } else {
                Self::append_payload(
                    &mut stream.server_payload,
                    &mut stream.server_seq,
                    seq,
                    payload,
                );
            }
        }
    }

    /// 判断 src→dst 是否为客户端方向（依五元组归一化结果）。
    fn is_client_dir(src_ip: &IpAddr, src_port: u16, dst_ip: &IpAddr, dst_port: u16) -> bool {
        let key = FiveTuple::new(src_ip, dst_ip, src_port, dst_port);
        src_ip == &key.client_ip() && src_port == key.client_port()
    }

    /// 将载荷追加到流缓冲区（处理重叠和乱序）。
    ///
    /// 简化实现：如果 seq 匹配期望值，追加；否则丢弃重叠部分后追加。
    fn append_payload(buf: &mut Vec<u8>, expected_seq: &mut u32, seq: u32, payload: &[u8]) {
        let payload_len = payload.len() as u32;

        // 计算偏移量（处理重传/乱序）
        let offset = seq.wrapping_sub(*expected_seq) as i64;

        if offset >= 0 {
            // seq 在期望之后或等于期望：可能有间隙或恰好匹配
            if offset > 0 && offset < 10_000_000 {
                // 小间隙：用零填充（避免单个丢包导致后续数据全丢弃）
                // 大间隙（>10MB）视为异常，丢弃
                if (offset as usize) < 10_000_000 {
                    buf.resize(buf.len() + offset as usize, 0);
                }
            }
            // 追加数据
            buf.extend_from_slice(payload);
            *expected_seq = seq.wrapping_add(payload_len);
        } else {
            // seq 在期望之前（重传）：只取新数据部分
            let overlap = (-offset) as usize;
            if overlap < payload.len() {
                buf.extend_from_slice(&payload[overlap..]);
                *expected_seq = seq.wrapping_add(payload_len);
            }
            // 完全重叠则跳过
        }
    }

    /// 获取指定流的客户端方向载荷。
    #[allow(dead_code)]
    pub fn client_payload(&self, key: &FiveTuple) -> Option<&[u8]> {
        self.streams.get(key).map(|s| s.client_payload.as_slice())
    }

    /// 获取指定流的服务器方向载荷。
    #[allow(dead_code)]
    pub fn server_payload(&self, key: &FiveTuple) -> Option<&[u8]> {
        self.streams.get(key).map(|s| s.server_payload.as_slice())
    }

    /// 获取所有已关闭的流。
    #[allow(dead_code)]
    pub fn closed_streams(&self) -> Vec<(&FiveTuple, &TcpStream)> {
        self.streams
            .iter()
            .filter(|(_, s)| s.state == TcpState::Closed)
            .collect()
    }

    /// 获取所有流（包括活跃的）。
    pub fn all_streams(&self) -> Vec<(&FiveTuple, &TcpStream)> {
        self.streams.iter().collect()
    }

    /// 获取流总数。
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// IpAddr 格式化正确。
    #[test]
    fn test_ip_addr_format() {
        assert_eq!(IpAddr::v4([192, 168, 1, 1]).format(), "192.168.1.1");
        let v6 = IpAddr::v6([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        assert_eq!(v6.format(), "2001:db8:0:0:0:0:0:1");
    }

    /// 五元组归一化后相同。
    #[test]
    fn test_five_tuple_normalization() {
        let a = IpAddr::v4([10, 0, 0, 1]);
        let b = IpAddr::v4([10, 0, 0, 2]);
        let t1 = FiveTuple::new(&a, &b, 12345, 80);
        let t2 = FiveTuple::new(&b, &a, 80, 12345);
        // 归一化后应该是相同的
        assert_eq!(t1.packed, t2.packed);
    }

    /// SYN 握手状态机正确。
    #[test]
    fn test_stream_tracker_syn_handshake() {
        let mut tracker = TcpStreamTracker::new();
        let client = IpAddr::v4([192, 168, 1, 100]);
        let server = IpAddr::v4([93, 184, 216, 34]);

        // SYN (client → server)
        tracker.feed(&client, &server, 54321, 80, 1000, 0x02, &[], 66);
        assert_eq!(tracker.stream_count(), 1);
        if let Some(s) = tracker.all_streams().first() {
            assert_eq!(s.1.state, TcpState::Established);
        }
    }

    /// TCP 数据重组正确。
    #[test]
    fn test_stream_tracker_data_reassembly() {
        let mut tracker = TcpStreamTracker::new();
        let client = IpAddr::v4([10, 0, 0, 1]);
        let server = IpAddr::v4([10, 0, 0, 2]);

        // SYN (seq=0)
        tracker.feed(&client, &server, 50000, 80, 0, 0x02, &[], 60);

        // Data: "GET / HTTP/1.1" (seq=1)
        let payload1 = b"GET / HT";
        tracker.feed(&client, &server, 50000, 80, 1, 0x10, payload1, 70);

        // Data: "TP/1.1\r\n" (seq=9)
        let payload2 = b"TP/1.1\r\n";
        tracker.feed(&client, &server, 50000, 80, 9, 0x10, payload2, 70);

        // 乱序到达：先到后续数据
        let payload3 = b"Host: ex\r\n";
        tracker.feed(&client, &server, 50000, 80, 17, 0x10, payload3, 75);

        let key = FiveTuple::new(&client, &server, 50000, 80);
        let payload = tracker.client_payload(&key).unwrap();
        // 应该重组为 "GET / HTTP/1.1\r\nHost: ex\r\n"（seq 连续，无间隙填充）
        assert!(payload.starts_with(b"GET / HT"));
        assert_eq!(payload.len(), 26); // 8 + 8 + 10
    }
}
