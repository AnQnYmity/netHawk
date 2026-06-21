//! ARP 协议解析模块
//!
//! 解析 ARP（Address Resolution Protocol）报文（RFC 826）。
//! 提取硬件/协议类型、操作码及发送者/目标地址。
//!
//! # 报文结构
//!
//! ARP 报文包含可变长度的硬件地址和协议地址字段，
//! 对于 Ethernet/IPv4 场景共 28 字节（固定 8 字节头 + 2×6 字节 MAC + 2×4 字节 IP）。
//!
//! # 参考
//! - RFC 826 — Ethernet Address Resolution Protocol

/// ARP 数据包（零拷贝引用）。
///
/// 硬件地址和协议地址以切片形式保存，兼容不同地址长度的网络。
#[allow(dead_code)]
pub struct ARPPacket<'a> {
    /// 硬件类型（1 = Ethernet）。
    pub hardware_type: u16,
    /// 协议类型（0x0800 = IPv4）。
    pub protocol_type: u16,
    /// 硬件地址长度（Ethernet = 6 字节）。
    pub hw_addr_len: u8,
    /// 协议地址长度（IPv4 = 4 字节）。
    pub proto_addr_len: u8,
    /// 操作码（1 = Request, 2 = Reply）。
    pub operation: u16,
    /// 发送者硬件地址（零拷贝引用）。
    pub sender_hw_addr: &'a [u8],
    /// 发送者协议地址（零拷贝引用）。
    pub sender_proto_addr: &'a [u8],
    /// 目标硬件地址（零拷贝引用）。
    pub target_hw_addr: &'a [u8],
    /// 目标协议地址（零拷贝引用）。
    pub target_proto_addr: &'a [u8],
}

impl<'a> ARPPacket<'a> {
    /// 从原始字节解析 ARP 报文。
    ///
    /// 校验项：
    /// - 数据长度 ≥ 8 字节（固定头）
    /// - 声明长度与实际数据一致
    ///
    /// # 错误
    ///
    /// 数据不足或声明长度不一致时返回错误。
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 8 {
            anyhow::bail!("ARP 报文长度过短：{} 字节（最少 8 字节）", raw.len());
        }

        let hw_addr_len = raw[4];
        let proto_addr_len = raw[5];

        let total = 8
            + (hw_addr_len as usize) * 2   // sender + target 硬件地址
            + (proto_addr_len as usize) * 2; // sender + target 协议地址

        if raw.len() < total {
            anyhow::bail!("ARP 报文声明 {} 字节，实际仅 {} 字节", total, raw.len());
        }

        let hw = hw_addr_len as usize;
        let pr = proto_addr_len as usize;

        let sender_hw_off = 8;
        let sender_pr_off = sender_hw_off + hw;
        let target_hw_off = sender_pr_off + pr;
        let target_pr_off = target_hw_off + hw;

        Ok(Self {
            hardware_type: u16::from_be_bytes([raw[0], raw[1]]),
            protocol_type: u16::from_be_bytes([raw[2], raw[3]]),
            hw_addr_len,
            proto_addr_len,
            operation: u16::from_be_bytes([raw[6], raw[7]]),
            sender_hw_addr: &raw[sender_hw_off..sender_pr_off],
            sender_proto_addr: &raw[sender_pr_off..target_hw_off],
            target_hw_addr: &raw[target_hw_off..target_pr_off],
            target_proto_addr: &raw[target_pr_off..target_pr_off + pr],
        })
    }

    /// 操作码 → 人类可读名称。
    pub fn operation_name(op: u16) -> &'static str {
        match op {
            1 => "REQUEST",
            2 => "REPLY",
            _ => "???",
        }
    }

    /// 格式化 MAC 地址（6 字节为 `xx:xx:xx:xx:xx:xx`）。
    #[allow(dead_code)]
    pub fn format_mac(addr: &[u8]) -> String {
        if addr.len() == 6 {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
            )
        } else {
            addr.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":")
        }
    }

    /// 格式化 IPv4 地址（4 字节为点分十进制 `x.x.x.x`）。
    pub fn format_ip(addr: &[u8]) -> String {
        if addr.len() == 4 {
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        } else {
            addr.iter()
                .map(|b| format!("{}", b))
                .collect::<Vec<_>>()
                .join(".")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造标准 Ethernet/IPv4 ARP Request。
    fn make_arp_request(
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
    ) -> Vec<u8> {
        let mut raw = vec![0u8; 28];
        raw[0..2].copy_from_slice(&[0x00, 0x01]); // Hardware Type: Ethernet
        raw[2..4].copy_from_slice(&[0x08, 0x00]); // Protocol Type: IPv4
        raw[4] = 6; // HW Addr Len
        raw[5] = 4; // Proto Addr Len
        raw[6..8].copy_from_slice(&[0x00, 0x01]); // Operation: Request
        raw[8..14].copy_from_slice(&sender_mac);
        raw[14..18].copy_from_slice(&sender_ip);
        raw[18..24].copy_from_slice(&target_mac);
        raw[24..28].copy_from_slice(&target_ip);
        raw
    }

    /// 合法 ARP Request，验证各字段解析正确。
    #[test]
    fn test_parse_valid_request() {
        let raw = make_arp_request(
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [192, 168, 1, 1],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [192, 168, 1, 100],
        );
        let arp = ARPPacket::parse(&raw).unwrap();
        assert_eq!(arp.hardware_type, 1);
        assert_eq!(arp.protocol_type, 0x0800);
        assert_eq!(arp.hw_addr_len, 6);
        assert_eq!(arp.proto_addr_len, 4);
        assert_eq!(arp.operation, 1);
        assert_eq!(arp.sender_hw_addr, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(arp.sender_proto_addr, &[192, 168, 1, 1]);
        assert_eq!(arp.target_hw_addr, &[0, 0, 0, 0, 0, 0]);
        assert_eq!(arp.target_proto_addr, &[192, 168, 1, 100]);
    }

    /// 构造标准 ARP Reply。
    #[test]
    fn test_parse_valid_reply() {
        let mut raw = make_arp_request(
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [10, 0, 0, 1],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [10, 0, 0, 2],
        );
        raw[6..8].copy_from_slice(&[0x00, 0x02]); // Reply
        let arp = ARPPacket::parse(&raw).unwrap();
        assert_eq!(arp.operation, 2);
    }

    /// 报文太短时应返回 Err。
    #[test]
    fn test_parse_too_short() {
        let raw = [0u8; 7];
        assert!(ARPPacket::parse(&raw).is_err());
    }

    /// 声明长度与实际不符时应返回 Err。
    #[test]
    fn test_parse_length_mismatch() {
        let raw = [0u8; 20]; // 标准 Ethernet/IPv4 需要 28
        let mut raw = raw.to_vec();
        raw[4] = 6;
        raw[5] = 4;
        assert!(ARPPacket::parse(&raw).is_err());
    }

    /// format_mac 输出格式正确。
    #[test]
    fn test_format_mac() {
        assert_eq!(
            ARPPacket::format_mac(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]),
            "00:1a:2b:3c:4d:5e"
        );
    }

    /// format_ip 输出格式正确。
    #[test]
    fn test_format_ip() {
        assert_eq!(ARPPacket::format_ip(&[192, 168, 0, 1]), "192.168.0.1");
    }

    /// operation_name 映射正确。
    #[test]
    fn test_operation_name() {
        assert_eq!(ARPPacket::operation_name(1), "REQUEST");
        assert_eq!(ARPPacket::operation_name(2), "REPLY");
        assert_eq!(ARPPacket::operation_name(99), "???");
    }
}
