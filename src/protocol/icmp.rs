//! ICMP/ICMPv6 协议解析模块
//!
//! 解析 ICMP（RFC 792）和 ICMPv6（RFC 4443）报文。
//! 两者共享相同的 4 字节基本头（Type + Code + Checksum），
//! 后续载荷随 Type 不同而变化。
//!
//! # 常见 ICMP 类型
//!
//! | Type | 名称 | 说明 |
//! |------|------|------|
//! | 0    | Echo Reply | ping 响应 |
//! | 3    | Destination Unreachable | 目标不可达 |
//! | 8    | Echo Request | ping 请求 |
//! | 11   | Time Exceeded | TTL 耗尽 |
//!
//! # 参考
//! - RFC 792 — Internet Control Message Protocol
//! - RFC 4443 — ICMPv6

/// ICMP/ICMPv6 数据包（零拷贝引用）。
///
/// 固定 4 字节头部 + 可变载荷。
#[allow(dead_code)]
pub struct ICMPPacket<'a> {
    /// ICMP 类型（0 = Echo Reply, 8 = Echo Request, 3 = Dest Unreachable, …）。
    pub icmp_type: u8,
    /// 类型子代码。
    pub code: u8,
    /// 校验和（网络字节序）。
    pub checksum: u16,
    /// 载荷（零拷贝引用），对于 Echo Request/Reply 包含 Identifier(2) + Sequence(2) + 数据。
    pub payload: &'a [u8],
}

impl<'a> ICMPPacket<'a> {
    /// 从原始字节解析 ICMP/ICMPv6 报文。
    ///
    /// 校验项：
    /// - 数据长度 ≥ 4 字节（固定头）
    ///
    /// 注意：不校验 checksum，由上层决定是否验证。
    ///
    /// # 错误
    ///
    /// 数据不足 4 字节时返回错误。
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 4 {
            anyhow::bail!("ICMP 报文长度过短：{} 字节（最少 4 字节）", raw.len());
        }
        Ok(Self {
            icmp_type: raw[0],
            code: raw[1],
            checksum: u16::from_be_bytes([raw[2], raw[3]]),
            payload: &raw[4..],
        })
    }

    /// ICMP Type → 人类可读名称。
    ///
    /// 注：ICMP 和 ICMPv6 共享类型号空间但语义不同。
    /// 冲突的类型号（3、4、5 等）沿用 ICMP 语义；
    /// 仅 ICMPv6 专用号（128-137）和 ICMP 未使用的号（1、2）标注 v6。
    pub fn type_name(t: u8) -> &'static str {
        match t {
            0 => "Echo Reply",
            3 => "Dest Unreachable",
            4 => "Source Quench",
            5 => "Redirect",
            8 => "Echo Request",
            9 => "Router Advertisement",
            10 => "Router Solicitation",
            11 => "Time Exceeded",
            12 => "Parameter Problem",
            13 => "Timestamp",
            14 => "Timestamp Reply",
            // ICMPv6-only types (no conflict with ICMP)
            1 => "Dest Unreachable (v6)",
            2 => "Packet Too Big (v6)",
            128 => "Echo Request (v6)",
            129 => "Echo Reply (v6)",
            133 => "Router Solicitation (v6)",
            134 => "Router Advertisement (v6)",
            135 => "Neighbor Solicitation (v6)",
            136 => "Neighbor Advertisement (v6)",
            137 => "Redirect (v6)",
            _ => "???",
        }
    }

    /// 提取 Echo Request/Reply 的 Identifier 字段（若载荷 ≥ 2 字节）。
    pub fn identifier(&self) -> Option<u16> {
        if self.payload.len() >= 2 {
            Some(u16::from_be_bytes([self.payload[0], self.payload[1]]))
        } else {
            None
        }
    }

    /// 提取 Echo Request/Reply 的 Sequence 字段（若载荷 ≥ 4 字节）。
    pub fn sequence(&self) -> Option<u16> {
        if self.payload.len() >= 4 {
            Some(u16::from_be_bytes([self.payload[2], self.payload[3]]))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造标准 ICMP Echo Request（ping）。
    fn make_echo_request(id: u16, seq: u16) -> Vec<u8> {
        let mut raw = vec![0u8; 8];
        raw[0] = 8; // Type: Echo Request
        raw[1] = 0; // Code
        // checksum 不校验
        raw[4..6].copy_from_slice(&id.to_be_bytes());
        raw[6..8].copy_from_slice(&seq.to_be_bytes());
        raw
    }

    /// 构造 ICMP Echo Reply。
    fn make_echo_reply(id: u16, seq: u16) -> Vec<u8> {
        let mut raw = vec![0u8; 8];
        raw[0] = 0; // Type: Echo Reply
        raw[1] = 0;
        raw[4..6].copy_from_slice(&id.to_be_bytes());
        raw[6..8].copy_from_slice(&seq.to_be_bytes());
        raw
    }

    /// 合法 Echo Request 解析验证。
    #[test]
    fn test_parse_echo_request() {
        let raw = make_echo_request(0x1234, 0x0001);
        let icmp = ICMPPacket::parse(&raw).unwrap();
        assert_eq!(icmp.icmp_type, 8);
        assert_eq!(icmp.code, 0);
        assert_eq!(icmp.identifier(), Some(0x1234));
        assert_eq!(icmp.sequence(), Some(0x0001));
    }

    /// Echo Reply 解析验证。
    #[test]
    fn test_parse_echo_reply() {
        let raw = make_echo_reply(0x5678, 0x0002);
        let icmp = ICMPPacket::parse(&raw).unwrap();
        assert_eq!(icmp.icmp_type, 0);
        assert_eq!(icmp.code, 0);
        assert_eq!(icmp.identifier(), Some(0x5678));
        assert_eq!(icmp.sequence(), Some(0x0002));
    }

    /// 报文太短应返回 Err。
    #[test]
    fn test_parse_too_short() {
        let raw = [0u8; 3];
        assert!(ICMPPacket::parse(&raw).is_err());
    }

    /// 最小 4 字节头部可解析，无 payload。
    #[test]
    fn test_parse_minimal() {
        let raw = [0x03, 0x01, 0x00, 0x00]; // Dest Unreachable, code=1 (host)
        let icmp = ICMPPacket::parse(&raw).unwrap();
        assert_eq!(icmp.icmp_type, 3);
        assert_eq!(icmp.code, 1);
        assert!(icmp.payload.is_empty());
        assert_eq!(icmp.identifier(), None);
        assert_eq!(icmp.sequence(), None);
    }

    /// type_name 映射正确。
    #[test]
    fn test_type_name() {
        assert_eq!(ICMPPacket::type_name(0), "Echo Reply");
        assert_eq!(ICMPPacket::type_name(8), "Echo Request");
        assert_eq!(ICMPPacket::type_name(3), "Dest Unreachable");
        assert_eq!(ICMPPacket::type_name(11), "Time Exceeded");
        assert_eq!(ICMPPacket::type_name(128), "Echo Request (v6)");
        assert_eq!(ICMPPacket::type_name(129), "Echo Reply (v6)");
        assert_eq!(ICMPPacket::type_name(255), "???");
    }
}
