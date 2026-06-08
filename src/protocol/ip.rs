//! IP 协议解析模块
//!
//! 支持 IPv4（RFC 791）和 IPv6（RFC 8200）头部解析。
//! 校验版本号、IHL、Payload Length 等字段，提取上层协议号
//! 和源/目的 IP 地址，并正确截断载荷。
//!
//! # 参考
//! - RFC 791 — Internet Protocol (IPv4)
//! - RFC 8200 — Internet Protocol, Version 6 (IPv6)

/// IPv4 数据包。
///
/// 头部最小 20 字节（IHL = 5），最大 60 字节（含选项）。
/// 当前解析的字段为最常用子集：TTL、上层协议号、源/目的 IP。
pub struct IPv4Packet<'a> {
    /// 存活时间（Time to Live）。
    pub ttl: u8,
    /// 上层协议号（6 = TCP, 17 = UDP, 1 = ICMP）。
    pub next_protocol: u8,
    /// 源 IPv4 地址（4 字节网络字节序）。
    pub src_ip: [u8; 4],
    /// 目的 IPv4 地址（4 字节网络字节序）。
    pub dst_ip: [u8; 4],
    /// 上层协议载荷（零拷贝引用）。
    pub payload: &'a [u8],
}

/// IPv6 数据包。
///
/// 固定 40 字节基本头，支持 Payload Length 一致性校验。
pub struct IPv6Packet<'a> {
    /// 下一个头部类型（17 = UDP, 6 = TCP, 58 = ICMPv6）。
    pub next_header: u8,
    /// 跳数限制（Hop Limit），类似 IPv4 TTL。
    pub hop_limit: u8,
    /// 源 IPv6 地址（16 字节）。
    pub src_ip: [u8; 16],
    /// 目的 IPv6 地址（16 字节）。
    pub dst_ip: [u8; 16],
    /// 上层协议载荷（零拷贝引用）。
    pub payload: &'a [u8],
}

impl<'a> IPv4Packet<'a> {
    /// 从原始字节解析 IPv4 数据包。
    ///
    /// 校验项：
    /// - 数据长度 ≥ 20 字节
    /// - 版本字段 = 4
    /// - IHL ≥ 5（头部至少 20 字节）
    ///
    /// 载荷起始偏移由 IHL 计算：`IHL * 4`。
    ///
    /// # 错误
    ///
    /// 数据不足、版本非法或 IHL 非法时返回错误。
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 20 {
            anyhow::bail!("IPv4 头太短：{} 字节。", raw.len());
        }
        let version = raw[0] >> 4;
        if version != 4 {
            anyhow::bail!("版本字段非法：{}（期望 4）", version);
        }
        let header_len = 4 * ((raw[0] & 0xF) as usize);
        if header_len < 20 {
            anyhow::bail!("IHL 字段非法：{}", header_len);
        }
        Ok(Self {
            ttl: raw[8],
            next_protocol: raw[9],
            src_ip: raw[12..16].try_into()?,
            dst_ip: raw[16..20].try_into()?,
            payload: &raw[header_len..raw.len()],
        })
    }

    /// 格式化 IPv4 地址为点分十进制（如 `"192.168.0.1"`）。
    pub fn format_ip(ip: &[u8; 4]) -> String {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    }
}

impl<'a> IPv6Packet<'a> {
    /// 从原始字节解析 IPv6 数据包。
    ///
    /// 校验项：
    /// - 数据长度 ≥ 40 字节
    /// - 版本字段 = 6
    /// - Payload Length 字段与实际数据一致
    ///
    /// # 错误
    ///
    /// 数据不足、版本非法或 Payload Length 不一致时返回错误。
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 40 {
            anyhow::bail!("IPv6 头太短：{} 字节。", raw.len());
        }

        let version = raw[0] >> 4;
        if version != 6 {
            anyhow::bail!("版本字段非法：{}（期望 6）", version);
        }

        let payload_len = u16::from_be_bytes([raw[4], raw[5]]) as usize;
        let total_len = 40 + payload_len;
        if raw.len() < total_len {
            anyhow::bail!(
                "IPv6 数据长度不足：头声明总长 {} 字节，实际仅 {} 字节",
                total_len,
                raw.len()
            );
        }

        Ok(Self {
            next_header: raw[6],
            hop_limit: raw[7],
            src_ip: raw[8..24].try_into()?,
            dst_ip: raw[24..40].try_into()?,
            payload: &raw[40..total_len],
        })
    }

    /// 格式化 IPv6 地址为标准冒号分隔形式（如 `"2001:db8::1"`）。
    ///
    /// 注意：当前实现输出完整的 8 组十六进制数，不做 `::` 零压缩。
    pub fn format_ip(ip: &[u8; 16]) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(8);
        for chunk in ip.chunks_exact(2) {
            let value = u16::from_be_bytes([chunk[0], chunk[1]]);
            parts.push(format!("{:x}", value));
        }
        parts.join(":")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造最小 IPv4 包（IHL=5，20 字节头，无选项）。
    fn make_ipv4(ttl: u8, protocol: u8, src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut raw = vec![0u8; 20];
        raw[0] = 0x45; // version=4, IHL=5（20字节头，无选项）
        raw[8] = ttl;
        raw[9] = protocol;
        raw[12..16].copy_from_slice(&src);
        raw[16..20].copy_from_slice(&dst);
        raw
    }

    /// 合法 IPv4 包，验证各字段解析正确。
    #[test]
    fn test_parse_valid() {
        let raw = make_ipv4(64, 6, [192, 168, 1, 1], [8, 8, 8, 8]);
        let pkt = IPv4Packet::parse(&raw).unwrap();
        assert_eq!(pkt.ttl, 64);
        assert_eq!(pkt.next_protocol, 6); // TCP
        assert_eq!(pkt.src_ip, [192, 168, 1, 1]);
        assert_eq!(pkt.dst_ip, [8, 8, 8, 8]);
        assert_eq!(pkt.payload.len(), 0); // 头20字节，无payload
    }

    /// 头太短时应返回 Err。
    #[test]
    fn test_parse_too_short() {
        let raw = [0u8; 19];
        assert!(IPv4Packet::parse(&raw).is_err());
    }

    /// IHL 非法（小于5）时应返回 Err。
    #[test]
    fn test_parse_invalid_ihl() {
        let mut raw = vec![0u8; 20];
        raw[0] = 0x44; // IHL=4，非法
        assert!(IPv4Packet::parse(&raw).is_err());
    }

    /// format_ip 输出格式正确。
    #[test]
    fn test_format_ip() {
        assert_eq!(IPv4Packet::format_ip(&[192, 168, 0, 1]), "192.168.0.1");
    }

    /// 构造最小 IPv6 包（40 字节头 + 可选载荷）。
    fn make_ipv6(
        next_header: u8,
        hop_limit: u8,
        src: [u8; 16],
        dst: [u8; 16],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut raw = vec![0u8; 40 + payload.len()];
        raw[0] = 0x60; // version=6
        let payload_len = payload.len() as u16;
        raw[4..6].copy_from_slice(&payload_len.to_be_bytes());
        raw[6] = next_header;
        raw[7] = hop_limit;
        raw[8..24].copy_from_slice(&src);
        raw[24..40].copy_from_slice(&dst);
        raw[40..].copy_from_slice(payload);
        raw
    }

    /// 合法 IPv6 包，验证各字段解析正确。
    #[test]
    fn test_ipv6_parse_valid() {
        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 2,
        ];
        let raw = make_ipv6(17, 128, src, dst, b"dns");
        let pkt = IPv6Packet::parse(&raw).unwrap();

        assert_eq!(pkt.next_header, 17);
        assert_eq!(pkt.hop_limit, 128);
        assert_eq!(pkt.src_ip, src);
        assert_eq!(pkt.dst_ip, dst);
        assert_eq!(pkt.payload, b"dns");
    }

    /// IPv6 头太短时应返回 Err。
    #[test]
    fn test_ipv6_parse_too_short() {
        let raw = [0u8; 39];
        assert!(IPv6Packet::parse(&raw).is_err());
    }

    /// 版本字段非法时应返回 Err。
    #[test]
    fn test_ipv6_parse_invalid_version() {
        let mut raw = vec![0u8; 40];
        raw[0] = 0x40; // version=4
        assert!(IPv6Packet::parse(&raw).is_err());
    }

    /// format_ip 输出格式正确。
    #[test]
    fn test_ipv6_format_ip() {
        let ip = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1,
        ];
        assert_eq!(IPv6Packet::format_ip(&ip), "2001:db8:0:0:0:0:0:1");
    }
}