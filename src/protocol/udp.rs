//! UDP 协议解析模块
//!
//! 解析 UDP 数据报头部（固定 8 字节），提取端口号和载荷。
//! UDP 头部结构简单——仅有源端口、目的端口、长度和校验和，
//! 无连接、无确认，解析逻辑比 TCP 轻量得多。
//!
//! # 参考
//! - RFC 768 — User Datagram Protocol

/// UDP 数据报。
///
/// 固定 8 字节头部 + 可变长载荷。校验和字段当前未解析
/// （IPv4 中可选，IPv6 中强制但通常由内核校验）。
pub struct UDPSegment<'a> {
    /// 源端口号。
    pub src_port: u16,
    /// 目的端口号。
    pub dst_port: u16,
    /// UDP 总长度（头部 8 字节 + 载荷字节数）。
    pub len: u16,
    /// 应用层载荷（零拷贝引用）。
    pub payload: &'a [u8],
}

impl<'a> UDPSegment<'a> {
    /// 从原始字节解析 UDP 数据报。
    ///
    /// 校验项：
    /// - 原始数据长度 ≥ 8 字节
    /// - 长度字段 ≥ 8（头部最小值）
    ///
    /// # 错误
    ///
    /// 数据不足或长度字段非法时返回错误。
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 8 {
            anyhow::bail!("UDP 头太短：{} 字节。", raw.len());
        }
        let len = u16::from_be_bytes(raw[4..6].try_into()?);
        if len < 8 {
            anyhow::bail!("长度字段非法：{} 字节。", len);
        }
        Ok(Self {
            src_port: u16::from_be_bytes(raw[0..2].try_into()?),
            dst_port: u16::from_be_bytes(raw[2..4].try_into()?),
            len,
            payload: &raw[8..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个合法 UDP 数据报：头部 8 字节 + 载荷。
    fn make_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut raw = vec![0u8; 8 + payload.len()];
        raw[0..2].copy_from_slice(&src_port.to_be_bytes());
        raw[2..4].copy_from_slice(&dst_port.to_be_bytes());
        let total_len = (8 + payload.len()) as u16;
        raw[4..6].copy_from_slice(&total_len.to_be_bytes());
        raw[8..].copy_from_slice(payload);
        raw
    }

    /// 合法 UDP 数据报，验证各字段解析正确。
    #[test]
    fn test_parse_valid() {
        let raw = make_udp(53, 12345, b"dns-query");
        let seg = UDPSegment::parse(&raw).unwrap();
        assert_eq!(seg.src_port, 53);
        assert_eq!(seg.dst_port, 12345);
        assert_eq!(seg.len, 17); // 8 + 9
        assert_eq!(seg.payload, b"dns-query");
    }

    /// 无载荷的 UDP 数据报（仅头部 8 字节）。
    #[test]
    fn test_parse_empty_payload() {
        let raw = make_udp(8080, 8081, b"");
        let seg = UDPSegment::parse(&raw).unwrap();
        assert_eq!(seg.len, 8);
        assert_eq!(seg.payload, b"");
    }

    /// 头太短时应返回 Err。
    #[test]
    fn test_parse_too_short() {
        let raw = [0u8; 7];
        assert!(UDPSegment::parse(&raw).is_err());
    }

    /// 长度字段非法（< 8）时应返回 Err。
    #[test]
    fn test_parse_invalid_len() {
        let mut raw = vec![0u8; 8];
        raw[4..6].copy_from_slice(&4u16.to_be_bytes()); // len=4
        assert!(UDPSegment::parse(&raw).is_err());
    }
}