//! TCP 协议解析模块
//!
//! 解析 TCP 段头部（20–60 字节可变长），提取端口、序号、
//! 标志位及载荷。TCP 头部比 UDP 复杂得多——可变长选项、
//! 12 个标志位（SYN、ACK、FIN 等）、32 位序号/确认号。
//!
//! # 参考
//! - RFC 793 — Transmission Control Protocol

/// TCP 段。
///
/// 头部最小 20 字节（`data_offset` = 5），最大 60 字节。
/// 序号和确认号字段当前解析但未在输出中使用（留待流重组阶段）。
pub struct TCPSegment<'a> {
    /// 源端口号。
    pub src_port: u16,
    /// 目的端口号。
    pub dst_port: u16,
    /// 序号（Sequence Number）。
    pub seq: u32,
    /// 确认号（Acknowledgment Number）。
    pub ack: u32,
    /// 标志位字节（`raw[13]`）：URG|ACK|PSH|RST|SYN|FIN（高位→低位）。
    pub flags: u8,
    /// 应用层载荷（零拷贝引用）。
    pub payload: &'a [u8],
}

impl<'a> TCPSegment<'a> {
    /// 从原始字节解析 TCP 段。
    ///
    /// 校验项：
    /// - 原始数据长度 ≥ 20 字节
    /// - `data_offset` 字段 ≥ 5（即头部至少 20 字节）
    ///
    /// 载荷起始偏移由 `data_offset * 4` 计算，支持 TCP 选项。
    ///
    /// # 错误
    ///
    /// 数据不足或 `data_offset` 非法时返回错误。
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 20 {
            anyhow::bail!("TCP 头太短：{} 字节。", raw.len());
        }
        let data_offset = ((raw[12] >> 4) as usize) * 4;
        if data_offset < 20 {
            anyhow::bail!("数据头长度字段非法：{} 字节。", data_offset);
        }
        Ok(Self {
            src_port: u16::from_be_bytes(raw[0..2].try_into()?),
            dst_port: u16::from_be_bytes(raw[2..4].try_into()?),
            seq: u32::from_be_bytes(raw[4..8].try_into()?),
            ack: u32::from_be_bytes(raw[8..12].try_into()?),
            flags: raw[13],
            payload: &raw[data_offset..raw.len()],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个合法的 TCP 段：头部 20 字节 + 载荷 4 字节。
    fn make_tcp(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut raw = vec![0u8; 24]; // 20字节头 + 4字节payload
        raw[0..2].copy_from_slice(&src_port.to_be_bytes());
        raw[2..4].copy_from_slice(&dst_port.to_be_bytes());
        raw[12] = 0x50; // data_offset=5（20字节），高4bit=5
        raw[13] = flags;
        raw[20..24].copy_from_slice(b"data");
        raw
    }

    /// 合法 TCP 段，验证各字段解析正确。
    #[test]
    fn test_parse_valid() {
        let raw = make_tcp(12345, 80, 0x02); // SYN
        let seg = TCPSegment::parse(&raw).unwrap();
        assert_eq!(seg.src_port, 12345);
        assert_eq!(seg.dst_port, 80);
        assert_eq!(seg.flags & 0x02, 0x02); // SYN 标志位置位
        assert_eq!(seg.payload, b"data");
    }

    /// 头太短时应返回 Err。
    #[test]
    fn test_parse_too_short() {
        let raw = [0u8; 19];
        assert!(TCPSegment::parse(&raw).is_err());
    }

    /// data_offset 非法时应返回 Err。
    #[test]
    fn test_parse_invalid_offset() {
        let mut raw = vec![0u8; 20];
        raw[12] = 0x10; // data_offset=1，非法（1*4=4 < 20）
        assert!(TCPSegment::parse(&raw).is_err());
    }
}