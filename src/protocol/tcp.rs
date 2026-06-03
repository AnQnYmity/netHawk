pub struct TCPSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

impl<'a> TCPSegment<'a> {
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 20 {
            anyhow::bail!("TCP 头太短：{} 字节。", raw.len());
        }
        let data_offset = ((raw[12] >> 4) as usize) * 4;
        if data_offset < 20 {
            anyhow::bail!("数据头长度字段非法：{} 字节。", data_offset);
        }
        Ok(Self {
            // from_be_bytes: 大端转小端
            src_port: u16::from_be_bytes(raw[0..2].try_into()?),
            dst_port: u16::from_be_bytes(raw[2..4].try_into()?),
            seq: u32::from_be_bytes(raw[4..8].try_into()?),
            ack: u32::from_be_bytes(raw[8..12].try_into()?),
            flags: raw[13],
            payload: &raw[data_offset..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
