pub struct IPv4Packet<'a> {
    // pub ver_headerLen: u8,
    // pub tos: u8,
    // pub totalLen: u16,
    // pub id: u16,
    // pub flg_fragOffset: u16,
    pub ttl: u8,
    pub next_protocol: u8,
    // pub checksum: u16,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    // pub options: [u8],
    pub payload: &'a [u8],
}

pub struct IPv6Packet {

}

impl<'a> IPv4Packet<'a> {
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 20 {
            anyhow::bail!("IPv4 头太短：{} 字节。", raw.len());
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
            payload: &raw[header_len..],
        })
    }

    pub fn format_ip(ip: &[u8; 4]) -> String {
        format!(
            "{}.{}.{}.{}",
            ip[0], ip[1], ip[2], ip[3]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}