//! 以太网帧解析模块
//!
//! 解析 Ethernet II 帧头部（固定 14 字节），提取源/目的 MAC 地址、
//! EtherType 和上层协议载荷。
//!
//! # 参考
//! - IEEE 802.3 — Ethernet

/// 以太网帧（Ethernet II 格式）。
///
/// 固定 14 字节头部：6 字节目的 MAC + 6 字节源 MAC + 2 字节 EtherType。
pub struct EthernetFrame<'a> {
    /// 目的 MAC 地址。
    pub dst_mac: [u8; 6],
    /// 源 MAC 地址。
    pub src_mac: [u8; 6],
    /// 上层协议类型（0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP）。
    pub ethernet_type: u16,
    /// 上层协议载荷（零拷贝引用）。
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// 从原始字节解析以太网帧头。
    ///
    /// 需要至少 14 字节。返回的 `payload` 指向第 15 字节开始的数据。
    ///
    /// # 错误
    ///
    /// 帧长度不足 14 字节时返回错误。
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 14 {
            anyhow::bail!("以太网帧长度过短：{} 字节", raw.len());
        }
        Ok(Self {
            dst_mac: raw[0..6].try_into()?,
            src_mac: raw[6..12].try_into()?,
            ethernet_type: u16::from_be_bytes([raw[12], raw[13]]),
            payload: &raw[14..raw.len()],
        })
    }

    /// 格式化 MAC 地址为 `xx:xx:xx:xx:xx:xx` 形式。
    pub fn format_mac(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个合法的 14 字节以太网帧头，验证各字段解析正确。
    #[test]
    fn test_parse_valid() {
        let mut raw = [0u8; 20]; // 14字节头 + 6字节payload
        raw[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // dst
        raw[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src
        raw[12..14].copy_from_slice(&[0x08, 0x00]); // EtherType: IPv4

        let frame = EthernetFrame::parse(&raw).unwrap();
        assert_eq!(frame.dst_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(frame.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(frame.ethernet_type, 0x0800);
        assert_eq!(frame.payload.len(), 6);
    }

    /// 帧太短时应返回 Err。
    #[test]
    fn test_parse_too_short() {
        let raw = [0u8; 13];
        assert!(EthernetFrame::parse(&raw).is_err());
    }

    /// format_mac 输出格式正确。
    #[test]
    fn test_format_mac() {
        let mac = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];
        assert_eq!(EthernetFrame::format_mac(&mac), "00:1a:2b:3c:4d:5e");
    }
}