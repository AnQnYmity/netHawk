//! 以太网帧解析模块
//!
//! 解析 Ethernet II 帧头部（固定 14 字节），提取源/目的 MAC 地址、
//! EtherType 和上层协议载荷。
//!
//! # 参考
//! - IEEE 802.3 — Ethernet

/// 802.1Q VLAN Tag。
///
/// 4 字节：2 字节 TPID (0x8100) + 2 字节 TCI（PCP|DEI|VID）。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct VlanTag {
    /// 优先级 (Priority Code Point, 0–7)。
    pub pcp: u8,
    /// 丢弃指示 (Drop Eligible Indicator, 0 或 1)。
    pub dei: bool,
    /// VLAN ID (1–4094)。
    pub vid: u16,
}

/// 以太网帧（Ethernet II / 802.1Q 格式）。
///
/// 标准帧 14 字节头部；若携带 802.1Q 标签则增至 18 字节。
/// `ethernet_type` 始终指向真实的上层协议类型（跳过 VLAN tag 后）。
pub struct EthernetFrame<'a> {
    /// 目的 MAC 地址。
    pub dst_mac: [u8; 6],
    /// 源 MAC 地址。
    pub src_mac: [u8; 6],
    /// 上层协议类型（0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP）。
    pub ethernet_type: u16,
    /// VLAN 标签（存在 802.1Q 时填充，否则 `None`）。
    #[allow(dead_code)]
    pub vlan: Option<VlanTag>,
    /// 上层协议载荷（零拷贝引用）。
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// 从原始字节解析以太网帧头。
    ///
    /// 自动识别 802.1Q VLAN 标签（TPID 0x8100）：若存在则跳过 4 字节，
    /// 从后续 2 字节读取真实 EtherType，并填充 `vlan` 字段。
    ///
    /// 需要至少 14 字节（无 VLAN）或 18 字节（有 VLAN）。
    ///
    /// # 错误
    ///
    /// 帧长度不足时返回错误。
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 14 {
            anyhow::bail!("以太网帧长度过短：{} 字节", raw.len());
        }

        let ethernet_type = u16::from_be_bytes([raw[12], raw[13]]);
        let (real_ethertype, vlan, payload_start) = if ethernet_type == 0x8100 {
            // 802.1Q VLAN：跳过 4 字节 tag 读真实 EtherType
            if raw.len() < 18 {
                anyhow::bail!("VLAN 帧长度过短：{} 字节（须 >= 18）", raw.len());
            }
            let tci = u16::from_be_bytes([raw[14], raw[15]]);
            let vlan_tag = VlanTag {
                pcp: ((tci >> 13) & 0x07) as u8,
                dei: ((tci >> 12) & 0x01) != 0,
                vid: tci & 0x0FFF,
            };
            let real_type = u16::from_be_bytes([raw[16], raw[17]]);
            (real_type, Some(vlan_tag), 18)
        } else {
            (ethernet_type, None, 14)
        };

        Ok(Self {
            dst_mac: raw[0..6].try_into()?,
            src_mac: raw[6..12].try_into()?,
            ethernet_type: real_ethertype,
            vlan,
            payload: &raw[payload_start..],
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

    // ── proptest 模糊测试 ──

    use proptest::prelude::*;

    proptest! {
        /// 任意字节切片输入不应导致 panic。
        #[test]
        fn parse_never_panics(raw in prop::collection::vec(any::<u8>(), 0..128)) {
            let _ = EthernetFrame::parse(&raw);
        }

        /// 长度 >= 14 的随机输入，若解析成功则 payload 起始偏移正确。
        #[test]
        fn valid_parse_has_correct_payload_offset(raw in prop::collection::vec(any::<u8>(), 14..128)) {
            if let Ok(frame) = EthernetFrame::parse(&raw) {
                let expected_offset = if u16::from_be_bytes([raw[12], raw[13]]) == 0x8100 { 18 } else { 14 };
                assert_eq!(raw.len() - frame.payload.len(), expected_offset,
                    "payload 起始偏移不一致");
            }
        }
    }
}
