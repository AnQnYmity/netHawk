//! DHCP 协议解析模块
//!
//! 解析 DHCP（Dynamic Host Configuration Protocol, RFC 2131）报文。
//! DHCP 基于 BOOTP（RFC 951），运行在 UDP 67（服务器）/68（客户端）端口上。
//!
//! # 报文结构
//!
//! ```text
//!   op(1) + htype(1) + hlen(1) + hops(1)
//!   + xid(4) + secs(2) + flags(2)
//!   + ciaddr(4) + yiaddr(4) + siaddr(4) + giaddr(4)
//!   + chaddr(16) + sname(64) + file(128)
//!   + options(variable, 至少 312 字节中的 DHCP Magic Cookie)
//! ```
//!
//! DHCP 选项使用 TLV 格式：Type(1) + Length(1) + Value
//! 关键选项包括：
//! - 53: DHCP Message Type (1=Discover, 2=Offer, 3=Request, 5=ACK, ...)
//! - 50: Requested IP Address
//! - 54: DHCP Server Identifier
//! - 55: Parameter Request List
//! - 51: IP Address Lease Time
//!
//! # 参考
//! - RFC 2131 — DHCP
//! - RFC 2132 — DHCP Options and BOOTP Vendor Extensions

/// DHCP 选项（零拷贝引用）。
pub struct DhcpOption<'a> {
    /// 选项类型代码。
    pub code: u8,
    /// 选项值（零拷贝引用）。
    pub value: &'a [u8],
}

/// DHCP 报文（零拷贝引用）。
///
/// 固定 240 字节 BOOTP 头 + 可变选项字段。
#[allow(dead_code)]
pub struct DhcpPacket<'a> {
    /// 操作码：1=BOOTREQUEST, 2=BOOTREPLY。
    pub op: u8,
    /// 硬件地址类型（1=Ethernet）。
    pub htype: u8,
    /// 硬件地址长度（6）。
    pub hlen: u8,
    /// 跳数。
    pub hops: u8,
    /// 事务 ID（匹配请求与响应）。
    pub xid: u32,
    /// 客户端启动耗时（秒）。
    pub secs: u16,
    /// 标志（bit 0 = Broadcast）。
    pub flags: u16,
    /// 客户端 IP 地址（0 表示首次请求）。
    pub ciaddr: [u8; 4],
    /// "你的"IP 地址（DHCP 服务器分配的地址）。
    pub yiaddr: [u8; 4],
    /// 下一个服务器 IP 地址（TFTP 等）。
    pub siaddr: [u8; 4],
    /// 中继代理 IP 地址。
    pub giaddr: [u8; 4],
    /// 客户端硬件地址（MAC）。
    pub chaddr: [u8; 16],
    /// 解析后的选项列表。
    pub options: Vec<DhcpOption<'a>>,
}

/// DHCP 消息类型（选项 53）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
    Unknown,
}

impl DhcpMessageType {
    /// 从 u8 值构造。
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => DhcpMessageType::Discover,
            2 => DhcpMessageType::Offer,
            3 => DhcpMessageType::Request,
            4 => DhcpMessageType::Decline,
            5 => DhcpMessageType::Ack,
            6 => DhcpMessageType::Nak,
            7 => DhcpMessageType::Release,
            8 => DhcpMessageType::Inform,
            _ => DhcpMessageType::Unknown,
        }
    }

    /// 转为人类可读名称。
    pub fn name(&self) -> &'static str {
        match self {
            DhcpMessageType::Discover => "DISCOVER",
            DhcpMessageType::Offer => "OFFER",
            DhcpMessageType::Request => "REQUEST",
            DhcpMessageType::Decline => "DECLINE",
            DhcpMessageType::Ack => "ACK",
            DhcpMessageType::Nak => "NAK",
            DhcpMessageType::Release => "RELEASE",
            DhcpMessageType::Inform => "INFORM",
            DhcpMessageType::Unknown => "???",
        }
    }
}

impl<'a> DhcpPacket<'a> {
    /// 从原始字节解析 DHCP 报文。
    ///
    /// 需要至少 240 字节（BOOTP 固定头）。
    ///
    /// # 错误
    ///
    /// 数据不足 240 字节时返回错误。
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        if raw.len() < 240 {
            anyhow::bail!("DHCP 报文长度过短：{} 字节（最少 240 字节）", raw.len());
        }

        let mut chaddr = [0u8; 16];
        chaddr.copy_from_slice(&raw[28..44]);

        // 解析选项：跳过 Magic Cookie (4 字节)
        let option_start = 240;
        let mut options = Vec::new();
        if raw.len() > option_start + 4 {
            let magic = &raw[option_start..option_start + 4];
            if magic == [0x63, 0x82, 0x53, 0x63] {
                // DHCP Magic Cookie 正确
                let mut pos = option_start + 4;
                while pos + 1 < raw.len() {
                    let code = raw[pos];
                    if code == 0 {
                        // Pad option
                        pos += 1;
                        continue;
                    }
                    if code == 255 {
                        // End option
                        break;
                    }
                    if pos + 2 > raw.len() {
                        break;
                    }
                    let len = raw[pos + 1] as usize;
                    pos += 2;
                    if pos + len > raw.len() {
                        break;
                    }
                    options.push(DhcpOption {
                        code,
                        value: &raw[pos..pos + len],
                    });
                    pos += len;
                }
            }
        }

        Ok(Self {
            op: raw[0],
            htype: raw[1],
            hlen: raw[2],
            hops: raw[3],
            xid: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            secs: u16::from_be_bytes([raw[8], raw[9]]),
            flags: u16::from_be_bytes([raw[10], raw[11]]),
            ciaddr: raw[12..16].try_into()?,
            yiaddr: raw[16..20].try_into()?,
            siaddr: raw[20..24].try_into()?,
            giaddr: raw[24..28].try_into()?,
            chaddr,
            options,
        })
    }

    /// 获取 DHCP 消息类型（选项 53）。
    pub fn message_type(&self) -> Option<DhcpMessageType> {
        self.get_option_u8(53).map(DhcpMessageType::from_u8)
    }

    /// 获取 Requested IP Address（选项 50）。
    pub fn requested_ip(&self) -> Option<[u8; 4]> {
        let opt = self.find_option(50)?;
        if opt.len() == 4 {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(opt);
            Some(addr)
        } else {
            None
        }
    }

    /// 获取 DHCP Server Identifier（选项 54）。
    pub fn server_identifier(&self) -> Option<[u8; 4]> {
        let opt = self.find_option(54)?;
        if opt.len() == 4 {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(opt);
            Some(addr)
        } else {
            None
        }
    }

    /// 查找选项的值（原始字节引用）。
    fn find_option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|o| o.code == code)
            .map(|o| o.value)
    }

    /// 获取单字节选项值。
    fn get_option_u8(&self, code: u8) -> Option<u8> {
        self.find_option(code).and_then(|v| v.first().copied())
    }
}

/// 格式化 IPv4 地址为点分十进制。
pub fn format_ipv4(addr: &[u8; 4]) -> String {
    format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
}

/// 格式化 MAC 地址为 `xx:xx:xx:xx:xx:xx`。
pub fn format_mac(addr: &[u8]) -> String {
    addr.iter()
        .take(6)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造标准 DHCP Discover 报文。
    fn make_dhcp_discover(client_mac: [u8; 6], xid: u32) -> Vec<u8> {
        let mut raw = vec![0u8; 300];
        raw[0] = 1; // op=BOOTREQUEST
        raw[1] = 1; // htype=Ethernet
        raw[2] = 6; // hlen
        raw[4..8].copy_from_slice(&xid.to_be_bytes());
        raw[28..34].copy_from_slice(&client_mac);

        // Magic Cookie
        raw[240..244].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);

        // Option 53: DHCP Message Type = Discover (1)
        raw[244] = 53;
        raw[245] = 1;
        raw[246] = 1;

        // Option 55: Parameter Request List
        raw[247] = 55;
        raw[248] = 4;
        raw[249] = 1; // Subnet Mask
        raw[250] = 3; // Router
        raw[251] = 6; // DNS Server
        raw[252] = 15; // Domain Name

        // End
        raw[253] = 255;

        raw
    }

    /// DHCP Discover 报文解析正确。
    #[test]
    fn test_parse_discover() {
        let raw = make_dhcp_discover([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 0x12345678);
        let pkt = DhcpPacket::parse(&raw).unwrap();
        assert_eq!(pkt.op, 1);
        assert_eq!(pkt.xid, 0x12345678);
        assert_eq!(pkt.message_type().unwrap(), DhcpMessageType::Discover);
        assert_eq!(format_mac(&pkt.chaddr[0..6]), "aa:bb:cc:dd:ee:ff");
    }

    /// DHCP 报文过短返回错误。
    #[test]
    fn test_parse_too_short() {
        let raw = [0u8; 200];
        assert!(DhcpPacket::parse(&raw).is_err());
    }

    /// 无效 Magic Cookie 返回错误。
    #[test]
    fn test_invalid_magic_cookie() {
        let mut raw = vec![0u8; 250];
        raw[0] = 1;
        // 错误的 Magic Cookie
        raw[240..244].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        let pkt = DhcpPacket::parse(&raw).unwrap();
        assert!(pkt.options.is_empty());
    }

    /// IPv4 地址格式化正确。
    #[test]
    fn test_format_ipv4() {
        assert_eq!(format_ipv4(&[192, 168, 1, 100]), "192.168.1.100");
    }

    /// MAC 地址格式化正确。
    #[test]
    fn test_format_mac() {
        assert_eq!(
            format_mac(&[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0xff, 0xff]),
            "00:1a:2b:3c:4d:5e"
        );
    }
}
