//! DNS 协议解析模块
//!
//! 解析 DNS 报文头部和第一个问题区（Question Section）。
//! 支持标签序列编码的域名解析；压缩指针（0xC0 前缀）暂未实现。
//!
//! # 参考
//! - RFC 1035 §4.1 — DNS 报文格式

/// DNS 报文头部（固定 12 字节）。
#[derive(Debug, Clone)]
pub struct DNSHeader {
    /// 事务 ID，匹配请求与响应。
    pub transaction_id: u16,
    /// 标志位：QR(1)|Opcode(4)|AA|TC|RD|RA|Z(3)|RCODE(4)
    pub flags: u16,
    /// 问题区条目数。
    pub questions: u16,
    /// 回答区条目数。
    pub answers: u16,
    /// 权威区条目数。
    pub authority: u16,
    /// 附加区条目数。
    pub additional: u16,
}

impl DNSHeader {
    /// 是否为响应报文（QR=1）。
    pub fn is_response(&self) -> bool {
        (self.flags >> 15) & 1 == 1
    }

    /// 操作码（Opcode）。
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 0xF) as u8
    }
}

/// DNS 问题区条目。
#[derive(Debug, Clone)]
pub struct DNSQuestion {
    /// 查询域名（点分格式，如 "www.example.com"）。
    pub qname: String,
    /// 查询类型（1=A, 28=AAAA, 5=CNAME, …）。
    pub qtype: u16,
    /// 查询类（通常 1=IN）。
    pub qclass: u16,
}

/// DNS 报文解析结果。
#[derive(Debug)]
pub struct DNSRequest {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    // 通常一次 DNS Request 包含多个 Question
}

impl DNSRequest {
    /// 从原始字节解析 DNS 报文。
    ///
    /// 至少解析 12 字节头部 + 第一个问题区。
    ///
    /// # 错误
    ///
    /// 报文长度不足 12 字节时返回错误。
    pub fn parse(raw: &[u8]) -> anyhow::Result<Self> {
        if raw.len() < 12 {
            anyhow::bail!("DNS 报文太短：{} 字节（最少 12 字节）", raw.len());
        }

        let header = DNSHeader {
            transaction_id: u16::from_be_bytes([raw[0], raw[1]]),
            flags: u16::from_be_bytes([raw[2], raw[3]]),
            questions: u16::from_be_bytes([raw[4], raw[5]]),
            answers: u16::from_be_bytes([raw[6], raw[7]]),
            authority: u16::from_be_bytes([raw[8], raw[9]]),
            additional: u16::from_be_bytes([raw[10], raw[11]]),
        };

        // 解析问题区，从偏移量 12 开始
        let mut offset = 12;
        let mut questions = Vec::new();

        for _ in 0..header.questions {
            let (qname, next) = decode_domain_name(raw, offset)?;
            offset = next;

            if offset + 4 > raw.len() {
                anyhow::bail!(
                    "DNS 报文截断：问题区字段超出报文末尾（偏移量 {}）",
                    offset
                );
            }

            let question = DNSQuestion {
                qname,
                qtype: u16::from_be_bytes([raw[offset], raw[offset + 1]]),
                qclass: u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]),
            };
            offset += 4;
            questions.push(question);
        }

        Ok(Self { header, questions })
    }
}

/// 解码 DNS 标签序列域名。
///
/// DNS 域名由一系列标签组成，每个标签以 1 字节长度前缀开头，
/// 后跟该长度的字节序列，以零长度字节（0x00）终止。
///
/// 例如 `[3, 'w','w','w', 7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0]`
/// 解码为 `"www.example.com"`。
///
/// 注意：当前实现 **不** 处理压缩指针（0xC0 前缀）。
/// 遇到压缩指针时返回错误。
///
/// # 返回值
///
/// 返回 `(域名字符串, 下一字段的偏移量)`。
fn decode_domain_name(raw: &[u8], start: usize) -> anyhow::Result<(String, usize)> {
    let mut offset = start;
    let mut labels: Vec<&str> = Vec::new();

    loop {
        if offset >= raw.len() {
            anyhow::bail!("域名解析越界（偏移量 {}）", offset);
        }

        let len = raw[offset];
        offset += 1;

        if len == 0 {
            // 终止符
            break;
        }

        // 检查压缩指针：高 2 位为 11
        if len & 0xC0 == 0xC0 {
            anyhow::bail!("遇到压缩指针（偏移量 {}），当前尚未支持", start);
        }

        let end = offset + len as usize;
        if end > raw.len() {
            anyhow::bail!("域名标签截断：声明 {} 字节，实际仅余 {} 字节", len, raw.len() - offset);
        }

        let label = std::str::from_utf8(&raw[offset..end])
            .map_err(|_| anyhow::anyhow!("域名标签包含非法 UTF-8 字节（偏移量 {}）", offset))?;
        labels.push(label);
        offset = end;
    }

    Ok((labels.join("."), offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小 DNS 查询报文：header(12) + question(可变)。
    fn make_dns_query(qname_bytes: &[u8], qtype: u16) -> Vec<u8> {
        let mut raw = vec![0u8; 12]; // header

        // transaction_id: 0x1234
        raw[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        // flags: RD=1 (0x0100)
        raw[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
        // questions: 1
        raw[4..6].copy_from_slice(&1u16.to_be_bytes());
        // answers / authority / additional: 0

        // question: qname + qtype + qclass
        raw.extend_from_slice(qname_bytes);
        raw.extend_from_slice(&qtype.to_be_bytes());
        raw.extend_from_slice(&1u16.to_be_bytes()); // QCLASS: IN

        raw
    }

    /// 编码域名为 DNS 标签序列。
    fn encode_domain(name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0); // 终止符
        bytes
    }

    // -----------------------------------------------------------------------
    // decode_domain_name 测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_simple_domain() {
        let domain_bytes = encode_domain("www.example.com");
        let (name, next) = decode_domain_name(&domain_bytes, 0).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(next, domain_bytes.len());
    }

    #[test]
    fn test_decode_single_label() {
        let raw = vec![4, b't', b'e', b's', b't', 0];
        let (name, _) = decode_domain_name(&raw, 0).unwrap();
        assert_eq!(name, "test");
    }

    #[test]
    fn test_decode_compression_pointer_rejected() {
        // 构造一个压缩指针：0xC0 0x0C
        let raw = [0xC0, 0x0C, 0x00];
        assert!(decode_domain_name(&raw, 0).is_err());
    }

    // -----------------------------------------------------------------------
    // DNS header 解析测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_dns_parse_query() {
        let domain = encode_domain("google.com");
        let raw = make_dns_query(&domain, 1); // QTYPE=A

        let dns = DNSRequest::parse(&raw).unwrap();
        assert_eq!(dns.header.transaction_id, 0x1234);
        assert!(!dns.header.is_response());
        assert_eq!(dns.header.opcode(), 0); // QUERY
        assert_eq!(dns.header.questions, 1);

        assert_eq!(dns.questions.len(), 1);
        assert_eq!(dns.questions[0].qname, "google.com");
        assert_eq!(dns.questions[0].qtype, 1);
        assert_eq!(dns.questions[0].qclass, 1);
    }

    #[test]
    fn test_dns_parse_aaaa_query() {
        let domain = encode_domain("ipv6.test.org");
        let raw = make_dns_query(&domain, 28); // QTYPE=AAAA

        let dns = DNSRequest::parse(&raw).unwrap();
        assert_eq!(dns.questions[0].qtype, 28);
        assert_eq!(dns.questions[0].qname, "ipv6.test.org");
    }

    #[test]
    fn test_dns_parse_response() {
        let mut raw = vec![0u8; 12];
        raw[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
        raw[4..6].copy_from_slice(&0u16.to_be_bytes()); // questions=0

        let dns = DNSRequest::parse(&raw).unwrap();
        assert!(dns.header.is_response());
    }

    #[test]
    fn test_dns_parse_too_short() {
        let raw = [0u8; 11];
        assert!(DNSRequest::parse(&raw).is_err());
    }
}