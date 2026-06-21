//! TLS ClientHello 解析模块
//!
//! 解析 TLS 记录层和 ClientHello 握手消息，提取 SNI、
//! 支持的密码套件列表、TLS 版本等关键信息。
//!
//! # 报文结构
//!
//! ```text
//! TLS Record Layer:
//!   ContentType(1) + Version(2) + Length(2) + Payload
//!
//! ClientHello (Handshake type=1):
//!   HandshakeType(1) + Length(3)
//!   + ClientVersion(2) + Random(32) + SessionID
//!   + CipherSuites + CompressionMethods + Extensions
//! ```
//!
//! # 参考
//! - RFC 8446 — TLS 1.3
//! - RFC 5246 — TLS 1.2

/// TLS ClientHello 解析结果。
///
/// 包含 ClientHello 中对外可见的关键字段。
pub struct TlsClientHello {
    /// TLS 记录版本（0x0301=TLS1.0, 0x0303=TLS1.2, 0x0304=TLS1.3）。
    pub record_version: u16,
    /// ClientHello 中声明的最高支持版本。
    pub client_version: u16,
    /// Server Name Indication（SNI），即客户端请求的域名。
    pub sni: Option<String>,
    /// 支持的密码套件 ID 列表。
    pub cipher_suites: Vec<u16>,
    /// ALPN 协议列表（如 "h2"、"http/1.1"）。
    pub alpn: Vec<String>,
}

/// 解析 TLS 记录层并尝试提取 ClientHello。
///
/// 从 TCP 载荷中检测 TLS ClientHello 并提取关键字段。
/// 非 ClientHello 时返回 `None`。
///
/// # 参数
///
/// * `data` — TCP 载荷（可能包含多个 TLS 记录）。
pub fn parse_client_hello(data: &[u8]) -> Option<TlsClientHello> {
    let mut offset = 0;

    while offset + 5 <= data.len() {
        let content_type = data[offset];
        // 只处理 Handshake 记录 (22)
        if content_type != 22 {
            // 不是握手消息，跳过（可能是 ChangeCipherSpec 或 ApplicationData）
            return None;
        }

        let record_version = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
        let record_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;

        if offset + 5 + record_len > data.len() {
            // 截断的记录
            return None;
        }

        let record_payload = &data[offset + 5..offset + 5 + record_len];

        // 解析 Handshake 层
        if let Some(hello) = parse_handshake_client_hello(record_payload, record_version) {
            return Some(hello);
        }

        offset += 5 + record_len;
    }

    None
}

/// 从 Handshake 记录载荷中解析 ClientHello。
fn parse_handshake_client_hello(data: &[u8], record_version: u16) -> Option<TlsClientHello> {
    if data.len() < 4 {
        return None;
    }

    let handshake_type = data[0];
    if handshake_type != 1 {
        // 不是 ClientHello
        return None;
    }

    // Handshake 长度（3 字节大端）
    let _handshake_len = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;

    if data.len() < 4 + 38 {
        return None;
    }

    let mut pos = 4;

    // ClientVersion (2 bytes)
    let client_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Random (32 bytes) — 跳过
    pos += 32;

    // Session ID
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;
    if pos > data.len() {
        return None;
    }

    // Cipher Suites
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + cipher_suites_len > data.len() {
        return None;
    }
    let mut cipher_suites = Vec::new();
    for i in (0..cipher_suites_len).step_by(2) {
        if pos + i + 1 < data.len() {
            cipher_suites.push(u16::from_be_bytes([data[pos + i], data[pos + i + 1]]));
        }
    }
    pos += cipher_suites_len;

    // Compression Methods
    if pos >= data.len() {
        return None;
    }
    let comp_methods_len = data[pos] as usize;
    pos += 1 + comp_methods_len;
    if pos > data.len() {
        return None;
    }

    // Extensions (optional in TLS 1.2, mandatory in TLS 1.3)
    let mut sni: Option<String> = None;
    let mut alpn: Vec<String> = Vec::new();

    if pos + 2 <= data.len() {
        let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        let ext_end = pos + extensions_len;
        if ext_end > data.len() {
            return None;
        }

        while pos + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if pos + ext_len > ext_end {
                break;
            }

            match ext_type {
                0x0000 => {
                    // SNI (Server Name Indication)
                    sni = parse_sni_extension(&data[pos..pos + ext_len]);
                }
                0x0010 => {
                    // ALPN (Application-Layer Protocol Negotiation)
                    alpn = parse_alpn_extension(&data[pos..pos + ext_len]);
                }
                _ => {} // 跳过其他扩展
            }

            pos += ext_len;
        }
    }

    Some(TlsClientHello {
        record_version,
        client_version,
        sni,
        cipher_suites,
        alpn,
    })
}

/// 解析 SNI 扩展（type 0x0000）。
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // SNI 扩展: ServerNameList
    if data.len() < 3 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if list_len + 2 > data.len() {
        return None;
    }

    let mut pos = 2;
    while pos + 3 <= data.len() {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if name_type == 0 && pos + name_len <= data.len() {
            // host_name (type=0)
            return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
        }
        pos += name_len;
    }

    None
}

/// 解析 ALPN 扩展（type 0x0010）。
fn parse_alpn_extension(data: &[u8]) -> Vec<String> {
    let mut protocols = Vec::new();
    if data.len() < 2 {
        return protocols;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if list_len + 2 > data.len() {
        return protocols;
    }

    let mut pos = 2;
    while pos < data.len() {
        let proto_len = data[pos] as usize;
        pos += 1;
        if pos + proto_len <= data.len()
            && let Ok(s) = String::from_utf8(data[pos..pos + proto_len].to_vec())
        {
            protocols.push(s);
        }
        pos += proto_len;
    }

    protocols
}

/// 密码套件 ID → 人类可读名称（常用子集）。
pub fn cipher_suite_name(id: u16) -> &'static str {
    match id {
        0x0000 => "TLS_NULL_WITH_NULL_NULL",
        0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA",
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256",
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256",
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384",
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        0x1301 => "TLS_AES_128_GCM_SHA256 (TLS 1.3)",
        0x1302 => "TLS_AES_256_GCM_SHA384 (TLS 1.3)",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)",
        _ => "???",
    }
}

/// TLS 版本号 → 人类可读名称。
pub fn version_name(v: u16) -> &'static str {
    match v {
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "???",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造最小 TLS 1.2 ClientHello（含 SNI + ALPN）。
    fn make_client_hello(sni: &str, alpn_protos: &[&str]) -> Vec<u8> {
        // 构建 Extensions 部分
        let mut extensions = Vec::new();

        // SNI 扩展
        let sni_bytes = sni.as_bytes();
        let sni_data = {
            let mut d = Vec::new();
            // ServerNameList length
            let name_list_len = 3 + sni_bytes.len(); // 1(name_type) + 2(len) + name
            d.extend_from_slice(&(name_list_len as u16).to_be_bytes());
            d.push(0); // name_type = host_name
            d.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
            d.extend_from_slice(sni_bytes);
            d
        };
        // SNI Extension: type(2) + len(2) + data
        extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // type=SNI
        extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_data);

        // ALPN 扩展
        if !alpn_protos.is_empty() {
            let mut alpn_data = Vec::new();
            let mut alpn_payload = Vec::new();
            for proto in alpn_protos {
                alpn_payload.push(proto.len() as u8);
                alpn_payload.extend_from_slice(proto.as_bytes());
            }
            alpn_data.extend_from_slice(&(alpn_payload.len() as u16).to_be_bytes());
            alpn_data.extend_from_slice(&alpn_payload);

            extensions.extend_from_slice(&0x0010u16.to_be_bytes()); // type=ALPN
            extensions.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&alpn_data);
        }

        let ext_len = extensions.len();

        // Handshake body
        let mut handshake = Vec::new();
        handshake.push(1); // ClientHello type
        // Length placeholder
        let body_len_pos = handshake.len();
        handshake.extend_from_slice(&[0, 0, 0]);

        let body_start = handshake.len();
        handshake.extend_from_slice(&0x0303u16.to_be_bytes()); // client_version = TLS1.2
        handshake.extend_from_slice(&[0u8; 32]); // random
        handshake.push(0); // session_id_len=0
        handshake.extend_from_slice(&[0, 2]); // cipher_suites_len=2
        handshake.extend_from_slice(&0xC02Fu16.to_be_bytes()); // 1 suite
        handshake.push(1); // compression_methods_len=1
        handshake.push(0); // null compression
        handshake.extend_from_slice(&(ext_len as u16).to_be_bytes());
        handshake.extend_from_slice(&extensions);

        let body_len = handshake.len() - body_start;
        handshake[body_len_pos] = ((body_len >> 16) & 0xFF) as u8;
        handshake[body_len_pos + 1] = ((body_len >> 8) & 0xFF) as u8;
        handshake[body_len_pos + 2] = (body_len & 0xFF) as u8;

        // TLS Record Layer
        let mut record = Vec::new();
        record.push(22); // ContentType=Handshake
        record.extend_from_slice(&0x0303u16.to_be_bytes()); // record_version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    /// 带 SNI 的 ClientHello 解析正确。
    #[test]
    fn test_parse_client_hello_sni() {
        let data = make_client_hello("www.example.com", &[]);
        let hello = parse_client_hello(&data).unwrap();
        assert_eq!(hello.client_version, 0x0303);
        assert_eq!(hello.sni.as_deref(), Some("www.example.com"));
    }

    /// 带 ALPN 的 ClientHello 解析正确。
    #[test]
    fn test_parse_client_hello_alpn() {
        let data = make_client_hello("example.com", &["h2", "http/1.1"]);
        let hello = parse_client_hello(&data).unwrap();
        assert_eq!(hello.alpn, vec!["h2", "http/1.1"]);
    }

    /// 非 ClientHello 报文正确处理。
    #[test]
    fn test_non_client_hello() {
        // 不是 Handshake 记录
        let data = vec![23, 0x03, 0x03, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // ApplicationData
        assert!(parse_client_hello(&data).is_none());
    }

    /// 空数据返回 None。
    #[test]
    fn test_empty_data() {
        assert!(parse_client_hello(&[]).is_none());
    }

    /// 加密套件名称映射正确。
    #[test]
    fn test_cipher_suite_name() {
        assert_eq!(
            cipher_suite_name(0x1301),
            "TLS_AES_128_GCM_SHA256 (TLS 1.3)"
        );
        assert_eq!(
            cipher_suite_name(0xC02F),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(cipher_suite_name(0xFFFF), "???");
    }

    /// TLS 版本名称正确。
    #[test]
    fn test_version_name() {
        assert_eq!(version_name(0x0303), "TLS 1.2");
        assert_eq!(version_name(0x0304), "TLS 1.3");
        assert_eq!(version_name(0x0000), "???");
    }
}
