//! HTTP/1.x 协议解析模块
//!
//! 解析明文 HTTP 请求和响应报文的请求行/状态行及头部字段。
//! 支持的分隔符为 CRLF（`\r\n`）。
//!
//! 注意：HTTPS（TLS 加密的 HTTP）报文内容不可解析——TCP payload
//! 在 TLS 握手完成后全部为密文，仅 TLS 握手信息可通过其它模块提取。
//!
//! # 参考
//! - RFC 7230 §3 — HTTP/1.1 Message Format

use std::fmt;

/// HTTP 报文类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HTTPMessageKind {
    /// 请求报文。
    Request,
    /// 响应报文。
    Response,
}

/// 解析后的 HTTP/1.x 报文。
///
/// 同时适用于请求（METHOD URI VERSION）和响应（VERSION CODE REASON）。
pub struct HTTPMessage<'a> {
    /// 报文类型：请求或响应。
    pub kind: HTTPMessageKind,
    /// 请求方法（仅请求报文，如 "GET"、"POST"）。
    pub method: Option<String>,
    /// 请求 URI（仅请求报文，如 "/index.html"）。
    pub uri: Option<String>,
    /// HTTP 版本（如 "HTTP/1.1"）。
    pub version: String,
    /// 响应状态码（仅响应报文，如 200、404）。
    pub status_code: Option<u16>,
    /// 响应原因短语（仅响应报文，如 "OK"、"Not Found"）。
    pub reason: Option<String>,
    /// 头部字段列表（按原始顺序），每个元素为 (名称, 值)。
    pub headers: Vec<(String, String)>,
    /// 报文体在原始 payload 中的起始偏移量（`headers_end` 之后的位置）。
    pub body_offset: usize,
    /// 原始 payload 引用。
    pub raw: &'a [u8],
}

impl<'a> HTTPMessage<'a> {
    /// 从原始字节解析 HTTP/1.x 报文。
    ///
    /// 解析请求行/状态行及所有头部字段，记录报文体偏移量。
    ///
    /// # 错误
    ///
    /// 数据不足（无法找到完整第一行或头部结束标记）时返回错误。
    pub fn parse(raw: &'a [u8]) -> anyhow::Result<Self> {
        // 1. 找到第一行结束位置
        let first_line_end = find_crlf(raw, 0)
            .ok_or_else(|| anyhow::anyhow!("HTTP 报文第一行不完整"))?;

        let first_line = std::str::from_utf8(&raw[..first_line_end])
            .map_err(|_| anyhow::anyhow!("HTTP 第一行包含非法 UTF-8 字节"))?;

        // 2. 判断请求 vs 响应，解析第一行
        let (kind, method, uri, version, status_code, reason) = parse_first_line(first_line)?;

        // 3. 解析头部字段
        let mut offset = first_line_end + 2; // 跳过 CRLF
        let mut headers: Vec<(String, String)> = Vec::new();

        // HTTP/0.9：第一行之后直接结束，无头部、无空行终止符
        if offset >= raw.len() {
            return Ok(Self {
                kind,
                method,
                uri,
                version,
                status_code,
                reason,
                headers,
                body_offset: offset,
                raw,
            });
        }

        loop {
            if offset >= raw.len() {
                anyhow::bail!("HTTP 头部截断：未找到空行终止符");
            }

            // 检查是否遇到空行（CRLF）：头部结束
            if raw[offset] == b'\r' && offset + 1 < raw.len() && raw[offset + 1] == b'\n' {
                offset += 2; // 跳过 CRLF
                break;
            }

            let line_end = find_crlf(raw, offset)
                .ok_or_else(|| anyhow::anyhow!("HTTP 头部行截断（偏移量 {}）", offset))?;

            let header_line = std::str::from_utf8(&raw[offset..line_end])
                .map_err(|_| anyhow::anyhow!("HTTP 头部包含非法 UTF-8 字节（偏移量 {}）", offset))?;

            if let Some((name, value)) = parse_header_line(header_line) {
                headers.push((name, value));
            }
            // 空行或格式异常的行跳过

            offset = line_end + 2; // 跳过 CRLF
        }

        Ok(Self {
            kind,
            method,
            uri,
            version,
            status_code,
            reason,
            headers,
            body_offset: offset,
            raw,
        })
    }

    /// 按名称查找头部值（大小写不敏感），返回第一个匹配。
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }
}

impl fmt::Debug for HTTPMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HTTPMessage")
            .field("kind", &self.kind)
            .field("method", &self.method)
            .field("uri", &self.uri)
            .field("version", &self.version)
            .field("status_code", &self.status_code)
            .field("reason", &self.reason)
            .field("header_count", &self.headers.len())
            .field("body_offset", &self.body_offset)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// 内部辅助函数
// ============================================================================

/// 从 `start` 偏移量开始查找 CRLF（`\r\n`）。
///
/// 返回 CR 的偏移量，或 `None` 若找不到。
fn find_crlf(raw: &[u8], start: usize) -> Option<usize> {
    raw[start..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|pos| start + pos)
}

/// 解析 HTTP 第一行（请求行或状态行）。
///
/// - 请求行：`METHOD SP URI SP VERSION`
/// - 状态行：`VERSION SP CODE SP REASON`
fn parse_first_line(
    line: &str,
) -> anyhow::Result<(HTTPMessageKind, Option<String>, Option<String>, String, Option<u16>, Option<String>)> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();

    if parts.len() < 2 {
        anyhow::bail!("HTTP 第一行格式非法：'{}'", line);
    }

    if parts[0].starts_with("HTTP/") {
        // 响应：HTTP/1.1 200 OK
        let version = parts[0].to_string();
        let status_code: u16 = parts
            .get(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("HTTP 状态码非法：'{}'", parts.get(1).unwrap_or(&"")))?;
        let reason = parts.get(2).map(|s| s.to_string());

        Ok((
            HTTPMessageKind::Response,
            None,
            None,
            version,
            Some(status_code),
            reason,
        ))
    } else {
        // 请求：GET /index.html HTTP/1.1
        let method = parts[0].to_string();
        let uri = parts.get(1).map(|s| s.to_string());
        let version = parts
            .get(2)
            .map(|s| s.to_string())
            .unwrap_or_else(|| "HTTP/0.9".to_string());

        Ok((
            HTTPMessageKind::Request,
            Some(method),
            uri,
            version,
            None,
            None,
        ))
    }
}

/// 解析单行 HTTP 头部 `Name: Value`。
///
/// 返回 `(名称, 值)`，值去除前后空白。若格式非法（无冒号），返回 `None`。
fn parse_header_line(line: &str) -> Option<(String, String)> {
    let (name, value) = line.split_once(':')?;
    Some((name.trim().to_string(), value.trim().to_string()))
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个 HTTP 请求报文原始字节。
    fn make_http_request(method: &str, uri: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut raw = format!("{} {} HTTP/1.1\r\n", method, uri).into_bytes();
        for (k, v) in headers {
            raw.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(body);
        raw
    }

    /// 构造一个 HTTP 响应报文原始字节。
    fn make_http_response(code: u16, reason: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut raw = format!("HTTP/1.1 {} {}\r\n", code, reason).into_bytes();
        for (k, v) in headers {
            raw.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(body);
        raw
    }

    // -----------------------------------------------------------------------
    // 请求解析测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_simple_get() {
        let raw = make_http_request("GET", "/", &[("Host", "example.com")], b"");
        let msg = HTTPMessage::parse(&raw).unwrap();

        assert_eq!(msg.kind, HTTPMessageKind::Request);
        assert_eq!(msg.method.as_deref(), Some("GET"));
        assert_eq!(msg.uri.as_deref(), Some("/"));
        assert_eq!(msg.version, "HTTP/1.1");
        assert_eq!(msg.status_code, None);
        assert_eq!(msg.header("host"), Some("example.com"));
        assert_eq!(msg.headers.len(), 1);
        assert_eq!(msg.body_offset, raw.len()); // body 为空
    }

    #[test]
    fn test_parse_post_with_body() {
        let body = b"name=value&key=123";
        let raw = make_http_request(
            "POST",
            "/api/submit",
            &[
                ("Host", "api.example.com"),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Content-Length", "18"),
            ],
            body,
        );
        let msg = HTTPMessage::parse(&raw).unwrap();

        assert_eq!(msg.method.as_deref(), Some("POST"));
        assert_eq!(msg.uri.as_deref(), Some("/api/submit"));
        assert_eq!(msg.headers.len(), 3);
        assert_eq!(
            msg.header("Content-Type"),
            Some("application/x-www-form-urlencoded")
        );

        // body_offset 应指向 body 起始位置
        assert!(msg.body_offset < raw.len());
        assert_eq!(&raw[msg.body_offset..], body);
    }

    #[test]
    fn test_parse_http09() {
        // HTTP/0.9 只有 GET 行，无版本号和头部
        let raw = b"GET /\r\n";
        let msg = HTTPMessage::parse(raw).unwrap();
        assert_eq!(msg.kind, HTTPMessageKind::Request);
        assert_eq!(msg.method.as_deref(), Some("GET"));
        assert_eq!(msg.version, "HTTP/0.9"); // 默认版本
    }

    // -----------------------------------------------------------------------
    // 响应解析测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_simple_response() {
        let raw = make_http_response(200, "OK", &[("Server", "nginx")], b"");
        let msg = HTTPMessage::parse(&raw).unwrap();

        assert_eq!(msg.kind, HTTPMessageKind::Response);
        assert_eq!(msg.status_code, Some(200));
        assert_eq!(msg.reason.as_deref(), Some("OK"));
        assert_eq!(msg.version, "HTTP/1.1");
        assert_eq!(msg.method, None);
        assert_eq!(msg.uri, None);
        assert_eq!(msg.header("Server"), Some("nginx"));
    }

    #[test]
    fn test_parse_404_response() {
        let raw = make_http_response(404, "Not Found", &[], b"<html>...</html>");
        let msg = HTTPMessage::parse(&raw).unwrap();

        assert_eq!(msg.status_code, Some(404));
        assert_eq!(msg.reason.as_deref(), Some("Not Found"));
        assert_eq!(&raw[msg.body_offset..], b"<html>...</html>");
    }

    // -----------------------------------------------------------------------
    // 错误处理测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_empty_input() {
        assert!(HTTPMessage::parse(b"").is_err());
    }

    #[test]
    fn test_parse_truncated() {
        let raw = b"GET / HTT"; // 不完整的行，没有 CRLF
        assert!(HTTPMessage::parse(raw).is_err());
    }

    #[test]
    fn test_parse_no_crlf_in_headers() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com"; // 头部后面没有 CRLF+CRLF
        assert!(HTTPMessage::parse(raw).is_err());
    }
}