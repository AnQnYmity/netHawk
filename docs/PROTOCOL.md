# 协议解析说明

netHawk 支持从链路层到应用层的逐层协议解析，采用零拷贝设计。

## 解析链

```
原始字节
  → EthernetFrame (L2)         MAC 地址、EtherType、VLAN
    → ARPPacket                ARP 请求/响应
    → IPv4Packet / IPv6Packet   (L3) IP 地址、TTL、协议号
      → ICMPPacket             ICMP type/code、Echo 标识
      → TCPSegment             (L4) 端口、seq、flags
        → HTTPMessage          (L7) 方法/状态码/头部
        → TlsClientHello       SNI、加密套件
      → UDPSegment             (L4) 端口、长度
        → DNSRequest           查询域名、类型
        → DhcpPacket           消息类型、分配 IP
```

## 支持协议

### L2 链路层

| 协议 | EtherType | 解析字段 |
|------|-----------|---------|
| Ethernet II | — | dst_mac, src_mac, ethernet_type |
| 802.1Q VLAN | 0x8100 | pcp, dei, vid（自动跳过 4 字节 tag） |

### L3 网络层

| 协议 | EtherType / NH | 解析字段 |
|------|---------------|---------|
| IPv4 | 0x0800 | ttl, protocol, src_ip, dst_ip |
| IPv6 | 0x86DD | next_header, hop_limit, src_ip, dst_ip |
| ARP | 0x0806 | operation, sender/target IP/MAC |

### L4 传输层

| 协议 | 协议号 | 解析字段 |
|------|--------|---------|
| TCP | 6 | src_port, dst_port, seq, ack, flags |
| UDP | 17 | src_port, dst_port, len |
| ICMP | 1 | icmp_type, code, checksum, identifier, sequence |
| ICMPv6 | 58 | 同上 |

### L7 应用层

| 协议 | 传输层 | 解析字段 |
|------|--------|---------|
| HTTP/1.x | TCP | method, uri, version, status, headers |
| DNS | UDP 53 | transaction_id, queries (qname, qtype) |
| DHCP | UDP 67/68 | op, xid, message_type, yiaddr, options |
| TLS | TCP 443 | record_version, client_version, sni, cipher_suites, alpn |

## 错误处理

所有解析器对畸形输入不 panic，返回 `Err` 或 `None`：

```rust
// 解析失败 → 跳过该包，继续下一个
let eth = match EthernetFrame::parse(packet.data) {
    Ok(e) => e,
    Err(_) => continue,
};
```

## 添加新协议

1. 在 `src/protocol/` 下创建 `newproto.rs`
2. 实现 `parse(raw: &[u8]) -> Result<Self>` 
3. 在 `protocol/mod.rs` 中 `pub mod newproto` + `pub use`
4. 在 `dispatch_from_*` 中添加路由规则
5. 在 `printer.rs` 的 `print_packet` 中添加打印逻辑
