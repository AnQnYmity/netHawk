# netHawk 架构设计

## 模块总览

```
src/
├── main.rs         # 入口点：日志初始化、子命令路由
├── lib.rs          # 库 crate 根：pub mod 声明
├── cli.rs          # CLI 定义（clap derive）与参数校验
├── capture.rs      # 实时捕获引擎（pcap Active 模式）
├── analyse.rs      # 离线分析引擎（pcap Offline 模式）
├── status.rs       # 流量统计引擎（实时 + 文件双模式）
├── printer.rs      # 输出格式化（单行/详细/JSON/hexdump）
├── tcp_stream.rs   # TCP 流跟踪与重组
└── protocol/       # 分层协议解析器
    ├── mod.rs      # ParseResult 枚举 + dispatch 路由函数
    ├── ethernet.rs # Ethernet II / 802.1Q
    ├── arp.rs      # ARP
    ├── ip.rs       # IPv4 / IPv6
    ├── tcp.rs      # TCP
    ├── udp.rs      # UDP
    ├── icmp.rs     # ICMP / ICMPv6
    ├── http.rs     # HTTP/1.x
    ├── dns.rs      # DNS
    ├── dhcp.rs     # DHCP
    └── tls.rs      # TLS ClientHello
```

## 数据流

```
网卡 / pcap 文件
    │
    ▼
┌──────────────┐     ┌──────────┐
│ CaptureEngine │     │ AnalyseEngine │
│ (实时)       │     │ (离线)        │
└──────┬───────┘     └──────┬───────┘
       │                    │
       └────────┬───────────┘
                │ pcap::Packet
                ▼
┌──────────────────────────────┐
│      protocol 解析链         │
│  EthernetFrame               │
│    → dispatch_from_ethernet  │
│      → IPv4/IPv6/ARP         │
│        → dispatch_from_ipv*  │
│          → TCP/UDP/ICMP      │
│            → HTTP/DNS/DHCP   │
└──────────────────────────────┘
                │
                ▼
┌──────────────────────────────┐
│        printer / 统计        │
│  print_one_liner (摘要)      │
│  print_packet    (详细)      │
│  print_json      (JSON)      │
│  hexdump         (十六进制)  │
│  StatAccumulator (统计累加)  │
└──────────────────────────────┘
```

## 设计原则

### 协议解析：零拷贝 + 分层
- 所有解析器接受 `&[u8]` 引用，不复制数据
- 每层解析后通过 `dispatch_*` 路由到下一层
- `ParseResult` 枚举统一封装各层结果

### 引擎：薄壳模式
- `CaptureEngine` / `AnalyzeEngine` 只负责数据获取和流程控制
- 解析和输出委托给 `protocol` 和 `printer`
- `StatEngine` 额外维护 `StatAccumulator` 进行聚合

### 错误处理：分层策略
- **bin crate（应用层）**：`anyhow::Result` 快速聚合
- **lib crate（协议层）**：具体错误类型，调用方可 match 处理
- **不可恢复**：`panic!` 仅用于逻辑断言，不用于用户输入错误

## 测试策略

| 层级 | 类型 | 位置 | 说明 |
|------|------|------|------|
| 单元测试 | `#[test]` | `src/*.rs` 内 `mod tests` | 函数级逻辑验证 |
| 协议模糊测试 | `proptest` | `src/protocol/*.rs` | 随机字节输入不 panic |
| 集成测试 | `#[test]` | `tests/` | CLI 端到端、多模块协作 |

## 性能关键路径

- **非阻塞抓包**：`setnonblock()` + 50ms 休眠，避免 CPU 空转
- **零拷贝解析**：`&[u8]` 引用传递，无 `Vec::clone()`
- **TCP 流重组**：按 seq 号插入，处理乱序和重叠
- **release profile**：`lto = true`、`codegen-units = 1`、`strip = true`
