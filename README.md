# netHawk

[![CI](https://github.com/AnQnYmity/netHawk/actions/workflows/ci.yml/badge.svg)](https://github.com/AnQnYmity/netHawk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

基于 Rust 的 Linux 原生网络数据包捕获与多层协议分析工具。对标 tcpdump 的能力 + Wireshark 的解析深度，纯命令行操作。

## 功能

- **实时抓包**：非阻塞模式，支持 BPF 过滤、包数限制、pcap 文件导出
- **离线分析**：加载 pcap/pcapng 文件，逐包分层解析
- **流量统计**：协议分布、Top N 会话排行、实时/离线双模式
- **协议深度解析**：Ethernet → IP → TCP/UDP → HTTP/DNS/TLS/DHCP
- **多格式输出**：单行摘要 / 详细逐层展开 / JSON / 十六进制 dump
- **TCP 流跟踪**：五元组归一化、乱序重组、HTTP 请求统计与导出
- **TLS 审计**：ClientHello SNI 提取、加密套件枚举

## 系统依赖

```bash
# Debian / Ubuntu
sudo apt install libpcap-dev

# Fedora / RHEL
sudo dnf install libpcap-devel

# Arch Linux
sudo pacman -S libpcap
```

## 构建

```bash
cargo build --release

# 可选：启用 JSON 输出
cargo build --release --features json
```

## 快速开始

### 实时抓包

```bash
# 抓取 eth0 上所有包
sudo nethawk capture -i eth0

# 抓 100 个 HTTP 包并保存
sudo nethawk capture -i eth0 -c 100 -f "tcp port 80" -w dump.pcap

# 详细展开 + 十六进制 dump
sudo nethawk capture -i eth0 -V -H

# JSON 输出，管道消费
sudo nethawk capture -i eth0 -j | jq '.src_ip'
```

### 离线分析

```bash
# 默认摘要模式
nethawk analyze dump.pcap

# 详细逐包展开
nethawk analyze dump.pcap -V

# 审计 HTTPS 访问域名
nethawk analyze dump.pcap --tls

# 跟踪 HTTP 流量
nethawk analyze dump.pcap --follow-http -V

# 导出 HTTP 请求/响应体
nethawk analyze dump.pcap --export
```

### 流量统计

```bash
# 实时 Top 20 会话，5 秒刷新
sudo nethawk stats -i eth0 -n 20 -I 5

# 离线统计 pcap 文件
nethawk stats -f dump.pcap
```

## 支持的协议

| 层级 | 协议 |
|------|------|
| L2 | Ethernet II, 802.1Q VLAN |
| L3 | IPv4, IPv6, ARP |
| L4 | TCP, UDP, ICMP, ICMPv6 |
| L7 | HTTP/1.x, DNS, TLS (ClientHello), DHCP |

## 项目结构

```
src/
├── main.rs          # 入口 + 日志初始化
├── lib.rs           # 库 crate 根
├── cli.rs           # CLI 定义 (clap derive)
├── capture.rs       # 实时捕获引擎
├── analyse.rs       # 离线分析引擎
├── status.rs        # 流量统计引擎
├── printer.rs       # 输出格式化
├── tcp_stream.rs    # TCP 流跟踪
└── protocol/        # 分层协议解析器
    ├── ethernet.rs  # Ethernet / VLAN
    ├── arp.rs       # ARP
    ├── ip.rs        # IPv4 / IPv6
    ├── tcp.rs       # TCP
    ├── udp.rs       # UDP
    ├── icmp.rs      # ICMP
    ├── http.rs      # HTTP/1.x
    ├── dns.rs       # DNS
    ├── dhcp.rs      # DHCP
    └── tls.rs       # TLS ClientHello
```

## 开发

```bash
# 运行测试
cargo test

# 代码检查
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

# 测试覆盖率
cargo tarpaulin --lib
```

详见 [CONTRIBUTING.md](CONTRIBUTING.md) 和 [docs/](docs/)。

## 文档

- [CLI 使用文档](docs/CLI.md) — 完整命令参考
- [架构设计](docs/ARCHITECTURE.md) — 模块总览与数据流
- [协议解析说明](docs/PROTOCOL.md) — 支持的协议与解析链
- [更新日志](CHANGELOG.md)

## 许可

MIT — 详见 [LICENSE](LICENSE)
