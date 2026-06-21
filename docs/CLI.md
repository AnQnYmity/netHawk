# netHawk CLI 使用文档

## 概述

netHawk 是一个基于 Rust 的 Linux 原生网络数据包捕获与协议分析工具，提供三个子命令。

## 全局选项

| 选项 | 说明 |
|------|------|
| `-v` | DEBUG 日志级别 |
| `-vv` | TRACE 日志级别 |
| `-h, --help` | 打印帮助信息 |
| `-V, --version` | 打印版本号 |

日志默认级别为 INFO。可设置 `RUST_LOG` 环境变量覆盖。

## 子命令

### `nethawk capture` — 实时数据包捕获

从网卡实时抓取网络数据包。

```
nethawk capture [OPTIONS]
```

**选项：**

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-i, --interface` | `any` | 网络接口名称 |
| `-c, --count` | 不限 | 捕获包数上限 |
| `-f, --filter` | 无 | BPF 过滤器（如 `"tcp port 80"`） |
| `-w, --write` | 无 | 输出 pcap 文件路径 |
| `-s, --snaplen` | `65535` | 快照长度（1–65535 字节） |
| `-t, --timeout` | `1000` | 超时时间（1–3600000 毫秒） |
| `-V, --verbose-output` | — | 展开所有协议字段（详细模式） |
| `-H, --hex` | — | 附带十六进制 raw dump |
| `-j, --json` | — | JSON 格式输出（需 `--features json` 编译） |

**示例：**

```bash
# 在 eth0 上捕获 100 个包，仅 TCP 80 端口
sudo nethawk capture -i eth0 -c 100 -f "tcp port 80"

# 捕获所有接口的包并写入文件
sudo nethawk capture -w capture.pcap

# 详细输出 + 十六进制 dump
sudo nethawk capture -i eth0 -V -H

# JSON 格式输出，管道消费
sudo nethawk capture -i eth0 -j | jq '.src_ip'
```

### `nethawk analyze` — 离线 pcap 分析

分析 pcap/pcapng 文件中的网络数据包。

```
nethawk analyze [OPTIONS] <FILE>
```

**选项：**

| 选项 | 说明 |
|------|------|
| `-V, --verbose-output` | 展开所有协议字段（详细模式） |
| `-H, --hex` | 附带十六进制 raw dump |
| `-j, --json` | JSON 格式输出（需 `--features json` 编译） |
| `-F, --follow-http` | 跟踪所有 TCP 流并统计 HTTP 请求数 |
| `--tls` | 提取 TLS ClientHello（SNI、加密套件） |
| `--dhcp` | 提取 DHCP 报文（消息类型、分配 IP） |
| `--export` | 按 TCP 流导出 HTTP 请求/响应到文件 |

> 默认模式、`--follow-http`、`--tls`、`--dhcp` 四者互斥，同时只能启用一个。

**参数：**

- `FILE`：pcap 或 pcapng 文件路径（必填）

**示例：**

```bash
# 默认摘要模式
nethawk analyze capture.pcap

# 详细逐包展开
nethawk analyze capture.pcap -V

# 审计 HTTPS 访问域名
nethawk analyze capture.pcap --tls

# 跟踪 HTTP 流量并显示 TCP 流详情
nethawk analyze capture.pcap -F -V

# 导出 HTTP 内容文件
nethawk analyze capture.pcap --export
```

### `nethawk stats` — 流量统计摘要

实时或离线的流量统计。

```
nethawk stats [OPTIONS] --interface <INTERFACE>
nethawk stats [OPTIONS] --file <FILE>
```

**选项：**

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `-i, --interface` | 无 | 网络接口（与 `-f` 互斥） |
| `-f, --file` | 无 | pcap 文件（与 `-i` 互斥） |
| `-n, --top` | `10` | Top N 会话数（1–1000） |
| `-I, --interval` | `1` | 统计间隔秒数（1–3600） |

**示例：**

```bash
# 实时统计 eth0 的 Top 20 会话，5 秒间隔
nethawk stats -i eth0 -n 20 -I 5

# 离线统计 pcap 文件
nethawk stats -f capture.pcap
```

## 当前版本

v0.3.0 — 核心功能完整：实时抓包、离线分析、流量统计、协议深度解析（Ethernet / IPv4 / IPv6 / ARP / TCP / UDP / ICMP / HTTP / DNS / TLS / DHCP）、TCP 流跟踪与 HTTP 导出。
