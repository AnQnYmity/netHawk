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

**示例：**

```bash
# 在 eth0 上捕获 100 个包，仅 TCP 80 端口
nethawk capture -i eth0 -c 100 -f "tcp port 80"

# 捕获所有接口的包并写入文件
nethawk capture -w capture.pcap
```

### `nethawk analyze` — 离线 pcap 分析

分析 pcap/pcapng 文件中的网络数据包。

```
nethawk analyze [OPTIONS] <FILE>
```

**选项：**

| 选项 | 说明 |
|------|------|
| `-V, --verbose-output` | 显示详细协议字段 |

**参数：**

- `FILE`：pcap 或 pcapng 文件路径（必填）

**示例：**

```bash
nethawk analyze capture.pcap -V
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

## 开发阶段

当前为 **阶段 0**：项目骨架。subcommand 实际功能正在开发中。
