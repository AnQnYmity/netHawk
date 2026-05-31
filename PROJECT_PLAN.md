# netHawk 项目推进方案

## 1. 项目概述

netHawk 是一个基于 Rust 语言实现的、面向 Linux 系统的原生网络数据包捕获与多层协议分析工具。目标是为 Linux 平台提供高性能、低资源占用的命令行网络诊断与分析能力，覆盖从链路层到应用层的协议栈解析。

**核心原则：**
- 性能优先：利用 Rust 的零成本抽象和 `async`/零拷贝设计，最小化 CPU 与内存开销
- 稳定可靠：通过 Rust 类型系统和 clippy 静态分析工具在编译期消除内存安全类 Bug
- 跨协议覆盖：从原始帧逐步解析到应用层负载，支持常见协议族（TCP/IP、UDP、HTTP、DNS、TLS 等）
- 开发者友好：清晰的模块边界、完善的文档和测试，降低社区贡献门槛

---

## 2. 技术选型与依赖

| 层级 | 关键技术 / crate | 用途 |
|------|------------------|------|
| 数据包捕获 | `pcap` / `libc` + raw socket | Linux 原生抓包，支持 BPF 过滤 |
| 链路层解析 | 自定义 parser | Ethernet II、802.1Q VLAN |
| 网络层解析 | `etherparse` / 自定义 parser | IPv4、IPv6、ARP、ICMP |
| 传输层解析 | 自定义 parser | TCP、UDP、ICMP |
| 应用层解析 | 自定义 parser | HTTP/1.x、DNS、TLS ClientHello |
| 异步运行时 | `tokio` | 多通道并发处理，异步 I/O |
| CLI 框架 | `clap` | 命令行参数解析与子命令 |
| 日志 | `tracing` / `env_logger` | 分级日志，调试与发布 |
| 测试与基准 | `criterion` / `proptest` | 性能基准与属性测试 |
| 序列化输出 | `serde` + `serde_json` | JSON / 结构化输出，便于管道消费 |

---

如果有额外时间与精力，将考虑原生代码代替pcap第三方库的实现。

## 3. 阶段规划

### 阶段 0：项目骨架搭建

**目标：** 可编译、可运行的空壳 CLI 工具。

- [ ] 初始化 Cargo 项目，配置 `Cargo.toml` 基础元数据与依赖项
- [ ] 搭建 CLI 入口，使用 `clap` 定义子命令框架：
  - `nethawk capture` — 实时抓包
  - `nethawk analyze` — 离线分析（pcap 文件）
  - `nethawk stats`  — 流量统计摘要
- [ ] 接入 `tracing` 日志系统，支持 `-v`/`-vv` 分级输出
- [ ] 配置 CI（GitHub Actions）：`cargo fmt`、`cargo clippy`、`cargo test`
- [ ] 编写 `CONTRIBUTING.md` 贡献指南

**验收标准：** `nethawk --help` 输出子命令列表，`cargo build --release` 成功。

---

### 阶段 1：核心捕获引擎

**目标：** 从网卡实时捕获原始链路层帧，支持 BPF 过滤与 pcap 文件输出。

- [ ] 封装 `pcap` crate，实现 `CaptureEngine`：
  - 网卡列表与选择（`nethawk capture -i eth0`）
  - 混杂模式开关
  - 数据包计数限制（`-c N`）
  - 超时与快照长度配置
- [ ] BPF 过滤器编译与应用（如 `tcp port 80`）
- [ ] pcap 文件写入器（保存为标准 `.pcap` 格式）
- [ ] 信号处理：`SIGINT`（Ctrl+C）后优雅关闭，输出捕获统计摘要
- [ ] 单元测试 + 集成测试（使用预录 pcap 样本）

**验收标准：** 可在指定网卡上实时抓包并写入 pcap 文件，Ctrl+C 后输出统计信息。

---

### 阶段 2：协议解析框架

**目标：** 构建可扩展的分层协议解析器栈，从链路层逐步解包至应用层。

- [ ] 定义核心 trait：`ProtocolLayer`、`PacketParser`、`ParseResult`
- [ ] 链路层解析器：
  - Ethernet II 帧头（DMAC、SMAC、EtherType）
  - 802.1Q VLAN Tag 识别
- [ ] 网络层解析器：
  - IPv4 头解析（版本、长度、TTL、协议号、源/目的 IP、分片标记）
  - IPv6 基本头 + 扩展头链
  - ARP 请求/响应
- [ ] 传输层解析器：
  - TCP 头（端口、序号、确认号、标志位、窗口）
  - UDP 头（端口、长度、校验和）
- [ ] 应用层解析器（v0.1 覆盖）：
  - HTTP/1.x 请求行/状态行 + 头部字段
  - DNS 查询/响应基本字段
- [ ] 错误处理策略：畸形包跳过 + 告警，不 panic
- [ ] 使用 `proptest` 对解析器进行模糊测试

**验收标准：** 解析已知 pcap 文件，输出各层协议字段到终端，对畸形包不崩溃。

---

### 阶段 3：实时展示与交互

**目标：** 用户可在终端实时查看数据包解析结果，支持过滤和格式化。

- [ ] `nethawk capture` 实时模式：
  - 默认表格视图（摘要行：时间戳、源/目的 IP、协议、长度、Info）
  - 详细视图（`--verbose`）：逐层展开所有字段
  - 十六进制 dump（`--hex`）
- [ ] 输出格式支持：
  - 人类可读文本（默认）
  - JSON 行（`--json`），适合 `jq` 或脚本消费
  - 彩色终端输出（ANSI 转义）
- [ ] 实时过滤：`--filter "http.request or dns"`
- [ ] 统计模式：`nethawk stats`：
  - 按协议分布的包数/字节数
  - Top N 会话（源 IP + 目的 IP + 端口）
  - 流速（pps、bps）

**验收标准：** 实时抓包时终端展示清晰可读的数据包信息，JSON 输出可通过管道正确消费。

---

### 阶段 4：离线分析与扩展

**目标：** 支持 pcap 文件离线深度分析，扩展应用层解析能力。

- [ ] `nethawk analyze` 离线分析：
  - 加载 pcap/pcapng 文件
  - 会话重组（TCP 流跟踪）
  - HTTP 请求/响应对匹配
- [ ] 扩展应用层协议：
  - TLS/SSL ClientHello 解析（SNI、支持的密码套件）
  - DHCP 请求/确认
  - ICMP 类型与代码解读
- [ ] 导出功能：
  - 按流导出 HTTP 请求/响应体
  - 按过滤器导出数据包子集为 pcap
- [ ] 性能基准测试：
  - 百万包解析吞吐量（pps）
  - 内存占用分析（`heaptrack` / `valgrind-massif`）

**验收标准：** 可加载 pcap 文件进行离线深度分析，导出指定流内容。

---

### 阶段 5：文档、发布与社区建设

**目标：** 项目达到可公开发布的质量标准。

- [ ] 编写完整用户文档：
  - `docs/` 目录下 Markdown 文档
  - 各子命令用法示例
  - 常见抓包场景（排查 HTTP 延迟、DNS 故障等）
- [ ] API 文档：`cargo doc` 发布到 GitHub Pages
- [ ] 打包发布：
  - Prebuilt 二进制（x86_64-unknown-linux-musl 静态链接）
  - `cargo install nethawk` 支持
- [ ] 建立 Issue 模板和 PR 模板
- [ ] 撰写设计文档，记录架构决策（ADR）

---

## 4. 项目里程碑时间线（截止到今天）

```
Day  1  阶段 0：骨架搭建

```

总计约 **20天**。

---

## 5. 开发规范

- **提交规范：** 遵循 [Conventional Commits](https://www.conventionalcommits.org/)（`feat:`、`fix:`、`docs:` 等）
- **测试要求：** 核心解析逻辑必须覆盖单元测试；每个阶段结束时跑集成测试

---

## 6. 风险与对策

| 风险 | 影响 | 对策 |
|------|------|------|
| `pcap` crate 对原始套接字的封装不满足需求 | 捕获引擎受阻 | 降级使用 `libc` + raw socket 自行封装 |
| 协议解析组合爆炸 | 阶段 2 工期膨胀 | 先覆盖最常用协议（TCP/UDP/HTTP/DNS），其余标记为社区扩展 |
| Linux 内核版本差异导致行为不一致 | 测试覆盖不足 | 在多个内核版本（LTS）的 CI 矩阵中运行集成测试 |
| 项目维护者精力有限 | 长期停滞 | 早期建立清晰的贡献文档，欢迎社区 PR |
