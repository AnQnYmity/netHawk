# Changelog

所有对本项目的重要更改都将记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [0.1.0] — 2026-05-31

### Added
- 初始化 Cargo 项目骨架，配置 `Cargo.toml` 依赖项
- 搭建 CLI 入口（`clap` derive），定义三个子命令：
  - `nethawk capture`：实时数据包捕获
  - `nethawk analyze`：离线 pcap 文件分析
  - `nethawk stats`：流量统计摘要
- 接入 `tracing` + `tracing-subscriber` 日志系统
  - `-v` → DEBUG，`-vv` → TRACE
  - 支持 `RUST_LOG` 环境变量覆盖
- 为每个子命令添加 `validate()` 参数校验方法
  - 快照长度范围检查（1–65535）
  - 超时时间范围检查（1–3600000 ms）
  - pcap 文件扩展名校验
  - 互斥参数校验（stats 的 `-i`/`-f`）
- 编写 45 个单元测试（CLI 解析 + 参数校验 + run() 集成）
- 配置 GitHub Actions CI 流水线：fmt → clippy → test → release build
- 完整的 `///` 文档注释（100% 公开项覆盖）
- 编写 `CONTRIBUTING.md` 贡献指南

## [0.1.1] — 2026-06-01

### Added
- 正式引入 `pcap` 库，修改了 `Cargo.toml`，build success
- 新创建了 `capture.rs`，定义结构体 `CaptureEngine` 并实现方法 `new()`、`run()`
- `CaptureArgs::run()` 委托给 `CaptureEngine`，cli.rs 不再直接持有 pcap 逻辑
- 支持 BPF 过滤器（`-f`）、包数上限（`-c`）、混杂模式
- 正式启动了抓包循环流程，现在可以在终端看到每个数据包的字节数输出
- 更新 `README.md`，新增系统依赖说明（需安装 `libpcap-dev`）

### Known Issues
- `CaptureEngine.output` 字段暂未使用，构建时有 dead_code warning，待阶段1 pcap 文件写入功能实现后消除

## [0.2.0] - 2026-06-02
- Stage 1 已经完成，可在指定网卡上实时抓包并写入 pcap 文件，Ctrl+C 后输出统计信息
- 引入了 `ctrlc` 库
- 修改了 `capture.rs` 的核心循环逻辑：现在循环会监听 `SIGINT` 信号
- 编写 1 个测试用例，修订 2 个原有测试用例

## [0.2.1] - 2026-06-03
- 进入 Stage 2，添加了对于 TCP, IP, 以太网帧的解析。部分字段尚不支持。
- 新建子模块 `protocol`，提供未来解析协议的支持。

### Known Issues
- 此版本尚不稳定，因为编译时会出现大量结构体为空的警告。

## [0.2.2] - 2026-06-05
- 添加了对于 DNS, HTTP 的解析，编写了其他头解析的单元测试。

### Known Issues
- 部分字段依旧没有加入。
- 结构体未被使用，会出现相关 warning.

## [0.2.3] - 2026-06-06
- 用 dispatch_from_ethernet / dispatch_from_ipv4 / dispatch_from_ipv6 替代嵌套 match 的 get_next_protocol，每条分发逻辑独立为一个函数
- 重写 print_packet 为顺序解析-逐层打印：ETH → IP → TCP/UDP 
- 新增 print_transport 和 format_tcp_flags 辅助函数 
- 修复协议号 17 映射为 TCP 的 bug（应为 UDP） 
- UDPSegment 补全字段与 parse() 方法 
- 抓包循环接入 print_packet，替代仅打印字节数的旧逻辑

### Known Issues
- ARP 暂不支持。

## [0.3.0] - 2026-06-21

### Added
- 完整协议解析栈：Ethernet / IPv4 / IPv6 / ARP / TCP / UDP / ICMP / HTTP/1.x / DNS / TLS / DHCP
- 802.1Q VLAN Tag 自动识别与跳过
- 实时数据包捕获引擎 `CaptureEngine`（非阻塞模式 + SIGINT 优雅退出）
- 离线分析引擎 `AnalyzeEngine`（pcap 文件加载、TLS/DHCP 深度检测）
- TCP 流跟踪与重组 `TcpStreamTracker`（五元组归一化、乱序容忍、HTTP 请求统计）
- 流量统计引擎 `StatEngine`（文件模式 + 实时模式，协议分布、Top N 会话）
- 三种输出格式：单行摘要 / 详细逐层展开 / JSON 行
- 彩色终端输出（ANSI 转义）
- 十六进制 raw dump 支持（`-H` / `--hex`）
- HTTP 请求/响应按 TCP 流导出（`--export`）
- CLI 参数校验（范围检查、互斥参数、扩展名验证）
- `proptest` 模糊测试（EthernetFrame / IPv4Packet / IPv6Packet）
- `docs/CLI.md`、`docs/ARCHITECTURE.md`、`docs/PROTOCOL.md` 完整文档

### Changed
- 协议路由分发函数（`dispatch_from_*`）统一到 `protocol/mod.rs`，消除跨模块重复
- `StatAccumulator::feed()` 拆分为 `feed_ipv4` / `feed_ipv6` / `feed_arp`，降低圈复杂度
- 错误处理统一使用 `anyhow::Result`（bin）和自定义错误类型（lib）

### Fixed
- `FiveTuple` 归一化：`new()` 实际比较字节序，修复方向一致性 bug
- `as i64` 跨平台类型转换保留，添加 `#[allow(clippy::unnecessary_cast)]` 说明
- 所有 `dead_code` 警告消除（协议预留字段/方法加 `#[allow(dead_code)]`）
- 修复协议号 17 映射为 TCP 的 bug（应为 UDP）
- UDPSegment 补全字段与 parse() 方法
- proptest 模糊测试下部分 payload 越界修复

### Known Issues
- 测试覆盖率 59.75%，IO 输出函数受 tarpaulin 插桩限制