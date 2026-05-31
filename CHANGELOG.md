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

[0.1.0]: https://github.com/your-org/nethawk/releases/tag/v0.1.0
