# netHawk 贡献指南

感谢你对 netHawk 的关注！本文档说明如何参与项目贡献。

## 行为准则

请保持友善、尊重和建设性的交流。我们致力于为所有人营造一个无骚扰的参与环境。

## 如何贡献

### 报告 Bug

1. 在 [Issues](../../issues) 中搜索，确认 Bug 未被报告
2. 使用 Bug Report 模板创建 Issue
3. 包含以下信息：
   - Rust 版本（`rustc --version`）
   - Linux 内核版本（`uname -r`）
   - 重现步骤
   - 预期行为 vs 实际行为
   - 相关日志（使用 `-vv` 运行）

### 提交代码

1. **Fork** 本仓库
2. 从 `main` 创建功能分支：`feat/<name>` 或 `fix/<name>`
3. 编写代码和测试
4. 确保本地通过所有检查：
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```
5. 提交代码（遵循 [Conventional Commits](https://www.conventionalcommits.org/)）：
   ```
   feat: 添加 HTTP/2 头部解析
   fix: 修复 VLAN tag 解析越界
   docs: 更新 capture 子命令文档
   ```
6. 推送并创建 Pull Request 到 `main` 分支

### PR 审查要求

- CI 全部绿灯（fmt、clippy、test、release build）
- 至少一位维护者 Code Review 通过
- 核心解析逻辑必须包含单元测试
- 如有性能影响，需附基准测试数据

## 开发环境

### 前置条件

- Rust 1.70+（推荐使用 [rustup](https://rustup.rs/)）
- Linux 系统（需要 `libpcap` 开发头文件）

### 安装依赖

```bash
# Debian/Ubuntu
sudo apt install libpcap-dev

# Fedora
sudo dnf install libpcap-devel
```

### 构建与运行

```bash
# Debug 构建
cargo build

# Release 构建
cargo build --release

# 运行测试
cargo test

# 查看帮助
cargo run -- --help
```

## 项目结构

```
netHawk/
├── .github/workflows/   # CI/CD 配置
├── src/
│   ├── main.rs          # 入口 + 日志初始化
│   ├── cli.rs           # clap CLI 定义与子命令
|   └── capture.rs       # 抓包引擎
├── Cargo.toml           # 项目元数据与依赖
├── PROJECT_PLAN.md      # 项目推进方案
└── CONTRIBUTING.md      # 本文件
```

## 开发阶段

当前项目处于 **阶段 2**：协议解析框架。后续阶段参见 [PROJECT_PLAN.md](PROJECT_PLAN.md)。

## 获取帮助

如有问题，请在 Issues 中提出，或通过 Discussion 讨论。
