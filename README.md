# netHawk
一个基于 Rust 语言实现的、面向 Linux 系统的原生网络数据包捕获与多层协议分析工具。

## 系统依赖

在构建前，需要先安装 `libpcap` 开发库：

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
```

## 用法

```bash
# 实时抓包（需要 root 权限）
sudo ./target/release/nethawk capture -i eth0

# 抓取 100 个包，使用 BPF 过滤器
sudo ./target/release/nethawk capture -i eth0 -c 100 -f "tcp port 80"

# 离线分析 pcap 文件
./target/release/nethawk analyze capture.pcap

# 流量统计
sudo ./target/release/nethawk stats -i eth0
```
