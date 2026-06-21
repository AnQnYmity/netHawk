//! 捕获引擎模块
//!
//! 封装 pcap 数据包捕获逻辑，提供 [`CaptureEngine`] 结构体和相关方法
//!
//! # 用法
//!
//! ```no run
//! let mut engine = CaptureEngine::new(&args);
//! engine.run()?;
//! ```

use crate::cli::CaptureArgs;
#[cfg(feature = "json")]
use crate::printer::print_json;
#[allow(unused_imports)]
use crate::printer::{hexdump, print_one_liner, print_packet};

use pcap::Capture;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// 网络数据包捕获引擎
///
/// 封装 pcap 会话的创建、BPF 过滤器设置和抓包循环
pub struct CaptureEngine {
    /// 当前 pcap 会话的捕获套接字。
    cap: pcap::Capture<pcap::Active>,

    /// 设置最大抓包上限。
    limit: u64,

    /// 指定输出路径。
    output: Option<String>,

    /// 详细输出模式。
    verbose: bool,

    /// 十六进制生数据。
    dump: bool,

    /// JSON 输出模式。
    #[cfg_attr(not(feature = "json"), allow(dead_code))]
    json: bool,

    /// Linux cooked capture (SLL) 模式下需跳过的头部字节数（0 表示以太网帧）。
    strip_header: usize,
}

impl CaptureEngine {
    /// 创建捕获引擎并初始化 pcap 会话。
    ///
    /// # 错误
    ///
    /// 网卡不存在或者权限不足时返回错误。
    pub fn new(args: &CaptureArgs) -> anyhow::Result<Self> {
        let mut cap = Capture::from_device(args.interface.as_str())?
            .promisc(true) // 混杂模式
            .snaplen(args.snaplen) // 快照长度
            .timeout(args.timeout) // 超时ms
            .open()?;
        // 启用 BPF 过滤器
        if let Some(ref f) = args.filter {
            cap.filter(f, true)?;
        }
        // 非阻塞模式：setnonblock 消耗 cap 并返回新的 cap，需在局部变量阶段调用
        let cap = cap.setnonblock()?;

        // 检测链路层类型：Linux 上 pcap 默认使用 cooked capture (SLL)，需剥离 16 字节头
        let datalink = cap.get_datalink();
        let link_name = datalink.get_name().unwrap_or_else(|_| "???".to_string());
        let strip_header = if link_name.contains("SLL") || link_name.contains("LINUX_SLL") {
            16
        } else {
            0 // 以太网帧 (EN10MB) 或其他，无需剥离
        };
        eprintln!("  链路层: {link_name} (剥离 {strip_header} 字节)");

        // 启用上限抓包计数
        let limit = args.count.unwrap_or(u64::MAX);
        Ok(Self {
            cap,
            limit,
            output: args.output.clone(),
            verbose: args.show_details,
            dump: args.hex,
            json: args.json,
            strip_header,
        })
    }

    /// 运行实时抓包循环。
    ///
    /// 非阻塞模式 + SIGINT 信号处理，逐包解析并输出（支持详细/hex/JSON/
    /// pcap 写入），达到数量上限或 Ctrl+C 后退出。
    #[allow(clippy::unnecessary_cast)] // tv_sec/tv_usec 类型因平台而异
    pub fn run(&mut self) -> anyhow::Result<()> {
        // 计数当前已抓获包数
        let mut captured = 0;
        let mut byte = 0;
        // pcap 文件保存路径
        // .as_deref() 将 Option<String> 转为 Option<&str>
        let mut writer = if let Some(path) = self.output.as_deref() {
            // Option<Result<Savefile, Error>>
            Some(self.cap.savefile(path)?)
        } else {
            None
        };

        let running = Arc::new(AtomicBool::new(true));
        let r = Arc::clone(&running);
        // 设置 signal handler
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })?;

        // 抓包循环（非阻塞：无包时立即返回，每 50ms 检查一次 running）
        while running.load(Ordering::SeqCst) {
            let now = Instant::now();
            match self.cap.next_packet() {
                Ok(packet) => {
                    // 剥离非以太网链路层头（如 Linux SLL 的 16 字节）
                    let raw = if self.strip_header > 0 && packet.data.len() > self.strip_header {
                        &packet.data[self.strip_header..]
                    } else {
                        packet.data
                    };

                    // JSON 输出（需 json feature + --json 标志）
                    #[cfg(feature = "json")]
                    if self.json {
                        print_json(
                            raw,
                            packet.header.ts.tv_sec as i64,
                            packet.header.ts.tv_usec as i64,
                        );
                    }

                    // 文本输出（json 未请求时的 fallback）
                    #[cfg(feature = "json")]
                    if !self.json {
                        if self.verbose {
                            print_packet(raw);
                        } else {
                            print_one_liner(
                                raw,
                                packet.header.ts.tv_sec as i64,
                                packet.header.ts.tv_usec as i64,
                            );
                        }
                    }

                    // 文本输出（json feature 不可用）
                    #[cfg(not(feature = "json"))]
                    if self.verbose {
                        print_packet(raw);
                    } else {
                        print_one_liner(
                            raw,
                            packet.header.ts.tv_sec as i64,
                            packet.header.ts.tv_usec as i64,
                        );
                    }

                    // 如果需要将十六进制数据 dump 出来：
                    if self.dump {
                        hexdump(packet.data);
                    }

                    // .as_mut() 拿到 Option 中的可变引用，不将其 move 出来。
                    if let Some(w) = writer.as_mut() {
                        w.write(&packet);
                    }

                    captured += 1;
                    byte += packet.data.len();
                    if captured >= self.limit {
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => {
                    std::io::stdout().flush().ok();
                    // 非阻塞模式下无包可读，短暂休眠避免 CPU 空转，然后回头检查 running
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                Err(_) => break, // 真实错误，退出
            }
            println!("解析数据包耗时：{} μs。", now.elapsed().as_micros());
        }
        println!("共抓取了 {} 个数据包，{} 字节。", captured, byte);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CaptureArgs;

    /// 无效网卡名应返回 Err，而不是 panic。
    #[test]
    fn test_capture_engine_invalid_interface() {
        let args = CaptureArgs {
            interface: "nonexistent_iface_xyz".into(),
            count: Some(1),
            filter: None,
            output: None,
            snaplen: 65535,
            timeout: 1000,
            show_details: true,
            hex: false,
            json: false,
        };
        assert!(CaptureEngine::new(&args).is_err());
    }
}
