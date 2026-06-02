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
use pcap::Capture;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

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
        // 启用上限抓包计数
        let limit = args.count.unwrap_or(u64::MAX);
        Ok(Self {
            cap,
            limit,
            output: args.output.clone(),
        })
    }

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
            match self.cap.next_packet() {
                Ok(packet) => {
                    println!("新抓取了 {} 字节", packet.data.len());

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
                    // 非阻塞模式下无包可读，短暂休眠避免 CPU 空转，然后回头检查 running
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                Err(_) => break, // 真实错误，退出
            }
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
        };
        assert!(CaptureEngine::new(&args).is_err());
    }
}
