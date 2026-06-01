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

use pcap::Capture;
use crate::cli::CaptureArgs;

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
            .promisc(true)                  // 混杂模式
            .snaplen(args.snaplen)          // 快照长度
            .timeout(args.timeout)          // 超时ms
            .open()?;
        // 启用 BPF 过滤器
        if let Some(ref f) = args.filter {
            cap.filter(f, true)?;
        }
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
        // 抓包循环
        while let Ok(packet) = self.cap.next_packet() {
            println!("新抓取了 {} 字节", packet.data.len());
            captured += 1;
            if captured >= self.limit { break; }
        }
        Ok(())
    }
}