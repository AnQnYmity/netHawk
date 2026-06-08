//! CLI 定义与子命令模块
//!
//! 使用 clap derive 定义 nethawk 的命令行接口，包含三个子命令：
//!
//! - `capture`：实时数据包捕获
//! - `analyze`：离线 pcap 文件分析
//! - `stats`：流量统计摘要
//!
//! 每个子命令均提供参数校验方法，确保用户输入合法后再执行。

use crate::capture::CaptureEngine;
use clap::{Parser, Subcommand};

// ============================================================================
// 顶层 CLI
// ============================================================================

/// netHawk — 网络数据包捕获与多层协议分析工具。
///
/// 顶层 CLI 结构体，包含全局选项（如日志级别）和子命令路由。
#[derive(Parser, Debug)]
#[command(name = "nethawk")]
#[command(version, about, long_about = None)]
#[command(help_template = "\
{before-help}{name} {version}
{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
")]
pub struct Cli {
    /// 日志详细程度：`-v` 开启 DEBUG，`-vv` 开启 TRACE。
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// 子命令：capture / analyze / stats。
    #[command(subcommand)]
    pub command: Commands,
}

// ============================================================================
// 子命令枚举
// ============================================================================

/// netHawk 支持的三个子命令。
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// 实时数据包捕获。
    Capture(CaptureArgs),
    /// 离线分析 pcap/pcapng 文件。
    Analyze(AnalyzeArgs),
    /// 流量统计摘要。
    Stats(StatsArgs),
}

// ============================================================================
// 公共校验工具
// ============================================================================

/// 校验具有标签 `label` 的数值参数是否在合法区间内。
///
/// 返回 `Ok(())` 或包含错误描述的字符串。
fn validate_range(value: i64, min: i64, max: i64, label: &str) -> Result<(), String> {
    if value < min || value > max {
        Err(format!(
            "{} 值 {} 不在合法范围 [{}, {}] 内",
            label, value, min, max
        ))
    } else {
        Ok(())
    }
}

/// 校验必需参数是否已提供（用于互斥参数组）。
fn require_one_of<T>(a: &Option<T>, b: &Option<T>, labels: (&str, &str)) -> Result<(), String> {
    if a.is_none() && b.is_none() {
        Err(format!("必须指定 {} 或 {} 中的一个", labels.0, labels.1))
    } else {
        Ok(())
    }
}

// ============================================================================
// capture 子命令
// ============================================================================

/// 实时数据包捕获参数。
///
/// 用于从网卡实时抓取网络数据包，支持 BPF 过滤、数量限制、输出为 pcap 文件。
///
/// # 示例
///
/// ```bash
/// nethawk capture -i eth0 -c 100 -f "tcp port 80" -w out.pcap
/// ```
#[derive(clap::Args, Debug)]
pub struct CaptureArgs {
    /// 监听的网络接口名称，默认 `any`。
    #[arg(short = 'i', long = "interface", default_value = "any")]
    pub interface: String,

    /// 捕获数据包数量上限（默认不限）。
    #[arg(short = 'c', long = "count")]
    pub count: Option<u64>,

    /// BPF 过滤器表达式（如 `"tcp port 80"`）。
    #[arg(short = 'f', long = "filter")]
    pub filter: Option<String>,

    /// 输出 pcap 文件路径。
    #[arg(short = 'w', long = "write")]
    pub output: Option<String>,

    /// 快照长度（字节），范围 1–65535，默认 65535。
    #[arg(short = 's', long = "snaplen", default_value = "65535")]
    pub snaplen: i32,

    /// 超时时间（毫秒），范围 1–3600000（1 小时），默认 1000。
    #[arg(short = 't', long = "timeout", default_value = "1000")]
    pub timeout: i32,

    /// 数据包详细信息。
    #[arg(short = 'V', long = "verbose-output")]
    pub show_details: bool,
}

impl CaptureArgs {
    /// 校验捕获参数合法性。
    ///
    /// 检查项：
    /// - `snaplen` 必须在 1–65535 之间
    /// - `timeout` 必须在 1–3600000 之间（1ms ~ 1h）
    /// - `count` 如果指定，必须大于 0
    ///
    /// # 错误
    ///
    /// 返回 `Err(String)` 描述具体违规项。
    pub fn validate(&self) -> Result<(), String> {
        validate_range(self.snaplen as i64, 1, 65535, "快照长度")?;
        validate_range(self.timeout as i64, 1, 3_600_000, "超时时间")?;
        if let Some(c) = self.count
            && c == 0
        {
            return Err("包数限制必须大于 0".to_string());
        }
        Ok(())
    }

    /// 运行实时捕获（阶段 0：打印参数并校验）。
    ///
    /// 先调用 `validate()` 校验参数，再打印确认信息。
    pub fn run(&self) -> anyhow::Result<()> {
        self.validate().map_err(anyhow::Error::msg)?;

        tracing::info!("[capture] 接口: {}", self.interface);
        tracing::info!("[capture] 数量限制: {:?}", self.count);
        tracing::info!("[capture] BPF 过滤器: {:?}", self.filter);
        tracing::info!("[capture] 输出文件: {:?}", self.output);
        tracing::info!("[capture] 快照长度: {}", self.snaplen);
        tracing::info!("[capture] 超时: {} ms", self.timeout);
        tracing::info!("[capture] 详细输出: {}", self.show_details);

        println!("  接口: {}", self.interface);
        if let Some(ref f) = self.filter {
            println!("  过滤器: {}", f);
        }
        if let Some(ref o) = self.output {
            println!("  输出文件: {}", o);
        }
        if let Some(c) = self.count {
            println!("  包数限制: {}", c);
        }

        // 创建监听引擎
        CaptureEngine::new(self)?.run()?;

        Ok(())
    }
}

// ============================================================================
// analyze 子命令
// ============================================================================

/// 离线分析参数。
///
/// 加载 pcap/pcapng 文件进行深度协议解析。
///
/// # 示例
///
/// ```bash
/// nethawk analyze capture.pcap -V
/// ```
#[derive(clap::Args, Debug)]
pub struct AnalyzeArgs {
    /// pcap/pcapng 文件路径。
    #[arg(value_name = "FILE")]
    pub file: String,

    /// 是否显示详细协议字段。
    #[arg(short = 'V', long = "verbose-output")]
    pub verbose_output: bool,

    /// JSON 格式输出（需启用 `json` feature）。
    #[cfg(feature = "json")]
    #[arg(short = 'j', long = "json")]
    pub json_output: bool,
}

impl AnalyzeArgs {
    /// 校验分析参数合法性。
    ///
    /// 检查项：
    /// - `file` 不为空
    /// - `file` 扩展名必须是 `.pcap` 或 `.pcapng`
    pub fn validate(&self) -> Result<(), String> {
        if self.file.trim().is_empty() {
            return Err("文件路径不能为空".to_string());
        }
        let lower = self.file.to_lowercase();
        if !lower.ends_with(".pcap") && !lower.ends_with(".pcapng") {
            return Err(format!(
                "不支持的文件格式 '{}'，仅支持 .pcap 或 .pcapng",
                self.file
            ));
        }
        Ok(())
    }

    /// 运行离线分析（阶段 0：打印参数并校验）。
    ///
    /// 先调用 `validate()` 校验参数，再打印确认信息。
    pub fn run(&self) -> anyhow::Result<()> {
        self.validate().map_err(anyhow::Error::msg)?;

        tracing::info!("[analyze] 文件: {}", self.file);
        tracing::info!("[analyze] 详细输出: {}", self.verbose_output);

        println!("离线分析模式（尚未实现）");
        println!("  文件: {}", self.file);
        if self.verbose_output {
            println!("  详细输出: 是");
        }
        Ok(())
    }
}

// ============================================================================
// stats 子命令
// ============================================================================

/// 流量统计参数。
///
/// 支持实时接口统计和离线 pcap 文件统计两种模式。
///
/// # 示例
///
/// ```bash
/// nethawk stats -i eth0 -n 20 -I 5
/// nethawk stats -f capture.pcap
/// ```
#[derive(clap::Args, Debug)]
pub struct StatsArgs {
    /// 监听的网络接口名称（实时统计，与 `-f` 互斥）。
    #[arg(short = 'i', long = "interface")]
    pub interface: Option<String>,

    /// pcap 文件路径（离线统计，与 `-i` 互斥）。
    #[arg(short = 'f', long = "file")]
    pub file: Option<String>,

    /// Top N 会话数，范围 1–1000，默认 10。
    #[arg(short = 'n', long = "top", default_value = "10")]
    pub top_n: usize,

    /// 统计间隔（秒），范围 1–3600，默认 1。
    #[arg(short = 'I', long = "interval", default_value = "1")]
    pub interval: u64,
}

impl StatsArgs {
    /// 校验统计参数合法性。
    ///
    /// 检查项：
    /// - 至少指定 `interface` 或 `file` 中的一个
    /// - `top_n` 必须在 1–1000 之间
    /// - `interval` 必须在 1–3600 之间（1s ~ 1h）
    pub fn validate(&self) -> Result<(), String> {
        require_one_of(&self.interface, &self.file, ("--interface", "--file"))?;
        validate_range(self.top_n as i64, 1, 1000, "Top N")?;
        validate_range(self.interval as i64, 1, 3600, "统计间隔")?;
        Ok(())
    }

    /// 运行流量统计（阶段 0：打印参数并校验）。
    ///
    /// 先调用 `validate()` 校验参数，再打印确认信息。
    pub fn run(&self) -> anyhow::Result<()> {
        self.validate().map_err(anyhow::Error::msg)?;

        tracing::info!("[stats] 接口: {:?}", self.interface);
        tracing::info!("[stats] 文件: {:?}", self.file);
        tracing::info!("[stats] Top N: {}", self.top_n);
        tracing::info!("[stats] 间隔: {} s", self.interval);

        println!("流量统计模式（尚未实现）");
        println!("  接口: {:?}", self.interface);
        if let Some(ref f) = self.file {
            println!("  文件: {}", f);
        }
        println!("  Top N: {}", self.top_n);
        println!("  间隔: {} s", self.interval);
        Ok(())
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // -----------------------------------------------------------------------
    // 公共校验工具测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_range_ok() {
        assert!(validate_range(5, 1, 10, "测试值").is_ok());
    }

    #[test]
    fn test_validate_range_below_min() {
        let err = validate_range(0, 1, 10, "测试值").unwrap_err();
        assert!(err.contains("不在合法范围"));
    }

    #[test]
    fn test_validate_range_above_max() {
        let err = validate_range(11, 1, 10, "测试值").unwrap_err();
        assert!(err.contains("不在合法范围"));
    }

    #[test]
    fn test_validate_range_boundary_min() {
        assert!(validate_range(1, 1, 10, "测试值").is_ok());
    }

    #[test]
    fn test_validate_range_boundary_max() {
        assert!(validate_range(10, 1, 10, "测试值").is_ok());
    }

    #[test]
    fn test_require_one_of_both_none() {
        let a: Option<&str> = None;
        let b: Option<&str> = None;
        let err = require_one_of(&a, &b, ("--interface", "--file")).unwrap_err();
        assert!(err.contains("--interface") && err.contains("--file"));
    }

    #[test]
    fn test_require_one_of_a_some() {
        let a = Some("eth0");
        let b: Option<&str> = None;
        assert!(require_one_of(&a, &b, ("--interface", "--file")).is_ok());
    }

    #[test]
    fn test_require_one_of_b_some() {
        let a: Option<&str> = None;
        let b = Some("test.pcap");
        assert!(require_one_of(&a, &b, ("--interface", "--file")).is_ok());
    }

    #[test]
    fn test_require_one_of_both_some() {
        let a = Some("eth0");
        let b = Some("test.pcap");
        assert!(require_one_of(&a, &b, ("--interface", "--file")).is_ok());
    }

    // -----------------------------------------------------------------------
    // CLI help 测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_capture_help() {
        let result = Cli::try_parse_from(["nethawk", "capture", "--help"]);
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("实时数据包捕获"));
    }

    #[test]
    fn test_analyze_help() {
        let result = Cli::try_parse_from(["nethawk", "analyze", "--help"]);
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("离线分析"));
    }

    #[test]
    fn test_stats_help() {
        let result = Cli::try_parse_from(["nethawk", "stats", "--help"]);
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("流量统计"));
    }

    // -----------------------------------------------------------------------
    // capture 子命令测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_capture_defaults() {
        let cli = Cli::try_parse_from(["nethawk", "capture"]).unwrap();
        match cli.command {
            Commands::Capture(cmd) => {
                assert_eq!(cmd.interface, "any");
                assert_eq!(cmd.count, None);
                assert_eq!(cmd.filter, None);
                assert_eq!(cmd.output, None);
                assert_eq!(cmd.snaplen, 65535);
                assert_eq!(cmd.timeout, 1000);
            }
            _ => panic!("expected Capture command"),
        }
    }

    #[test]
    fn test_capture_validate_defaults() {
        let args = CaptureArgs {
            interface: "eth0".into(),
            count: None,
            filter: None,
            output: None,
            snaplen: 65535,
            timeout: 1000,
            show_details: true,
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_capture_validate_invalid_snaplen() {
        let args = CaptureArgs {
            interface: "eth0".into(),
            count: None,
            filter: None,
            output: None,
            snaplen: 0,
            timeout: 1000,
            show_details: true,
        };
        let err = args.validate().unwrap_err();
        assert!(err.contains("快照长度"));
    }

    #[test]
    fn test_capture_validate_invalid_timeout() {
        let args = CaptureArgs {
            interface: "eth0".into(),
            count: None,
            filter: None,
            output: None,
            snaplen: 1024,
            timeout: 0,
            show_details: true,
        };
        let err = args.validate().unwrap_err();
        assert!(err.contains("超时时间"));
    }

    #[test]
    fn test_capture_validate_zero_count() {
        let args = CaptureArgs {
            interface: "eth0".into(),
            count: Some(0),
            filter: None,
            output: None,
            snaplen: 1024,
            timeout: 1000,
            show_details: true,
        };
        let err = args.validate().unwrap_err();
        assert!(err.contains("包数限制"));
    }

    #[test]
    fn test_capture_validate_boundary_snaplen_max() {
        let args = CaptureArgs {
            interface: "eth0".into(),
            count: None,
            filter: None,
            output: None,
            snaplen: 65535,
            timeout: 1000,
            show_details: true,
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_capture_validate_boundary_timeout_max() {
        let args = CaptureArgs {
            interface: "eth0".into(),
            count: None,
            filter: None,
            output: None,
            snaplen: 1024,
            timeout: 3_600_000,
            show_details: true,
        };
        assert!(args.validate().is_ok());
    }

    // -----------------------------------------------------------------------
    // analyze 子命令测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_analyze_validate_pcap() {
        let args = AnalyzeArgs {
            file: "test.pcap".into(),
            verbose_output: false,
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_analyze_validate_pcapng() {
        let args = AnalyzeArgs {
            file: "test.pcapng".into(),
            verbose_output: true,
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_analyze_validate_invalid_ext() {
        let args = AnalyzeArgs {
            file: "test.txt".into(),
            verbose_output: false,
        };
        let err = args.validate().unwrap_err();
        assert!(err.contains("不支持的文件格式"));
    }

    #[test]
    fn test_analyze_validate_empty() {
        let args = AnalyzeArgs {
            file: "".into(),
            verbose_output: false,
        };
        let err = args.validate().unwrap_err();
        assert!(err.contains("不能为空"));
    }

    // -----------------------------------------------------------------------
    // stats 子命令测试
    // -----------------------------------------------------------------------

    #[test]
    fn test_stats_validate_interface_only() {
        let args = StatsArgs {
            interface: Some("eth0".into()),
            file: None,
            top_n: 10,
            interval: 1,
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_stats_validate_file_only() {
        let args = StatsArgs {
            interface: None,
            file: Some("test.pcap".into()),
            top_n: 10,
            interval: 1,
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_stats_validate_both_missing() {
        let args = StatsArgs {
            interface: None,
            file: None,
            top_n: 10,
            interval: 1,
        };
        let err = args.validate().unwrap_err();
        assert!(err.contains("--interface") && err.contains("--file"));
    }

    #[test]
    fn test_stats_validate_invalid_top_n_zero() {
        let args = StatsArgs {
            interface: Some("eth0".into()),
            file: None,
            top_n: 0,
            interval: 1,
        };
        let err = args.validate().unwrap_err();
        assert!(err.contains("Top N"));
    }

    #[test]
    fn test_stats_validate_invalid_top_n_overflow() {
        let args = StatsArgs {
            interface: Some("eth0".into()),
            file: None,
            top_n: 1001,
            interval: 1,
        };
        let err = args.validate().unwrap_err();
        assert!(err.contains("Top N"));
    }

    #[test]
    fn test_stats_validate_invalid_interval_zero() {
        let args = StatsArgs {
            interface: Some("eth0".into()),
            file: None,
            top_n: 10,
            interval: 0,
        };
        let err = args.validate().unwrap_err();
        assert!(err.contains("统计间隔"));
    }

    #[test]
    fn test_stats_validate_boundary_top_n_min() {
        let args = StatsArgs {
            interface: Some("eth0".into()),
            file: None,
            top_n: 1,
            interval: 1,
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_stats_validate_boundary_top_n_max() {
        let args = StatsArgs {
            interface: Some("eth0".into()),
            file: None,
            top_n: 1000,
            interval: 1,
        };
        assert!(args.validate().is_ok());
    }
}