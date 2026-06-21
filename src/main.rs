//! netHawk — 网络数据包捕获与多层协议分析工具
//!
//! 阶段 0：项目骨架，CLI 入口与子命令框架。
//!
//! # 架构
//!
//! - `main.rs`：入口点，负责日志初始化和子命令路由
//! - `cli.rs`：CLI 定义、参数校验和子命令 stub 实现
//!
//! # 日志系统
//!
//! 使用 `tracing-subscriber` 提供分级日志输出：
//! - 默认：`INFO`
//! - `-v`：`DEBUG`
//! - `-vv`：`TRACE`
//!
//! 同时支持 `RUST_LOG` 环境变量覆盖日志级别。

mod analyse;
mod capture;
mod cli;
mod printer;
mod protocol;
mod status;
mod tcp_stream;

use clap::Parser;
use cli::{Cli, Commands};

/// 应用程序入口点。
///
/// 解析命令行参数 → 初始化日志 → 路由到对应子命令。
///
/// # 错误
///
/// 当子命令执行失败时返回错误。
fn main() -> anyhow::Result<()> {
    run_app(Cli::parse())
}

/// 核心应用程序逻辑（可独立测试）。
///
/// 接收已解析的 CLI 参数，初始化日志并路由到对应子命令。
fn run_app(cli: Cli) -> anyhow::Result<()> {
    // 初始化日志系统：-v → DEBUG，-vv → TRACE，默认 INFO
    init_logging(cli.verbose);

    tracing::info!("netHawk v{} 启动", env!("CARGO_PKG_VERSION"));

    match cli.command {
        Commands::Capture(cmd) => cmd.run()?,
        Commands::Analyze(cmd) => cmd.run()?,
        Commands::Stats(cmd) => cmd.run()?,
    }

    Ok(())
}

/// 将 verbose 计数映射为日志级别字符串。
///
/// # 映射规则
///
/// | verbose | 日志级别 | 说明 |
/// |---------|---------|------|
/// | 0       | INFO    | 默认 |
/// | 1       | DEBUG   | `-v` |
/// | ≥2      | TRACE   | `-vv` 或更多 |
pub fn verbosity_to_level(verbose: u8) -> &'static str {
    match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    }
}

/// 根据 verbose 计数初始化 tracing subscriber。
///
/// 使用 `try_init()` 确保多次调用不 panic（测试场景下安全）。
///
/// # 环境变量覆盖
///
/// 如果设置了 `RUST_LOG` 环境变量，将优先使用其值，忽略 `verbose` 参数。
fn init_logging(verbose: u8) {
    let level = verbosity_to_level(verbose);

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));

    // try_init 允许重复初始化不 panic，测试中多个 run_app 调用可共存
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::Write;

    // -----------------------------------------------------------------------
    // CLI 解析测试
    // -----------------------------------------------------------------------

    /// 测试 `--help` 触发 clap 错误输出（预期行为）。
    #[test]
    fn test_cli_no_args_shows_help() {
        let result = Cli::try_parse_from(["nethawk", "--help"]);
        assert!(result.is_err(), "--help 应当触发 clap 退出（Err）");
    }

    /// 测试 `-vv` 累加 verbose 计数。
    #[test]
    fn test_cli_verbose_count() {
        let cli = Cli::try_parse_from(["nethawk", "-vv", "capture"]).unwrap();
        assert_eq!(cli.verbose, 2);
    }

    /// 测试单次 `-v` 得到 verbose = 1。
    #[test]
    fn test_cli_verbose_single() {
        let cli = Cli::try_parse_from(["nethawk", "-v", "capture"]).unwrap();
        assert_eq!(cli.verbose, 1);
    }

    /// 测试三次 `-v` 得到 verbose = 3。
    #[test]
    fn test_cli_verbose_triple() {
        let cli = Cli::try_parse_from(["nethawk", "-v", "-v", "-v", "capture"]).unwrap();
        assert_eq!(cli.verbose, 3);
    }

    /// 测试 capture 子命令完整参数解析。
    #[test]
    fn test_cli_capture_subcommand() {
        let cli = Cli::try_parse_from(["nethawk", "capture", "-i", "eth0", "-c", "100"]).unwrap();
        match cli.command {
            Commands::Capture(cmd) => {
                assert_eq!(cmd.interface, "eth0");
                assert_eq!(cmd.count, Some(100));
            }
            _ => panic!("expected Capture command"),
        }
    }

    /// 测试 analyze 子命令参数解析。
    #[test]
    fn test_cli_analyze_subcommand() {
        let cli = Cli::try_parse_from(["nethawk", "analyze", "test.pcap"]).unwrap();
        match cli.command {
            Commands::Analyze(cmd) => {
                assert_eq!(cmd.file, "test.pcap");
            }
            _ => panic!("expected Analyze command"),
        }
    }

    /// 测试 stats 子命令 -i 参数解析。
    #[test]
    fn test_cli_stats_subcommand() {
        let cli = Cli::try_parse_from(["nethawk", "stats", "-i", "eth0"]).unwrap();
        match cli.command {
            Commands::Stats(cmd) => {
                assert_eq!(cmd.interface.as_deref(), Some("eth0"));
            }
            _ => panic!("expected Stats command"),
        }
    }

    /// 测试 stats 子命令 -f 参数解析。
    #[test]
    fn test_cli_stats_from_file() {
        let cli =
            Cli::try_parse_from(["nethawk", "stats", "-f", "capture.pcap", "-i", "eth0"]).unwrap();
        match cli.command {
            Commands::Stats(cmd) => {
                assert_eq!(cmd.file, Some("capture.pcap".into()));
                assert_eq!(cmd.interface, Some("eth0".into()));
            }
            _ => panic!("expected Stats command"),
        }
    }

    // -----------------------------------------------------------------------
    // 子命令 run() 集成测试
    // -----------------------------------------------------------------------

    /// 测试 capture run() 在默认参数下：参数校验通过（实际抓包需要 root，CI 中预期返回网卡错误而非校验错误）。
    #[test]
    fn test_capture_run_defaults() {
        let args = cli::CaptureArgs {
            interface: "any".into(),
            count: None,
            filter: None,
            output: None,
            snaplen: 65535,
            timeout: 1000,
            show_details: false,
            hex: false,
            json: false,
        };
        // 参数合法，错误只能来自网卡权限/不存在，不是校验失败
        let result = args.run();
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("snaplen") && !msg.contains("timeout") && !msg.contains("count"),
                "不应该是参数校验错误: {msg}"
            );
        }
    }

    /// 测试 capture run() 在校验失败时返回错误。
    #[test]
    fn test_capture_run_validation_error() {
        let args = cli::CaptureArgs {
            interface: "any".into(),
            count: None,
            filter: None,
            output: None,
            snaplen: 0, // 非法值
            timeout: 1000,
            show_details: false,
            hex: false,
            json: false,
        };
        assert!(args.run().is_err());
    }

    /// 测试 analyze run() 成功执行（使用临时 pcap 文件）。
    #[test]
    fn test_analyze_run_valid() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CNT: AtomicU32 = AtomicU32::new(0);
        let id = CNT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir();
        let path = dir.join(format!("test_main_analyze_{id}.pcap"));
        let p = path.to_str().unwrap();
        // 写入最小 pcap 文件
        let mut f = std::fs::File::create(p).unwrap();
        let hdr: [u8; 24] = [
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0,
            0, 1, 0, 0, 0,
        ];
        f.write_all(&hdr).unwrap();
        // 一个最小 ICMP 包
        let mut pkt = vec![0u8; 42];
        pkt[12..14].copy_from_slice(&[0x08, 0x00]);
        pkt[14] = 0x45;
        pkt[23] = 1;
        pkt[26..30].copy_from_slice(&[172, 24, 229, 162]);
        pkt[30..34].copy_from_slice(&[8, 8, 8, 8]);
        pkt[34..36].copy_from_slice(&[0x08, 0x00]);
        let l = pkt.len() as u32;
        f.write_all(&1u32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(&l.to_le_bytes()).unwrap();
        f.write_all(&l.to_le_bytes()).unwrap();
        f.write_all(&pkt).unwrap();
        drop(f);

        let args = cli::AnalyzeArgs {
            file: p.to_string(),
            verbose_output: false,
            json_output: false,
            hex: false,
            follow_http: false,
            tls: false,
            dhcp: false,
            export: false,
        };
        assert!(args.run().is_ok());
        let _ = std::fs::remove_file(&path);
    }

    /// 测试 analyze run() 在校验失败时返回错误。
    #[test]
    fn test_analyze_run_validation_error() {
        let args = cli::AnalyzeArgs {
            file: "test.txt".into(), // 不支持的文件格式
            verbose_output: false,
            json_output: false,
            hex: false,
            follow_http: false,
            tls: false,
            dhcp: false,
            export: false,
        };
        assert!(args.run().is_err());
    }

    /// 测试 stats run()：参数合法，错误只能来自网卡权限/不存在。
    #[test]
    fn test_stats_run_valid() {
        let args = cli::StatsArgs {
            interface: Some("eth0".into()),
            file: None,
            top_n: 10,
            interval: 1,
        };
        let result = args.run();
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("必须指定") && !msg.contains("非法") && !msg.contains("不在合法范围"),
                "不应该是参数校验错误: {msg}"
            );
        }
    }

    /// 测试 stats run() 在校验失败时返回错误。
    #[test]
    fn test_stats_run_validation_error() {
        let args = cli::StatsArgs {
            interface: None,
            file: None, // 两者均未指定
            top_n: 10,
            interval: 1,
        };
        assert!(args.run().is_err());
    }

    // -----------------------------------------------------------------------
    // 日志级别映射测试
    // -----------------------------------------------------------------------

    /// 测试 verbose=0 映射为 INFO。
    #[test]
    fn test_verbosity_to_level_info() {
        assert_eq!(verbosity_to_level(0), "info");
    }

    /// 测试 verbose=1 映射为 DEBUG。
    #[test]
    fn test_verbosity_to_level_debug() {
        assert_eq!(verbosity_to_level(1), "debug");
    }

    /// 测试 verbose=2 映射为 TRACE。
    #[test]
    fn test_verbosity_to_level_trace() {
        assert_eq!(verbosity_to_level(2), "trace");
    }

    /// 测试 verbose=255 映射为 TRACE（边界值）。
    #[test]
    fn test_verbosity_to_level_trace_max() {
        assert_eq!(verbosity_to_level(255), "trace");
    }

    // -----------------------------------------------------------------------
    // run_app 集成测试
    // -----------------------------------------------------------------------

    /// 测试 run_app 使用有效 capture 命令：参数解析正确（抓包需要 root，CI 中预期网卡错误而非解析错误）。
    #[test]
    fn test_run_app_capture_valid() {
        let cli = Cli::try_parse_from(["nethawk", "capture"]).unwrap();
        // 参数解析本身应成功；运行时若因权限失败则错误不应包含校验关键字
        let result = run_app(cli);
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("snaplen") && !msg.contains("timeout") && !msg.contains("count"),
                "不应该是参数校验错误: {msg}"
            );
        }
    }

    /// 测试 run_app 使用有效 analyze 命令（临时 pcap 文件）。
    #[test]
    fn test_run_app_analyze_valid() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static CNT: AtomicU32 = AtomicU32::new(0);
        let id = CNT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir();
        let path = dir.join(format!("test_main_runapp_{id}.pcap"));
        let p = path.to_str().unwrap();
        let mut f = std::fs::File::create(p).unwrap();
        let hdr: [u8; 24] = [
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0,
            0, 1, 0, 0, 0,
        ];
        f.write_all(&hdr).unwrap();
        let pkt = vec![0u8; 42];
        let l = pkt.len() as u32;
        f.write_all(&1u32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(&l.to_le_bytes()).unwrap();
        f.write_all(&l.to_le_bytes()).unwrap();
        f.write_all(&pkt).unwrap();
        drop(f);

        let cli = Cli::try_parse_from(["nethawk", "analyze", p]).unwrap();
        assert!(run_app(cli).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    /// 测试 run_app 使用有效 stats 命令（参数合法，错误只能来自网卡权限）。
    #[test]
    fn test_run_app_stats_valid() {
        let cli = Cli::try_parse_from(["nethawk", "stats", "-i", "eth0"]).unwrap();
        let result = run_app(cli);
        if let Err(ref e) = result {
            let msg = e.to_string();
            assert!(
                !msg.contains("必须指定") && !msg.contains("非法") && !msg.contains("不在合法范围"),
                "不应该是参数校验错误: {msg}"
            );
        }
    }

    /// 测试 run_app 在 analyze 校验失败时返回错误。
    #[test]
    fn test_run_app_analyze_invalid() {
        let cli = Cli::try_parse_from(["nethawk", "analyze", "bad.txt"]).unwrap();
        assert!(run_app(cli).is_err());
    }
}
