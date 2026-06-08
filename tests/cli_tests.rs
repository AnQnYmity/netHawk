//! CLI 集成测试
//!
//! 通过 `std::process::Command` 调用编译好的二进制，验证：
//! - help/version 输出
//! - 各子命令参数校验（合法/非法输入）
//! - analyze 离线分析基本流程

use std::process::Command;

/// 获取二进制路径。
fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nethawk"))
}

/// 运行命令并断言成功（退出码 0），返回 stdout。
fn assert_ok(cmd: &mut Command) -> String {
    let output = cmd.output().expect("启动 nethawk 失败");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        output.status.success(),
        "期望成功，实际失败\nstdout: {stdout}\nstderr: {stderr}"
    );
    stdout
}

/// 运行命令并断言失败（退出码非 0），返回 stderr。
fn assert_err(cmd: &mut Command) -> String {
    let output = cmd.output().expect("启动 nethawk 失败");
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        !output.status.success(),
        "期望失败，实际成功\nstderr: {stderr}"
    );
    stderr
}

// ============================================================================
// 全局选项
// ============================================================================

#[test]
fn help_output() {
    let out = assert_ok(bin().arg("--help"));
    assert!(out.contains("capture"), "--help 应包含 capture 子命令");
    assert!(out.contains("analyze"), "--help 应包含 analyze 子命令");
    assert!(out.contains("stats"), "--help 应包含 stats 子命令");
}

#[test]
fn version_output() {
    let out = assert_ok(bin().arg("--version"));
    assert!(out.starts_with("nethawk "), "--version 应以程序名开头");
}

#[test]
fn verbose_flag_accepted() {
    assert_ok(bin().arg("-vv").arg("analyze").arg("test.pcap"));
}

// ============================================================================
// capture 子命令
// ============================================================================

#[test]
fn capture_help() {
    let out = assert_ok(bin().arg("capture").arg("--help"));
    assert!(out.contains("interface"), "capture --help 应包含 --interface");
    assert!(out.contains("count"), "capture --help 应包含 --count");
}

#[test]
fn capture_invalid_count_zero() {
    let err = assert_err(bin().arg("capture").arg("-c").arg("0"));
    assert!(err.contains("包数限制"), "应报告 '包数限制' 相关错误");
}

#[test]
fn capture_invalid_snaplen() {
    let err = assert_err(bin().arg("capture").arg("-s").arg("0"));
    assert!(err.contains("快照长度") || err.contains("snaplen"));
}

#[test]
fn capture_invalid_timeout() {
    let err = assert_err(bin().arg("capture").arg("-t").arg("0"));
    assert!(err.contains("超时时间") || err.contains("timeout"));
}

// ============================================================================
// analyze 子命令
// ============================================================================

#[test]
fn analyze_help() {
    let out = assert_ok(bin().arg("analyze").arg("--help"));
    assert!(out.contains("FILE"), "analyze --help 应包含 FILE 参数");
}

#[test]
fn analyze_missing_file() {
    let err = assert_err(bin().arg("analyze"));
    assert!(err.contains("FILE") || err.contains("required") || err.contains("参数"));
}

#[test]
fn analyze_invalid_extension() {
    let err = assert_err(bin().arg("analyze").arg("test.txt"));
    assert!(err.contains("不支持") || err.contains("格式") || err.contains(".pcap"));
}

#[test]
fn analyze_valid_pcapng() {
    let out = assert_ok(bin().arg("analyze").arg("test.pcapng"));
    assert!(out.contains("离线分析") || out.contains("analyze"), "应进入 analyze 模式");
}

#[test]
fn analyze_verbose_flag() {
    let out = assert_ok(bin().arg("analyze").arg("-V").arg("test.pcap"));
    assert!(out.contains("离线分析"), "verbose 模式下应正常进入分析");
}

#[test]
fn analyze_empty_filename() {
    let err = assert_err(bin().arg("analyze").arg(""));
    assert!(err.contains("不能为空") || err.contains("文件路径"));
}

// ============================================================================
// stats 子命令
// ============================================================================

#[test]
fn stats_help() {
    let out = assert_ok(bin().arg("stats").arg("--help"));
    assert!(out.contains("interface"), "stats --help 应包含 --interface");
    assert!(out.contains("top"), "stats --help 应包含 --top");
}

#[test]
fn stats_missing_source() {
    let err = assert_err(bin().arg("stats"));
    assert!(err.contains("必须指定") || err.contains("--interface") || err.contains("--file"));
}

#[test]
fn stats_interface_valid() {
    let out = assert_ok(bin().arg("stats").arg("-i").arg("eth0"));
    assert!(out.contains("流量统计") || out.contains("stats"));
}

#[test]
fn stats_file_valid() {
    let out = assert_ok(bin().arg("stats").arg("-f").arg("test.pcap"));
    assert!(out.contains("流量统计") || out.contains("stats"));
}

#[test]
fn stats_invalid_top_n() {
    let err = assert_err(bin().arg("stats").arg("-i").arg("eth0").arg("-n").arg("0"));
    assert!(err.contains("Top N"));
}

#[test]
fn stats_invalid_interval() {
    let err = assert_err(bin().arg("stats").arg("-i").arg("eth0").arg("-I").arg("0"));
    assert!(err.contains("统计间隔"));
}

#[test]
fn stats_custom_interval() {
    let out = assert_ok(bin().arg("stats").arg("-i").arg("eth0").arg("-n").arg("20").arg("-I").arg("5"));
    assert!(out.contains("20") || out.contains("5"), "应接受自定义参数");
}
