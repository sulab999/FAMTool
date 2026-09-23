//! famtool CLI —— 跨平台文件/文件夹操作监控记录工具。
//!
//! 不带路径参数时默认监控整个磁盘(按平台应用系统路径排除)。

use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use famtool_core::config::{default_excludes, Config};
use famtool_core::logger::{ConsoleMode, Logger};
use famtool_core::record::{event_label, Record, EVENT_TYPES};
use famtool_core::{engine, Feed};

/// 文件/文件夹操作监控工具 —— 跨平台记录创建、修改、重命名、删除等操作
#[derive(Parser)]
#[command(name = "famtool", version, about)]
struct Cli {
    /// 要监控的文件或文件夹路径(可多个;缺省为整个磁盘)
    #[arg(value_name = "PATH")]
    paths: Vec<std::path::PathBuf>,

    /// 加密日志位置（实际数据在 <FILE>.store 目录）
    #[arg(
        short = 'o',
        long = "log-file",
        default_value = "famtool.log",
        value_name = "FILE"
    )]
    log_file: std::path::PathBuf,

    /// 排除路径前缀(可多次指定;缺省为平台默认系统路径)
    #[arg(long = "exclude", value_name = "PATH")]
    excludes: Vec<std::path::PathBuf>,

    /// 不递归监控子目录
    #[arg(long)]
    no_recursive: bool,

    /// 事件聚合窗口(毫秒),用于合并一次操作产生的高频重复事件
    #[arg(long, default_value_t = 1000, value_name = "MS")]
    debounce: u64,

    /// 控制台输出解密后的 JSON
    #[arg(long)]
    json: bool,

    /// 同时记录"访问"事件(读取等)
    #[arg(long)]
    track_access: bool,

    /// 不在控制台输出,只写日志文件
    #[arg(short = 'q', long)]
    quiet: bool,
    /// 接收原生 Endpoint Security 审计（需要授权的 root 辅助程序）
    #[arg(long)]
    system_audit: bool,
    /// 日志保留天数，默认近 30 天
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..=36500))]
    retention_days: u32,
    /// 读取最近 N 条（最多 10000）；搜索时为每页数量（1–1000）
    #[arg(long, value_name = "N")]
    history: Option<usize>,
    /// 搜索整个加密数据库（返回 JSON 分页结果，可为空字符串）
    #[arg(long)]
    search: Option<String>,
    #[arg(long, default_value = "")]
    event: String,
    #[arg(long, default_value = "")]
    application: String,
    /// 匹配进程用户或文件属主
    #[arg(long, default_value = "")]
    user: String,
    /// 开始日期 YYYY-MM-DD
    #[arg(long, default_value = "")]
    since: String,
    /// 结束日期 YYYY-MM-DD，包含当天
    #[arg(long, default_value = "")]
    until: String,
    /// 上次查询返回的 next_cursor JSON
    #[arg(long)]
    cursor: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let cfg = Config {
        roots: if cli.paths.is_empty() {
            famtool_core::config::default_roots()
        } else {
            cli.paths
        },
        excludes: if cli.excludes.is_empty() {
            default_excludes()
        } else {
            cli.excludes
        },
        log_file: cli.log_file,
        debounce_ms: cli.debounce,
        track_access: cli.track_access,
        recursive: !cli.no_recursive,
        retention_days: cli.retention_days,
        audit_enabled: cli.system_audit,
    };

    let console = if cli.quiet {
        ConsoleMode::Silent
    } else if cli.json {
        ConsoleMode::Json
    } else {
        ConsoleMode::Human
    };
    if cli.search.is_some()
        || !cli.event.is_empty()
        || !cli.application.is_empty()
        || !cli.user.is_empty()
        || !cli.since.is_empty()
        || !cli.until.is_empty()
        || cli.cursor.is_some()
    {
        use famtool_core::search::{self, Query};
        let result = (|| {
            let q = Query {
                text: cli.search.unwrap_or_default(),
                event: cli.event,
                application: cli.application,
                user: cli.user,
                since_ms: search::date_bound(&cli.since, false)?,
                until_ms: search::date_bound(&cli.until, true)?,
                cursor: cli
                    .cursor
                    .as_deref()
                    .map(serde_json::from_str)
                    .transpose()
                    .map_err(std::io::Error::other)?,
                limit: cli.history.unwrap_or(200),
                ..Query::default()
            };
            search::search(&cfg.log_file, &q, &AtomicBool::new(false))
        })();
        match result {
            Ok(page) => {
                println!("{}", serde_json::to_string(&page).unwrap());
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("历史搜索失败: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    if let Some(limit) = cli.history {
        match Logger::read_recent(&cfg.log_file, limit) {
            Ok(records) => {
                for rec in records {
                    println!("{}", serde_json::to_string(&rec).unwrap());
                }
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("读取历史失败: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    let (feed, mut session) = match engine::start_with_console(&cfg, console) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("错误: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Ctrl+C(及 SIGINT/SIGTERM 对应的终止信号)优雅退出
    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        let _ = ctrlc::set_handler(move || running.store(false, Ordering::SeqCst));
    }

    if !cli.quiet {
        eprintln!(
            "开始监控 {} 个路径(递归: {}),日志文件: {}",
            cfg.roots.len(),
            if cfg.recursive { "是" } else { "否" },
            famtool_core::logger::storage_dir(&cfg.log_file).display()
        );
        eprintln!("按 Ctrl+C 停止。");
    }

    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut total: u64 = 0;
    let mut handle = |rec: &Record| {
        *counts.entry(rec.event.clone()).or_insert(0) += 1;
        total += 1;
    };

    let mut had_error = false;
    loop {
        if !running.load(Ordering::SeqCst) {
            break;
        }
        match feed.recv_timeout(Duration::from_millis(200)) {
            Ok(Feed::Rec(rec)) => handle(&rec),
            Ok(Feed::Err(e)) => {
                had_error = true;
                eprintln!("{e}");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_disconnected) => break,
        }
    }

    // 收尾:停止引擎并排干剩余记录
    session.stop();
    had_error |= session.has_failed();
    let drain_until = Instant::now() + Duration::from_secs(3);
    while Instant::now() < drain_until {
        match feed.recv_timeout(Duration::from_millis(200)) {
            Ok(Feed::Rec(rec)) => handle(&rec),
            Ok(Feed::Err(e)) => {
                had_error = true;
                eprintln!("{e}");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(_disconnected) => break,
        }
    }

    if !cli.quiet {
        eprintln!("\n已停止,共记录 {total} 个事件:");
        for ev in EVENT_TYPES {
            if let Some(n) = counts.get(ev) {
                eprintln!("  {}: {n}", event_label(ev));
            }
        }
    }
    if had_error {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
