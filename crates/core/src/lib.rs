//! famtool-core —— 跨平台文件/文件夹监控核心库。
//!
//! 职责:采集操作系统原生文件系统事件(notify),按时间窗口聚合收敛成
//! "创建/修改/重命名/删除"记录,管理监控会话的启动与停止,持久化配置。

pub mod aggregator;
pub mod attributor;
pub mod config;
pub mod engine;
pub mod logger;
pub mod record;

pub use config::Config;
pub use engine::{Feed, Session};
pub use record::Record;

pub mod crypto;

pub mod diagnostics;
pub mod search;

pub mod audit;
/// 审计辅助进程库:共享协议/传输 + 平台采集通道
pub mod audit_pipe;
/// Linux fanotify 采集通道(纯解析函数跨平台可测,运行时仅 Linux)
#[cfg(any(target_os = "linux", test))]
pub mod audit_fanotify;
/// Windows 安全日志采集通道(纯解析函数跨平台可测,运行时仅 Windows)
#[cfg(any(target_os = "windows", test))]
pub mod audit_security_log;
