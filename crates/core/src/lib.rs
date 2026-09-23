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
// audit-pipe 依赖 macOS /dev/auditpipe 与 OpenBSM,仅 macOS 可用。
#[cfg(target_os = "macos")]
pub mod audit_pipe;
