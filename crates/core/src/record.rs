//! 监控记录结构与展示标签。

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

/// 一条监控记录，序列化后加密存入事务数据库。
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Record {
    pub time: DateTime<Local>,
    /// created / modified / renamed / renamed_in / renamed_out / removed / accessed
    pub event: String,
    /// file / folder / unknown
    pub object: String,
    pub path: String,
    /// 重命名时的原路径
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default)]
    pub actor: Actor,
    /// 文件属主(用户列在无归因进程时兜底使用;删除事件回查最近属主)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Box<crate::diagnostics::Diagnostic>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<Box<crate::audit::Evidence>>,
}

/// 控制台/GUI 中文标签
pub fn event_label(event: &str) -> &str {
    match event {
        "created" => "创建",
        "modified" => "修改",
        "renamed" => "重命名",
        "renamed_in" => "移入",
        "renamed_out" => "移出",
        "removed" => "删除",
        "accessed" => "访问",
        "diagnostic" => "监控诊断",
        other => other,
    }
}

pub fn object_label(object: &str) -> &str {
    match object {
        "file" => "文件",
        "folder" => "文件夹",
        "monitor" => "监控",
        other => other,
    }
}

/// 全部事件类型(固定顺序,用于统计与过滤)
pub const EVENT_TYPES: [&str; 8] = [
    "created",
    "modified",
    "renamed",
    "renamed_in",
    "renamed_out",
    "removed",
    "accessed",
    "diagnostic",
];

/// Only OS-reported identities may be attributed to an operation.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct Actor {
    pub process_id: Option<u32>,
    pub application: Option<String>,
    pub user: Option<String>,
    pub source: Option<String>,
}

impl Actor {
    pub fn from_pid(pid: Option<u32>) -> Self {
        let Some(pid) = pid else {
            return Self::default();
        };
        let mut actor = Self {
            process_id: Some(pid),
            source: Some("notify_process_id; identity_snapshot".into()),
            ..Self::default()
        };
        // An identity snapshot can fail if the reported process has already exited.
        #[cfg(unix)]
        if let Ok(output) = std::process::Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "user=", "-o", "comm="])
            .output()
        {
            if output.status.success() {
                let line = String::from_utf8_lossy(&output.stdout);
                let line = line.trim();
                if let Some((user, app)) = line.split_once(char::is_whitespace) {
                    actor.user = Some(user.to_string());
                    actor.application = Some(app.trim().to_string());
                }
            }
        }
        #[cfg(windows)]
        if pid == std::process::id() {
            actor.application = std::env::current_exe()
                .ok()
                .map(|p| p.display().to_string());
            actor.user = std::env::var("USERNAME").ok();
        }
        actor
    }
}
