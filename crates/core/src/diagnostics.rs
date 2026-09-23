//! Fixed-size, rate-limited diagnostic aggregation, independent of the event queue.
use crate::record::Record;
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Code {
    CaptureFull,
    Rescan,
    WatchError,
    DisplayFull,
    Maintenance,
    AuditError,
    AuditGap,
}
impl Code {
    pub fn name(self) -> &'static str {
        match self {
            Self::CaptureFull => "capture_queue_full",
            Self::Rescan => "system_rescan_required",
            Self::WatchError => "watch_error",
            Self::DisplayFull => "display_queue_full",
            Self::Maintenance => "maintenance_error",
            Self::AuditError => "system_audit_error",
            Self::AuditGap => "system_audit_gap",
        }
    }
    fn message(self) -> &'static str {
        match self {
            Self::CaptureFull => "采集队列已满，部分原始通知未进入聚合；可缩小监控范围或增加排除路径。已接收记录继续保存。",
            Self::Rescan => "系统报告文件通知可能不完整，需要重新扫描核对当前状态；此信号不等同于程序队列溢出，也不能还原遗漏的操作。",
            Self::WatchError => "文件系统监控后端报告错误，请检查路径和访问权限。",
            Self::DisplayFull => "界面消费积压，部分实时展示已跳过；这些记录已保存，可在历史搜索中查询。",
            Self::Maintenance => "过期日志清理失败，下次维护周期将重试。",
            Self::AuditError => "原生系统审计不可用或连接异常，普通文件监控继续运行。",
            Self::AuditGap => "系统审计检测到事件缺口，部分操作身份可能缺失。",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub count: u64,
    pub first_time: chrono::DateTime<Local>,
    pub last_time: chrono::DateTime<Local>,
    pub message: String,
    pub sample: String,
}
#[derive(Default)]
pub struct Diagnostics(Mutex<BTreeMap<Code, Diagnostic>>);
impl Diagnostics {
    pub fn note(&self, code: Code, sample: &str) {
        let now = Local::now();
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let entry = state.entry(code).or_insert_with(|| Diagnostic {
            code: code.name().into(),
            count: 0,
            first_time: now,
            last_time: now,
            message: code.message().into(),
            sample: String::new(),
        });
        entry.count = entry.count.saturating_add(1);
        entry.last_time = now;
        if !sample.is_empty() {
            entry.sample = sample.chars().take(1024).collect();
        }
    }
    pub fn drain(&self) -> Vec<Record> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        std::mem::take(&mut *state)
            .into_values()
            .map(|d| Record {
                time: d.last_time,
                event: "diagnostic".into(),
                object: "monitor".into(),
                path: d.sample.clone(),
                from: None,
                actor: Default::default(),
                owner: None,
                diagnostic: Some(Box::new(d)),
                audit: None,
            })
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinct_causes_are_coalesced_without_losing_counts() {
        let d = Diagnostics::default();
        for _ in 0..100 {
            d.note(Code::CaptureFull, "/test");
        }
        d.note(Code::Rescan, "");
        d.note(Code::DisplayFull, "");
        let rows = d.drain();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].diagnostic.as_ref().unwrap().count, 100);
        assert_eq!(
            rows[1].diagnostic.as_ref().unwrap().code,
            "system_rescan_required"
        );
        assert!(d.drain().is_empty());
    }
}
