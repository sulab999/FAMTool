//! Search encrypted history in bounded pages without building a plaintext index.
use crate::{
    crypto::{error, Crypto},
    logger::storage_dir,
    record::Record,
};
use chrono::{Local, NaiveDate, TimeZone};
use rusqlite::{params, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

const SCAN_LIMIT: usize = 5000;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cursor {
    pub time_ms: i64,
    pub id: i64,
    pub snapshot_id: i64,
}
#[derive(Clone, Debug)]
pub struct Query {
    pub text: String,
    pub event: String,
    pub object: String,
    pub application: String,
    pub user: String,
    pub since_ms: Option<i64>,
    /// Exclusive upper bound.
    pub until_ms: Option<i64>,
    pub limit: usize,
    pub cursor: Option<Cursor>,
}
impl Default for Query {
    fn default() -> Self {
        Self {
            text: String::new(),
            event: String::new(),
            object: String::new(),
            application: String::new(),
            user: String::new(),
            since_ms: None,
            until_ms: None,
            limit: 200,
            cursor: None,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Page {
    pub records: Vec<Record>,
    pub next_cursor: Option<Cursor>,
    pub scanned: usize,
    pub snapshot_id: i64,
}

impl Query {
    pub fn validate(&self) -> io::Result<()> {
        if !(1..=1000).contains(&self.limit) {
            return Err(error("每页数量必须为 1–1000"));
        }
        if self
            .since_ms
            .zip(self.until_ms)
            .is_some_and(|(a, b)| a >= b)
        {
            return Err(error("开始时间必须早于结束时间"));
        }
        Ok(())
    }
    fn matches(&self, r: &Record) -> bool {
        let contains = |s: &str, query: &str| query.is_empty() || s.to_lowercase().contains(query);
        if !self.event.is_empty() && r.event != self.event {
            return false;
        }
        if !self.object.is_empty() && r.object != self.object {
            return false;
        }
        if !self.application.is_empty()
            && ![
                r.actor.application.as_deref(),
                r.audit.as_ref().map(|a| a.executable.as_str()),
                r.audit
                    .as_ref()
                    .and_then(|a| a.parent.as_ref())
                    .and_then(|p| p.executable.as_deref()),
                r.audit
                    .as_ref()
                    .and_then(|a| a.responsible.as_ref())
                    .and_then(|p| p.executable.as_deref()),
            ]
            .into_iter()
            .flatten()
            .any(|s| contains(s, &self.application))
        {
            return false;
        }
        if !self.user.is_empty()
            && ![r.actor.user.as_deref(), r.owner.as_deref()]
                .into_iter()
                .flatten()
                .any(|s| contains(s, &self.user))
        {
            return false;
        }
        if self.text.is_empty() {
            return true;
        }
        let pid = r
            .actor
            .process_id
            .map(|p| p.to_string())
            .unwrap_or_default();
        let found = [
            Some(r.path.as_str()),
            r.from.as_deref(),
            r.actor.application.as_deref(),
            r.actor.user.as_deref(),
            r.owner.as_deref(),
            r.actor.source.as_deref(),
            Some(r.event.as_str()),
            Some(pid.as_str()),
            r.diagnostic.as_ref().map(|d| d.code.as_str()),
            r.diagnostic.as_ref().map(|d| d.message.as_str()),
            r.audit.as_ref().map(|a| a.executable.as_str()),
            r.audit
                .as_ref()
                .and_then(|a| a.parent.as_ref())
                .and_then(|p| p.executable.as_deref()),
            r.audit
                .as_ref()
                .and_then(|a| a.responsible.as_ref())
                .and_then(|p| p.executable.as_deref()),
        ]
        .into_iter()
        .flatten()
        .any(|s| contains(s, &self.text));
        found
    }
}

/// Returns at most one bounded scan page. A nonempty cursor means more rows can
/// be searched, even when this page has no matches. New inserts are excluded by
/// the initial snapshot id; ordering is stable for identical timestamps.
pub fn search(path: &Path, query: &Query, cancel: &AtomicBool) -> io::Result<Page> {
    query.validate()?;
    if cancel.load(Ordering::Relaxed) {
        return Err(io::ErrorKind::Interrupted.into());
    }
    let dir = storage_dir(path);
    let db =
        Connection::open_with_flags(dir.join("events.sqlite3"), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(error)?;
    db.busy_timeout(Duration::from_secs(2)).map_err(error)?;
    let crypto = Crypto::read(&dir.join("master.key"))?;
    let sentinel: Vec<u8> = db
        .query_row("SELECT value FROM meta WHERE id=1", [], |r| r.get(0))
        .map_err(error)?;
    if crypto.open_bytes(&sentinel)? != b"famtool-v1" {
        return Err(error("日志密钥校验失败"));
    }
    let snapshot = match &query.cursor {
        Some(c) => c.snapshot_id,
        None => db
            .query_row("SELECT COALESCE(MAX(id),0) FROM records", [], |r| r.get(0))
            .map_err(error)?,
    };
    let before_time = query.cursor.as_ref().map_or(i64::MAX, |c| c.time_ms);
    let before_id = query.cursor.as_ref().map_or(i64::MAX, |c| c.id);
    let mut stmt = db
        .prepare(
            "SELECT id,time_ms,payload FROM records
        WHERE time_ms >= ?1 AND time_ms < ?2 AND (time_ms,id) < (?3,?4) AND id <= ?5
        ORDER BY time_ms DESC,id DESC LIMIT ?6",
        )
        .map_err(error)?;
    let mut rows = stmt
        .query(params![
            query.since_ms.unwrap_or(i64::MIN),
            query.until_ms.unwrap_or(i64::MAX),
            before_time,
            before_id,
            snapshot,
            SCAN_LIMIT as i64 + 1
        ])
        .map_err(error)?;
    let mut q = query.clone();
    q.text = q.text.trim().to_lowercase();
    q.application = q.application.trim().to_lowercase();
    q.user = q.user.trim().to_lowercase();
    let mut page = Page {
        records: Vec::new(),
        next_cursor: None,
        scanned: 0,
        snapshot_id: snapshot,
    };
    let mut last = None;
    while let Some(row) = rows.next().map_err(error)? {
        if cancel.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if page.scanned == SCAN_LIMIT || page.records.len() == q.limit {
            page.next_cursor = last;
            break;
        }
        let id = row.get(0).map_err(error)?;
        let time_ms = row.get(1).map_err(error)?;
        let payload: Vec<u8> = row.get(2).map_err(error)?;
        let rec: Record = serde_json::from_slice(&crypto.open_bytes(&payload)?).map_err(error)?;
        last = Some(Cursor {
            id,
            time_ms,
            snapshot_id: snapshot,
        });
        page.scanned += 1;
        if q.matches(&rec) {
            page.records.push(rec);
        }
    }
    Ok(page)
}

/// Local calendar date; end dates include the entire specified day.
pub fn date_bound(text: &str, end: bool) -> io::Result<Option<i64>> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    let mut date = NaiveDate::parse_from_str(text.trim(), "%Y-%m-%d")
        .map_err(|_| error("日期格式应为 YYYY-MM-DD"))?;
    if end {
        date = date.succ_opt().ok_or_else(|| error("结束日期超出范围"))?;
    }
    let local = Local
        .from_local_datetime(&date.and_hms_opt(0, 0, 0).ok_or_else(|| error("无效日期"))?)
        .earliest()
        .ok_or_else(|| error("该本地日期不存在"))?;
    Ok(Some(local.timestamp_millis()))
}

/// GUI time selections include the selected end second, including its milliseconds.
/// Reject ambiguous/nonexistent local times rather than silently choosing a DST offset.
pub fn local_time_bound(time: chrono::NaiveDateTime, end: bool) -> io::Result<i64> {
    let local = Local
        .from_local_datetime(&time)
        .single()
        .ok_or_else(|| error("所选本地时间不存在或处于夏令时重复时段，请选择其他时间"))?;
    local
        .timestamp_millis()
        .checked_add(if end { 1000 } else { 0 })
        .ok_or_else(|| error("时间超出范围"))
}

/// A completed search stores only one boundary per page, not all decrypted records.
/// The full scan uses a SQLite read snapshot, so totals are consistent while new
/// events are inserted. The reader is released when indexing completes.
pub struct SearchIndex {
    path: std::path::PathBuf,
    query: Query,
    ends: Vec<Cursor>,
    total: usize,
    scanned: usize,
    snapshot_id: i64,
}

#[derive(Debug, Serialize)]
pub struct NumberedPage {
    pub records: Vec<Record>,
    pub total: usize,
    pub total_pages: usize,
    pub page: usize,
    pub page_size: usize,
    pub scanned: usize,
}

fn reader(path: &Path) -> io::Result<(Connection, Crypto)> {
    let dir = storage_dir(path);
    let db =
        Connection::open_with_flags(dir.join("events.sqlite3"), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(error)?;
    db.busy_timeout(Duration::from_secs(2)).map_err(error)?;
    let crypto = Crypto::read(&dir.join("master.key"))?;
    let sentinel: Vec<u8> = db
        .query_row("SELECT value FROM meta WHERE id=1", [], |r| r.get(0))
        .map_err(error)?;
    if crypto.open_bytes(&sentinel)? != b"famtool-v1" {
        return Err(error("日志密钥校验失败"));
    }
    Ok((db, crypto))
}
fn check_cancel(cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(io::ErrorKind::Interrupted.into())
    } else {
        Ok(())
    }
}

pub fn build_index(
    path: &Path,
    query: &Query,
    cancel: &AtomicBool,
    mut progress: impl FnMut(usize, usize),
) -> io::Result<SearchIndex> {
    query.validate()?;
    if query.cursor.is_some() {
        return Err(error("页码搜索不能使用游标参数"));
    }
    check_cancel(cancel)?;
    let (db, crypto) = reader(path)?;
    db.execute_batch("BEGIN DEFERRED;").map_err(error)?;
    let snapshot_id = db
        .query_row("SELECT COALESCE(MAX(id),0) FROM records", [], |r| r.get(0))
        .map_err(error)?;
    let mut q = query.clone();
    q.text = q.text.trim().to_lowercase();
    q.application = q.application.trim().to_lowercase();
    q.user = q.user.trim().to_lowercase();
    let mut index = SearchIndex {
        path: path.into(),
        query: q,
        ends: Vec::new(),
        total: 0,
        scanned: 0,
        snapshot_id,
    };
    let mut stmt = db.prepare("SELECT id,time_ms,payload FROM records WHERE time_ms >= ?1 AND time_ms < ?2 AND id <= ?3 ORDER BY time_ms DESC,id DESC").map_err(error)?;
    let mut rows = stmt
        .query(params![
            query.since_ms.unwrap_or(i64::MIN),
            query.until_ms.unwrap_or(i64::MAX),
            snapshot_id
        ])
        .map_err(error)?;
    let mut last_match = None;
    let mut notified = std::time::Instant::now();
    progress(0, 0);
    while let Some(row) = rows.next().map_err(error)? {
        check_cancel(cancel)?;
        let payload: Vec<u8> = row.get(2).map_err(error)?;
        let record: Record =
            serde_json::from_slice(&crypto.open_bytes(&payload)?).map_err(error)?;
        index.scanned += 1;
        if index.query.matches(&record) {
            index.total += 1;
            last_match = Some(Cursor {
                id: row.get(0).map_err(error)?,
                time_ms: row.get(1).map_err(error)?,
                snapshot_id,
            });
            if index.total.is_multiple_of(query.limit) {
                index.ends.push(last_match.clone().unwrap());
            }
        }
        if notified.elapsed() >= Duration::from_millis(150) {
            progress(index.scanned, index.total);
            notified = std::time::Instant::now();
        }
    }
    if !index.total.is_multiple_of(query.limit) {
        index.ends.push(last_match.unwrap());
    }
    check_cancel(cancel)?;
    progress(index.scanned, index.total);
    // Cancellation may also be requested by the final progress callback.
    check_cancel(cancel)?;
    Ok(index)
}
impl SearchIndex {
    pub fn page(&self, page: usize, cancel: &AtomicBool) -> io::Result<NumberedPage> {
        check_cancel(cancel)?;
        if page == 0 || page > self.ends.len().max(1) {
            return Err(error("页码超出搜索结果范围"));
        }
        let mut result = NumberedPage {
            records: Vec::new(),
            total: self.total,
            total_pages: self.ends.len(),
            page: if self.total == 0 { 0 } else { page },
            page_size: self.query.limit,
            scanned: self.scanned,
        };
        if self.total == 0 {
            return Ok(result);
        }
        let (db, crypto) = reader(&self.path)?;
        let first = Cursor {
            id: i64::MAX,
            time_ms: i64::MAX,
            snapshot_id: self.snapshot_id,
        };
        let upper = if page == 1 {
            &first
        } else {
            &self.ends[page - 2]
        };
        let lower = &self.ends[page - 1];
        let mut stmt = db.prepare("SELECT payload FROM records WHERE time_ms >= ?1 AND time_ms < ?2 AND (time_ms,id) < (?3,?4) AND (time_ms,id) >= (?5,?6) AND id <= ?7 ORDER BY time_ms DESC,id DESC").map_err(error)?;
        let mut rows = stmt
            .query(params![
                self.query.since_ms.unwrap_or(i64::MIN),
                self.query.until_ms.unwrap_or(i64::MAX),
                upper.time_ms,
                upper.id,
                lower.time_ms,
                lower.id,
                self.snapshot_id
            ])
            .map_err(error)?;
        while let Some(row) = rows.next().map_err(error)? {
            check_cancel(cancel)?;
            let payload: Vec<u8> = row.get(0).map_err(error)?;
            let record: Record =
                serde_json::from_slice(&crypto.open_bytes(&payload)?).map_err(error)?;
            if self.query.matches(&record) {
                result.records.push(record);
            }
            if result.records.len() > self.query.limit {
                return Err(error("搜索结果已变化，请重新搜索"));
            }
        }
        let expected = self
            .query
            .limit
            .min(self.total - (page - 1) * self.query.limit);
        if result.records.len() != expected {
            return Err(error("该页记录已过期或被删除，请重新搜索以更新总数和页码"));
        }
        check_cancel(cancel)?;
        Ok(result)
    }
}
