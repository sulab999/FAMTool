//! Desktop lifecycle and IPC service; the core remains the only database writer.
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs::File,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
};
use famtool_core::{
    config::{self, Config},
    engine::{self, Feed, Session},
    logger::{ConsoleMode, Logger},
    record::Record,
    search::{self, NumberedPage, Query, SearchIndex},
};

const LIVE_CAP: usize = 3000;
#[derive(Clone, Serialize)]
pub struct LiveRecord {
    pub id: u64,
    pub record: Record,
}
#[derive(Default)]
struct Live {
    rows: VecDeque<LiveRecord>,
    next_id: u64,
    received: u64,
    errors: VecDeque<String>,
}
impl Live {
    fn push(&mut self, r: Record) {
        self.next_id += 1;
        self.rows.push_back(LiveRecord {
            id: self.next_id,
            record: r,
        });
        if self.rows.len() > LIVE_CAP {
            self.rows.pop_front();
        }
    }
    fn error(&mut self, e: String) {
        self.errors.push_back(e);
        if self.errors.len() > 10 {
            self.errors.pop_front();
        }
    }
}
struct Control {
    config: Config,
    session: Option<Session>,
    consumer: Option<JoinHandle<()>>,
    managed: bool,
    discovery: Option<(PathBuf, PathBuf)>,
}
impl Control {
    fn stop(&mut self) {
        if let Some((file, socket)) = self.discovery.take() {
            crate::audit_permissions::clear_endpoint(&file, &socket);
        }
        if let Some(mut s) = self.session.take() {
            s.stop();
        }
        if let Some(h) = self.consumer.take() {
            let _ = h.join();
        }
    }
    fn running(&self) -> bool {
        self.session.as_ref().is_some_and(Session::is_running)
    }
    fn start(&mut self, live: &Arc<Mutex<Live>>) -> Result<(), String> {
        self.stop();
        let records = Logger::with_retention(
            &self.config.log_file,
            ConsoleMode::Silent,
            self.config.retention_days,
        )
        .and_then(|l| l.recent(LIVE_CAP))
        .map_err(|e| e.to_string())?;
        {
            let mut l = live.lock().unwrap_or_else(|e| e.into_inner());
            l.rows.clear();
            l.received = 0;
            for r in records {
                l.push(r);
            }
        }
        let (rx, mut session) = engine::start(&self.config)?;
        let sink = live.clone();
        let consumer = match std::thread::Builder::new()
            .name("desktop-feed".into())
            .spawn(move || {
                for msg in rx {
                    let mut l = sink.lock().unwrap_or_else(|e| e.into_inner());
                    match msg {
                        Feed::Rec(r) => {
                            l.received += 1;
                            l.push(*r);
                        }
                        Feed::Err(e) => l.error(e),
                    }
                }
            }) {
            Ok(h) => h,
            Err(e) => {
                session.stop();
                return Err(e.to_string());
            }
        };
        if self.managed && self.config.audit_enabled {
            let state = session.audit_status();
            if state.supported && state.state == "waiting" {
                let socket = PathBuf::from(state.socket_path);
                match crate::audit_permissions::publish_endpoint(&socket) {
                    Ok(file) => self.discovery = Some((file, socket)),
                    Err(e) => live
                        .lock()
                        .unwrap()
                        .error(format!("发布审计连接位置失败: {e}")),
                }
            }
        }
        self.session = Some(session);
        self.consumer = Some(consumer);
        Ok(())
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        self.stop();
    }
}
#[derive(Serialize)]
pub struct Snapshot {
    pub config: Config,
    pub defaults: Config,
    pub running: bool,
    pub received: u64,
    pub buffered: usize,
    pub records: Vec<LiveRecord>,
    pub errors: Vec<String>,
    pub writable: bool,
    pub audit: famtool_core::audit::AuditStatus,
}
#[derive(Deserialize)]
pub struct SearchRequest {
    pub request_id: String,
    pub text: String,
    pub event: String,
    pub application: String,
    pub user: String,
    pub since: String,
    pub until: String,
    pub limit: usize,
}
#[derive(Serialize)]
pub struct DeleteResult {
    pub deleted: usize,
    pub resume_error: Option<String>,
}

struct SearchSession {
    id: String,
    cancel: Arc<AtomicBool>,
    index: Option<Arc<SearchIndex>>,
}

pub struct Desktop {
    control: Mutex<Control>,
    live: Arc<Mutex<Live>>,
    search: Mutex<Option<SearchSession>>,
    cancelled_searches: Mutex<VecDeque<String>>,
    pub quitting: AtomicBool,
    _lock: Option<File>,
    writable: bool,
}
impl Desktop {
    pub fn new(config: Config, lock: Option<File>, error: Option<String>) -> Self {
        let writable = lock.is_some() && error.is_none();
        let live = Arc::new(Mutex::new(Live::default()));
        if let Some(e) = error {
            live.lock().unwrap().error(e);
        }
        Self {
            control: Mutex::new(Control {
                config,
                session: None,
                consumer: None,
                managed: false,
                discovery: None,
            }),
            live,
            search: Mutex::new(None),
            cancelled_searches: Mutex::new(VecDeque::new()),
            quitting: AtomicBool::new(false),
            _lock: lock,
            writable,
        }
    }
    pub fn enable_managed_discovery(&self) {
        self.control.lock().unwrap().managed = true;
    }
    pub fn prepare_audit(&self) -> Result<(), String> {
        self.require_writable()?;
        let mut c = self.control.lock().unwrap();
        if !c.config.audit_enabled {
            let mut cfg = c.config.clone();
            cfg.audit_enabled = true;
            cfg.save().map_err(|e| e.to_string())?;
            c.stop();
            c.config = cfg;
        }
        if !c.running() {
            c.start(&self.live)?;
        }
        let status = c.session.as_ref().unwrap().audit_status();
        if !status.supported || status.state == "unavailable" {
            return Err(status.message);
        }
        if c.managed {
            let socket = PathBuf::from(status.socket_path);
            let file = crate::audit_permissions::publish_endpoint(&socket)?;
            c.discovery = Some((file, socket));
        }
        Ok(())
    }
    fn require_writable(&self) -> Result<(), String> {
        if self.writable {
            Ok(())
        } else {
            Err("已有其他 GUI 实例运行或配置不可用，请退出旧版本后重新打开。".into())
        }
    }
    pub fn set_running(&self, running: bool) -> Result<(), String> {
        self.require_writable()?;
        let mut c = self.control.lock().unwrap_or_else(|e| e.into_inner());
        if running {
            if !c.running() {
                if let Err(e) = c.start(&self.live) {
                    self.live.lock().unwrap().error(e.clone());
                    return Err(e);
                }
            }
        } else {
            c.stop();
        }
        Ok(())
    }
    pub fn shutdown(&self) {
        self.cancel_search(None);
        self.control
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stop();
    }
    pub fn snapshot(&self) -> Snapshot {
        let c = self.control.lock().unwrap_or_else(|e| e.into_inner());
        let l = self.live.lock().unwrap_or_else(|e| e.into_inner());
        Snapshot {
            config: c.config.clone(),
            defaults: Config::default(),
            running: c.running(),
            received: l.received,
            buffered: l.rows.len(),
            records: l.rows.iter().rev().take(500).cloned().collect(),
            errors: l.errors.iter().cloned().collect(),
            writable: self.writable,
            audit: c
                .session
                .as_ref()
                .map(Session::audit_status)
                .unwrap_or_else(|| {
                    let mut a = famtool_core::audit::AuditStatus::idle(
                        c.config.audit_enabled,
                        &c.config.log_file,
                    );
                    if a.enabled {
                        a.state = "paused".into();
                        a.message = "启动监控后等待原生审计辅助程序连接".into();
                    }
                    a
                }),
        }
    }
    pub fn apply(&self, cfg: Config) -> Result<(), String> {
        self.require_writable()?;
        cfg.validate().map_err(|e| e.to_string())?;
        for root in &cfg.roots {
            if !root.exists() {
                return Err(format!("监控路径不存在: {}", root.display()));
            }
        }
        let mut c = self.control.lock().unwrap_or_else(|e| e.into_inner());
        cfg.save().map_err(|e| e.to_string())?;
        self.cancel_search(None);
        let restart = c.running();
        c.stop();
        c.config = cfg;
        self.live.lock().unwrap().rows.clear();
        if restart {
            c.start(&self.live)?;
        }
        Ok(())
    }
    pub fn clear_display(&self) {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .rows
            .clear();
    }
    pub fn cancel_search(&self, id: Option<&str>) {
        if id.is_some_and(|id| id.len() > 100) {
            return;
        }
        let mut active = self.search.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(id) = id {
            let mut cancelled = self.cancelled_searches.lock().unwrap();
            if !cancelled.iter().any(|s| s == id) {
                cancelled.push_back(id.into());
            }
            while cancelled.len() > 32 {
                cancelled.pop_front();
            }
        }
        if let Some(session) = &mut *active {
            if id.is_none_or(|id| id == session.id) {
                session.cancel.store(true, Ordering::Relaxed);
                session.index = None;
            }
        }
    }
    pub fn search(
        &self,
        r: SearchRequest,
        progress: impl FnMut(usize, usize),
    ) -> Result<NumberedPage, String> {
        if r.request_id.is_empty() || r.request_id.len() > 100 {
            return Err("无效查询标识".into());
        }
        let path = self.control.lock().unwrap().config.log_file.clone();
        let cancel = {
            let mut active = self.search.lock().unwrap();
            if self
                .cancelled_searches
                .lock()
                .unwrap()
                .contains(&r.request_id)
            {
                return Err("查询已取消".into());
            }
            if let Some(session) = &*active {
                if session.id == r.request_id {
                    return Err("查询已取消或已经提交，请重新搜索".into());
                }
                session.cancel.store(true, Ordering::Relaxed);
            }
            let cancel = Arc::new(AtomicBool::new(false));
            *active = Some(SearchSession {
                id: r.request_id.clone(),
                cancel: cancel.clone(),
                index: None,
            });
            cancel
        };
        let q = Query {
            text: r.text,
            event: r.event,
            application: r.application,
            user: r.user,
            since_ms: time_bound(&r.since, false)?,
            until_ms: time_bound(&r.until, true)?,
            limit: r.limit,
            ..Query::default()
        };
        let index =
            Arc::new(search::build_index(&path, &q, &cancel, progress).map_err(search_error)?);
        let page = index.page(1, &cancel).map_err(search_error)?;
        let mut active = self.search.lock().unwrap();
        if let Some(session) = &mut *active {
            if session.id == r.request_id && !session.cancel.load(Ordering::Relaxed) {
                session.index = Some(index);
                return Ok(page);
            }
        }
        Err("查询已取消".into())
    }
    pub fn history_page(&self, id: &str, page: usize) -> Result<NumberedPage, String> {
        let (index, cancel) = {
            let active = self.search.lock().unwrap();
            let session = active
                .as_ref()
                .filter(|s| s.id == id && !s.cancel.load(Ordering::Relaxed))
                .ok_or("搜索结果已失效，请重新搜索")?;
            (
                session.index.clone().ok_or("查询尚未完成，请稍候")?,
                session.cancel.clone(),
            )
        };
        index.page(page, &cancel).map_err(search_error)
    }
    pub fn delete(&self, confirmation: &str) -> Result<DeleteResult, String> {
        self.require_writable()?;
        if confirmation != "DELETE_ALL_LOGS" {
            return Err("需要确认删除全部日志".into());
        }
        let mut c = self.control.lock().unwrap();
        self.cancel_search(None);
        let restart = c.running();
        c.stop();
        let result = Logger::delete_all(&c.config.log_file).map_err(|e| e.to_string());
        if result.is_ok() {
            let mut l = self.live.lock().unwrap();
            l.rows.clear();
            l.received = 0;
            l.errors.clear();
        }
        let resume_error = if restart {
            c.start(&self.live).err()
        } else {
            None
        };
        if let Some(e) = &resume_error {
            self.live
                .lock()
                .unwrap()
                .error(format!("恢复监控失败: {e}"));
        }
        result.map(|deleted| DeleteResult {
            deleted,
            resume_error,
        })
    }
    pub fn location(&self, which: &str) -> Result<PathBuf, String> {
        match which {
            "logs" => Ok(famtool_core::logger::storage_dir(
                &self.control.lock().unwrap().config.log_file,
            )),
            "config" => Ok(config::data_dir()),
            _ => Err("未知位置".into()),
        }
    }
}
fn search_error(error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::Interrupted {
        "查询已取消".into()
    } else {
        error.to_string()
    }
}
fn time_bound(text: &str, end: bool) -> Result<Option<i64>, String> {
    if text.is_empty() {
        return Ok(None);
    }
    let local = chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M"))
        .map_err(|_| "无效日期时间".to_string())?;
    search::local_time_bound(local, end)
        .map(Some)
        .map_err(|e| e.to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn time_inputs_are_local_and_second_inclusive() {
        let t = "2026-09-22T12:30:00";
        assert_eq!(
            time_bound(t, true).unwrap().unwrap() - time_bound(t, false).unwrap().unwrap(),
            1000
        );
        assert!(time_bound("bad", false).is_err());
        assert_eq!(time_bound("", true).unwrap(), None);
    }
    #[test]
    fn read_only_instance_cannot_change_monitor_or_delete() {
        let d = Desktop::new(Config::default(), None, None);
        assert!(d.set_running(true).is_err());
        assert!(d.delete("DELETE_ALL_LOGS").is_err());
        assert!(!d.snapshot().writable);
    }
    #[test]
    fn cancelled_query_does_not_return_records() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            log_file: dir.path().join("log"),
            ..Config::default()
        };
        let _l = Logger::new(&cfg.log_file, ConsoleMode::Silent).unwrap();
        let d = Desktop::new(cfg, None, None);
        *d.search.lock().unwrap() = Some(SearchSession {
            id: "q".into(),
            cancel: Arc::new(AtomicBool::new(false)),
            index: None,
        });
        d.cancel_search(Some("q"));
        let r = SearchRequest {
            request_id: "q".into(),
            text: String::new(),
            event: String::new(),
            application: String::new(),
            user: String::new(),
            since: String::new(),
            until: String::new(),
            limit: 200,
        };
        assert!(d.search(r, |_, _| {}).unwrap_err().contains("取消"));
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[test]
    fn confirmed_delete_restores_running_state_and_paused_state() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("watch");
        std::fs::create_dir(&root).unwrap();
        let cfg = Config {
            roots: vec![root],
            excludes: vec![],
            log_file: dir.path().join("log"),
            ..Config::default()
        };
        let _ = Logger::new(&cfg.log_file, ConsoleMode::Silent).unwrap();
        let lock = File::create(dir.path().join("lock")).unwrap();
        let d = Desktop::new(cfg, Some(lock), None);
        assert!(d.delete("wrong").is_err());
        assert_eq!(d.delete("DELETE_ALL_LOGS").unwrap().deleted, 0);
        assert!(!d.snapshot().running);
        d.set_running(true).unwrap();
        assert!(d.snapshot().running);
        let result = d.delete("DELETE_ALL_LOGS").unwrap();
        assert!(result.resume_error.is_none());
        assert!(d.snapshot().running);
        d.shutdown();
        assert!(!d.snapshot().running);
    }
}

#[cfg(test)]
mod pagination_tests {
    use super::*;
    fn request(id: &str) -> SearchRequest {
        SearchRequest {
            request_id: id.into(),
            text: String::new(),
            event: String::new(),
            application: String::new(),
            user: String::new(),
            since: String::new(),
            until: String::new(),
            limit: 200,
        }
    }
    #[test]
    fn numbered_pages_and_cancelled_sessions_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            log_file: dir.path().join("log"),
            ..Config::default()
        };
        let mut logger = Logger::new(&cfg.log_file, ConsoleMode::Silent).unwrap();
        let r = Record {
            time: chrono::Local::now(),
            event: "modified".into(),
            object: "file".into(),
            path: "/test".into(),
            from: None,
            actor: Default::default(),
            owner: None,
            diagnostic: None,
            audit: None,
        };
        logger.log_batch(&vec![r; 401]).unwrap();
        drop(logger);
        let d = Desktop::new(cfg, None, None);
        let result = d.search(request("first"), |_, _| {}).unwrap();
        assert_eq!(result.total, 401);
        assert_eq!(result.total_pages, 3);
        assert_eq!(d.history_page("first", 3).unwrap().records.len(), 1);
        assert!(d.history_page("other", 1).is_err());
        assert!(d.history_page("first", 4).is_err());
        d.cancel_search(Some("future"));
        assert!(d
            .search(request("future"), |_, _| {})
            .unwrap_err()
            .contains("取消"));
        assert!(
            d.history_page("first", 1).is_ok(),
            "cancelling a different request must not destroy this index"
        );
        d.cancel_search(Some("first"));
        assert!(d.history_page("first", 1).is_err());
        let next = d.search(request("next"), |_, _| {}).unwrap();
        assert_eq!(next.total, 401);
        assert!(d.history_page("first", 1).is_err());
    }
}
