//! 监控引擎:持有 watcher 与聚合线程,对外暴露 Feed 通道与会话控制。
//!
//! 线程模型:
//!   watcher 回调线程(notify 内部) --Event--> 聚合线程 --Record--> 转发线程 --Feed--> 消费者
//! 停止:置位 stop -> 驻留线程退出并 drop watcher -> 上游通道断开 -> 聚合线程结算残余批次退出。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use notify::{recommended_watcher, Event, RecursiveMode, Watcher};

use crate::aggregator::{self, Options as AggOptions};
use crate::config::{self, Config};
use crate::diagnostics::{Code, Diagnostics};
use crate::logger::{storage_dir, ConsoleMode, Logger};
use crate::record::Record;

/// 推送给消费者的消息
pub enum Feed {
    Rec(Box<Record>),
    Err(String),
}

pub struct Session {
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    audit: crate::audit::AuditSession,
    watcher_park: Option<JoinHandle<()>>,
    aggregator: Option<JoinHandle<()>>,
    forwarder: Option<JoinHandle<()>>,
}

impl Session {
    /// 停止监控。会等待各线程退出并排空通道。
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.audit.stop();
        if let Some(h) = self.watcher_park.take() {
            let _ = h.join();
        }
        if let Some(h) = self.aggregator.take() {
            let _ = h.join();
        }
        if let Some(h) = self.forwarder.take() {
            let _ = h.join();
        }
    }

    pub fn audit_status(&self) -> crate::audit::AuditStatus {
        self.audit.status()
    }

    pub fn has_failed(&self) -> bool {
        self.failed.load(Ordering::SeqCst)
    }

    pub fn is_running(&self) -> bool {
        self.watcher_park.as_ref().is_some_and(|h| !h.is_finished())
            && self.aggregator.as_ref().is_some_and(|h| !h.is_finished())
            && self.forwarder.as_ref().is_some_and(|h| !h.is_finished())
            && !self.stop.load(Ordering::SeqCst)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

/// 启动一个监控会话。返回 Feed 接收端与会话;会话停止后接收端在排空剩余记录后断开。
pub fn start(cfg: &Config) -> Result<(Receiver<Feed>, Session), String> {
    start_with_console(cfg, ConsoleMode::Silent)
}
pub fn start_with_console(
    cfg: &Config,
    console: ConsoleMode,
) -> Result<(Receiver<Feed>, Session), String> {
    cfg.validate().map_err(|e| e.to_string())?;
    let mut logger = Logger::with_retention(&cfg.log_file, console, cfg.retention_days)
        .map_err(|e| format!("打开加密日志失败: {e}"))?;
    if cfg.roots.is_empty() {
        return Err("没有配置监控路径".into());
    }

    // 规范化根路径并校验
    let mut roots = Vec::with_capacity(cfg.roots.len());
    for p in &cfg.roots {
        match dunce::canonicalize(p) {
            Ok(rp) if rp.exists() => roots.push(rp),
            _ => return Err(format!("监控路径不存在或无法访问: {}", p.display())),
        }
    }

    // 排除列表规范化(前缀匹配,不存在也能匹配)
    let mut excludes: Vec<PathBuf> = cfg
        .excludes
        .iter()
        .map(|p| dunce::canonicalize(p).unwrap_or_else(|_| p.clone()))
        .collect();
    // 程序自身数据目录(配置/日志写入噪音)
    if let Ok(c) = dunce::canonicalize(config::data_dir()) {
        excludes.push(c);
    }

    let store = storage_dir(&cfg.log_file);
    excludes.push(dunce::canonicalize(&store).map_err(|e| e.to_string())?);
    let skip_path = dunce::canonicalize(&cfg.log_file).unwrap_or_else(|_| cfg.log_file.clone());
    let (ev_tx, ev_rx) = mpsc::sync_channel::<Event>(16384);
    let (feed_tx, feed_rx) = mpsc::sync_channel::<Feed>(8192);
    let (rec_tx, rec_rx) = mpsc::sync_channel::<Vec<Record>>(64);
    let stop = Arc::new(AtomicBool::new(false));
    let failed = Arc::new(AtomicBool::new(false));
    let diagnostics = Arc::new(Diagnostics::default());
    let callback_diagnostics = diagnostics.clone();
    let excludes = Arc::new(excludes);
    let audit_excludes = excludes.clone();
    let callback_stop = stop.clone();
    let track_access = cfg.track_access;
    let mut watcher = recommended_watcher(move |res: notify::Result<Event>| {
        if callback_stop.load(Ordering::Relaxed) {
            return;
        }
        match res {
            Ok(ev) => enqueue_event(ev, &excludes, track_access, &ev_tx, &callback_diagnostics),
            Err(e) => callback_diagnostics.note(Code::WatchError, &e.to_string()),
        }
    })
    .map_err(|e| format!("初始化文件系统监控失败: {e}"))?;

    let mode = if cfg.recursive {
        RecursiveMode::Recursive
    } else {
        RecursiveMode::NonRecursive
    };
    let mut ok = 0usize;
    for p in &roots {
        match watcher.watch(p, mode) {
            Ok(()) => ok += 1,
            Err(e) => {
                diagnostics.note(Code::WatchError, &format!("无法监控 {}: {e}", p.display()));
            }
        }
    }
    if ok == 0 {
        logger
            .log_batch(&diagnostics.drain())
            .map_err(|e| format!("保存监控失败诊断: {e}"))?;
        return Err(format!(
            "所有 {} 个监控路径都无法监控(全部失败)",
            roots.len()
        ));
    }

    let audit = crate::audit::AuditSession::start(
        cfg,
        roots.clone(),
        (*audit_excludes).clone(),
        rec_tx.clone(),
        diagnostics.clone(),
    );

    let debounce = Duration::from_millis(cfg.debounce_ms.max(1));
    let agg_opts = AggOptions {
        debounce,
        track_access: cfg.track_access,
        skip_path,
        root_grace: {
            let grace = Duration::from_secs(2) + debounce * 2;
            let now = Instant::now();
            roots.iter().map(|p| (p.clone(), now + grace)).collect()
        },
    };
    let aggregator = thread::Builder::new()
        .name("fmon-aggregator".into())
        .spawn(move || aggregator::run(ev_rx, rec_tx, agg_opts))
        .map_err(|e| format!("启动聚合线程失败: {e}"))?;

    let writer_stop = stop.clone();
    let writer_failed = failed.clone();
    let forwarder = thread::Builder::new()
        .name("fmon-storage".into())
        .spawn(move || {
            store_records(
                rec_rx,
                logger,
                feed_tx,
                diagnostics,
                writer_stop,
                writer_failed,
            )
        })
        .map_err(|e| format!("启动存储线程失败: {e}"))?;

    // watcher 移交驻留线程:stop 前保持存活,stop 后 drop 结束监控
    let park_stop = stop.clone();
    let watcher_park = thread::Builder::new()
        .name("fmon-watcher-park".into())
        .spawn(move || {
            while !park_stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(100));
            }
            drop(watcher);
        })
        .map_err(|e| format!("启动监控线程失败: {e}"))?;

    Ok((
        feed_rx,
        Session {
            stop,
            failed,
            audit,
            watcher_park: Some(watcher_park),
            aggregator: Some(aggregator),
            forwarder: Some(forwarder),
        },
    ))
}

fn store_records(
    rec_rx: Receiver<Vec<Record>>,
    mut logger: Logger,
    feed_tx: mpsc::SyncSender<Feed>,
    diagnostics: Arc<Diagnostics>,
    writer_stop: Arc<AtomicBool>,
    writer_failed: Arc<AtomicBool>,
) {
    let mut last_diagnostics = Instant::now();
    loop {
        let (mut batch, finished) = match rec_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(records) => (records, false),
            Err(mpsc::RecvTimeoutError::Timeout) => (Vec::new(), false),
            Err(mpsc::RecvTimeoutError::Disconnected) => (Vec::new(), true),
        };
        if let Err(e) = logger.maintenance() {
            diagnostics.note(Code::Maintenance, &e.to_string());
        }
        // Limit repeated warnings to one summary per cause every five seconds.
        // Always flush the final counters after the producer disconnects.
        if finished || last_diagnostics.elapsed() >= Duration::from_secs(5) {
            batch.extend(diagnostics.drain());
            last_diagnostics = Instant::now();
        }
        let mut result = logger.log_batch(&batch);
        for _ in 0..3 {
            if result.is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(200));
            result = logger.log_batch(&batch);
        }
        if let Err(e) = result {
            writer_failed.store(true, Ordering::SeqCst);
            writer_stop.store(true, Ordering::SeqCst);
            let msg = format!("持久化失败，监控已停止，未保存记录可能丢失: {e}");
            eprintln!("{msg}");
            let _ = feed_tx.try_send(Feed::Err(msg));
            break;
        }
        for r in batch {
            let is_diagnostic = r.diagnostic.is_some();
            if let Some(d) = &r.diagnostic {
                let _ = feed_tx.try_send(Feed::Err(format!(
                    "{}（{} 次，已保存至历史诊断）",
                    d.message, d.count
                )));
            }
            if let Err(mpsc::TrySendError::Full(_)) = feed_tx.try_send(Feed::Rec(Box::new(r))) {
                // Do not recursively count skipped diagnostic displays.
                if !is_diagnostic {
                    diagnostics.note(Code::DisplayFull, "");
                }
            }
        }
        if finished {
            // The final batch itself may overflow the display queue.
            if let Err(e) = logger.log_batch(&diagnostics.drain()) {
                writer_failed.store(true, Ordering::SeqCst);
                eprintln!("收尾诊断写入失败: {e}");
            }
            break;
        }
    }
}

fn enqueue_event(
    mut ev: Event,
    excludes: &[PathBuf],
    track_access: bool,
    tx: &mpsc::SyncSender<Event>,
    diagnostics: &Diagnostics,
) {
    // Rescan events may have NO paths; capture the signal before filtering.
    if ev.need_rescan() {
        diagnostics.note(
            Code::Rescan,
            ev.paths
                .first()
                .map(|p| p.to_string_lossy())
                .as_deref()
                .unwrap_or(""),
        );
    }
    if matches!(ev.kind, notify::EventKind::Access(_)) && !track_access {
        return;
    }
    if !matches!(
        ev.kind,
        notify::EventKind::Create(_)
            | notify::EventKind::Modify(_)
            | notify::EventKind::Remove(_)
            | notify::EventKind::Access(_)
    ) {
        return;
    }
    ev.paths
        .retain(|p| !excludes.iter().any(|x| p.starts_with(x)));
    if ev.paths.is_empty() {
        return;
    }
    match tx.try_send(ev) {
        Err(mpsc::TrySendError::Full(ev)) => diagnostics.note(
            Code::CaptureFull,
            ev.paths
                .first()
                .map(|p| p.to_string_lossy())
                .as_deref()
                .unwrap_or(""),
        ),
        // Disconnection is a shutdown/storage failure, not a queue overflow.
        Err(mpsc::TrySendError::Disconnected(_)) | Ok(()) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::{
        event::{AccessKind, CreateKind, Flag},
        EventKind,
    };
    #[test]
    fn rescan_empty_paths_and_overflow_are_distinct() {
        let (tx, rx) = mpsc::sync_channel(1);
        let d = Diagnostics::default();
        enqueue_event(
            Event::new(EventKind::Other).set_flag(Flag::Rescan),
            &[],
            false,
            &tx,
            &d,
        );
        for _ in 0..3 {
            enqueue_event(
                Event::new(EventKind::Create(CreateKind::File)).add_path("/test".into()),
                &[],
                false,
                &tx,
                &d,
            );
        }
        let records = d.drain();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].diagnostic.as_ref().unwrap().count, 2);
        assert_eq!(records[1].diagnostic.as_ref().unwrap().count, 1);
        drop(rx);
        enqueue_event(
            Event::new(EventKind::Create(CreateKind::File)).add_path("/test".into()),
            &[],
            false,
            &tx,
            &d,
        );
        assert!(d.drain().is_empty(), "shutdown is not overflow");
    }
    #[test]
    fn ignored_access_and_excluded_paths_do_not_fill_queue() {
        let (tx, rx) = mpsc::sync_channel(1);
        let d = Diagnostics::default();
        for _ in 0..100 {
            enqueue_event(
                Event::new(EventKind::Access(AccessKind::Any)).add_path("/test".into()),
                &[],
                false,
                &tx,
                &d,
            );
            enqueue_event(
                Event::new(EventKind::Create(CreateKind::File)).add_path("/skip/file".into()),
                &["/skip".into()],
                false,
                &tx,
                &d,
            );
        }
        assert!(rx.try_recv().is_err());
        assert!(d.drain().is_empty());
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    #[test]
    fn stop_flushes_diagnostics_even_when_display_queue_is_full() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
        let (tx, rx) = mpsc::sync_channel(1);
        let (feed_tx, _feed_rx) = mpsc::sync_channel(1);
        let diagnostics = Arc::new(Diagnostics::default());
        diagnostics.note(Code::CaptureFull, "/overflow");
        diagnostics.note(Code::Rescan, "");
        let record = Record {
            time: chrono::Local::now(),
            event: "created".into(),
            object: "file".into(),
            path: "/saved".into(),
            from: None,
            actor: Default::default(),
            owner: None,
            diagnostic: None,
            audit: None,
        };
        tx.send(vec![record.clone(), record]).unwrap();
        drop(tx);
        let failed = Arc::new(AtomicBool::new(false));
        store_records(
            rx,
            logger,
            feed_tx,
            diagnostics,
            Arc::new(AtomicBool::new(false)),
            failed.clone(),
        );
        assert!(!failed.load(Ordering::Relaxed));
        let records = Logger::read_recent(&path, 100).unwrap();
        assert_eq!(records.iter().filter(|r| r.event == "created").count(), 2);
        for code in [
            "capture_queue_full",
            "system_rescan_required",
            "display_queue_full",
        ] {
            assert!(
                records
                    .iter()
                    .any(|r| r.diagnostic.as_ref().is_some_and(|d| d.code == code)),
                "missing {code}"
            );
        }
    }
}
