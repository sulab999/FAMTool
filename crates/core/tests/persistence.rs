use std::{
    fs,
    time::{Duration, Instant},
};
use famtool_core::{
    config::Config,
    engine::{self, Feed},
    logger::{storage_dir, ConsoleMode, Logger},
    record::{Actor, Record},
};

fn record(days: i64) -> Record {
    Record {
        time: chrono::Local::now() - chrono::Duration::days(days),
        event: "modified".into(),
        object: "file".into(),
        path: "/private/report.txt".into(),
        from: None,
        actor: Actor {
            process_id: Some(42),
            application: Some("Editor".into()),
            user: Some("alice".into()),
            source: Some("test_audit".into()),
        },
        owner: None,
        diagnostic: None,
        audit: None,
    }
}
#[test]
fn history_is_read_only_and_actor_survives_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("log");
    assert!(Logger::read_recent(&path, 1).is_err());
    assert!(!storage_dir(&path).exists());
    let mut logger = Logger::with_retention(&path, ConsoleMode::Silent, 90).unwrap();
    logger.log(&record(60)).unwrap();
    drop(logger);
    let history = Logger::read_recent(&path, 10).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].actor.user.as_deref(), Some("alice"));
    assert_eq!(history[0].actor.application.as_deref(), Some("Editor"));
    let logger = Logger::with_retention(&path, ConsoleMode::Silent, 30).unwrap();
    assert!(logger.recent(10).unwrap().is_empty());
}
#[test]
fn wrong_key_and_bad_payload_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("log");
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    logger.log(&record(0)).unwrap();
    drop(logger);
    let key = storage_dir(&path).join("master.key");
    let original = fs::read(&key).unwrap();
    fs::write(&key, [0u8; 32]).unwrap();
    assert!(Logger::new(&path, ConsoleMode::Silent).is_err());
    fs::write(&key, original).unwrap();
    let db = rusqlite::Connection::open(storage_dir(&path).join("events.sqlite3")).unwrap();
    db.execute("UPDATE records SET payload = zeroblob(64)", [])
        .unwrap();
    drop(db);
    assert!(Logger::read_recent(&path, 10).is_err());
}
#[test]
fn invalid_configuration_is_rejected() {
    let mut cfg = Config::default();
    assert_eq!(cfg.retention_days, 30);
    cfg.retention_days = 0;
    assert!(cfg.validate().is_err());
    cfg.retention_days = 30;
    cfg.debounce_ms = u64::MAX;
    assert!(cfg.validate().is_err());
}
#[test]
fn real_watcher_persists_before_delivery_and_drains_on_stop() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("watched");
    fs::create_dir(&root).unwrap();
    let cfg = Config {
        roots: vec![root.clone()],
        excludes: vec![],
        log_file: tmp.path().join("log"),
        debounce_ms: 50,
        ..Config::default()
    };
    let (feed, mut session) = engine::start(&cfg).unwrap();
    let file = root.join("example.txt");
    fs::write(&file, b"test").unwrap();
    let until = Instant::now() + Duration::from_secs(8);
    let mut found = false;
    while Instant::now() < until {
        if let Ok(Feed::Rec(rec)) = feed.recv_timeout(Duration::from_millis(100)) {
            if rec.path.ends_with("example.txt") {
                found = true;
                break;
            }
        }
    }
    assert!(found, "watcher did not deliver a file event");
    assert!(!Logger::read_recent(&cfg.log_file, 100).unwrap().is_empty());
    // Allow the native watcher to deliver into an unfinished aggregation window.
    fs::write(root.join("tail.txt"), b"tail").unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    session.stop();
    assert!(!session.is_running());
    assert!(Logger::read_recent(&cfg.log_file, 100)
        .unwrap()
        .iter()
        .any(|r| r.path.ends_with("tail.txt")));
}

#[test]
fn search_old_records_filters_cursor_and_concurrent_insert() {
    use std::sync::atomic::AtomicBool;
    use famtool_core::search::{self, Query};
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("log");
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    let base = record(0);
    let records: Vec<_> = (0..5100)
        .map(|i| {
            let mut r = base.clone();
            r.path = format!("/test/{i}");
            r
        })
        .collect();
    logger.log_batch(&records).unwrap();
    let cancel = AtomicBool::new(false);
    let mut q = Query {
        text: "/test/0".into(),
        ..Query::default()
    };
    let page = search::search(&path, &q, &cancel).unwrap();
    assert_eq!(page.scanned, 5000);
    assert!(page.records.is_empty());
    assert!(page.next_cursor.is_some());
    q.cursor = page.next_cursor;
    let page = search::search(&path, &q, &cancel).unwrap();
    assert_eq!(page.records.len(), 1);
    assert!(page.next_cursor.is_none());
    let mut q = Query {
        application: "editor".into(),
        user: "ALICE".into(),
        event: "modified".into(),
        limit: 2,
        ..Query::default()
    };
    let first = search::search(&path, &q, &cancel).unwrap();
    assert_eq!(first.records[0].path, "/test/5099");
    let mut late = base.clone();
    late.path = "/late".into();
    logger.log(&late).unwrap();
    q.cursor = first.next_cursor;
    let second = search::search(&path, &q, &cancel).unwrap();
    assert_eq!(second.records[0].path, "/test/5097");
    q.cursor = None;
    q.since_ms = Some(base.time.timestamp_millis() + 1);
    assert!(search::search(&path, &q, &cancel)
        .unwrap()
        .records
        .is_empty());
    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        search::search(&path, &Query::default(), &cancel)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::Interrupted
    );
}
#[test]
fn batch_is_atomic_and_diagnostics_are_encrypted_searchable() {
    use famtool_core::{
        diagnostics::{Code, Diagnostics},
        search::{self, Query},
    };
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("log");
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    let db = rusqlite::Connection::open(storage_dir(&path).join("events.sqlite3")).unwrap();
    let a = record(0);
    let mut b = a.clone();
    b.time += chrono::Duration::seconds(1);
    db.execute_batch(&format!("CREATE TRIGGER reject_test BEFORE INSERT ON records WHEN NEW.time_ms={} BEGIN SELECT RAISE(ABORT,'test'); END",b.time.timestamp_millis())).unwrap();
    assert!(logger.log_batch(&[a, b]).is_err());
    assert!(logger.recent(10).unwrap().is_empty());
    db.execute_batch("DROP TRIGGER reject_test").unwrap();
    drop(db);
    let d = Diagnostics::default();
    d.note(Code::CaptureFull, "/private/diagnostic-secret");
    d.note(Code::CaptureFull, "");
    d.note(Code::Rescan, "");
    logger.log_batch(&d.drain()).unwrap();
    drop(logger);
    let q = Query {
        text: "capture_queue_full".into(),
        event: "diagnostic".into(),
        ..Query::default()
    };
    let page = search::search(&path, &q, &std::sync::atomic::AtomicBool::new(false)).unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].diagnostic.as_ref().unwrap().count, 2);
    let data = fs::read(storage_dir(&path).join("events.sqlite3")).unwrap();
    assert!(!data
        .windows(b"diagnostic-secret".len())
        .any(|w| w == b"diagnostic-secret"));
}
#[test]
fn search_dates_owner_old_path_and_tampering() {
    use famtool_core::search::{self, Query};
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("log");
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    let mut r = record(0);
    r.owner = Some("OtherUser".into());
    r.from = Some("/old/报告.txt".into());
    logger.log(&r).unwrap();
    let q = Query {
        text: "报告".into(),
        user: "otheruser".into(),
        ..Query::default()
    };
    let cancel = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(search::search(&path, &q, &cancel).unwrap().records.len(), 1);
    assert!(search::date_bound("2026-02-30", false).is_err());
    assert!(
        search::date_bound("2026-09-22", true).unwrap()
            > search::date_bound("2026-09-22", false).unwrap()
    );
    drop(logger);
    fs::write(storage_dir(&path).join("master.key"), [0u8; 32]).unwrap();
    assert!(search::search(&path, &Query::default(), &cancel).is_err());
}

#[test]
fn deletion_preserves_keys_configuration_and_allows_future_writes() {
    use famtool_core::diagnostics::{Code, Diagnostics};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log");
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    let d = Diagnostics::default();
    d.note(Code::Rescan, "");
    logger.log(&record(0)).unwrap();
    logger.log_batch(&d.drain()).unwrap();
    drop(logger);
    let key = fs::read(storage_dir(&path).join("master.key")).unwrap();
    assert_eq!(Logger::delete_all(&path).unwrap(), 2);
    assert_eq!(
        fs::read(storage_dir(&path).join("master.key")).unwrap(),
        key
    );
    assert!(Logger::read_recent(&path, 100).unwrap().is_empty());
    assert_eq!(Logger::delete_all(&path).unwrap(), 0);
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    logger.log(&record(0)).unwrap();
    assert_eq!(logger.recent(100).unwrap().len(), 1);
    assert!(Logger::delete_all(&dir.path().join("missing")).is_err());
    assert!(!storage_dir(&dir.path().join("missing")).exists());
}
#[test]
fn deletion_wrong_key_fails_without_removing_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log");
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    logger.log(&record(0)).unwrap();
    drop(logger);
    let key_path = storage_dir(&path).join("master.key");
    let key = fs::read(&key_path).unwrap();
    fs::write(&key_path, [0u8; 32]).unwrap();
    assert!(Logger::delete_all(&path).is_err());
    fs::write(&key_path, key).unwrap();
    assert_eq!(Logger::read_recent(&path, 10).unwrap().len(), 1);
}
#[test]
fn exact_time_range_includes_end_second_but_not_next_second() {
    use famtool_core::search::{self, Query};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log");
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    let local = chrono::Local::now()
        .date_naive()
        .and_hms_opt(12, 30, 0)
        .unwrap();
    let start = search::local_time_bound(local, false).unwrap();
    let end = search::local_time_bound(local, true).unwrap();
    assert_eq!(end - start, 1000);
    let rows: Vec<_> = [start - 1, start, start + 999, end]
        .into_iter()
        .map(|ms| {
            let mut r = record(0);
            r.time = chrono::DateTime::from_timestamp_millis(ms)
                .unwrap()
                .with_timezone(&chrono::Local);
            r
        })
        .collect();
    logger.log_batch(&rows).unwrap();
    drop(logger);
    let q = Query {
        since_ms: Some(start),
        until_ms: Some(end),
        ..Query::default()
    };
    assert_eq!(
        search::search(&path, &q, &std::sync::atomic::AtomicBool::new(false))
            .unwrap()
            .records
            .len(),
        2
    );
    assert!(Query {
        since_ms: Some(end),
        until_ms: Some(start),
        ..Query::default()
    }
    .validate()
    .is_err());
}

#[test]
fn full_search_counts_all_matches_and_supports_direct_page_selection() {
    use std::sync::atomic::AtomicBool;
    use famtool_core::search::{self, Query};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log");
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    let base = record(0);
    let rows: Vec<_> = (0..6501)
        .map(|i| {
            let mut r = base.clone();
            r.path = if i % 3 == 0 {
                format!("/needle/{i}")
            } else {
                format!("/other/{i}")
            };
            r
        })
        .collect();
    logger.log_batch(&rows).unwrap();
    let cancel = AtomicBool::new(false);
    let q = Query {
        text: "needle".into(),
        limit: 200,
        ..Query::default()
    };
    let index = search::build_index(&path, &q, &cancel, |_, _| {}).unwrap();
    let first = index.page(1, &cancel).unwrap();
    assert_eq!(first.total, 2167);
    assert_eq!(first.total_pages, 11);
    assert_eq!(first.scanned, 6501);
    assert_eq!(first.records.len(), 200);
    let last = index.page(11, &cancel).unwrap();
    assert_eq!(last.records.len(), 167);
    assert_eq!(last.records.last().unwrap().path, "/needle/0");
    let middle = index.page(6, &cancel).unwrap();
    assert_eq!(middle.records.len(), 200);
    let again = index.page(1, &cancel).unwrap();
    assert_eq!(again.records[0].path, first.records[0].path);
    let mut new = base.clone();
    new.path = "/needle/new".into();
    logger.log(&new).unwrap();
    assert_eq!(index.page(1, &cancel).unwrap().total, 2167);
    assert_eq!(
        index.page(1, &cancel).unwrap().records[0].path,
        first.records[0].path
    );
    assert!(index.page(0, &cancel).is_err());
    assert!(index.page(12, &cancel).is_err());
    let mut all = std::collections::HashSet::new();
    for page in 1..=11 {
        for r in index.page(page, &cancel).unwrap().records {
            assert!(all.insert(r.path));
        }
    }
    assert_eq!(all.len(), 2167);
}
#[test]
fn counted_search_handles_empty_exact_boundary_cancellation_and_expiry() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use famtool_core::search::{self, Query};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log");
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    let cancel = AtomicBool::new(false);
    let q = Query {
        limit: 200,
        ..Query::default()
    };
    let empty = search::build_index(&path, &q, &cancel, |_, _| {})
        .unwrap()
        .page(1, &cancel)
        .unwrap();
    assert_eq!((empty.total, empty.total_pages, empty.page), (0, 0, 0));
    logger.log_batch(&vec![record(0); 400]).unwrap();
    let index = search::build_index(&path, &q, &cancel, |_, _| {}).unwrap();
    assert_eq!(index.page(2, &cancel).unwrap().total_pages, 2);
    assert_eq!(index.page(2, &cancel).unwrap().records.len(), 200);
    assert!(index.page(3, &cancel).is_err());
    let error = search::build_index(&path, &q, &cancel, |_, _| {
        cancel.store(true, Ordering::Relaxed)
    })
    .err()
    .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
    assert_eq!(
        index.page(1, &cancel).unwrap_err().kind(),
        std::io::ErrorKind::Interrupted
    );
    cancel.store(false, Ordering::Relaxed);
    let db = rusqlite::Connection::open(storage_dir(&path).join("events.sqlite3")).unwrap();
    db.execute("DELETE FROM records WHERE id=400", []).unwrap();
    assert!(index
        .page(1, &cancel)
        .unwrap_err()
        .to_string()
        .contains("重新搜索"));
}
#[test]
fn count_uses_a_consistent_database_snapshot_during_writes() {
    use std::sync::atomic::AtomicBool;
    use famtool_core::search::{self, Query};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("log");
    let mut logger = Logger::new(&path, ConsoleMode::Silent).unwrap();
    logger.log_batch(&vec![record(0); 205]).unwrap();
    let cancel = AtomicBool::new(false);
    let mut inserted = false;
    let index = search::build_index(&path, &Query::default(), &cancel, |_, _| {
        if !inserted {
            logger.log(&record(0)).unwrap();
            inserted = true;
        }
    })
    .unwrap();
    assert_eq!(index.page(2, &cancel).unwrap().total, 205);
    assert_eq!(index.page(2, &cancel).unwrap().records.len(), 5);
    let fresh = search::build_index(&path, &Query::default(), &cancel, |_, _| {}).unwrap();
    assert_eq!(fresh.page(1, &cancel).unwrap().total, 206);
}
