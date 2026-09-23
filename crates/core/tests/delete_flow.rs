use std::time::Duration;
use famtool_core::{
    config::Config,
    engine::{self, Feed},
    logger::{storage_dir, Logger},
};

#[test]
fn delete_all_flow_matches_gui() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("watch");
    std::fs::create_dir(&root).unwrap();
    let cfg = Config {
        roots: vec![root.clone()],
        excludes: vec![],
        log_file: tmp.path().join("log"),
        debounce_ms: 100,
        ..Config::default()
    };
    // 1) 正常运行写入(engine 持有 WAL 连接)
    let (feed, mut session) = engine::start(&cfg).unwrap();
    for i in 0..5 {
        std::fs::write(root.join(format!("f{i}.txt")), b"x").unwrap();
    }
    let until = std::time::Instant::now() + Duration::from_secs(6);
    let mut got = 0;
    while std::time::Instant::now() < until && got < 5 {
        if let Ok(Feed::Rec(_)) = feed.recv_timeout(Duration::from_millis(100)) {
            got += 1;
        }
    }
    assert!(got >= 1, "未写入任何记录");
    // 2) GUI 删除流程: stop → delete_all → restart
    session.stop();
    let dir = storage_dir(&cfg.log_file);
    let before: i64 = {
        let db = rusqlite::Connection::open(dir.join("events.sqlite3")).unwrap();
        db.query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0)).unwrap()
    };
    let deleted = Logger::delete_all(&cfg.log_file).unwrap();
    // 3) 删除后:外部新连接与只读连接看到的计数
    let after_rw: i64 = {
        let db = rusqlite::Connection::open(dir.join("events.sqlite3")).unwrap();
        db.query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0)).unwrap()
    };
    let after_ro = Logger::read_recent(&cfg.log_file, 100).unwrap().len();
    // 4) 重启引擎后再看
    let (_feed2, mut session2) = engine::start(&cfg).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let after_restart = Logger::read_recent(&cfg.log_file, 100).unwrap().len();
    session2.stop();
    // WAL 文件状态
    let wal = std::fs::metadata(dir.join("events.sqlite3-wal")).map(|m| m.len()).unwrap_or(0);
    let main_len = std::fs::metadata(dir.join("events.sqlite3")).unwrap().len();
    let raw = std::fs::read(dir.join("events.sqlite3")).unwrap();
    let residue = raw.windows(b"/secret".len()).any(|w| w == b"/secret");
    println!(
        "写入={got} 删除前计数={before} delete_all返回={deleted} 删除后RW={after_rw} 删除后RO={after_ro} 重启后={after_restart} wal大小={wal} 主库大小={main_len} 内容残留={residue}"
    );
    assert!(!residue, "主库文件仍残留可读路径数据");
    assert!(main_len < 100_000, "删除后主库文件未收缩: {main_len}");
    assert_eq!(after_rw, 0, "RW 连接仍能看到记录");
    assert_eq!(after_ro, 0, "只读连接仍能看到记录");
    assert_eq!(after_restart, 0, "重启后仍能看到记录");
}
