//! Durable SQLite transactions containing authenticated encrypted records.
use crate::{
    crypto::{error, private_dir, Crypto},
    record::{event_label, object_label, Record},
};
use rusqlite::{params, Connection};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq)]
pub enum ConsoleMode {
    Silent,
    Human,
    Json,
}

pub fn storage_dir(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".store");
    PathBuf::from(name)
}

pub struct Logger {
    db: Connection,
    crypto: Crypto,
    console: ConsoleMode,
    retention_days: u32,
    maintenance_at: Instant,
}
impl Logger {
    /// Delete only records in the existing database; never remove keys/configuration
    /// or unlink a live SQLite/WAL file. Callers pause their writer before deletion.
    pub fn delete_all(path: &Path) -> io::Result<usize> {
        let dir = storage_dir(path);
        let mut db = Connection::open_with_flags(
            dir.join("events.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )
        .map_err(error)?;
        db.busy_timeout(Duration::from_secs(5)).map_err(error)?;
        let crypto = Crypto::read(&dir.join("master.key"))?;
        let sentinel: Vec<u8> = db
            .query_row("SELECT value FROM meta WHERE id=1", [], |r| r.get(0))
            .map_err(error)?;
        if crypto.open_bytes(&sentinel)? != b"famtool-v1" {
            return Err(error("日志密钥校验失败"));
        }
        db.execute_batch("PRAGMA secure_delete=ON; PRAGMA synchronous=FULL;")
            .map_err(error)?;
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(error)?;
        let count = tx.execute("DELETE FROM records", []).map_err(error)?;
        tx.commit().map_err(error)?;
        // 同步到主库文件:截断 WAL 并回收空间,否则主文件不收缩、修改时间不变,
        // 外部查看像"没有更新";secure_delete=ON 保证旧内容不残留
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
            .map_err(error)?;
        Ok(count)
    }

    /// Reading history must never create a store or change its retention policy.
    pub fn read_recent(path: &Path, limit: usize) -> io::Result<Vec<Record>> {
        let dir = storage_dir(path);
        let db = Connection::open_with_flags(
            dir.join("events.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(error)?;
        let crypto = Crypto::read(&dir.join("master.key"))?;
        Self {
            db,
            crypto,
            console: ConsoleMode::Silent,
            retention_days: 30,
            maintenance_at: Instant::now(),
        }
        .recent(limit)
    }
    pub fn new(path: &Path, console: ConsoleMode) -> io::Result<Self> {
        Self::with_retention(path, console, 30)
    }
    pub fn with_retention(
        path: &Path,
        console: ConsoleMode,
        retention_days: u32,
    ) -> io::Result<Self> {
        if !(1..=36500).contains(&retention_days) {
            return Err(error("日志保留天数必须为 1–36500"));
        }
        let dir = storage_dir(path);
        private_dir(&dir)?;
        let db_path = dir.join("events.sqlite3");
        let crypto = Crypto::open(&dir.join("master.key"), !db_path.exists())?;
        let db = Connection::open(db_path).map_err(error)?;
        db.busy_timeout(Duration::from_secs(5)).map_err(error)?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
            CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY, time_ms INTEGER NOT NULL, payload BLOB NOT NULL);
            CREATE INDEX IF NOT EXISTS records_time ON records(time_ms);").map_err(error)?;
        db.execute(
            "INSERT OR IGNORE INTO meta VALUES (1, ?1)",
            params![crypto.seal(b"famtool-v1")?],
        )
        .map_err(error)?;
        let sentinel: Vec<u8> = db
            .query_row("SELECT value FROM meta WHERE id=1", [], |r| r.get(0))
            .map_err(error)?;
        if crypto.open_bytes(&sentinel)? != b"famtool-v1" {
            return Err(error("日志密钥校验失败"));
        }
        let mut logger = Self {
            db,
            crypto,
            console,
            retention_days,
            maintenance_at: Instant::now(),
        };
        logger.prune(chrono::Utc::now().timestamp_millis())?;
        Ok(logger)
    }
    pub fn log(&mut self, rec: &Record) -> io::Result<()> {
        self.log_batch(std::slice::from_ref(rec))
    }
    /// Commit the entire batch before exposing any records to consumers.
    pub fn log_batch(&mut self, records: &[Record]) -> io::Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let tx = self.db.transaction().map_err(error)?;
        {
            let mut insert = tx
                .prepare_cached("INSERT INTO records(time_ms,payload) VALUES (?1,?2)")
                .map_err(error)?;
            for rec in records {
                let payload = self.crypto.seal(&serde_json::to_vec(rec).map_err(error)?)?;
                insert
                    .execute(params![rec.time.timestamp_millis(), payload])
                    .map_err(error)?;
            }
        }
        tx.commit().map_err(error)?;
        for rec in records {
            self.print(rec);
        }
        Ok(())
    }
    fn print(&self, rec: &Record) {
        let json = serde_json::to_vec(rec).unwrap_or_default();
        match self.console {
            ConsoleMode::Silent => {}
            ConsoleMode::Json => {
                let _ = writeln!(io::stdout().lock(), "{}", String::from_utf8_lossy(&json));
            }
            ConsoleMode::Human => {
                let mut line = format!(
                    "[{}] [{}] [{}]",
                    rec.time.format("%Y-%m-%d %H:%M:%S%.3f"),
                    event_label(&rec.event),
                    object_label(&rec.object),
                );
                if let Some(app) = &rec.actor.application {
                    line.push_str(&format!(" [{app}"));
                    if let Some(u) = rec.actor.user.as_deref().or(rec.owner.as_deref()) {
                        line.push_str(&format!("·{u}"));
                    }
                    line.push(']');
                } else if let Some(u) = &rec.owner {
                    line.push_str(&format!(" [·{u}]"));
                }
                if let Some(d) = &rec.diagnostic {
                    line.push_str(&format!(" [{} ×{}] {}", d.code, d.count, d.message));
                }
                let _ = writeln!(io::stdout().lock(), "{line} {}", rec.path);
            }
        }
    }
    pub fn maintenance(&mut self) -> io::Result<()> {
        if self.maintenance_at.elapsed() >= Duration::from_secs(60) {
            self.maintenance_at = Instant::now();
            self.prune(chrono::Utc::now().timestamp_millis())?;
        }
        Ok(())
    }
    fn prune(&mut self, now_ms: i64) -> io::Result<()> {
        let cutoff = now_ms - i64::from(self.retention_days) * 86_400_000;
        self.db
            .execute("DELETE FROM records WHERE time_ms < ?1", [cutoff])
            .map_err(error)?;
        self.db
            .execute_batch("PRAGMA wal_checkpoint(PASSIVE);")
            .map_err(error)?;
        Ok(())
    }
    pub fn recent(&self, limit: usize) -> io::Result<Vec<Record>> {
        let mut stmt = self
            .db
            .prepare("SELECT payload FROM records ORDER BY time_ms DESC, id DESC LIMIT ?1")
            .map_err(error)?;
        let rows = stmt
            .query_map([limit.min(10000) as i64], |r| r.get::<_, Vec<u8>>(0))
            .map_err(error)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                serde_json::from_slice(&self.crypto.open_bytes(&row.map_err(error)?)?)
                    .map_err(error)?,
            );
        }
        out.reverse();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> Record {
        Record {
            time: chrono::Local::now(),
            event: "created".into(),
            object: "file".into(),
            path: "/secret/private-file".into(),
            from: None,
            actor: Default::default(),
            owner: None,
            diagnostic: None,
            audit: None,
        }
    }
    #[test]
    fn durable_encrypted_retention_and_missing_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("log");
        let mut l = Logger::new(&path, ConsoleMode::Silent).unwrap();
        let mut old = record();
        old.time -= chrono::Duration::days(31);
        l.log(&old).unwrap();
        l.log(&record()).unwrap();
        drop(l);
        let l = Logger::new(&path, ConsoleMode::Silent).unwrap();
        assert_eq!(l.recent(100).unwrap().len(), 1);
        drop(l);
        for name in ["events.sqlite3", "events.sqlite3-wal"] {
            if let Ok(data) = std::fs::read(storage_dir(&path).join(name)) {
                assert!(!data
                    .windows(b"/secret/private-file".len())
                    .any(|b| b == b"/secret/private-file"));
            }
        }
        std::fs::remove_file(storage_dir(&path).join("master.key")).unwrap();
        assert!(Logger::new(&path, ConsoleMode::Silent).is_err());
    }
    #[test]
    fn tamper_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let c = Crypto::open(&tmp.path().join("key"), true).unwrap();
        let mut bytes = c.seal(b"secret").unwrap();
        assert_eq!(c.open_bytes(&bytes).unwrap(), b"secret");
        *bytes.last_mut().unwrap() ^= 1;
        assert!(c.open_bytes(&bytes).is_err());
    }
}
