//! macOS native Endpoint Security receiver. Only root peers may provide evidence.
// 协议类型(Wire/Scope 等)仅在 macOS 接收器中消费;其他平台保留完整定义以稳定序列化格式
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use crate::{
    config::Config,
    diagnostics::Diagnostics,
    record::{Actor, Record},
};
#[cfg(target_os = "macos")]
use crate::diagnostics::Code;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
        Arc, Mutex,
    },
    thread::JoinHandle,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessRef {
    pub pid: u32,
    pub pid_version: Option<u32>,
    pub executable: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub event_type: u32,
    pub pid: u32,
    pub pid_version: u32,
    pub executable: String,
    pub uid: u32,
    pub real_uid: u32,
    pub audit_uid: u32,
    pub parent: Option<ProcessRef>,
    pub responsible: Option<ProcessRef>,
    pub signing_id: String,
    pub team_id: String,
    pub sequence: u64,
    pub global_sequence: u64,
    pub mach_time: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct AuditStatus {
    pub enabled: bool,
    pub supported: bool,
    pub state: String,
    pub message: String,
    pub socket_path: String,
    pub received: u64,
}
impl AuditStatus {
    pub fn idle(enabled: bool, log_file: &Path) -> Self {
        Self {
            enabled,
            supported: cfg!(target_os = "macos"),
            state: if enabled { "waiting" } else { "disabled" }.into(),
            message: if enabled {
                "请在监控设置中申请权限并启用 root 审计服务"
            } else {
                "系统审计未启用"
            }
            .into(),
            socket_path: crate::logger::storage_dir(log_file)
                .join("audit.sock")
                .display()
                .to_string(),
            received: 0,
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Wire {
    Hello {
        protocol: u32,
    },
    Status {
        protocol: u32,
        state: String,
        message: String,
    },
    Heartbeat {
        protocol: u32,
        dropped: u64,
    },
    Event {
        protocol: u32,
        time_ms: i64,
        event: String,
        path: String,
        from: Option<String>,
        object: String,
        user: String,
        owner: String,
        path_truncated: bool,
        audit: Box<Evidence>,
    },
}
#[derive(Serialize)]
struct Scope {
    protocol: u32,
    roots: Vec<PathBuf>,
    excludes: Vec<PathBuf>,
    recursive: bool,
    track_access: bool,
}
impl Scope {
    fn includes(&self, path: &str) -> bool {
        let p = Path::new(path);
        p.is_absolute()
            && !self.excludes.iter().any(|e| p.starts_with(e))
            && self.roots.iter().any(|r| {
                p == r || (p.starts_with(r) && (self.recursive || p.parent() == Some(r.as_path())))
            })
    }
}
fn decode_event(wire: Wire, scope: &Scope) -> Result<Option<Record>, String> {
    let Wire::Event {
        protocol,
        time_ms,
        event,
        path,
        from,
        object,
        user,
        owner,
        path_truncated,
        audit,
    } = wire
    else {
        return Ok(None);
    };
    if protocol != 1
        || path_truncated
        || audit.pid == 0
        || !Path::new(&audit.executable).is_absolute()
    {
        return Err("审计事件协议、身份或完整路径无效".into());
    }
    if !matches!(
        event.as_str(),
        "created" | "modified" | "removed" | "renamed" | "accessed"
    ) || !matches!(object.as_str(), "file" | "folder" | "unknown")
    {
        return Err("不支持的审计事件类型".into());
    }
    if !Path::new(&path).is_absolute()
        || from.as_deref().is_some_and(|p| !Path::new(p).is_absolute())
    {
        return Err("审计路径必须为绝对路径".into());
    }
    if event == "accessed" && !scope.track_access {
        return Ok(None);
    }
    if !scope.includes(&path) && !from.as_deref().is_some_and(|p| scope.includes(p)) {
        return Ok(None);
    }
    let time = chrono::DateTime::from_timestamp_millis(time_ms)
        .ok_or("审计时间无效")?
        .with_timezone(&chrono::Local);
    let app = Path::new(&audit.executable)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| audit.executable.clone());
    let actor = Actor {
        process_id: Some(audit.pid),
        application: Some(app),
        user: Some(user),
        source: Some("endpoint_security".into()),
    };
    Ok(Some(Record {
        time,
        event,
        object,
        path,
        from,
        actor,
        owner: Some(owner),
        diagnostic: None,
        audit: Some(audit),
    }))
}

pub struct AuditSession {
    state: Arc<Mutex<AuditStatus>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl AuditSession {
    pub fn start(
        cfg: &Config,
        roots: Vec<PathBuf>,
        excludes: Vec<PathBuf>,
        tx: SyncSender<Vec<Record>>,
        diagnostics: Arc<Diagnostics>,
    ) -> Self {
        let state = Arc::new(Mutex::new(AuditStatus::idle(
            cfg.audit_enabled,
            &cfg.log_file,
        )));
        let stop = Arc::new(AtomicBool::new(false));
        // macOS 分支会重排 thread 字段并启动线程,其余平台仅持有状态
        #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
        let mut session = Self {
            state: state.clone(),
            stop: stop.clone(),
            thread: None,
        };
        if !cfg.audit_enabled {
            return session;
        }
        #[cfg(target_os = "macos")]
        {
            let scope = Scope {
                protocol: 1,
                roots,
                excludes: excludes
                    .into_iter()
                    .map(|p| {
                        if p.is_absolute() {
                            p
                        } else {
                            std::env::current_dir().unwrap_or_default().join(p)
                        }
                    })
                    .collect(),
                recursive: cfg.recursive,
                track_access: cfg.track_access,
            };
            let dir = crate::logger::storage_dir(&cfg.log_file);
            match macos::listener(&dir) {
                Ok((listener, path, lock)) => {
                    state.lock().unwrap().socket_path = path.display().to_string();
                    let clean_path = path.clone();
                    match std::thread::Builder::new()
                        .name("fmon-audit".into())
                        .spawn(move || {
                            let _lock = lock;
                            macos::receive(listener, &scope, tx, &diagnostics, &state, &stop);
                            let _ = std::fs::remove_file(path);
                        }) {
                        Ok(thread) => session.thread = Some(thread),
                        Err(e) => {
                            let _ = std::fs::remove_file(clean_path);
                            session.set_error(e.to_string());
                        }
                    }
                }
                Err(e) => {
                    diagnostics.note(Code::AuditError, &e.to_string());
                    session.set_error(e.to_string());
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (roots, excludes, tx, diagnostics);
            session.set_error("当前版本的原生审计仅支持 macOS Endpoint Security".into());
        }
        session
    }
    fn set_error(&self, message: String) {
        let mut s = self.state.lock().unwrap();
        s.state = "unavailable".into();
        s.message = message;
    }
    pub fn status(&self) -> AuditStatus {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}
impl Drop for AuditSession {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use fs2::FileExt;
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Write},
        os::{
            fd::AsRawFd,
            unix::{
                fs::{FileTypeExt, MetadataExt, PermissionsExt},
                net::{UnixListener, UnixStream},
            },
        },
        time::{Duration, Instant},
    };
    pub(super) fn listener(dir: &Path) -> std::io::Result<(UnixListener, PathBuf, File)> {
        let dir = dunce::canonicalize(dir)?;
        let path = dir.join("audit.sock");
        if path.as_os_str().as_encoded_bytes().len() >= 104 {
            return Err(std::io::Error::other(
                "审计套接字路径过长，请使用较短的日志位置",
            ));
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join("audit.lock"))?;
        lock.try_lock_exclusive()?;
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
                return Err(std::io::Error::other("拒绝覆盖非本用户的审计套接字"));
            }
            if UnixStream::connect(&path).is_ok() {
                return Err(std::io::Error::other("已有审计接收器运行"));
            }
            std::fs::remove_file(&path)?;
        }
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok((listener, path, lock))
    }
    fn trusted(stream: &UnixStream) -> bool {
        let mut uid = 0;
        let mut gid = 0;
        unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0 && uid == 0 }
    }
    fn update(state: &Mutex<AuditStatus>, name: &str, message: &str) {
        let mut s = state.lock().unwrap();
        s.state = name.into();
        s.message = message.chars().take(1024).collect();
    }
    pub(super) fn receive(
        listener: UnixListener,
        scope: &Scope,
        tx: SyncSender<Vec<Record>>,
        diagnostics: &Diagnostics,
        state: &Mutex<AuditStatus>,
        stop: &AtomicBool,
    ) {
        while !stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if !trusted(&stream) {
                        diagnostics.note(Code::AuditError, "拒绝非 root 进程提交审计记录");
                        continue;
                    }
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    update(state, "connecting", "正在验证原生审计协议");
                    if let Err(e) = connection(&mut stream, scope, &tx, diagnostics, state, stop) {
                        diagnostics.note(Code::AuditError, &e);
                        update(state, "disconnected", &e);
                    }
                    let current = state.lock().unwrap().state.clone();
                    if matches!(current.as_str(), "running" | "connecting") {
                        if !stop.load(Ordering::Relaxed) {
                            diagnostics.note(Code::AuditError, "原生审计连接已断开");
                        }
                        update(
                            state,
                            "waiting",
                            "审计连接已断开，等待辅助程序重新连接；普通文件监控继续运行",
                        );
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(e) => {
                    diagnostics.note(Code::AuditError, &e.to_string());
                    update(state, "unavailable", &e.to_string());
                    break;
                }
            }
        }
    }
    fn connection(
        stream: &mut UnixStream,
        scope: &Scope,
        tx: &SyncSender<Vec<Record>>,
        diagnostics: &Diagnostics,
        state: &Mutex<AuditStatus>,
        stop: &AtomicBool,
    ) -> Result<(), String> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut hello = false;
        let mut running = false;
        let mut last = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            match stream.read(&mut chunk) {
                Ok(0) => {
                    return if buffer.is_empty() {
                        Ok(())
                    } else {
                        Err("审计连接在消息完成前中断".into())
                    }
                }
                Ok(n) => {
                    buffer.extend_from_slice(&chunk[..n]);
                    while let Some(pos) = buffer.iter().position(|b| *b == b'\n') {
                        if pos > 65535 {
                            return Err("审计消息超过大小限制".into());
                        }
                        let bytes: Vec<u8> = buffer.drain(..=pos).collect();
                        let wire: Wire = serde_json::from_slice(&bytes)
                            .map_err(|e| format!("无效审计消息: {e}"))?;
                        match wire {
                            Wire::Hello { protocol: 1 } if !hello => {
                                hello = true;
                                let mut data =
                                    serde_json::to_vec(scope).map_err(|e| e.to_string())?;
                                data.push(b'\n');
                                stream.write_all(&data).map_err(|e| e.to_string())?;
                            }
                            Wire::Status {
                                protocol: 1,
                                state: name,
                                message,
                            } if hello => {
                                if !matches!(
                                    name.as_str(),
                                    "running"
                                        | "not_entitled"
                                        | "not_permitted"
                                        | "not_privileged"
                                        | "too_many_clients"
                                        | "failed"
                                ) {
                                    return Err("未知审计状态".into());
                                }
                                running = name == "running";
                                update(state, &name, &message);
                                if !running {
                                    diagnostics.note(Code::AuditError, &message);
                                }
                            }
                            Wire::Heartbeat {
                                protocol: 1,
                                dropped,
                            } if hello && running => {
                                if dropped > 0 {
                                    diagnostics.note(
                                        Code::AuditGap,
                                        &format!("辅助程序或 ES 序列缺口: {dropped} 条"),
                                    );
                                }
                            }
                            event @ Wire::Event { .. } if hello && running => {
                                if let Some(record) = decode_event(event, scope)? {
                                    match tx.try_send(vec![record]) {
                                        Ok(()) => state.lock().unwrap().received += 1,
                                        Err(std::sync::mpsc::TrySendError::Full(_)) => diagnostics
                                            .note(
                                                Code::AuditGap,
                                                "审计入库队列已满，一条审计记录未入队",
                                            ),
                                        Err(_) => return Ok(()),
                                    }
                                }
                            }
                            _ => return Err("审计握手顺序或协议版本无效".into()),
                        }
                        last = Instant::now();
                    }
                    if buffer.len() > 65535 {
                        return Err("审计消息超过大小限制".into());
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(e) => return Err(e.to_string()),
            }
            if last.elapsed() > Duration::from_secs(10) {
                return Err("审计辅助程序心跳超时".into());
            }
        }
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn rejects_unprivileged_peer_and_releases_socket_lock() {
            let dir = tempfile::tempdir().unwrap();
            let (listener, path, lock) = listener(dir.path()).unwrap();
            let client = UnixStream::connect(&path).unwrap();
            let (server, _) = listener.accept().unwrap();
            if unsafe { libc::geteuid() } != 0 {
                assert!(!trusted(&server));
            }
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert!(super::listener(dir.path()).is_err());
            drop(client);
            drop(server);
            drop(listener);
            drop(lock);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> Scope {
        Scope {
            protocol: 1,
            roots: vec!["/watched".into()],
            excludes: vec!["/watched/secret".into()],
            recursive: true,
            track_access: false,
        }
    }
    fn event() -> serde_json::Value {
        serde_json::json!({
            "type":"event","protocol":1,"time_ms":chrono::Local::now().timestamp_millis(),"event":"removed","path":"/watched/授权书_副本.png","object":"file","user":"alice","owner":"bob","path_truncated":false,
            "audit":{"event_type":46,"pid":5678,"pid_version":12,"executable":"/bin/rm","uid":501,"real_uid":501,"audit_uid":501,"parent":{"pid":4321,"pid_version":9,"executable":"/bin/zsh"},"responsible":{"pid":123,"pid_version":4,"executable":"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"},"signing_id":"com.apple.rm","team_id":"","sequence":4,"global_sequence":8,"mach_time":99}
        })
    }
    fn decode(value: serde_json::Value) -> Result<Option<Record>, String> {
        decode_event(serde_json::from_value(value).unwrap(), &scope())
    }
    #[test]
    fn unlink_identity_survives_encryption_and_is_searchable() {
        let record = decode(event()).unwrap().unwrap();
        assert_eq!(record.actor.application.as_deref(), Some("rm"));
        assert_eq!(record.actor.user.as_deref(), Some("alice"));
        assert_eq!(record.owner.as_deref(), Some("bob"));
        assert_eq!(record.actor.source.as_deref(), Some("endpoint_security"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log");
        let mut logger =
            crate::logger::Logger::new(&path, crate::logger::ConsoleMode::Silent).unwrap();
        logger.log(&record).unwrap();
        drop(logger);
        let restored = crate::logger::Logger::read_recent(&path, 10).unwrap();
        assert_eq!(restored[0].audit.as_ref().unwrap().pid_version, 12);
        assert_eq!(
            restored[0]
                .audit
                .as_ref()
                .unwrap()
                .parent
                .as_ref()
                .unwrap()
                .pid,
            4321
        );
        let q = crate::search::Query {
            application: "Terminal".into(),
            ..Default::default()
        };
        let cancel = AtomicBool::new(false);
        let index = crate::search::build_index(&path, &q, &cancel, |_, _| {}).unwrap();
        assert_eq!(index.page(1, &cancel).unwrap().total, 1);
        let bytes =
            std::fs::read(crate::logger::storage_dir(&path).join("events.sqlite3")).unwrap();
        assert!(!bytes.windows(b"/bin/rm".len()).any(|w| w == b"/bin/rm"));
    }
    #[test]
    fn invalid_or_out_of_scope_audit_events_are_not_attributed() {
        let mut e = event();
        e["path"] = "/other/secret.png".into();
        assert!(decode(e).unwrap().is_none());
        let mut e = event();
        e["path"] = "/watched/secret/a.png".into();
        assert!(decode(e).unwrap().is_none());
        let mut e = event();
        e["path_truncated"] = true.into();
        assert!(decode(e).is_err());
        let mut e = event();
        e["protocol"] = 2.into();
        assert!(decode(e).is_err());
        let mut e = event();
        e["audit"]["pid"] = 0.into();
        assert!(decode(e).is_err());
        let mut e = event();
        e["path"] = "relative.png".into();
        assert!(decode(e).is_err());
    }
    #[test]
    fn legacy_records_remain_without_audit_evidence() {
        let record:Record=serde_json::from_value(serde_json::json!({"time":chrono::Local::now(),"event":"removed","object":"file","path":"/old","from":null})).unwrap();
        assert!(record.audit.is_none());
        assert!(record.actor.source.is_none());
    }
    #[test]
    fn disabled_receiver_creates_no_socket() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = Config {
            audit_enabled: false,
            log_file: dir.path().join("log"),
            ..Default::default()
        };
        let (tx, _) = std::sync::mpsc::sync_channel(1);
        let a = AuditSession::start(&cfg, vec![], vec![], tx, Arc::new(Diagnostics::default()));
        assert_eq!(a.status().state, "disabled");
        assert!(!crate::logger::storage_dir(&cfg.log_file).exists());
    }
}
