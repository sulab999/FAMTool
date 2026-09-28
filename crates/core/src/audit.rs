//! 跨平台原生审计接收器:root/管理员辅助进程通过 JSON 行协议推送可信事件。
//!
//! 传输层:macOS/Linux 使用 unix 套接字(macOS 经 getpeereid、Linux 经
//! SO_PEERCRED 校验对端为 root);Windows 使用命名管道(SDDL 限制为当前
//! 用户,并经 GetNamedPipeClientProcessId 校验对端进程已提权)。
//! 协议与入库链路各平台完全一致,采集端来源由事件自带 source 标注。
// 协议类型(Wire/Scope 等)在部分目标平台上仅用于稳定序列化格式
#![cfg_attr(not(any(unix, windows)), allow(dead_code))]
use crate::{
    config::Config,
    diagnostics::{Code, Diagnostics},
    record::{Actor, Record},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
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

/// 当前平台是否存在系统审计采集通道
pub fn platform_supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux", target_os = "windows"))
}

/// 接收端点位置(unix: 套接字;windows: 命名管道名)
pub fn endpoint_path(log_file: &Path) -> PathBuf {
    crate::logger::storage_dir(log_file).join("audit.sock")
}

impl AuditStatus {
    pub fn idle(enabled: bool, log_file: &Path) -> Self {
        #[cfg(target_os = "macos")]
        let hint = "请在监控设置中申请权限并启用 root 审计服务";
        #[cfg(target_os = "linux")]
        let hint = "请在监控设置中「以管理员方式启动审计」(fanotify 采集需要 root)";
        #[cfg(target_os = "windows")]
        let hint = "请在监控设置中「以管理员方式启动审计」(安全日志采集需要管理员)";
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        let hint = "当前平台没有系统审计通道";
        Self {
            enabled,
            supported: platform_supported(),
            state: if enabled { "waiting" } else { "disabled" }.into(),
            message: if enabled { hint } else { "系统审计未启用" }.into(),
            socket_path: if cfg!(target_os = "windows") {
                String::new()
            } else {
                endpoint_path(log_file).display().to_string()
            },
            received: 0,
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Wire {
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
        /// 采集通道标识(endpoint_security / bsm_auditpipe / fanotify / security_log);
        /// 缺省 endpoint_security 以兼容旧版辅助程序
        #[serde(default)]
        source: Option<String>,
        audit: Box<Evidence>,
    },
}
#[derive(Serialize)]
pub(crate) struct Scope {
    pub(crate) protocol: u32,
    pub(crate) roots: Vec<PathBuf>,
    pub(crate) excludes: Vec<PathBuf>,
    pub(crate) recursive: bool,
    pub(crate) track_access: bool,
}

/// 路径前缀比较(Windows 文件系统大小写不敏感)
fn starts_with_dir(path: &Path, base: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let mut pc = path.components();
        let mut bc = base.components();
        loop {
            match (pc.next(), bc.next()) {
                (Some(a), Some(b)) => {
                    if !a.as_os_str().eq_ignore_ascii_case(b.as_os_str()) {
                        return false;
                    }
                }
                (None, Some(_)) => return false,
                (_, None) => return true,
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    path.starts_with(base)
}
fn same_dir(a: &Path, b: &Path) -> bool {
    starts_with_dir(a, b) && starts_with_dir(b, a)
}

impl Scope {
    fn includes(&self, path: &str) -> bool {
        let p = Path::new(path);
        p.is_absolute()
            && !self.excludes.iter().any(|e| starts_with_dir(p, e))
            && self.roots.iter().any(|r| {
                same_dir(p, r)
                    || (starts_with_dir(p, r)
                        && (self.recursive || p.parent().is_some_and(|d| same_dir(d, r))))
            })
    }
}

fn make_scope(cfg: &Config, roots: Vec<PathBuf>, excludes: Vec<PathBuf>) -> Scope {
    Scope {
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
    }
}

fn valid_source(source: &str) -> bool {
    !source.is_empty()
        && source.len() <= 32
        && source
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub(crate) fn decode_event(wire: Wire, scope: &Scope) -> Result<Option<Record>, String> {
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
        source,
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
    let source = match source.as_deref() {
        Some(s) if valid_source(s) => s.to_string(),
        Some(_) => return Err("审计事件来源标识无效".into()),
        None => "endpoint_security".into(),
    };
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
        source: Some(source),
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

fn update(state: &Mutex<AuditStatus>, name: &str, message: &str) {
    let mut s = state.lock().unwrap();
    s.state = name.into();
    s.message = message.chars().take(1024).collect();
}

/// 单条连接会话:握手 → 下发 Scope → 接收 Status/Event/Heartbeat。
/// 各平台传输(套接字/管道)仅提供 Read+Write 即可复用本循环。
fn connection<S: Read + Write>(
    stream: &mut S,
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
    let mut last = std::time::Instant::now();
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
                            let mut data = serde_json::to_vec(scope).map_err(|e| e.to_string())?;
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
                                    &format!("采集端或内核事件缺口: {dropped} 条"),
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
                    last = std::time::Instant::now();
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
        if last.elapsed() > std::time::Duration::from_secs(10) {
            return Err("审计辅助程序心跳超时".into());
        }
    }
    Ok(())
}

/// 连接中断后的统一善后状态(各平台接收循环复用)
fn after_disconnect(
    state: &Mutex<AuditStatus>,
    diagnostics: &Diagnostics,
    stop: &AtomicBool,
) {
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

pub struct AuditSession {
    state: Arc<Mutex<AuditStatus>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    /// Windows: 停止时连接管道以唤醒阻塞中的 accept
    #[cfg(target_os = "windows")]
    wake_name: Option<String>,
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
        // 平台分支会启动接收线程;无审计通道的平台仅持有状态
        #[cfg_attr(not(any(unix, windows)), allow(unused_mut))]
        let mut session = Self {
            state: state.clone(),
            stop: stop.clone(),
            thread: None,
            #[cfg(target_os = "windows")]
            wake_name: None,
        };
        if !cfg.audit_enabled {
            return session;
        }
        let scope = make_scope(cfg, roots, excludes);
        #[cfg(unix)]
        {
            let dir = crate::logger::storage_dir(&cfg.log_file);
            match unix::listener(&dir) {
                Ok((listener, path, lock)) => {
                    state.lock().unwrap().socket_path = path.display().to_string();
                    let clean_path = path.clone();
                    match std::thread::Builder::new()
                        .name("fmon-audit".into())
                        .spawn(move || {
                            let _lock = lock;
                            unix::receive(listener, &scope, tx, &diagnostics, &state, &stop);
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
        #[cfg(target_os = "windows")]
        {
            match windows_pipe::listener() {
                Ok(server) => {
                    let name = server.name().to_string();
                    state.lock().unwrap().socket_path = name.clone();
                    session.wake_name = Some(name);
                    match std::thread::Builder::new()
                        .name("fmon-audit".into())
                        .spawn(move || {
                            windows_pipe::receive(server, &scope, tx, &diagnostics, &state, &stop)
                        }) {
                        Ok(thread) => session.thread = Some(thread),
                        Err(e) => session.set_error(e.to_string()),
                    }
                }
                Err(e) => {
                    diagnostics.note(Code::AuditError, &e.to_string());
                    session.set_error(e.to_string());
                }
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (scope, tx, diagnostics);
            session.set_error("当前平台没有系统审计采集通道".into());
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
        #[cfg(target_os = "windows")]
        if let Some(name) = self.wake_name.take() {
            // accept 可能阻塞在 ConnectNamedPipe:主动连接一次使其返回
            std::thread::spawn(move || windows_pipe::wake_client(&name));
        }
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

#[cfg(unix)]
mod unix {
    use super::*;
    use fs2::FileExt;
    use std::{
        fs::{File, OpenOptions},
        os::{
            fd::AsRawFd,
            unix::{
                fs::{FileTypeExt, MetadataExt, PermissionsExt},
                net::{UnixListener, UnixStream},
            },
        },
        time::Duration,
    };
    pub(super) fn listener(dir: &Path) -> std::io::Result<(UnixListener, PathBuf, File)> {
        let dir = dunce::canonicalize(dir)?;
        let path = dir.join("audit.sock");
        if path.as_os_str().as_encoded_bytes().len() >= 100 {
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
    /// 对端身份:仅接受 root(macOS 走 getpeereid,Linux 走 SO_PEERCRED)
    fn trusted(stream: &UnixStream) -> bool {
        #[cfg(target_os = "macos")]
        {
            let mut uid = 0;
            let mut gid = 0;
            unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0 && uid == 0 }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut cred as *mut libc::ucred).cast(),
                    &mut len,
                )
            };
            rc == 0 && cred.uid == 0
        }
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
                    after_disconnect(state, diagnostics, stop);
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

#[cfg(target_os = "windows")]
mod windows_pipe {
    //! 命名管道接收器:SDDL 将管道 ACL 限制为当前用户与 SYSTEM,
    //! 再用 GetNamedPipeClientProcessId → TokenElevation 校验连接方为管理员进程。
    use super::*;
    use std::os::windows::io::RawHandle;
    use std::{io, ptr};

    const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const PIPE_TYPE_BYTE: u32 = 0;
    const PIPE_READMODE_BYTE: u32 = 0;
    const PIPE_WAIT: u32 = 0;
    const PIPE_UNLIMITED_INSTANCES: u32 = 255;
    const ERROR_PIPE_CONNECTED: u32 = 535;
    const ERROR_IO_PENDING: u32 = 998;
    const ERROR_IO_INCOMPLETE: u32 = 996;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;
    const GENERIC_READ: u32 = 0x8000_0000;
    const OPEN_EXISTING: u32 = 3;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_ELEVATION_CLASS: u32 = 20;
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

    type BOOL = i32;
    type DWORD = u32;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Overlapped {
        internal: *mut core::ffi::c_void,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: RawHandle,
    }
    #[repr(C)]
    struct SecurityAttributes {
        length: DWORD,
        security_descriptor: *mut core::ffi::c_void,
        inherit_handle: BOOL,
    }
    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: DWORD,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateNamedPipeW(
            name: *const u16,
            open_mode: DWORD,
            pipe_mode: DWORD,
            max_instances: DWORD,
            out_buffer: DWORD,
            in_buffer: DWORD,
            default_timeout: DWORD,
            sa: *const SecurityAttributes,
        ) -> RawHandle;
        fn ConnectNamedPipe(pipe: RawHandle, overlapped: *mut Overlapped) -> BOOL;
        fn DisconnectNamedPipe(pipe: RawHandle) -> BOOL;
        fn CloseHandle(handle: RawHandle) -> BOOL;
        fn CreateFileW(
            name: *const u16,
            access: DWORD,
            share: DWORD,
            sa: *const core::ffi::c_void,
            disposition: DWORD,
            flags: DWORD,
            template: RawHandle,
        ) -> RawHandle;
        fn CreateEventW(
            sa: *const core::ffi::c_void,
            manual_reset: BOOL,
            initial: BOOL,
            name: *const u16,
        ) -> RawHandle;
        fn WaitForSingleObject(handle: RawHandle, ms: DWORD) -> DWORD;
        fn ReadFile(
            file: RawHandle,
            buffer: *mut u8,
            len: DWORD,
            read: *mut DWORD,
            overlapped: *mut Overlapped,
        ) -> BOOL;
        fn WriteFile(
            file: RawHandle,
            buffer: *const u8,
            len: DWORD,
            written: *mut DWORD,
            overlapped: *mut Overlapped,
        ) -> BOOL;
        fn GetOverlappedResult(
            file: RawHandle,
            overlapped: *mut Overlapped,
            transferred: *mut DWORD,
            wait: BOOL,
        ) -> BOOL;
        fn CancelIoEx(file: RawHandle, overlapped: *mut Overlapped) -> BOOL;
        fn GetLastError() -> DWORD;
        fn GetNamedPipeClientProcessId(pipe: RawHandle, client_pid: *mut DWORD) -> BOOL;
        fn OpenProcess(access: DWORD, inherit: BOOL, pid: DWORD) -> RawHandle;
        fn OpenProcessToken(process: RawHandle, access: DWORD, token: *mut RawHandle) -> BOOL;
        fn GetTokenInformation(
            token: RawHandle,
            class: DWORD,
            info: *mut core::ffi::c_void,
            len: DWORD,
            returned: *mut DWORD,
        ) -> BOOL;
        fn GetCurrentProcess() -> RawHandle;
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl: *const u16,
            revision: DWORD,
            sd: *mut *mut core::ffi::c_void,
            size: *mut DWORD,
        ) -> BOOL;
        fn LocalFree(ptr: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
    }

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }
    fn invalid() -> RawHandle {
        -1isize as RawHandle
    }
    fn last_error() -> io::Error {
        io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
    }

    pub(super) fn pipe_name() -> String {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 ^ (std::process::id() as u64) << 16)
            .unwrap_or(0x5eed);
        // xorshift 混合出 8 位十六进制,避免管道名被预测抢占
        let mut x = seed | 1;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        format!(r"\\.\pipe\famtool-audit-{x:08x}")
    }

    /// 当前用户的 SDDL:仅当前用户与 SYSTEM 可完全控制
    fn user_sddl() -> Vec<u16> {
        let mut sid = String::from("S-1-5-18"); // 兜底:SYSTEM
        unsafe {
            let mut token = invalid();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) != 0 {
                #[repr(C)]
                struct SidAndAttributes {
                    sid: *mut core::ffi::c_void,
                    attributes: DWORD,
                }
                #[repr(C)]
                struct TokenUser {
                    user: SidAndAttributes,
                }
                let mut tu = TokenUser {
                    user: SidAndAttributes {
                        sid: ptr::null_mut(),
                        attributes: 0,
                    },
                };
                let mut ret = 0;
                if GetTokenInformation(
                    token,
                    1, // TokenUser
                    (&mut tu as *mut TokenUser).cast(),
                    std::mem::size_of::<TokenUser>() as DWORD,
                    &mut ret,
                ) != 0
                {
                    #[link(name = "advapi32")]
                    extern "system" {
                        fn ConvertSidToStringSidW(sid: *const core::ffi::c_void, str: *mut *mut u16) -> BOOL;
                    }
                    let mut str_sid: *mut u16 = ptr::null_mut();
                    if ConvertSidToStringSidW(tu.user.sid, &mut str_sid) != 0 {
                        let mut len = 0;
                        while *str_sid.add(len) != 0 {
                            len += 1;
                        }
                        sid = String::from_utf16_lossy(std::slice::from_raw_parts(str_sid, len));
                        LocalFree(str_sid as *mut _);
                    }
                }
                CloseHandle(token);
            }
        }
        wide(&format!("D:(A;;GA;;;{sid})(A;;GA;;;SY)(A;;GA;;;BA)"))
    }

    /// 管道服务端流:overlapped 读(200ms 超时→WouldBlock,供停止轮询),
    /// overlapped 写(2s 超时,与 unix 侧写超时对等)
    pub struct PipeStream {
        pipe: RawHandle,
        read_event: RawHandle,
        write_event: RawHandle,
    }
    impl PipeStream {
        fn zeroed_ov(&self, event: RawHandle) -> Overlapped {
            Overlapped {
                internal: ptr::null_mut(),
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                event,
            }
        }
    }
    impl Read for PipeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut ov = self.zeroed_ov(self.read_event);
            let mut got: DWORD = 0;
            let ok = unsafe {
                ReadFile(
                    self.pipe,
                    buf.as_mut_ptr(),
                    buf.len() as DWORD,
                    &mut got,
                    &mut ov,
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err != ERROR_IO_PENDING && err != ERROR_IO_INCOMPLETE {
                    return Err(io::Error::from_raw_os_error(err as i32));
                }
                let wait = unsafe { WaitForSingleObject(self.read_event, 200) };
                if wait == WAIT_TIMEOUT {
                    unsafe { CancelIoEx(self.pipe, &mut ov) };
                    // 取消后必须等待请求结束才能安全复用 ov/事件
                    unsafe { WaitForSingleObject(self.read_event, 1000) };
                    let mut drained = 0;
                    unsafe { GetOverlappedResult(self.pipe, &mut ov, &mut drained, 0) };
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                if wait != WAIT_OBJECT_0 {
                    return Err(io::Error::from(io::ErrorKind::Other));
                }
                let mut transferred = 0;
                if unsafe { GetOverlappedResult(self.pipe, &mut ov, &mut transferred, 0) } == 0 {
                    return Err(last_error());
                }
                got = transferred;
            }
            Ok(got as usize)
        }
    }
    impl Write for PipeStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut ov = self.zeroed_ov(self.write_event);
            let mut done: DWORD = 0;
            let ok = unsafe {
                WriteFile(
                    self.pipe,
                    buf.as_ptr(),
                    buf.len() as DWORD,
                    &mut done,
                    &mut ov,
                )
            };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err != ERROR_IO_PENDING {
                    return Err(io::Error::from_raw_os_error(err as i32));
                }
                let wait = unsafe { WaitForSingleObject(self.write_event, 2000) };
                if wait != WAIT_OBJECT_0 {
                    unsafe { CancelIoEx(self.pipe, &mut ov) };
                    unsafe { WaitForSingleObject(self.write_event, 1000) };
                    let mut drained = 0;
                    unsafe { GetOverlappedResult(self.pipe, &mut ov, &mut drained, 0) };
                    return Err(io::Error::from(io::ErrorKind::TimedOut));
                }
                let mut transferred = 0;
                if unsafe { GetOverlappedResult(self.pipe, &mut ov, &mut transferred, 0) } == 0 {
                    return Err(last_error());
                }
                done = transferred;
            }
            Ok(done as usize)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Drop for PipeStream {
        fn drop(&mut self) {
            // 让未完成的异步请求失效后再关闭句柄
            unsafe { CancelIoEx(self.pipe, ptr::null_mut()) };
            unsafe {
                CloseHandle(self.read_event);
                CloseHandle(self.write_event);
                DisconnectNamedPipe(self.pipe);
                CloseHandle(self.pipe);
            }
        }
    }

    pub struct Listener {
        name: String,
        sa: Vec<u16>,
    }
    impl Listener {
        pub fn name(&self) -> &str {
            &self.name
        }
    }
    pub(super) fn listener() -> io::Result<Listener> {
        // 用 FIRST_PIPE_INSTANCE 探测独占创建权,防止管道名被抢先注册
        let sa = user_sddl();
        let sd = create_sd(&sa)?;
        let mut last = None;
        for _ in 0..5 {
            let name = pipe_name();
            let wide_name = wide(&name);
            let handle = unsafe {
                let mut attrs = SecurityAttributes {
                    length: std::mem::size_of::<SecurityAttributes>() as DWORD,
                    security_descriptor: sd,
                    inherit_handle: 0,
                };
                CreateNamedPipeW(
                    wide_name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    8192,
                    65536,
                    0,
                    &mut attrs,
                )
            };
            if handle != invalid() {
                unsafe { CloseHandle(handle) };
                unsafe { LocalFree(sd) };
                return Ok(Listener { name, sa });
            }
            last = Some(last_error());
        }
        unsafe { LocalFree(sd) };
        Err(last.unwrap_or_else(|| io::Error::other("无法创建审计命名管道")))
    }
    fn accept_instance(l: &Listener) -> io::Result<PipeStream> {
        let name = wide(&l.name);
        let sd = create_sd(&l.sa)?;
        let handle = unsafe {
            let mut sa = SecurityAttributes {
                length: std::mem::size_of::<SecurityAttributes>() as DWORD,
                security_descriptor: sd,
                inherit_handle: 0,
            };
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                8192,
                65536,
                0,
                &mut sa,
            )
        };
        unsafe { LocalFree(sd) };
        if handle == invalid() {
            return Err(last_error());
        }
        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if event == invalid() {
            unsafe { CloseHandle(handle) };
            return Err(last_error());
        }
        let wevent = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if wevent == invalid() {
            unsafe {
                CloseHandle(event);
                CloseHandle(handle);
            };
            return Err(last_error());
        }
        let conn = unsafe { ConnectNamedPipe(handle, ptr::null_mut()) };
        if conn == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_PIPE_CONNECTED {
                unsafe {
                    CloseHandle(wevent);
                    CloseHandle(event);
                    CloseHandle(handle);
                };
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }
        Ok(PipeStream {
            pipe: handle,
            read_event: event,
            write_event: wevent,
        })
    }
    fn create_sd(sddl: &[u16]) -> io::Result<*mut core::ffi::c_void> {
        let mut sd: *mut core::ffi::c_void = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
                &mut sd,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_error());
        }
        Ok(sd)
    }
    /// 校验对端进程已提权(管理员),与 unix 侧 uid==0 校验对等
    fn trusted(pipe: &PipeStream) -> bool {
        let mut pid = 0u32;
        if unsafe { GetNamedPipeClientProcessId(pipe.pipe, &mut pid) } == 0 {
            return false;
        }
        is_elevated(pid)
    }
    fn is_elevated(pid: u32) -> bool {
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process == invalid() {
                return false;
            }
            let mut token = invalid();
            let mut elevated = false;
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) != 0 {
                let mut elev = TokenElevation {
                    token_is_elevated: 0,
                };
                let mut ret = 0;
                if GetTokenInformation(
                    token,
                    TOKEN_ELEVATION_CLASS,
                    (&mut elev as *mut TokenElevation).cast(),
                    std::mem::size_of::<TokenElevation>() as DWORD,
                    &mut ret,
                ) != 0
                {
                    elevated = elev.token_is_elevated != 0;
                }
                CloseHandle(token);
            }
            CloseHandle(process);
            elevated
        }
    }
    /// GUI 停止时唤醒阻塞的 ConnectNamedPipe
    pub(super) fn wake_client(name: &str) {
        let wide_name = wide(name);
        unsafe {
            let h = CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                invalid(),
            );
            if h != invalid() {
                CloseHandle(h);
            }
        }
    }
    pub(super) fn receive(
        l: Listener,
        scope: &Scope,
        tx: SyncSender<Vec<Record>>,
        diagnostics: &Diagnostics,
        state: &Mutex<AuditStatus>,
        stop: &AtomicBool,
    ) {
        while !stop.load(Ordering::Relaxed) {
            match accept_instance(&l) {
                Ok(mut stream) => {
                    if !trusted(&stream) {
                        diagnostics.note(Code::AuditError, "拒绝非管理员进程提交审计记录");
                        continue;
                    }
                    update(state, "connecting", "正在验证原生审计协议");
                    if let Err(e) = connection(&mut stream, scope, &tx, diagnostics, state, stop) {
                        diagnostics.note(Code::AuditError, &e);
                        update(state, "disconnected", &e);
                    }
                    after_disconnect(state, diagnostics, stop);
                }
                Err(_) if stop.load(Ordering::Relaxed) => break,
                Err(e) => {
                    diagnostics.note(Code::AuditError, &e.to_string());
                    update(state, "unavailable", &e.to_string());
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
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
    fn event_source_labels_are_honored_and_validated() {
        // 缺省 source 向后兼容为 endpoint_security
        let record = decode(event()).unwrap().unwrap();
        assert_eq!(record.actor.source.as_deref(), Some("endpoint_security"));
        for source in ["fanotify", "security_log", "bsm_auditpipe"] {
            let mut e = event();
            e["source"] = source.into();
            let record = decode(e).unwrap().unwrap();
            assert_eq!(record.actor.source.as_deref(), Some(source));
        }
        // 注入来源标识必须被拒绝(白名单字符集)
        for bad in ["ES; <script>", "UPPER", "", "a".repeat(33).as_str()] {
            let mut e = event();
            e["source"] = bad.into();
            assert!(decode(e).is_err(), "must reject source {bad:?}");
        }
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
    #[test]
    fn audit_is_supported_on_all_desktop_platforms() {
        // 接收器与状态:三平台均报告支持(通道能力由辅助程序 --check 报告)
        assert!(platform_supported());
        let dir = tempfile::tempdir().unwrap();
        let status = AuditStatus::idle(true, &dir.path().join("log"));
        assert!(status.supported);
        assert_eq!(status.state, "waiting");
        assert!(!status.message.is_empty());
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn scope_matching_is_case_insensitive_on_windows() {
        let scope = Scope {
            protocol: 1,
            roots: vec![r"C:\Watched".into()],
            excludes: vec![r"c:\watched\secret".into()],
            recursive: true,
            track_access: false,
        };
        assert!(scope.includes(r"C:\watched\A.txt"));
        assert!(scope.includes(r"c:\WATCHED\a.txt"));
        assert!(!scope.includes(r"C:\watchedx\a.txt"));
        assert!(!scope.includes(r"C:\Watched\Secret\a.txt"));
    }
}
