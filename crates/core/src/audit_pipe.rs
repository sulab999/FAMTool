//! OpenBSM 审计管道(/dev/auditpipe)采集端:无需 Apple 授权、仅需 root 的
//! 系统审计来源,作为 Endpoint Security 辅助程序在本机未获授权签名时的
//! 实际可用通道。
//!
//! 运行形态:独立辅助进程(通常由 GUI 通过系统密码框以 root 启动),
//! 连接 GUI 在 `<日志>.store/audit.sock` 上的接收器,使用与 ES 辅助程序
//! 相同的 JSON 行协议(Hello → Scope → Status running → Event/Heartbeat)。
//! GUI 侧的协议校验、路径过滤、加密入库、界面状态全部复用现有实现。
//!
//! BSM 解析基于 OpenBSM 固定 ABI;关键布局均在本机用 C 编译器实测校准:
//! header32=19B/header64=23B(event 在偏移 4),subject* 的 pid 在偏移 21,
//! fd 级路径查询必须用 proc_pidfdinfo(flavor 2,路径偏移 176)。

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

// ---- BSM token ID(SDK bsm/audit_record.h) ----
const AUT_HEADER32: u8 = 0x14;
const AUT_HEADER32_EX: u8 = 0x15;
const AUT_TRAILER: u8 = 0x13;
const AUT_PATH: u8 = 0x23;
const AUT_SUBJECT32: u8 = 0x24;
const AUT_RETURN32: u8 = 0x27;
const AUT_TEXT: u8 = 0x28;
const AUT_ARG32: u8 = 0x2d;
const AUT_ATTR32: u8 = 0x3e;
const AUT_ARG64: u8 = 0x71;
const AUT_RETURN64: u8 = 0x72;
const AUT_HEADER64: u8 = 0x74;
const AUT_HEADER64_EX: u8 = 0x79;
const AUT_SUBJECT64: u8 = 0x75;
const AUT_SUBJECT32_EX: u8 = 0x7a;
const AUT_SUBJECT64_EX: u8 = 0x7c;

// ---- 事件号(SDK bsm/audit_kevents.h) ----
const AUE_LINK: u16 = 5;
const AUE_UNLINK: u16 = 6;
const AUE_SYMLINK: u16 = 21;
const AUE_RENAME: u16 = 42;
const AUE_TRUNCATE: u16 = 43;
const AUE_MKDIR: u16 = 47;
const AUE_RMDIR: u16 = 48;
const AUE_OPEN_RW: u16 = 80;
const AUE_OPEN_RTC: u16 = 75;
const AUE_OPEN_W: u16 = 76;
const AUE_OPEN_WC: u16 = 77;
const AUE_OPEN_RWC: u16 = 81;
const AUE_OPEN_RWT: u16 = 82;
const AUE_OPEN_RWTC: u16 = 83;
const AUE_OPENAT_RTC: u16 = 273;
const AUE_OPENAT_W: u16 = 274;
const AUE_OPENAT_WC: u16 = 275;
const AUE_OPENAT_RW: u16 = 278;
const AUE_OPENAT_RWC: u16 = 279;
const AUE_OPENAT_RWT: u16 = 280;
const AUE_OPENAT_RWTC: u16 = 281;
const AUE_RENAMEAT: u16 = 282;
const AUE_UNLINKAT: u16 = 286;
const AUE_MKDIRAT: u16 = 43148;
const AUE_SYMLINKAT: u16 = 43152;

// 预选类掩码:/etc/security/audit_class — fr(读)0x01 fw(写)0x02 fc(建)0x10 fd(删)0x20
const CLASS_WRITE_CREATE_DELETE: u32 = 0x02 | 0x10 | 0x20;

/// 与 GUI 接收端约定的事件分类结果
#[derive(Debug, PartialEq)]
pub enum PipeEvent {
    Created { path: String, folder: bool },
    Modified { path: String },
    Removed { path: String, folder: bool },
    Renamed { from: String, to: String },
    Accessed { path: String },
}

/// 单条 BSM 记录的解析产物
pub struct BsmEvent {
    pub event: u16,
    pub paths: Vec<String>,
    pub pid: i32,
    pub auid: u32,
    pub euid: u32,
    pub ruid: u32,
    pub success: bool,
}

impl BsmEvent {
    pub fn to_pipe_event(&self, track_access: bool) -> Option<PipeEvent> {
        if !self.success {
            return None;
        }
        let p0 = self.paths.first()?;
        match self.event {
            AUE_MKDIR | AUE_MKDIRAT => Some(PipeEvent::Created { path: p0.clone(), folder: true }),
            AUE_LINK | AUE_SYMLINK | AUE_SYMLINKAT => {
                Some(PipeEvent::Created { path: p0.clone(), folder: false })
            }
            AUE_OPEN_RTC | AUE_OPEN_WC | AUE_OPEN_RWC | AUE_OPEN_RWTC | AUE_OPENAT_RTC
            | AUE_OPENAT_WC | AUE_OPENAT_RWC | AUE_OPENAT_RWTC => {
                Some(PipeEvent::Created { path: p0.clone(), folder: false })
            }
            AUE_UNLINK | AUE_UNLINKAT => {
                Some(PipeEvent::Removed { path: p0.clone(), folder: false })
            }
            AUE_RMDIR => Some(PipeEvent::Removed { path: p0.clone(), folder: true }),
            AUE_RENAME | AUE_RENAMEAT => {
                let to = self.paths.get(1)?;
                Some(PipeEvent::Renamed { from: p0.clone(), to: to.clone() })
            }
            AUE_TRUNCATE | AUE_OPEN_W | AUE_OPEN_RW | AUE_OPEN_RWT | AUE_OPENAT_W
            | AUE_OPENAT_RW | AUE_OPENAT_RWT => Some(PipeEvent::Modified { path: p0.clone() }),
            _ => track_access.then_some(PipeEvent::Accessed { path: p0.clone() }),
        }
    }
}

/// 解析一条 BSM 记录(auditpipe 每次 read 返回一条完整记录)。
/// 未知 token 无法确定长度时中止本记录解析,已取得的字段仍有效。
pub fn parse_record(rec: &[u8]) -> Option<BsmEvent> {
    if rec.len() < 7 {
        return None;
    }
    let event = u16::from_be_bytes([rec[4], rec[5]]);
    let mut pos = match rec[0] {
        AUT_HEADER32 => 19,
        AUT_HEADER64 => 23,
        // 罕见变体,布局不稳定,整条跳过
        AUT_HEADER32_EX | AUT_HEADER64_EX => return None,
        _ => return None,
    };
    let (mut pid, mut auid, mut euid, mut ruid) = (0i32, 0u32, u32::MAX, u32::MAX);
    let mut have_subject = false;
    let mut paths: Vec<String> = Vec::new();
    let mut success = true;
    let step = |p: usize, n: usize| (p + n <= rec.len()).then_some(p + n);
    while let Some(next) = step(pos, 0) {
        let _ = next;
        if pos >= rec.len() {
            break;
        }
        let id = rec[pos];
        match id {
            AUT_SUBJECT32 | AUT_SUBJECT32_EX => {
                if pos + 25 > rec.len() {
                    break;
                }
                let u32at = |o: usize| u32::from_be_bytes([rec[o], rec[o + 1], rec[o + 2], rec[o + 3]]);
                auid = u32at(pos + 1);
                euid = u32at(pos + 5);
                ruid = u32at(pos + 13);
                pid = u32at(pos + 21) as i32;
                have_subject = true;
                let Some(p) = step(pos, if id == AUT_SUBJECT32 { 37 } else { 53 }) else { break };
                pos = p;
            }
            AUT_SUBJECT64 | AUT_SUBJECT64_EX => {
                if pos + 29 > rec.len() {
                    break;
                }
                let u32at = |o: usize| u32::from_be_bytes([rec[o], rec[o + 1], rec[o + 2], rec[o + 3]]);
                auid = u32at(pos + 1);
                euid = u32at(pos + 5);
                ruid = u32at(pos + 13);
                pid = i64::from_be_bytes([
                    rec[pos + 21], rec[pos + 22], rec[pos + 23], rec[pos + 24],
                    rec[pos + 25], rec[pos + 26], rec[pos + 27], rec[pos + 28],
                ]) as i32;
                have_subject = true;
                let Some(p) = step(pos, if id == AUT_SUBJECT64 { 45 } else { 69 }) else { break };
                pos = p;
            }
            AUT_PATH => {
                if pos + 3 > rec.len() {
                    break;
                }
                let len = u16::from_be_bytes([rec[pos + 1], rec[pos + 2]]) as usize;
                let Some(end) = step(pos, 3 + len) else { break };
                let text = &rec[pos + 3..end];
                let text = text.strip_suffix(b"\0").unwrap_or(text);
                if let Some(nul) = text.iter().position(|b| *b == 0) {
                    paths.push(String::from_utf8_lossy(&text[..nul]).into_owned());
                } else {
                    paths.push(String::from_utf8_lossy(text).into_owned());
                }
                pos = end;
            }
            AUT_RETURN32 => {
                if pos + 6 > rec.len() {
                    break;
                }
                success = rec[pos + 1] == 0;
                let Some(p) = step(pos, 6) else { break };
                pos = p;
            }
            AUT_RETURN64 => {
                if pos + 10 > rec.len() {
                    break;
                }
                success = rec[pos + 1] == 0;
                let Some(p) = step(pos, 10) else { break };
                pos = p;
            }
            AUT_TRAILER => match step(pos, 5) {
                Some(p) => pos = p,
                None => break,
            },
            AUT_TEXT | AUT_ARG32 | AUT_ARG64 => {
                if pos + 3 > rec.len() {
                    break;
                }
                let len = u16::from_be_bytes([rec[pos + 1], rec[pos + 2]]) as usize;
                match step(pos, 3 + len) {
                    Some(p) => pos = p,
                    None => break,
                }
            }
            AUT_ATTR32 => match step(pos, 29) {
                Some(p) => pos = p,
                None => break,
            },
            _ => break,
        }
    }
    if paths.is_empty() || !have_subject {
        return None;
    }
    Some(BsmEvent { event, paths, pid, auid, euid, ruid, success })
}

// ---- auditpipe 设备 ------------------------------------------------------------

#[cfg(target_os = "macos")]
mod ffi {
    pub const AUDITPIPE_SET_PRESELECT_FLAGS: libc::c_ulong = 0x8008_4107;
    pub const AUDITPIPE_SET_PRESELECT_NAFLAGS: libc::c_ulong = 0x8008_4109;
    pub const AUDITPIPE_SET_PRESELECT_MODE: libc::c_ulong = 0x8004_410f;
    pub const AUDITPIPE_PRESELECT_MODE_LOCAL: libc::c_int = 2;
    extern "C" {
        pub fn ioctl(fd: i32, request: libc::c_ulong, ...) -> i32;
        pub fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
    }
}

/// 打开并配置 auditpipe。普通用户得到"权限拒绝"(设备为 root 0600)。
#[cfg(target_os = "macos")]
pub fn open_pipe(read_access: bool) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/auditpipe")?;
    let mut mask = CLASS_WRITE_CREATE_DELETE;
    if read_access {
        mask |= 0x01; // fr
    }
    let args = [mask, mask];
    unsafe {
        // 本机 auditd 未运行时内核审计处于关闭状态,管道收不到任何记录;
        // 用 auditon(A_SETCOND, AUC_AUDITING) 打开内核审计(仅影响记录生成,
        // 不写审计文件;管道本地预选独立于全局策略)
        let mut cond: libc::c_int = 1; // AUC_AUDITING
        const A_SETCOND: i32 = 38;
        const SYS_AUDITON: i32 = 351;
        let rc = libc::syscall(SYS_AUDITON, A_SETCOND, &mut cond as *mut libc::c_int, 4usize);
        eprintln!("audit-pipe: auditon(A_SETCOND) rc={rc}");
        // 读回验证:新系统上开关会被立即重置,表明内核审计管线已停用
        let mut now_cond: libc::c_int = 0;
        const A_GETCOND: i32 = 37;
        libc::syscall(SYS_AUDITON, A_GETCOND, &mut now_cond as *mut libc::c_int, 4usize);
        eprintln!("audit-pipe: auditon(A_GETCOND) cond={now_cond}");
        if now_cond != 1 {
            return Err(std::io::Error::other(
                "此 macOS 版本已停用 OpenBSM 内核审计(auditd 已移除、审计开关被系统重置),                 管道无法收到记录;完整系统审计需 Endpoint Security 授权(Apple 申请)",
            ));
        }
        // 必须先切到"本地预选"模式,否则管道沿用全局审计标志(默认不含文件类事件)
        if ffi::ioctl(
            f.as_raw_fd(),
            ffi::AUDITPIPE_SET_PRESELECT_MODE,
            &ffi::AUDITPIPE_PRESELECT_MODE_LOCAL,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if ffi::ioctl(f.as_raw_fd(), ffi::AUDITPIPE_SET_PRESELECT_FLAGS, args.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if ffi::ioctl(f.as_raw_fd(), ffi::AUDITPIPE_SET_PRESELECT_NAFLAGS, args.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(f)
}

/// pid → 可执行文件路径(root 可查任意进程)
#[cfg(target_os = "macos")]
pub fn executable_of(pid: i32) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = unsafe { ffi::proc_pidpath(pid, buf.as_mut_ptr(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

// ---- 辅助进程:连接 GUI 接收器并按协议推送 ------------------------------------

#[derive(Deserialize)]
pub struct Endpoint {
    pub protocol: u32,
    pub uid: u32,
    pub socket: PathBuf,
}

#[derive(Deserialize)]
pub struct Scope {
    pub protocol: u32,
    pub roots: Vec<PathBuf>,
    pub excludes: Vec<PathBuf>,
    pub recursive: bool,
    pub track_access: bool,
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

/// 读取 GUI 发布的接收端位置(audit-endpoint.json)
pub fn discover_endpoint() -> Option<Endpoint> {
    let path = crate::config::data_dir().join("audit-endpoint.json");
    let data = std::fs::read(&path).ok()?;
    let ep: Endpoint = serde_json::from_slice(&data).ok()?;
    (ep.protocol == 1).then_some(ep)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn send_json(stream: &mut UnixStream, value: &serde_json::Value) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(value).unwrap_or_default();
    line.push(b'\n');
    stream.write_all(&line)
}

/// 以 root 连接 GUI 接收器并持续推送审计事件。
/// 返回值用于测试与错误报告;正常情况下随 GUI 退出而退出。
pub fn run_helper(socket: Option<PathBuf>) -> Result<(), String> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = socket;
        return Err("OpenBSM 管道采集仅支持 macOS".into());
    }
    #[cfg(target_os = "macos")]
    {
        let root = unsafe { libc::geteuid() } == 0;
        let mut endpoint_misses = 0u32;
        loop {
            // 解析套接字路径:参数优先,否则从 endpoint 文件发现
            let sock = match socket.clone().or_else(|| discover_endpoint().map(|e| e.socket)) {
                Some(s) => s,
                None => {
                    return Err(
                        "未找到审计接收位置(audit-endpoint.json)。请先在主界面启动监控并开启审计。"
                            .into(),
                    )
                }
            };
            match UnixStream::connect(&sock) {
                Ok(mut stream) => {
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
                    match session(&mut stream, root) {
                        Ok(Termination::SocketClosed) => {
                            // GUI 重启中:等 endpoint 重新出现
                        }
                        Ok(Termination::NotPrivileged) => return Ok(()),
                        Ok(Termination::EndpointGone) | Err(_) => {
                            return Ok(());
                        }
                    }
                }
                Err(_) => {
                    endpoint_misses += 1;
                    // 接收器不在且 endpoint 文件也消失 → 退出
                    if discover_endpoint().is_none() {
                        return Ok(());
                    }
                    if endpoint_misses > 150 {
                        return Err("多次无法连接审计接收器".into());
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}

enum Termination {
    SocketClosed,
    NotPrivileged,
    EndpointGone,
}

#[cfg(target_os = "macos")]
fn session(stream: &mut UnixStream, root: bool) -> Result<Termination, String> {
    // 1) Hello
    send_json(
        stream,
        &serde_json::json!({"type":"hello","protocol":1}),
    )
    .map_err(|e| format!("发送握手失败: {e}"))?;
    // 2) 等待 Scope
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("读取监控范围失败: {e}"))?;
    if line.trim().is_empty() {
        return Ok(Termination::SocketClosed);
    }
    let scope: Scope =
        serde_json::from_str(line.trim()).map_err(|e| format!("监控范围格式错误: {e}"))?;
    if scope.protocol != 1 {
        return Err("不支持的协议版本".into());
    }
    // 3) 非 root:报告后退出
    if !root {
        send_json(
            stream,
            &serde_json::json!({"type":"status","protocol":1,"state":"not_privileged",
                "message":"OpenBSM 采集需要管理员权限:请通过主界面的管理员密码方式启动,或使用 sudo 运行本辅助程序"}),
        )
        .map_err(|e| e.to_string())?;
        eprintln!("非 root 运行,已向主界面报告 not_privileged");
        return Ok(Termination::NotPrivileged);
    }
    // 4) 打开 auditpipe
    let mut pipe = match open_pipe(scope.track_access) {
        Ok(p) => p,
        Err(e) => {
            send_json(
                stream,
                &serde_json::json!({"type":"status","protocol":1,"state":"not_permitted",
                    "message":format!("无法打开 /dev/auditpipe: {e}")}),
            )
            .map_err(|e| e.to_string())?;
            return Err(format!("auditpipe 打开失败: {e}"));
        }
    };
    send_json(
        stream,
        &serde_json::json!({"type":"status","protocol":1,"state":"running",
            "message":"OpenBSM 审计管道已连接(管理员授权)"}),
    )
    .map_err(|e| e.to_string())?;
    eprintln!("audit-pipe: running, scope roots={:?} access={}", scope.roots, scope.track_access);

    // 5) 事件循环
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(4096);
    let writer = std::thread::Builder::new()
        .name("audit-pipe-writer".into())
        .spawn({
            let mut stream = stream.try_clone().map_err(|e| e.to_string())?;
            move || {
                while let Ok(buf) = rx.recv() {
                    if stream.write_all(&buf).is_err() {
                        break;
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;
    let mut sequence: u64 = 0;
    let mut dropped: u64 = 0;
    let mut read_count: u64 = 0;
    let mut wb_count: u64 = 0;
    let mut last_beat = std::time::Instant::now();
    let mut buf = vec![0u8; 64 * 1024];
    use std::io::Read;
    use std::os::fd::AsRawFd;
    loop {
        // 该设备的 O_NONBLOCK 实测不生效(主线程会阻塞在 read),
        // 因此先用 poll 等待可读,只在有数据时读取
        let mut pfd = libc::pollfd {
            fd: pipe.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let prc = unsafe { libc::poll(&mut pfd, 1, 200) };
        if prc <= 0 || pfd.revents & libc::POLLIN == 0 {
            // 无数据:落入心跳/退出检查
            if last_beat.elapsed() >= Duration::from_secs(2) {
                eprintln!(
                    "audit-pipe: idle sent={sequence} dropped={dropped} endpoint={}",
                    discover_endpoint().is_some()
                );
                let beat = serde_json::json!({"type":"heartbeat","protocol":1,"dropped":dropped});
                let mut line = serde_json::to_vec(&beat).unwrap_or_default();
                line.push(b'\n');
                if tx.try_send(line).is_err() {
                    break;
                }
                last_beat = std::time::Instant::now();
            }
            if discover_endpoint().is_none() {
                drop(tx);
                let _ = writer.join();
                return Ok(Termination::EndpointGone);
            }
            continue;
        }
        match pipe.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                read_count += 1;
                if let Some(ev) = parse_record(&buf[..n]) {
                    match emit(&ev, &scope, &mut sequence, &tx) {
                        Emit::Sent => {}
                        Emit::Dropped => dropped += 1,
                        Emit::SocketClosed => break,
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {
                wb_count += 1;
            }
            Err(_) => {
                dropped += 1;
            }
        }
        if last_beat.elapsed() >= Duration::from_secs(2) {
            eprintln!(
                "audit-pipe: sent={sequence} dropped={dropped} reads={read_count} wouldblock={wb_count} endpoint={}",
                discover_endpoint().is_some()
            );
            let beat = serde_json::json!({"type":"heartbeat","protocol":1,"dropped":dropped});
            let mut line = serde_json::to_vec(&beat).unwrap_or_default();
            line.push(b'\n');
            if tx.try_send(line).is_err() {
                break;
            }
            last_beat = std::time::Instant::now();
        }
        // GUI 退出(endpoint 清理)→ 结束
        if discover_endpoint().is_none() {
            drop(tx);
            let _ = writer.join();
            return Ok(Termination::EndpointGone);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(tx);
    let _ = writer.join();
    Ok(Termination::SocketClosed)
}

enum Emit {
    Sent,
    Dropped,
    SocketClosed,
}

#[cfg(target_os = "macos")]
fn emit(
    ev: &BsmEvent,
    scope: &Scope,
    sequence: &mut u64,
    tx: &std::sync::mpsc::SyncSender<Vec<u8>>,
) -> Emit {
    let Some(pipe_ev) = ev.to_pipe_event(scope.track_access) else {
        return Emit::Dropped;
    };
    // 双端过滤:辅助进程侧先按范围过滤
    let (path, from) = match &pipe_ev {
        PipeEvent::Renamed { from, to } => (to.clone(), Some(from.clone())),
        PipeEvent::Created { path, .. }
        | PipeEvent::Modified { path }
        | PipeEvent::Removed { path, .. }
        | PipeEvent::Accessed { path } => (path.clone(), None),
    };
    if !scope.includes(&path) && !from.as_deref().is_some_and(|f| scope.includes(f)) {
        return Emit::Dropped;
    }
    // 进程身份:执行文件必须可解析(协议校验要求绝对路径)
    let Some(exe) = executable_of(ev.pid) else {
        return Emit::Dropped;
    };
    let user = crate::attributor::uid_to_name(ev.euid).unwrap_or_default();
    let owner = crate::attributor::uid_to_name(
        std::fs::symlink_metadata(&path)
            .ok()
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.uid()
            })
            .unwrap_or(ev.euid),
    )
    .unwrap_or_default();
    let parent = parent_ref(ev.pid);
    *sequence += 1;
    let (event_label, object) = match &pipe_ev {
        PipeEvent::Created { folder, .. } => ("created", if *folder { "folder" } else { "file" }),
        PipeEvent::Modified { .. } => ("modified", "file"),
        PipeEvent::Removed { folder, .. } => ("removed", if *folder { "folder" } else { "file" }),
        PipeEvent::Renamed { .. } => ("renamed", "file"),
        PipeEvent::Accessed { .. } => ("accessed", "file"),
    };
    let value = serde_json::json!({
        "type":"event","protocol":1,"time_ms":now_ms(),
        "event":event_label,"path":path,"from":from,
        "object":object,"user":user,"owner":owner,"path_truncated":false,
        "audit":{
            "event_type":ev.event,"pid":ev.pid,"pid_version":0,
            "executable":exe,"uid":ev.euid,"real_uid":ev.ruid,"audit_uid":ev.auid,
            "parent":parent,"responsible":null,
            "signing_id":"","team_id":"",
            "sequence":*sequence,"global_sequence":*sequence,"mach_time":0
        }
    });
    let mut line = serde_json::to_vec(&value).unwrap_or_default();
    line.push(b'\n');
    match tx.try_send(line) {
        Ok(()) => Emit::Sent,
        Err(_) => Emit::SocketClosed,
    }
}

/// 父进程引用(ppid 经 PROC_PIDTBSDINFO 偏移 16 获取)
#[cfg(target_os = "macos")]
fn parent_ref(pid: i32) -> serde_json::Value {
    let mut bsd = [0u8; 256];
    const PROC_PIDTBSDINFO: i32 = 3;
    extern "C" {
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut core::ffi::c_void,
            buffersize: i32,
        ) -> i32;
    }
    let got = unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, bsd.as_mut_ptr().cast(), bsd.len() as i32) };
    if got < 24 {
        return serde_json::Value::Null;
    }
    let ppid = u32::from_be_bytes([bsd[16], bsd[17], bsd[18], bsd[19]]) as i64;
    if ppid <= 0 {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "pid": ppid, "pid_version": 0,
        "executable": executable_of(ppid as i32),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16b(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }
    fn u32b(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }
    fn subject32(pid: i32, auid: u32, euid: u32, ruid: u32) -> Vec<u8> {
        let mut t = vec![AUT_SUBJECT32];
        t.extend_from_slice(&u32b(auid));
        t.extend_from_slice(&u32b(euid));
        t.extend_from_slice(&u32b(20)); // egid
        t.extend_from_slice(&u32b(ruid));
        t.extend_from_slice(&u32b(20)); // rgid
        t.extend_from_slice(&u32b(pid as u32));
        t.extend_from_slice(&u32b(0)); // sid
        t.extend_from_slice(&u32b(0)); // tid
        t.extend_from_slice(&u32b(0));
        t
    }
    fn path_token(p: &str) -> Vec<u8> {
        let mut t = vec![AUT_PATH];
        t.extend_from_slice(&u16b((p.len() + 1) as u16));
        t.extend_from_slice(p.as_bytes());
        t.push(0);
        t
    }
    fn record(event: u16, tokens: &[&[u8]]) -> Vec<u8> {
        let mut rec = vec![AUT_HEADER32];
        rec.extend_from_slice(&[0, 0]);
        rec.push(11);
        rec.extend_from_slice(&u16b(event));
        rec.push(0);
        rec.extend_from_slice(&u32b(0));
        rec.extend_from_slice(&u32b(0));
        rec.extend_from_slice(&u32b(0));
        for t in tokens {
            rec.extend_from_slice(t);
        }
        let total = rec.len() + 5;
        rec[1..3].copy_from_slice(&u16b(total as u16));
        rec.extend_from_slice(&[AUT_TRAILER, 0, 5, 0xb1, 0x05]);
        rec
    }

    #[test]
    fn unlink_with_identity() {
        let rec = record(
            AUE_UNLINK,
            &[&subject32(1234, 501, 501, 501), &path_token("/private/tmp/x.txt")],
        );
        let ev = parse_record(&rec).unwrap();
        assert_eq!(ev.pid, 1234);
        assert_eq!(ev.euid, 501);
        assert_eq!(ev.paths, vec!["/private/tmp/x.txt"]);
        assert_eq!(
            ev.to_pipe_event(false),
            Some(PipeEvent::Removed { path: "/private/tmp/x.txt".into(), folder: false })
        );
    }

    #[test]
    fn rename_pairs_paths_in_order() {
        let rec = record(
            AUE_RENAME,
            &[
                &subject32(7, 501, 501, 501),
                &path_token("/private/tmp/a"),
                &path_token("/private/tmp/b"),
            ],
        );
        let ev = parse_record(&rec).unwrap();
        assert_eq!(
            ev.to_pipe_event(false),
            Some(PipeEvent::Renamed { from: "/private/tmp/a".into(), to: "/private/tmp/b".into() })
        );
    }

    #[test]
    fn mkdir_and_create_labels() {
        let rec = record(AUE_MKDIR, &[&subject32(1, 0, 0, 0), &path_token("/tmp/d")]);
        assert_eq!(
            parse_record(&rec).unwrap().to_pipe_event(false),
            Some(PipeEvent::Created { path: "/tmp/d".into(), folder: true })
        );
        let rec = record(AUE_OPEN_WC, &[&subject32(1, 0, 0, 0), &path_token("/tmp/n")]);
        assert_eq!(
            parse_record(&rec).unwrap().to_pipe_event(false),
            Some(PipeEvent::Created { path: "/tmp/n".into(), folder: false })
        );
    }

    #[test]
    fn failed_syscall_skipped_and_reads_gated() {
        let mut ret = vec![AUT_RETURN32, 2];
        ret.extend_from_slice(&u32b(0));
        let rec = record(AUE_UNLINK, &[&subject32(1, 0, 0, 0), &path_token("/x"), &ret]);
        assert!(parse_record(&rec).unwrap().to_pipe_event(false).is_none());
        let rec = record(72, &[&subject32(1, 0, 0, 0), &path_token("/r")]); // AUE_OPEN_R
        assert!(parse_record(&rec).unwrap().to_pipe_event(false).is_none());
        assert!(parse_record(&rec).unwrap().to_pipe_event(true).is_some());
    }

    #[test]
    fn header64_and_unknown_token() {
        let mut rec = vec![AUT_HEADER64];
        rec.extend_from_slice(&[0, 0]);
        rec.push(11);
        rec.extend_from_slice(&u16b(AUE_TRUNCATE));
        rec.push(0);
        rec.extend_from_slice(&[0u8; 8]);
        rec.extend_from_slice(&u32b(0));
        rec.extend_from_slice(&u32b(0));
        rec.extend_from_slice(&subject32(5, 501, 501, 501));
        rec.extend_from_slice(&path_token("/t"));
        assert_eq!(
            parse_record(&rec).unwrap().to_pipe_event(false),
            Some(PipeEvent::Modified { path: "/t".into() })
        );
        // 未知 token 截断解析:path 丢失的记录整体丢弃
        let rec = record(AUE_UNLINK, &[&subject32(2, 0, 0, 0), &[0x99u8], &path_token("/y")]);
        assert!(parse_record(&rec).is_none());
    }
}

#[cfg(all(test, target_os = "macos"))]
mod handshake_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    #[test]
    fn helper_handshake_then_not_privileged_without_root() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root 环境下该路径不可测(会直接打开 auditpipe)
        }
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("s");
        let listener = UnixListener::bind(&sock).unwrap();
        let sock2 = sock.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<String>();
        let helper = std::thread::spawn(move || {
            let result = run_helper(Some(sock2)).err().unwrap_or_default();
            let _ = done_tx.send(result);
        });
        let (mut stream, _) = listener.accept().unwrap();
        // 1) Hello
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("\"hello\""), "应先收到 hello: {line}");
        // 2) 下发 Scope
        let scope = serde_json::json!({
            "protocol":1,"roots":["/private/tmp"],"excludes":[],
            "recursive":true,"track_access":false
        });
        stream
            .write_all(format!("{scope}\n").as_bytes())
            .unwrap();
        // 3) 应收到 not_privileged 状态后辅助进程退出
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("\"not_privileged\""), "非 root 应报告状态: {line}");
        drop(listener);
        helper.join().unwrap();
        assert!(done_rx.recv().unwrap().is_empty(), "非 root 路径应正常退出");
    }
}
