//! 系统审计辅助进程(以 root/管理员运行):连接 GUI 接收器,按与 Endpoint
//! Security 辅助程序相同的 JSON 行协议(Hello → Scope → Status running →
//! Event/Heartbeat)推送带权威进程身份的事件。
//!
//! 各平台采集通道:
//!   macOS   OpenBSM 审计管道 /dev/auditpipe(BSM 记录解析,布局以 C 实测校准)
//!   Linux   fanotify(FAN_REPORT_FH|DIR_FID|PIDFD + 文件系统级标记,
//!           /proc/<pid>/exe 归因;纯解析函数可在任意宿主平台测试)
//!   Windows SACL + 安全日志 4660/4663(auditpol + PowerShell 配置,
//!           wevtapi 订阅;XML 解析为纯函数可在宿主平台测试)
//!
//! GUI 侧的协议校验、路径过滤、加密入库、界面状态全部复用接收器实现。

use serde::Deserialize;
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// ---- 与 GUI 接收端约定的通用类型 --------------------------------------------

#[derive(Deserialize)]
pub struct Endpoint {
    pub protocol: u32,
    #[allow(dead_code)]
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
    pub fn includes(&self, path: &str) -> bool {
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

/// 读取 GUI 发布的接收端位置(audit-endpoint.json)
pub fn discover_endpoint() -> Option<Endpoint> {
    let path = crate::config::data_dir().join("audit-endpoint.json");
    let data = std::fs::read(&path).ok()?;
    let ep: Endpoint = serde_json::from_slice(&data).ok()?;
    (ep.protocol == 1).then_some(ep)
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub(crate) fn send_json<W: Write>(w: &mut W, value: &serde_json::Value) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(value).unwrap_or_default();
    line.push(b'\n');
    w.write_all(&line)
}

/// 一条已归因事件的通用字段,由各平台采集通道填充
pub(crate) struct EventBits {
    pub(crate) event: &'static str,
    pub(crate) path: String,
    pub(crate) from: Option<String>,
    pub(crate) object: &'static str,
    pub(crate) user: String,
    pub(crate) owner: String,
    /// 事件类型码(macOS: BSM 事件号;Linux: fanotify mask 低位;Windows: 访问掩码)
    pub(crate) event_type: u32,
    pub(crate) pid: u32,
    pub(crate) exe: String,
    pub(crate) uid: u32,
    pub(crate) real_uid: u32,
    pub(crate) audit_uid: u32,
    pub(crate) parent: Option<serde_json::Value>,
    /// 采集通道标识(随事件推送,GUI 校验白名单后写入 actor.source)
    pub(crate) source: &'static str,
}

pub(crate) fn wire_line(bits: &EventBits, sequence: u64) -> Vec<u8> {
    let value = serde_json::json!({
        "type":"event","protocol":1,"time_ms":now_ms(),
        "source":bits.source,
        "event":bits.event,"path":bits.path,"from":bits.from,
        "object":bits.object,"user":bits.user,"owner":bits.owner,"path_truncated":false,
        "audit":{
            "event_type":bits.event_type,"pid":bits.pid,"pid_version":0,
            "executable":bits.exe,"uid":bits.uid,"real_uid":bits.real_uid,
            "audit_uid":bits.audit_uid,
            "parent":bits.parent,"responsible":null,
            "signing_id":"","team_id":"",
            "sequence":sequence,"global_sequence":sequence,"mach_time":0
        }
    });
    let mut line = serde_json::to_vec(&value).unwrap_or_default();
    line.push(b'\n');
    line
}

/// 文件属主用户名(best-effort;Windows 通道未取属主,GUI 用户列回落到进程用户)
#[cfg(unix)]
pub(crate) fn owner_name(path: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if let Some(n) = crate::attributor::uid_to_name(m.uid()) {
            return n;
        }
    }
    let _ = path;
    String::new()
}

// ---- 平台采集通道 -------------------------------------------------------------

pub(crate) trait Collector {
    /// 非阻塞采集:把范围内事件的协议行追加到 out
    fn collect(&mut self, scope: &Scope, sequence: &mut u64, out: &mut Vec<Vec<u8>>) -> Result<(), String>;
    /// 累计丢弃/缺口条数(随心跳上报)
    fn dropped(&mut self) -> u64 {
        0
    }
}

fn open_collector(scope: &Scope) -> Result<Box<dyn Collector>, String> {
    #[cfg(target_os = "macos")]
    {
        bsm::BsmCollector::open(scope).map(|c| Box::new(c) as Box<dyn Collector>)
    }
    #[cfg(target_os = "linux")]
    {
        crate::audit_fanotify::FanotifyCollector::open(scope)
            .map(|c| Box::new(c) as Box<dyn Collector>)
    }
    #[cfg(target_os = "windows")]
    {
        crate::audit_security_log::SecurityLogCollector::open(scope)
            .map(|c| Box::new(c) as Box<dyn Collector>)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = scope;
        Err("当前平台没有系统审计采集通道".into())
    }
}

/// 本进程是否具备采集权限(root / 已提权)
fn privileged() -> bool {
    #[cfg(unix)]
    return unsafe { libc::geteuid() } == 0;
    #[cfg(target_os = "windows")]
    return crate::audit_security_log::self_elevated();
    #[cfg(not(any(unix, target_os = "windows")))]
    return false;
}

/// 通道能力的平台描述(状态/日志展示)
pub fn channel_description() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "OpenBSM 审计管道(/dev/auditpipe)"
    }
    #[cfg(target_os = "linux")]
    {
        "内核 fanotify 文件系统事件"
    }
    #[cfg(target_os = "windows")]
    {
        "Windows 安全日志对象访问审计(4663/4660)"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "无"
    }
}

// ---- 传输层(辅助进程作为客户端) ---------------------------------------------

pub enum Conn {
    #[cfg(unix)]
    Unix(std::os::unix::net::UnixStream),
    #[cfg(target_os = "windows")]
    Pipe(std::fs::File),
    #[cfg(not(any(unix, target_os = "windows")))]
    Void,
}
impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Conn::Unix(s) => s.read(buf),
            #[cfg(target_os = "windows")]
            Conn::Pipe(f) => f.read(buf),
            #[cfg(not(any(unix, target_os = "windows")))]
            Conn::Void => Err(std::io::Error::other("无可用传输")),
        }
    }
}
impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Conn::Unix(s) => s.write(buf),
            #[cfg(target_os = "windows")]
            Conn::Pipe(f) => f.write(buf),
            #[cfg(not(any(unix, target_os = "windows")))]
            Conn::Void => Err(std::io::Error::other("无可用传输")),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Conn::Unix(s) => s.flush(),
            #[cfg(target_os = "windows")]
            Conn::Pipe(f) => f.flush(),
            #[cfg(not(any(unix, target_os = "windows")))]
            Conn::Void => Ok(()),
        }
    }
}

#[cfg(target_os = "windows")]
mod win_client {
    use std::io;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            sa: *const core::ffi::c_void,
            disposition: u32,
            flags: u32,
            template: RawHandle,
        ) -> RawHandle;
        fn GetLastError() -> u32;
    }
    pub fn open_pipe(path: &str) -> io::Result<std::fs::File> {
        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                core::ptr::null(),
                OPEN_EXISTING,
                0,
                -1isize as RawHandle,
            )
        };
        if h == -1isize as RawHandle {
            return Err(io::Error::from_raw_os_error(unsafe { GetLastError() } as i32));
        }
        Ok(unsafe { std::fs::File::from_raw_handle(h) })
    }
}

fn connect(socket: &Path) -> std::io::Result<Conn> {
    #[cfg(unix)]
    {
        let stream = std::os::unix::net::UnixStream::connect(socket)?;
        let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
        Ok(Conn::Unix(stream))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Conn::Pipe(win_client::open_pipe(&socket.to_string_lossy())?))
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = socket;
        Err(std::io::Error::other("无可用传输"))
    }
}

// ---- 辅助进程主流程 -----------------------------------------------------------

enum Termination {
    SocketClosed,
    NotPrivileged,
    EndpointGone,
}

/// 以 root/管理员连接 GUI 接收器并持续推送审计事件。
/// 正常情况下随 GUI 退出而退出。
pub fn run_helper(socket: Option<PathBuf>) -> Result<(), String> {
    let mut endpoint_misses = 0u32;
    loop {
        // 解析接收端位置:参数优先,否则从 endpoint 文件发现
        let sock = match socket.clone().or_else(|| discover_endpoint().map(|e| e.socket)) {
            Some(s) => s,
            None => {
                return Err(
                    "未找到审计接收位置(audit-endpoint.json)。请先在主界面启动监控并开启审计。"
                        .into(),
                )
            }
        };
        match connect(&sock) {
            Ok(mut conn) => match session(&mut conn) {
                Ok(Termination::SocketClosed) => {
                    // GUI 重启中:等 endpoint 重新出现
                }
                Ok(Termination::NotPrivileged) => return Ok(()),
                Ok(Termination::EndpointGone) | Err(_) => return Ok(()),
            },
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

fn session(conn: &mut Conn) -> Result<Termination, String> {
    // 1) Hello
    send_json(conn, &serde_json::json!({"type":"hello","protocol":1}))
        .map_err(|e| format!("发送握手失败: {e}"))?;
    // 2) 等待 Scope
    let mut reader = std::io::BufReader::new(&mut *conn);
    let mut line = String::new();
    use std::io::BufRead;
    reader
        .read_line(&mut line)
        .map_err(|e| format!("读取监控范围失败: {e}"))?;
    drop(reader);
    if line.trim().is_empty() {
        return Ok(Termination::SocketClosed);
    }
    let scope: Scope =
        serde_json::from_str(line.trim()).map_err(|e| format!("监控范围格式错误: {e}"))?;
    if scope.protocol != 1 {
        return Err("不支持的协议版本".into());
    }
    // 3) 权限不足:报告后退出
    if !privileged() {
        send_json(
            conn,
            &serde_json::json!({"type":"status","protocol":1,"state":"not_privileged",
                "message":"系统审计采集需要管理员权限:请通过主界面的管理员授权方式启动,或使用 sudo/pkexec(提升权限的执行程序)运行本辅助程序"}),
        )
        .map_err(|e| e.to_string())?;
        eprintln!("非管理员运行,已向主界面报告 not_privileged");
        return Ok(Termination::NotPrivileged);
    }
    // 4) 打开采集通道
    let mut source = match open_collector(&scope) {
        Ok(s) => s,
        Err(e) => {
            let _ = send_json(
                conn,
                &serde_json::json!({"type":"status","protocol":1,"state":"not_permitted",
                    "message":format!("无法启动采集通道: {e}")}),
            );
            return Err(format!("采集通道启动失败: {e}"));
        }
    };
    send_json(
        conn,
        &serde_json::json!({"type":"status","protocol":1,"state":"running",
            "message":format!("{}已连接(管理员授权)", channel_description())}),
    )
    .map_err(|e| e.to_string())?;
    eprintln!(
        "audit-helper: running channel={} roots={:?}",
        channel_description(),
        scope.roots
    );

    // 5) 事件循环:collect → 写协议行 → 2s 心跳 → endpoint 消失即退出
    let mut sequence: u64 = 0;
    let mut last_beat = Instant::now();
    let mut lines: Vec<Vec<u8>> = Vec::new();
    loop {
        lines.clear();
        source.collect(&scope, &mut sequence, &mut lines)?;
        for line in &lines {
            if conn.write_all(line).is_err() {
                return Ok(Termination::SocketClosed);
            }
        }
        if last_beat.elapsed() >= Duration::from_secs(2) {
            let beat = serde_json::json!({"type":"heartbeat","protocol":1,"dropped":source.dropped()});
            if send_json(conn, &beat).is_err() {
                return Ok(Termination::SocketClosed);
            }
            eprintln!(
                "audit-helper: sent={sequence} dropped={}",
                source.dropped()
            );
            last_beat = Instant::now();
            // GUI 退出(endpoint 清理)→ 结束
            if discover_endpoint().is_none() {
                return Ok(Termination::EndpointGone);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `--check`:以当前身份探测采集通道能力(不启动采集)
pub fn run_check() -> serde_json::Value {
    let root = privileged();
    let detail = check_channel();
    serde_json::json!({
        "privileged": root,
        "channel": channel_description(),
        "message": if !root {
            "当前以普通用户运行:采集通道需要管理员授权后由辅助程序启动"
        } else {
            &detail.1[..]
        },
        "ok": root && detail.0,
        "state": match (root, detail.0) {
            (true, true) => "available",
            (true, false) => "not_permitted",
            (false, _) => "not_privileged",
        },
    })
}

/// `--teardown`:清理持久化的采集配置(目前仅 Windows SACL 需要)
pub fn run_teardown(roots: &[PathBuf]) -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        crate::audit_security_log::teardown(roots)?;
        Ok("已移除本工具添加的 SACL 审核项(审核策略可经 auditpol 手动恢复)".into())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = roots;
        Ok("当前平台的采集通道不残留系统配置,无需清理".into())
    }
}

fn check_channel() -> (bool, String) {
    #[cfg(target_os = "macos")]
    {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/auditpipe")
        {
            Ok(_) => (true, "/dev/auditpipe 可打开".into()),
            Err(e) => (false, format!("无法打开 /dev/auditpipe: {e}")),
        }
    }
    #[cfg(target_os = "linux")]
    {
        crate::audit_fanotify::probe()
    }
    #[cfg(target_os = "windows")]
    {
        crate::audit_security_log::probe()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        (false, "当前平台没有系统审计采集通道".into())
    }
}

// ---- macOS: OpenBSM /dev/auditpipe 通道 --------------------------------------
// BSM 解析基于 OpenBSM 固定 ABI;关键布局均在本机用 C 编译器实测校准:
// header32=19B/header64=23B(event 在偏移 4),subject* 的 pid 在偏移 21,
// fd 级路径查询必须用 proc_pidfdinfo(flavor 2,路径偏移 176)。

#[cfg(any(target_os = "macos", test))]
mod bsm_parse {
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
    pub const AUE_LINK: u16 = 5;
    pub const AUE_UNLINK: u16 = 6;
    pub const AUE_SYMLINK: u16 = 21;
    pub const AUE_RENAME: u16 = 42;
    pub const AUE_TRUNCATE: u16 = 43;
    pub const AUE_MKDIR: u16 = 47;
    pub const AUE_RMDIR: u16 = 48;
    pub const AUE_OPEN_RW: u16 = 80;
    pub const AUE_OPEN_RTC: u16 = 75;
    pub const AUE_OPEN_W: u16 = 76;
    pub const AUE_OPEN_WC: u16 = 77;
    pub const AUE_OPEN_RWTC: u16 = 82;
    pub const AUE_OPENAT_RTC: u16 = 273;
    pub const AUE_OPENAT_W: u16 = 274;
    pub const AUE_OPENAT_WC: u16 = 275;
    pub const AUE_OPENAT_RW: u16 = 278;
    pub const AUE_OPENAT_RWT: u16 = 280;
    pub const AUE_OPENAT_RWTC: u16 = 281;
    pub const AUE_RENAMEAT: u16 = 282;
    pub const AUE_UNLINKAT: u16 = 286;
    pub const AUE_MKDIRAT: u16 = 43148;
    pub const AUE_SYMLINKAT: u16 = 43152;

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
                AUE_MKDIR | AUE_MKDIRAT => {
                    Some(PipeEvent::Created { path: p0.clone(), folder: true })
                }
                AUE_LINK | AUE_SYMLINK | AUE_SYMLINKAT => {
                    Some(PipeEvent::Created { path: p0.clone(), folder: false })
                }
                AUE_OPEN_RTC | AUE_OPEN_WC | AUE_OPENAT_RTC | AUE_OPENAT_WC
                | AUE_OPENAT_RWTC => {
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
                AUE_TRUNCATE | AUE_OPEN_W | AUE_OPEN_RW | AUE_OPENAT_W | AUE_OPENAT_RW
                | AUE_OPENAT_RWT | AUE_OPEN_RWTC => Some(PipeEvent::Modified { path: p0.clone() }),
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
        while pos < rec.len() {
            let id = rec[pos];
            match id {
                AUT_SUBJECT32 | AUT_SUBJECT32_EX => {
                    if pos + 25 > rec.len() {
                        break;
                    }
                    let u32at = |o: usize| {
                        u32::from_be_bytes([rec[o], rec[o + 1], rec[o + 2], rec[o + 3]])
                    };
                    auid = u32at(pos + 1);
                    euid = u32at(pos + 5);
                    ruid = u32at(pos + 13);
                    pid = u32at(pos + 21) as i32;
                    have_subject = true;
                    let Some(p) = step(pos, if id == AUT_SUBJECT32 { 37 } else { 53 }) else {
                        break
                    };
                    pos = p;
                }
                AUT_SUBJECT64 | AUT_SUBJECT64_EX => {
                    if pos + 29 > rec.len() {
                        break;
                    }
                    let u32at = |o: usize| {
                        u32::from_be_bytes([rec[o], rec[o + 1], rec[o + 2], rec[o + 3]])
                    };
                    auid = u32at(pos + 1);
                    euid = u32at(pos + 5);
                    ruid = u32at(pos + 13);
                    pid = i64::from_be_bytes([
                        rec[pos + 21],
                        rec[pos + 22],
                        rec[pos + 23],
                        rec[pos + 24],
                        rec[pos + 25],
                        rec[pos + 26],
                        rec[pos + 27],
                        rec[pos + 28],
                    ]) as i32;
                    have_subject = true;
                    let Some(p) = step(pos, if id == AUT_SUBJECT64 { 45 } else { 69 }) else {
                        break
                    };
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
}

#[cfg(any(target_os = "macos", test))]
pub use bsm_parse::{parse_record, BsmEvent, PipeEvent};

#[cfg(target_os = "macos")]
mod bsm {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    // 预选类掩码:/etc/security/audit_class — fr(读)0x01 fw(写)0x02 fc(建)0x10 fd(删)0x20
    const CLASS_WRITE_CREATE_DELETE: u32 = 0x02 | 0x10 | 0x20;

    #[link(name = "System")]
    extern "C" {
        fn ioctl(fd: libc::c_int, request: libc::c_ulong, ...) -> libc::c_int;
        fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut core::ffi::c_void,
            buffersize: i32,
        ) -> i32;
        fn poll(fds: *mut libc::pollfd, nfds: libc::nfds_t, timeout: i32) -> i32;
    }
    const AUDITPIPE_SET_PRESELECT_FLAGS: libc::c_ulong = 0x8008_4107;
    const AUDITPIPE_SET_PRESELECT_NAFLAGS: libc::c_ulong = 0x8008_4109;
    const AUDITPIPE_SET_PRESELECT_MODE: libc::c_ulong = 0x8004_410f;
    const AUDITPIPE_PRESELECT_MODE_LOCAL: libc::c_int = 2;

    /// 打开并配置 auditpipe。普通用户得到"权限拒绝"(设备为 root 0600)。
    pub fn open_pipe(read_access: bool) -> std::io::Result<std::fs::File> {
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
            let rc =
                libc::syscall(SYS_AUDITON, A_SETCOND, &mut cond as *mut libc::c_int, 4usize);
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
            if ioctl(
                f.as_raw_fd(),
                AUDITPIPE_SET_PRESELECT_MODE,
                &AUDITPIPE_PRESELECT_MODE_LOCAL,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if ioctl(f.as_raw_fd(), AUDITPIPE_SET_PRESELECT_FLAGS, args.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if ioctl(f.as_raw_fd(), AUDITPIPE_SET_PRESELECT_NAFLAGS, args.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(f)
    }

    /// pid → 可执行文件路径(root 可查任意进程)
    pub fn executable_of(pid: i32) -> Option<String> {
        let mut buf = [0u8; 4096];
        let n = unsafe { proc_pidpath(pid, buf.as_mut_ptr(), buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&buf[..n as usize]).into_owned())
    }

    /// 父进程引用(ppid 经 PROC_PIDTBSDINFO 偏移 16 获取)
    fn parent_ref(pid: i32) -> serde_json::Value {
        let mut bsd = [0u8; 256];
        const PROC_PIDTBSDINFO: i32 = 3;
        let got =
            unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, bsd.as_mut_ptr().cast(), bsd.len() as i32) };
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

    pub(super) struct BsmCollector {
        pipe: std::fs::File,
        dropped: u64,
    }
    impl BsmCollector {
        pub fn open(scope: &Scope) -> Result<Self, String> {
            let pipe = open_pipe(scope.track_access).map_err(|e| e.to_string())?;
            Ok(Self { pipe, dropped: 0 })
        }
    }
    impl Collector for BsmCollector {
        fn collect(
            &mut self,
            scope: &Scope,
            sequence: &mut u64,
            out: &mut Vec<Vec<u8>>,
        ) -> Result<(), String> {
            use std::io::Read;
            // 该设备的 O_NONBLOCK 实测不生效,用 poll 等待可读(0ms:由外层循环节奏驱动)
            let mut pfd = libc::pollfd {
                fd: self.pipe.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { poll(&mut pfd, 1, 0) };
            if prc <= 0 || pfd.revents & libc::POLLIN == 0 {
                return Ok(());
            }
            let mut buf = vec![0u8; 64 * 1024];
            let n = match self.pipe.read(&mut buf) {
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(())
                }
                Err(e) => return Err(e.to_string()),
            };
            if n == 0 {
                return Ok(());
            }
            let Some(ev) = parse_record(&buf[..n]) else {
                self.dropped += 1;
                return Ok(());
            };
            match emit_bsm(&ev, scope, sequence) {
                Some(line) => out.push(line),
                None => self.dropped += 1,
            }
            Ok(())
        }
        fn dropped(&mut self) -> u64 {
            self.dropped
        }
    }

    /// BSM 记录 → 协议行(范围过滤 + 权威进程身份)
    fn emit_bsm(ev: &BsmEvent, scope: &Scope, sequence: &mut u64) -> Option<Vec<u8>> {
        if ev.pid <= 0 {
            return None; // 内核事件(pid 0/-1)无进程可归因
        }
        let pipe_ev = ev.to_pipe_event(scope.track_access)?;
        let (path, from, folder) = match &pipe_ev {
            PipeEvent::Renamed { from, to } => (to.clone(), Some(from.clone()), false),
            PipeEvent::Created { path, folder } => (path.clone(), None, *folder),
            PipeEvent::Removed { path, folder } => (path.clone(), None, *folder),
            PipeEvent::Modified { path } | PipeEvent::Accessed { path } => {
                (path.clone(), None, false)
            }
        };
        // 双端过滤:辅助进程侧先按范围过滤
        if !scope.includes(&path) && !from.as_deref().is_some_and(|f| scope.includes(f)) {
            return None;
        }
        // 进程身份:执行文件必须可解析(协议校验要求绝对路径)
        let exe = executable_of(ev.pid)?;
        *sequence += 1;
        let (event, object) = match &pipe_ev {
            PipeEvent::Created { .. } => ("created", if folder { "folder" } else { "file" }),
            PipeEvent::Modified { .. } => ("modified", "file"),
            PipeEvent::Removed { .. } => ("removed", if folder { "folder" } else { "file" }),
            PipeEvent::Renamed { .. } => ("renamed", "file"),
            PipeEvent::Accessed { .. } => ("accessed", "file"),
        };
        let user = crate::attributor::uid_to_name(ev.euid).unwrap_or_default();
        let owner = owner_name(&path);
        let parent = parent_ref(ev.pid);
        Some(wire_line(
            &EventBits {
                event,
                path,
                from,
                object,
                user,
                owner,
                event_type: ev.event as u32,
                pid: ev.pid.max(0) as u32,
                exe,
                uid: ev.euid,
                real_uid: ev.ruid,
                audit_uid: ev.auid,
                parent: (parent != serde_json::Value::Null).then_some(parent),
                source: "bsm_auditpipe",
            },
            *sequence,
        ))
    }
}

#[cfg(test)]
mod bsm_tests {
    use super::*;

    fn u16b(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }
    fn u32b(v: u32) -> [u8; 4] {
        v.to_be_bytes()
    }
    fn subject32(pid: i32, auid: u32, euid: u32, ruid: u32) -> Vec<u8> {
        let mut t = vec![0x24 /*AUT_SUBJECT32*/];
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
        let mut t = vec![0x23 /*AUT_PATH*/];
        t.extend_from_slice(&u16b((p.len() + 1) as u16));
        t.extend_from_slice(p.as_bytes());
        t.push(0);
        t
    }
    fn record(event: u16, tokens: &[&[u8]]) -> Vec<u8> {
        let mut rec = vec![0x14 /*AUT_HEADER32*/];
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
        rec.extend_from_slice(&[0x13 /*AUT_TRAILER*/, 0, 5, 0xb1, 0x05]);
        rec
    }

    #[test]
    fn unlink_with_identity() {
        let rec = record(
            bsm_parse::AUE_UNLINK,
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
            bsm_parse::AUE_RENAME,
            &[
                &subject32(7, 501, 501, 501),
                &path_token("/private/tmp/a"),
                &path_token("/private/tmp/b"),
            ],
        );
        let ev = parse_record(&rec).unwrap();
        assert_eq!(
            ev.to_pipe_event(false),
            Some(PipeEvent::Renamed {
                from: "/private/tmp/a".into(),
                to: "/private/tmp/b".into()
            })
        );
    }

    #[test]
    fn mkdir_and_create_labels() {
        let rec = record(
            bsm_parse::AUE_MKDIR,
            &[&subject32(1, 0, 0, 0), &path_token("/tmp/d")],
        );
        assert_eq!(
            parse_record(&rec).unwrap().to_pipe_event(false),
            Some(PipeEvent::Created { path: "/tmp/d".into(), folder: true })
        );
        let rec = record(
            bsm_parse::AUE_OPEN_WC,
            &[&subject32(1, 0, 0, 0), &path_token("/tmp/n")],
        );
        assert_eq!(
            parse_record(&rec).unwrap().to_pipe_event(false),
            Some(PipeEvent::Created { path: "/tmp/n".into(), folder: false })
        );
    }

    #[test]
    fn failed_syscall_skipped_and_reads_gated() {
        let mut ret = vec![0x27 /*AUT_RETURN32*/, 2];
        ret.extend_from_slice(&u32b(0));
        let rec = record(
            bsm_parse::AUE_UNLINK,
            &[&subject32(1, 0, 0, 0), &path_token("/x"), &ret],
        );
        assert!(parse_record(&rec).unwrap().to_pipe_event(false).is_none());
        let rec = record(72, &[&subject32(1, 0, 0, 0), &path_token("/r")]); // AUE_OPEN_R
        assert!(parse_record(&rec).unwrap().to_pipe_event(false).is_none());
        assert!(parse_record(&rec).unwrap().to_pipe_event(true).is_some());
    }

    #[test]
    fn header64_and_unknown_token() {
        let mut rec = vec![0x74 /*AUT_HEADER64*/];
        rec.extend_from_slice(&[0, 0]);
        rec.push(11);
        rec.extend_from_slice(&u16b(bsm_parse::AUE_TRUNCATE));
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
        let rec = record(
            bsm_parse::AUE_UNLINK,
            &[&subject32(2, 0, 0, 0), &[0x99u8], &path_token("/y")],
        );
        assert!(parse_record(&rec).is_none());
    }

    #[test]
    fn wire_line_roundtrips_through_gui_decoder() {
        let bits = EventBits {
            event: "removed",
            path: "/tmp/删除_副本.txt".into(),
            from: None,
            object: "file",
            user: "alice".into(),
            owner: "bob".into(),
            event_type: 43148,
            pid: 4242,
            exe: "/bin/rm".into(),
            uid: 501,
            real_uid: 501,
            audit_uid: 501,
            parent: Some(serde_json::json!({"pid":11,"pid_version":0,"executable":"/bin/zsh"})),
            source: "fanotify",
        };
        let line = wire_line(&bits, 7);
        let wire: crate::audit::Wire = serde_json::from_slice(&line).unwrap();
        let scope = crate::audit::Scope {
            protocol: 1,
            roots: vec!["/tmp".into()],
            excludes: vec![],
            recursive: true,
            track_access: false,
        };
        let record = crate::audit::decode_event(wire, &scope).unwrap().unwrap();
        assert_eq!(record.actor.source.as_deref(), Some("fanotify"));
        assert_eq!(record.actor.process_id, Some(4242));
        assert_eq!(record.audit.as_ref().unwrap().parent.as_ref().unwrap().pid, 11);
    }

    #[test]
    fn scope_prefix_rules() {
        let scope = Scope {
            protocol: 1,
            roots: vec!["/watched".into()],
            excludes: vec!["/watched/secret".into()],
            recursive: false,
            track_access: false,
        };
        assert!(scope.includes("/watched"));
        assert!(scope.includes("/watched/a.png"));
        assert!(!scope.includes("/watched/sub/a.png"));
        assert!(!scope.includes("/watchedx/a.png"));
        assert!(!scope.includes("relative.png"));
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
        stream.write_all(format!("{scope}\n").as_bytes()).unwrap();
        // 3) 应收到 not_privileged 状态后辅助进程退出
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("\"not_privileged\""), "非 root 应报告状态: {line}");
        drop(listener);
        helper.join().unwrap();
        assert!(done_rx.recv().unwrap().is_empty(), "非 root 路径应正常退出");
    }
}
