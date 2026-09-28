//! Linux fanotify 采集通道:文件系统级事件 + 权威进程归因。
//!
//! 运行形态:root(或 CAP_SYS_ADMIN)辅助进程连接 GUI 接收器,复用
//! `audit_pipe` 的 JSON 行协议推送事件,无需 auditd、不改动系统审计策略。
//!
//! 机制:
//!   fanotify_init(FAN_CLASS_NOTIF | FAN_NONBLOCK | FAN_REPORT_FID
//!                 | FAN_REPORT_DIR_FID | FAN_REPORT_PIDFD)
//!   fanotify_mark(FAN_MARK_ADD | FAN_MARK_FILESYSTEM, 建/删/重命名/改[/读])
//!   事件带句柄(FID=目标、DFID=目录)与目录内文件名(DFID_NAME),用
//!   open_by_handle_at 还原绝对路径;pid → /proc/<pid>/exe 为内核记录的
//!   权威执行文件,满足协议"可执行文件必须为绝对路径"的归因校验。
//!
//! 纯解析函数(字节流 → 事件)与平台无关,可在任意开发机上单元测试;
//! 系统调用封装仅在 Linux 编译。

#[allow(unused_imports)] // Linux 运行时段通过 super::* 使用
use std::path::PathBuf;

// ---- fanotify ABI(uapi/linux/fanotify.h, metadata v3) ----
pub const FANOTIFY_METADATA_VERSION: u8 = 3;
pub const FAN_EVENT_METADATA_LEN: usize = 24;
pub const FAN_NOFD: i32 = -1;

// 事件掩码
pub const FAN_ACCESS: u64 = 0x0000_0001;
pub const FAN_MODIFY: u64 = 0x0000_0002;
pub const FAN_CREATE: u64 = 0x0000_0100;
pub const FAN_DELETE: u64 = 0x0000_0200;
pub const FAN_RENAME: u64 = 0x1000_0000;
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
pub const FAN_ONDIR: u64 = 0x4000_0000;
pub const FAN_EVENT_ON_CHILD: u64 = 0x0800_0000;

// init flags
pub const FAN_CLASS_NOTIF: u32 = 0;
pub const FAN_NONBLOCK: u32 = 0x0000_0002;
pub const FAN_REPORT_FID: u32 = 0x0000_0200;
pub const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;
pub const FAN_REPORT_PIDFD: u32 = 0x0000_0800;

// mark flags
pub const FAN_MARK_ADD: u32 = 0x0000_0001;
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

// 附加信息记录类型
pub const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
pub const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
pub const FAN_EVENT_INFO_TYPE_DFID: u8 = 3;
pub const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;

/// file_handle(f_handle 数据已拷贝)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHandle {
    pub handle_type: i32,
    pub bytes: Vec<u8>,
}

/// 一条目录句柄记录(DFID/DFID_NAME):目录句柄 + 其内文件名
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub handle: FileHandle,
    /// DFID_NAME 记录携带的名字(可能多个,如重命名的 [旧名, 新名]);
    /// 内核取不到名字时为空 Vec
    pub names: Vec<Vec<u8>>,
}

/// 一条事件的结构化解析结果
#[derive(Debug, Clone, PartialEq)]
pub struct FanEvent {
    pub mask: u64,
    pub pid: i32,
    pub fd: i32,
    /// 目标文件句柄(FID;修改/访问类事件用它定位对象)
    pub target: Option<FileHandle>,
    /// 目录句柄记录,按内核写出顺序(重命名: [旧目录(旧名), 新目录(新名)])
    pub dirs: Vec<DirEntryInfo>,
    /// FAN_REPORT_PIDFD 提供的 pidfd(取出后即应关闭)
    pub pidfd: Option<i32>,
}

impl FanEvent {
    pub fn is_dir(&self) -> bool {
        self.mask & FAN_ONDIR != 0
    }
    /// 分类;None 表示与文件操作无关(忽略)
    pub fn classify(&self, track_access: bool) -> Option<FanClass> {
        let m = self.mask;
        if m & FAN_Q_OVERFLOW != 0 {
            return Some(FanClass::Overflow);
        }
        if m & FAN_RENAME != 0 {
            // 重命名需要两个目录记录(或一个记录两个名字)才能成对
            let names: usize = self.dirs.iter().map(|d| d.names.len()).sum();
            return (names >= 2).then_some(FanClass::Renamed);
        }
        if m & FAN_CREATE != 0 {
            return Some(FanClass::Created);
        }
        if m & FAN_DELETE != 0 {
            return Some(FanClass::Deleted);
        }
        if m & FAN_MODIFY != 0 {
            return Some(FanClass::Modified);
        }
        if m & FAN_ACCESS != 0 && track_access {
            return Some(FanClass::Accessed);
        }
        None
    }
    /// 展平的全部名字(按记录顺序)
    pub fn all_names(&self) -> Vec<&[u8]> {
        self.dirs.iter().flat_map(|d| d.names.iter().map(|n| n.as_slice())).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanClass {
    Created,
    Deleted,
    Renamed,
    Modified,
    Accessed,
    Overflow,
}

/// 从 read 缓冲区解析事件流(fanotify 一次 read 返回若干条完整事件)。
/// 长度不自洽即停止本批解析(ABI 变化时宁可漏报不误报)。
pub fn parse_stream(buf: &[u8]) -> Vec<FanEvent> {
    let mut events = Vec::new();
    let mut pos = 0usize;
    while pos + FAN_EVENT_METADATA_LEN <= buf.len() {
        let head = &buf[pos..pos + FAN_EVENT_METADATA_LEN];
        let event_len = u32::from_ne_bytes(head[0..4].try_into().unwrap()) as usize;
        let vers = head[4];
        let metadata_len = u16::from_ne_bytes(head[6..8].try_into().unwrap()) as usize;
        if vers != FANOTIFY_METADATA_VERSION
            || event_len < metadata_len
            || metadata_len < FAN_EVENT_METADATA_LEN
            || pos + event_len > buf.len()
        {
            break;
        }
        let mask = u64::from_ne_bytes(head[8..16].try_into().unwrap());
        let fd = i32::from_ne_bytes(head[16..20].try_into().unwrap());
        let pid = i32::from_ne_bytes(head[20..24].try_into().unwrap());
        let mut ev = FanEvent {
            mask,
            pid,
            fd,
            target: None,
            dirs: Vec::new(),
            pidfd: None,
        };
        let mut q = pos + metadata_len;
        let end = pos + event_len;
        while q + 4 <= end {
            let info_type = buf[q];
            let info_len = u16::from_ne_bytes(buf[q + 2..q + 4].try_into().unwrap()) as usize;
            if info_len < 4 || q + info_len > end {
                break;
            }
            let body = &buf[q + 4..q + info_len];
            match info_type {
                FAN_EVENT_INFO_TYPE_FID => {
                    if let Some((handle, _)) = parse_fid_record(body) {
                        ev.target = Some(handle);
                    }
                }
                FAN_EVENT_INFO_TYPE_DFID | FAN_EVENT_INFO_TYPE_DFID_NAME => {
                    if let Some((handle, names)) = parse_fid_record(body) {
                        ev.dirs.push(DirEntryInfo { handle, names });
                    }
                }
                FAN_EVENT_INFO_TYPE_PIDFD if body.len() >= 4 => {
                    ev.pidfd = Some(i32::from_ne_bytes(body[0..4].try_into().unwrap()));
                }
                _ => {}
            }
            q += info_len;
        }
        events.push(ev);
        pos = end;
    }
    events
}

/// fanotify_event_info_fid: hdr(已消费) + fsid(8B) + file_handle + [名字 NUL...]
fn parse_fid_record(body: &[u8]) -> Option<(FileHandle, Vec<Vec<u8>>)> {
    if body.len() < 16 {
        return None;
    }
    let handle_bytes = u32::from_ne_bytes(body[8..12].try_into().unwrap()) as usize;
    let handle_type = i32::from_ne_bytes(body[12..16].try_into().unwrap());
    if body.len() < 16 + handle_bytes {
        return None;
    }
    let handle = FileHandle {
        handle_type,
        bytes: body[16..16 + handle_bytes].to_vec(),
    };
    let mut names = Vec::new();
    let mut rest = &body[16 + handle_bytes..];
    while !rest.is_empty() {
        let nul = rest.iter().position(|b| *b == 0)?;
        if nul == 0 {
            break;
        }
        names.push(rest[..nul].to_vec());
        rest = &rest[nul + 1..];
    }
    Some((handle, names))
}

/// 内核把不可获取名称的路径记为字面量 "(NULL)"
pub fn name_is_null(name: &[u8]) -> bool {
    name == b"(NULL)"
}

/// 事件的路径素材解析结果(纯函数,路径句柄→字符串由运行时的 resolver 完成)
#[derive(Debug, PartialEq, Eq)]
pub enum EventPaths<'a> {
    /// 单对象事件:目录句柄 + 名字(或目标句柄,dir=None)
    One {
        dir: Option<&'a FileHandle>,
        name: Option<&'a [u8]>,
        target: Option<&'a FileHandle>,
    },
    /// 重命名:旧(目录,名字)与新(目录,名字)
    Pair {
        from_dir: Option<&'a FileHandle>,
        from_name: &'a [u8],
        to_dir: Option<&'a FileHandle>,
        to_name: &'a [u8],
    },
}

impl FanEvent {
    /// 提取路径素材;名字缺失(如 "(NULL)")时返回 None 由调用方丢弃
    pub fn paths(&self, class: FanClass) -> Option<EventPaths<'_>> {
        match class {
            FanClass::Renamed => {
                let flat: Vec<(Option<&FileHandle>, &[u8])> = self
                    .dirs
                    .iter()
                    .flat_map(|d| d.names.iter().map(|n| (Some(&d.handle), n.as_slice())))
                    .collect();
                if flat.len() < 2 {
                    return None;
                }
                let (from_dir, from_name) = *flat.first()?;
                let (to_dir, to_name) = *flat.last()?;
                if name_is_null(from_name) || name_is_null(to_name) {
                    return None;
                }
                Some(EventPaths::Pair {
                    from_dir,
                    from_name,
                    to_dir,
                    to_name,
                })
            }
            FanClass::Created | FanClass::Deleted => {
                let dir = self.dirs.first();
                let name = dir?.names.first().map(|n| n.as_slice()).filter(|n| !name_is_null(n));
                Some(EventPaths::One {
                    dir: dir.map(|d| &d.handle),
                    name,
                    target: None,
                })
            }
            FanClass::Modified | FanClass::Accessed => {
                // 修改/访问优先用目标 FID 定位;无 FID 时退回目录+名字
                if self.target.is_some() {
                    return Some(EventPaths::One {
                        dir: None,
                        name: None,
                        target: self.target.as_ref(),
                    });
                }
                let dir = self.dirs.first()?;
                let name = dir.names.first().map(|n| n.as_slice()).filter(|n| !name_is_null(n))?;
                Some(EventPaths::One {
                    dir: Some(&dir.handle),
                    name: Some(name),
                    target: None,
                })
            }
            FanClass::Overflow => None,
        }
    }
}

// ---- Linux 运行时:系统调用封装与采集器 ---------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::audit_pipe::{Collector, EventBits, Scope};
    use std::ffi::{CString, OsStr};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::{Path, PathBuf};

    const FILE_HANDLE_BYTES: usize = 128;
    #[repr(C)]
    struct RawFileHandle {
        handle_bytes: u32,
        handle_type: i32,
        f_handle: [u8; FILE_HANDLE_BYTES],
    }

    extern "C" {
        fn fanotify_init(flags: u32, event_f_flags: u32) -> i32;
        fn fanotify_mark(
            fanotify_fd: i32,
            flags: u32,
            mask: u64,
            dirfd: i32,
            pathname: *const libc::c_char,
        ) -> i32;
        fn open_by_handle_at(mount_fd: i32, handle: *const RawFileHandle, flags: i32) -> i32;
    }
    const O_PATH: i32 = 0o10000000;
    const O_CLOEXEC: i32 = libc::O_CLOEXEC;

    /// fanotify fd + 各监控根所在挂载点的代表 fd(供 open_by_handle_at)
    pub struct Source {
        fan: OwnedFd,
        mounts: Vec<OwnedFd>,
        buf: Vec<u8>,
        dropped: u64,
    }

    impl Source {
        pub fn open(roots: &[PathBuf], track_access: bool) -> std::io::Result<Self> {
            let flags = FAN_CLASS_NOTIF
                | FAN_NONBLOCK
                | FAN_REPORT_FID
                | FAN_REPORT_DIR_FID
                | FAN_REPORT_PIDFD;
            let fd = unsafe { fanotify_init(flags, (libc::O_RDONLY | O_CLOEXEC) as u32) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: fd 为本次调用新建的 fanotify 句柄
            let fan = unsafe { OwnedFd::from_raw_fd(fd) };
            let mut mask =
                FAN_CREATE | FAN_DELETE | FAN_RENAME | FAN_MODIFY | FAN_EVENT_ON_CHILD;
            if track_access {
                mask |= FAN_ACCESS;
            }
            let mut mounts: Vec<OwnedFd> = Vec::new();
            let mut seen = std::collections::HashSet::new();
            for root in roots {
                let Ok(md) = std::fs::metadata(root) else {
                    continue;
                };
                use std::os::unix::fs::MetadataExt;
                if !seen.insert(md.dev()) {
                    continue; // 同一挂载点只标记一次
                }
                let dir: &Path =
                    if md.is_dir() { root.as_path() } else { root.parent().unwrap_or(Path::new("/")) };
                let cdir = CString::new(dir.as_os_str().as_bytes())
                    .map_err(|_| std::io::Error::other("挂载代表目录路径含 NUL"))?;
                let mfd =
                    unsafe { libc::open(cdir.as_ptr(), libc::O_RDONLY | O_PATH | O_CLOEXEC) };
                if mfd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // SAFETY: mfd 为刚打开的有效 fd
                let mfd = unsafe { OwnedFd::from_raw_fd(mfd) };
                let rc = unsafe {
                    fanotify_mark(
                        fan.as_raw_fd(),
                        FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                        mask,
                        mfd.as_raw_fd(),
                        std::ptr::null(),
                    )
                };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                mounts.push(mfd);
            }
            if mounts.is_empty() {
                return Err(std::io::Error::other("没有可标记的监控根路径"));
            }
            Ok(Self {
                fan,
                mounts,
                buf: vec![0u8; 128 * 1024],
                dropped: 0,
            })
        }

        /// 内核句柄 → 绝对路径(open_by_handle_at + /proc/self/fd 符号链接)
        fn resolve(&self, mount: &OwnedFd, handle: &FileHandle) -> Option<String> {
            if handle.bytes.len() > FILE_HANDLE_BYTES {
                return None;
            }
            let mut raw = RawFileHandle {
                handle_bytes: handle.bytes.len() as u32,
                handle_type: handle.handle_type,
                f_handle: [0u8; FILE_HANDLE_BYTES],
            };
            raw.f_handle[..handle.bytes.len()].copy_from_slice(&handle.bytes);
            let fd = unsafe { open_by_handle_at(mount.as_raw_fd(), &raw, O_PATH | O_CLOEXEC) };
            if fd < 0 {
                return None;
            }
            let link = PathBuf::from(format!("/proc/self/fd/{fd}"));
            let path = std::fs::read_link(&link)
                .ok()
                .map(|p| p.to_string_lossy().into_owned());
            unsafe { libc::close(fd) };
            path
        }

        /// 在候选挂载点中解析句柄(对象可能位于任一监控根所在文件系统)
        fn resolve_any(&self, handle: &FileHandle) -> Option<String> {
            self.mounts.iter().find_map(|m| self.resolve(m, handle))
        }

        /// 读取并解析一批事件(nonblocking;无数据返回空)
        pub fn read_events(&mut self) -> std::io::Result<Vec<FanEvent>> {
            let n = unsafe {
                libc::read(
                    self.fan.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(libc::EAGAIN) => Ok(Vec::new()),
                    Some(libc::EMSGSIZE) => {
                        self.dropped += 1; // 单条事件大于缓冲区:计缺口后继续
                        Ok(Vec::new())
                    }
                    _ => Err(err),
                };
            }
            if n == 0 {
                return Ok(Vec::new());
            }
            let events = parse_stream(&self.buf[..n as usize]);
            for ev in &events {
                if let Some(pidfd) = ev.pidfd {
                    unsafe { libc::close(pidfd) }; // 只用 metadata.pid,pidfd 防泄漏直接关闭
                }
            }
            if events.iter().any(|e| e.mask & FAN_Q_OVERFLOW != 0) {
                self.dropped += 1;
            }
            Ok(events)
        }

        pub fn dropped(&self) -> u64 {
            self.dropped
        }
    }

    /// /proc 进程身份(root 可查任意进程)
    pub struct ProcIdentity {
        pub exe: String,
        pub euid: u32,
        pub ruid: u32,
        pub loginuid: u32,
        pub parent: Option<serde_json::Value>,
    }

    fn proc_exe(pid: i32) -> Option<String> {
        if pid <= 0 {
            return None;
        }
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        exe.is_absolute().then(|| exe.to_string_lossy().into_owned())
    }
    fn proc_uids(pid: i32) -> (u32, u32) {
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            return (u32::MAX, u32::MAX);
        };
        status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:").map(|v| v.split_whitespace().map(str::to_owned).collect::<Vec<_>>()))
            .map(|cols| {
                let real = cols.first().and_then(|v| v.parse().ok()).unwrap_or(u32::MAX);
                let eff = cols.get(1).and_then(|v| v.parse().ok()).unwrap_or(u32::MAX);
                (eff, real)
            })
            .unwrap_or((u32::MAX, u32::MAX))
    }
    fn proc_loginuid(pid: i32) -> u32 {
        std::fs::read_to_string(format!("/proc/{pid}/loginuid"))
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(u32::MAX)
    }
    fn proc_parent(pid: i32) -> Option<serde_json::Value> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // comm 字段可含空格与括号:从最后一个 ')' 之后解析,第 2 列即 ppid
        let rest = stat.rsplit(')').next()?;
        let ppid: i32 = rest.split_whitespace().next()?.parse().ok()?;
        if ppid <= 0 {
            return None;
        }
        Some(serde_json::json!({
            "pid": ppid, "pid_version": 0, "executable": proc_exe(ppid)
        }))
    }
    fn identity(pid: i32) -> Option<ProcIdentity> {
        let exe = proc_exe(pid)?;
        let (euid, ruid) = proc_uids(pid);
        Some(ProcIdentity {
            exe,
            euid,
            ruid,
            loginuid: proc_loginuid(pid),
            parent: proc_parent(pid),
        })
    }

    pub struct FanotifyCollector {
        src: Source,
    }
    impl FanotifyCollector {
        pub fn open(scope: &Scope) -> Result<Self, String> {
            Source::open(&scope.roots, scope.track_access)
                .map(|src| Self { src })
                .map_err(|e| format!("fanotify 初始化失败: {e}"))
        }
    }

    impl Collector for FanotifyCollector {
        fn collect(
            &mut self,
            scope: &Scope,
            sequence: &mut u64,
            out: &mut Vec<Vec<u8>>,
        ) -> Result<(), String> {
            let events = self.src.read_events().map_err(|e| e.to_string())?;
            for ev in events {
                if let Some(line) = self.collect_one(&ev, scope, sequence) {
                    out.push(line);
                }
            }
            Ok(())
        }
        fn dropped(&mut self) -> u64 {
            self.src.dropped()
        }
    }

    impl FanotifyCollector {
        /// 单条事件 → 协议行;范围外/无法还原路径/无法归因时返回 None(丢弃)
        fn collect_one(
            &mut self,
            ev: &FanEvent,
            scope: &Scope,
            sequence: &mut u64,
        ) -> Option<Vec<u8>> {
            let class = ev.classify(scope.track_access)?;
            if matches!(class, FanClass::Overflow) || ev.pid <= 0 {
                return None;
            }
            let paths = ev.paths(class)?;
            // 句柄 → 绝对路径
            let (path, from) = match &paths {
                EventPaths::One { dir, name, target } => {
                    let resolved = if let Some(t) = target {
                        self.src.resolve_any(t)?
                    } else {
                        // 创建/删除事件缺少目录内文件名("(NULL)")时无法定位对象,保守丢弃
                        if matches!(class, FanClass::Created | FanClass::Deleted)
                            && name.is_none()
                        {
                            return None;
                        }
                        let dir = dir.and_then(|d| self.src.resolve_any(d))?;
                        match name {
                            Some(n) => Self::join_os(&dir, OsStr::from_bytes(n)),
                            None => dir,
                        }
                    };
                    (resolved, None)
                }
                EventPaths::Pair { from_dir, from_name, to_dir, to_name } => {
                    let fd = from_dir.and_then(|d| self.src.resolve_any(d))?;
                    let td = to_dir.and_then(|d| self.src.resolve_any(d))?;
                    (
                        Self::join_os(&td, OsStr::from_bytes(to_name)),
                        Some(Self::join_os(&fd, OsStr::from_bytes(from_name))),
                    )
                }
            };
            if !scope.includes(&path) && !from.as_deref().is_some_and(|f| scope.includes(f)) {
                return None;
            }
            // 权威进程身份:执行文件缺失(进程已退出)时按协议要求丢弃
            let ident = identity(ev.pid)?;
            let user = crate::attributor::uid_to_name(ident.euid).unwrap_or_default();
            let owner = crate::audit_pipe::owner_name(&path);
            let (event, object) = match class {
                FanClass::Created => ("created", if ev.is_dir() { "folder" } else { "file" }),
                FanClass::Deleted => ("removed", if ev.is_dir() { "folder" } else { "file" }),
                FanClass::Renamed => ("renamed", if ev.is_dir() { "folder" } else { "file" }),
                FanClass::Modified => ("modified", "file"),
                FanClass::Accessed => ("accessed", "file"),
                FanClass::Overflow => return None,
            };
            *sequence += 1;
            Some(crate::audit_pipe::wire_line(
                &EventBits {
                    event,
                    path,
                    from,
                    object,
                    user,
                    owner,
                    event_type: (ev.mask & u32::MAX as u64) as u32,
                    pid: ev.pid as u32,
                    exe: ident.exe,
                    uid: ident.euid,
                    real_uid: ident.ruid,
                    audit_uid: ident.loginuid,
                    parent: ident.parent,
                    source: "fanotify",
                },
                *sequence,
            ))
        }
    }
    impl FanotifyCollector {
        fn join_os(dir: &str, name: &OsStr) -> String {
            if dir.ends_with('/') {
                format!("{dir}{}", name.to_string_lossy())
            } else {
                format!("{dir}/{}", name.to_string_lossy())
            }
        }
    }

    pub fn probe() -> (bool, String) {
        let flags = FAN_CLASS_NOTIF
            | FAN_NONBLOCK
            | FAN_REPORT_FID
            | FAN_REPORT_DIR_FID
            | FAN_REPORT_PIDFD;
        let fd = unsafe { fanotify_init(flags, (libc::O_RDONLY | O_CLOEXEC) as u32) };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            (true, "fanotify(FID/DFID/PIDFD 报告模式)可用".into())
        } else {
            let err = std::io::Error::last_os_error();
            (
                false,
                match err.raw_os_error() {
                    Some(libc::EPERM) => {
                        "fanotify 需要 CAP_SYS_ADMIN(以 root/pkexec 启动辅助程序)".into()
                    }
                    Some(libc::ENOSYS) => "内核未提供 fanotify".into(),
                    _ => format!("fanotify_init 失败: {err}"),
                },
            )
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{probe, FanotifyCollector};

#[cfg(not(target_os = "linux"))]
/// 非 Linux 平台的探测占位(用于 --check 交叉构建)
pub fn probe() -> (bool, String) {
    (false, "fanotify 仅适用于 Linux".into())
}

// ---- 纯解析单元测试(跨平台可跑) --------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(mask: u64, fd: i32, pid: i32, event_len: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&event_len.to_ne_bytes());
        v.push(FANOTIFY_METADATA_VERSION);
        v.push(0); // reserved
        v.extend_from_slice(&(FAN_EVENT_METADATA_LEN as u16).to_ne_bytes());
        v.extend_from_slice(&mask.to_ne_bytes());
        v.extend_from_slice(&fd.to_ne_bytes());
        v.extend_from_slice(&pid.to_ne_bytes());
        v
    }
    fn fid_record(kind: u8, handle: &[u8], names: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8; 8]); // fsid
        body.extend_from_slice(&(handle.len() as u32).to_ne_bytes());
        body.extend_from_slice(&0x77i32.to_ne_bytes()); // handle_type
        body.extend_from_slice(handle);
        for n in names {
            body.extend_from_slice(n);
            body.push(0);
        }
        let mut v = Vec::new();
        v.push(kind);
        v.push(0);
        v.extend_from_slice(&((body.len() + 4) as u16).to_ne_bytes());
        v.extend_from_slice(&body);
        v
    }
    fn one(mask: u64, pid: i32, records: &[Vec<u8>]) -> Vec<u8> {
        let rec_len: usize = records.iter().map(|r| r.len()).sum();
        let mut buf = metadata(mask, FAN_NOFD, pid, (FAN_EVENT_METADATA_LEN + rec_len) as u32);
        for r in records {
            buf.extend_from_slice(r);
        }
        buf
    }

    #[test]
    fn create_event_parses_dir_handle_and_name() {
        let buf = one(
            FAN_CREATE | FAN_ONDIR | FAN_EVENT_ON_CHILD,
            1234,
            &[fid_record(FAN_EVENT_INFO_TYPE_DFID_NAME, b"fh", &[b"notes.txt"])],
        );
        let events = parse_stream(&buf);
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.pid, 1234);
        assert!(ev.is_dir());
        assert_eq!(ev.dirs[0].handle.bytes, b"fh");
        assert_eq!(ev.dirs[0].names, vec![b"notes.txt".to_vec()]);
        assert_eq!(ev.classify(false), Some(FanClass::Created));
        assert_eq!(
            ev.paths(FanClass::Created),
            Some(EventPaths::One {
                dir: Some(&ev.dirs[0].handle),
                name: Some(b"notes.txt".as_slice()),
                target: None
            })
        );
    }

    #[test]
    fn rename_pairs_old_and_new_names() {
        // 内核顺序:先旧目录+旧名,后新目录+新名
        let buf = one(
            FAN_RENAME,
            9,
            &[
                fid_record(FAN_EVENT_INFO_TYPE_DFID_NAME, b"d1", &[b"old.txt"]),
                fid_record(FAN_EVENT_INFO_TYPE_DFID_NAME, b"d2", &[b"new.txt"]),
            ],
        );
        let events = parse_stream(&buf);
        let ev = &events[0];
        assert_eq!(ev.classify(false), Some(FanClass::Renamed));
        match ev.paths(FanClass::Renamed).unwrap() {
            EventPaths::Pair { from_name, to_name, .. } => {
                assert_eq!(from_name, b"old.txt");
                assert_eq!(to_name, b"new.txt");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rename_in_single_record_with_two_names() {
        let buf = one(
            FAN_RENAME,
            9,
            &[fid_record(FAN_EVENT_INFO_TYPE_DFID_NAME, b"d", &[b"a.txt", "b.txt".as_bytes()])],
        );
        let ev = &parse_stream(&buf)[0];
        assert_eq!(ev.classify(false), Some(FanClass::Renamed));
        match ev.paths(FanClass::Renamed).unwrap() {
            EventPaths::Pair { from_name, to_name, .. } => {
                assert_eq!(from_name, b"a.txt");
                assert_eq!(to_name, b"b.txt");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn null_names_are_dropped() {
        let ev = FanEvent {
            mask: FAN_CREATE,
            pid: 1,
            fd: FAN_NOFD,
            target: None,
            dirs: vec![DirEntryInfo {
                handle: FileHandle { handle_type: 0x77, bytes: vec![1] },
                names: vec![b"(NULL)".to_vec()],
            }],
            pidfd: None,
        };
        assert_eq!(ev.paths(FanClass::Created), Some(EventPaths::One {
            dir: Some(&ev.dirs[0].handle),
            name: None,
            target: None
        }));
        // 重命名遇到 (NULL):素材不完整则必须成对,丢弃由上层处理
        assert!(name_is_null(b"(NULL)"));
    }

    #[test]
    fn modify_uses_target_handle() {
        let buf = one(
            FAN_MODIFY,
            5,
            &[
                fid_record(FAN_EVENT_INFO_TYPE_FID, b"v", &[]),
                fid_record(FAN_EVENT_INFO_TYPE_DFID, b"d", &[]),
            ],
        );
        let ev = &parse_stream(&buf)[0];
        assert_eq!(ev.classify(false), Some(FanClass::Modified));
        match ev.paths(FanClass::Modified).unwrap() {
            EventPaths::One { target: Some(t), dir: None, .. } => assert_eq!(t.bytes, b"v"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn overflow_and_priority_classification() {
        let m = |mask: u64| FanEvent {
            mask,
            pid: 2,
            fd: FAN_NOFD,
            target: None,
            dirs: vec![],
            pidfd: None,
        };
        assert_eq!(m(FAN_Q_OVERFLOW).classify(false), Some(FanClass::Overflow));
        assert_eq!(m(FAN_DELETE).classify(false), Some(FanClass::Deleted));
        assert_eq!(m(FAN_MODIFY).classify(false), Some(FanClass::Modified));
        assert_eq!(m(FAN_ACCESS).classify(false), None);
        assert_eq!(m(FAN_ACCESS).classify(true), Some(FanClass::Accessed));
        assert_eq!(m(FAN_CREATE | FAN_MODIFY).classify(false), Some(FanClass::Created));
    }

    #[test]
    fn truncated_or_bad_version_streams_stop_cleanly() {
        let mut buf = metadata(FAN_CREATE, FAN_NOFD, 7, 24);
        buf[4] = 2; // ABI 版本不符:整批丢弃
        assert!(parse_stream(&buf).is_empty());
        let buf = metadata(FAN_CREATE, FAN_NOFD, 7, 9999); // 声明长度超界
        assert!(parse_stream(&buf).is_empty());
        // 自洽性:附加记录越界则忽略记录,事件仍产出
        let mut b = metadata(FAN_CREATE, FAN_NOFD, 7, 24 + 6);
        b.extend_from_slice(&[FAN_EVENT_INFO_TYPE_FID, 0, 9, 0, 0, 0]);
        let events = parse_stream(&b);
        assert_eq!(events.len(), 1);
        assert!(events[0].target.is_none());
    }

    #[test]
    fn multiple_events_in_one_read() {
        let mut buf =
            one(FAN_CREATE, 1, &[fid_record(FAN_EVENT_INFO_TYPE_DFID_NAME, b"h", &[b"a"])]);
        buf.extend_from_slice(&one(FAN_DELETE, 2, &[]));
        let events = parse_stream(&buf);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].pid, 1);
        assert_eq!(events[1].pid, 2);
    }

    #[test]
    fn pidfd_record_extracted() {
        let mut rec = vec![FAN_EVENT_INFO_TYPE_PIDFD, 0, 8, 0];
        rec.extend_from_slice(&4321i32.to_ne_bytes());
        let buf = one(FAN_MODIFY, 3, &[rec]);
        let ev = &parse_stream(&buf)[0];
        assert_eq!(ev.pidfd, Some(4321));
    }
}
