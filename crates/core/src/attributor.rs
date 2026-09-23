//! 操作者归因:尽力为每条记录推断"关联进程"与"所属用户"。
//!
//! macOS FSEvents / Linux inotify / Windows RDCW 都不随事件附带操作者身份
//! (macOS 仅对本进程自身事件附带 PID),因此这里做三层尽力归因,证据强度递减:
//!
//! 1. `fd_scan`     —— 事件发生时扫描所有进程打开的文件描述符,发现某进程
//!    正持有该文件(写入者通常在写后短暂持有,长写者持续持有)。
//!    证据最强,来源标记为 `fd_scan; open_descriptor`。
//! 2. `path_inferred` —— 按路径布局推断所属应用(如 `~/Library/Containers/<bundle>/…`、
//!    `~/Library/Application Support/<App>/…`、`~/.config/<App>/…`)。
//!    启发式,GUI 中以斜体展示,来源标记为 `path_inferred`。
//! 3. `notify_process_id` —— 系统原生报告的本进程自身事件(notify OWN_EVENT)。
//!
//! 用户列:优先取归因到的进程属主;兜底取文件属主(stat→getpwuid,删除事件
//! 查最近缓存的属主)。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::record::{Actor, Record};

/// fd 扫描最小间隔与批次上限(超过则跳过扫描,仅做推断)
const SCAN_INTERVAL: Duration = Duration::from_millis(1000);
const SCAN_MAX_PATHS: usize = 40;
/// 归因缓存有效期
const FD_TTL: Duration = Duration::from_secs(20);
const INFER_TTL: Duration = Duration::from_secs(60);
const OWNER_TTL: Duration = Duration::from_secs(600);

#[derive(Default)]
pub struct Attributor {
    last_scan: Option<Instant>,
    /// 最近一次 fd 扫描结果: 路径 → pid
    fd_map: HashMap<PathBuf, i32>,
    /// 路径 → (归因, 时刻)
    cache: HashMap<PathBuf, (Actor, Instant)>,
    /// 路径 → (属主, 时刻) 供删除事件回查
    owner_cache: HashMap<PathBuf, (String, Instant)>,
    /// uid → 用户名
    #[cfg(unix)]
    uid_names: HashMap<u32, String>,
    /// pid → (进程名, uid),本次进程生命周期内有效
    pid_meta: HashMap<i32, (String, Option<u32>)>,
}

impl Attributor {
    /// 对一批刚产生的记录做归因(填充 actor 与 owner)。
    /// 在聚合线程 finalize 之后调用。
    pub fn attribute(&mut self, recs: &mut [Record]) {
        if recs.is_empty() {
            return;
        }
        let scan_due = self.last_scan.is_none_or(|t| t.elapsed() >= SCAN_INTERVAL);
        let need_scan = scan_due
            && recs.len() <= SCAN_MAX_PATHS
            && recs.iter().any(|r| r.actor.process_id.is_none());
        if need_scan {
            self.scan_open_files();
            self.last_scan = Some(Instant::now());
        }

        let now = Instant::now();
        let mut native_actors = HashMap::new();
        for rec in recs.iter_mut() {
            // ---- 用户/属主 ----
            if rec.owner.is_none() {
                rec.owner = self.owner_of(&rec.path);
            }
            if rec.owner.is_none() {
                if let Some(f) = &rec.from {
                    rec.owner = self.owner_of(f);
                }
            }
            // ---- 进程归因(系统原生报告的自身事件优先保留) ----
            if let Some(pid) = rec.actor.process_id {
                rec.actor = native_actors
                    .entry(pid)
                    .or_insert_with(|| Actor::from_pid(Some(pid)))
                    .clone();
                continue;
            }
            let key = PathBuf::from(&rec.path);
            if let Some((actor, exp)) = self.cache.get(&key) {
                if *exp > now {
                    rec.actor = actor.clone();
                    continue;
                }
            }
            let from_key = rec.from.as_deref().map(PathBuf::from);
            let actor = self
                .by_fd(&key)
                .or_else(|| from_key.as_ref().and_then(|k| self.by_fd(k)))
                .or_else(|| {
                    infer_app(&rec.path).map(|app| Actor {
                        process_id: None,
                        application: Some(app),
                        user: None,
                        source: Some("path_inferred".into()),
                    })
                });
            if let Some(actor) = actor {
                let inferred = actor
                    .source
                    .as_deref()
                    .is_some_and(|s| s.starts_with("path_inferred"));
                let ttl = if inferred { INFER_TTL } else { FD_TTL };
                self.cache.insert(key, (actor.clone(), now + ttl));
                rec.actor = actor;
            }
        }

        if self.owner_cache.len() > 50_000 {
            self.owner_cache.clear();
        }
        if self.cache.len() > 50_000 {
            self.cache.clear();
        }
    }

    /// 文件属主:stat → uid → 用户名;删除后查缓存
    fn owner_of(&mut self, path: &str) -> Option<String> {
        let p = Path::new(path);
        #[cfg(unix)]
        if let Ok(md) = std::fs::symlink_metadata(p) {
            use std::os::unix::fs::MetadataExt;
            let name = self.uid_name(md.uid());
            if let Some(name) = name {
                self.owner_cache
                    .insert(p.to_path_buf(), (name.clone(), Instant::now()));
                return Some(name);
            }
        }
        let _ = p;
        self.owner_cache
            .get(p)
            .filter(|(_, t)| t.elapsed() < OWNER_TTL)
            .map(|(n, _)| n.clone())
    }

    /// uid → 用户名(带缓存;getpwuid_r 查询目录服务)
    #[cfg(unix)]
    fn uid_name(&mut self, uid: u32) -> Option<String> {
        if let Some(n) = self.uid_names.get(&uid) {
            return Some(n.clone());
        }
        let name = unsafe {
            let mut pwd: libc::passwd = std::mem::zeroed();
            let mut buf = [0u8; 4096];
            let mut result: *mut libc::passwd = std::ptr::null_mut();
            let rc = libc::getpwuid_r(
                uid as libc::uid_t,
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            );
            if rc == 0 && !result.is_null() {
                std::ffi::CStr::from_ptr(pwd.pw_name)
                    .to_string_lossy()
                    .into_owned()
                    .into()
            } else {
                None
            }
        };
        if self.uid_names.len() >= 4096 {
            self.uid_names.clear();
        }
        if let Some(n) = &name {
            self.uid_names.insert(uid, n.clone());
        }
        name
    }

    #[cfg(not(unix))]
    fn uid_name(&mut self, _uid: u32) -> Option<String> {
        None
    }

    /// 用 fd 扫描结果归因
    fn by_fd(&mut self, path: &Path) -> Option<Actor> {
        if self.last_scan.is_none_or(|t| t.elapsed() > FD_TTL) {
            return None;
        }
        let pid = *self.fd_map.get(path)?;
        if std::env::var_os("WJ_DEBUG").is_some() {
            eprintln!(
                "[attr] fd命中 {path:?} pid={pid} identity={:?}",
                self.pid_info(pid)
            );
        }
        let (app, uid) = self.pid_info(pid)?;
        Some(Actor {
            process_id: Some(pid as u32),
            application: Some(app),
            user: uid.and_then(|u| self.uid_name(u)),
            source: Some("fd_scan; open_descriptor".into()),
        })
    }

    /// pid → (进程名, uid)。查不到时清缓存避免进程死亡后沿用旧名。
    fn pid_info(&mut self, pid: i32) -> Option<(String, Option<u32>)> {
        if let Some(info) = self.pid_meta.get(&pid) {
            return Some(info.clone());
        }
        let info = pid_identity(pid)?;
        self.pid_meta.insert(pid, info.clone());
        Some(info)
    }

    // ---- 平台实现 ----------------------------------------------------------

    /// 扫描全部进程的打开文件,重建 fd_map。仅 macOS/Linux;Windows 为空实现。
    #[cfg(target_os = "macos")]
    fn scan_open_files(&mut self) {
        self.fd_map.clear();
        self.pid_meta.clear();
        let deadline = Instant::now() + Duration::from_millis(200);
        let pids: Vec<i32> = unsafe { macos_ffi::list_pids_sysctl() };
        let dbg2 = std::env::var_os("WJ_DEBUG").is_some();
        let self_dbg = std::process::id() as i32;
        for pid in pids {
            if Instant::now() >= deadline || self.fd_map.len() >= 50_000 {
                break;
            }
            if pid <= 0 {
                continue;
            }
            // 列出该进程的 fd
            let mut fds = vec![0u8; 8192];
            let got = unsafe {
                proc_pidinfo(
                    pid,
                    PROC_PIDLISTFDS,
                    0,
                    fds.as_mut_ptr().cast(),
                    fds.len() as i32,
                )
            };
            if got <= 0 {
                if dbg2 && pid == self_dbg {
                    eprintln!("[attr] 自身 LISTFDS 失败 got={got}");
                }
                continue;
            }
            if dbg2 && pid == self_dbg {
                eprintln!("[attr] 自身 LISTFDS got={got} 字节");
            }
            for chunk in fds[..got.min(fds.len() as i32) as usize].chunks_exact(8) {
                if Instant::now() >= deadline {
                    break;
                }
                let fd = i32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let ty = i32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
                if ty != PROX_FDTYPE_VNODE {
                    continue;
                }
                // proc_vnodepathinfo: pvipath[1024] + vnode_path[1024] + vnode_info
                let mut vbuf = [0u8; 4096];
                // 注意:fd 级 flavor 必须用 proc_pidfdinfo,proc_pidinfo 的同名编号是别的东西
                let vgot = unsafe {
                    proc_pidfdinfo(
                        pid,
                        fd,
                        PROC_PIDFDVNODEPATHINFO,
                        vbuf.as_mut_ptr().cast(),
                        vbuf.len() as i32,
                    )
                };
                if vgot as usize <= VNODE_PATH_OFF {
                    continue;
                }
                let end = (vgot as usize).min(vbuf.len());
                if let Ok(cstr) = std::ffi::CStr::from_bytes_until_nul(&vbuf[VNODE_PATH_OFF..end]) {
                    let path = cstr.to_string_lossy();
                    if !path.is_empty() {
                        // fork 会继承 fd,同一文件可能被多个进程持有:
                        // 保留首个(通常为持有者/父进程,后继承的子进程不覆盖)
                        self.fd_map
                            .entry(PathBuf::from(path.as_ref()))
                            .or_insert(pid);
                    }
                }
            }
        }
        if std::env::var_os("WJ_DEBUG").is_some() {
            eprintln!("[attr] 扫描完成: 进程持有文件数={}", self.fd_map.len());
        }
    }

    #[cfg(target_os = "linux")]
    fn scan_open_files(&mut self) {
        self.fd_map.clear();
        self.pid_meta.clear();
        let deadline = Instant::now() + Duration::from_millis(200);
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return;
        };
        for entry in dir.flatten() {
            if Instant::now() >= deadline || self.fd_map.len() >= 50_000 {
                break;
            }
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            let fd_dir = entry.path().join("fd");
            for fd in std::fs::read_dir(&fd_dir).into_iter().flatten().flatten() {
                if Instant::now() >= deadline {
                    break;
                }
                if let Ok(target) = std::fs::read_link(fd.path()) {
                    if target.is_absolute() {
                        self.fd_map.insert(target, pid);
                    }
                }
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn scan_open_files(&mut self) {}
}

/// pid → (进程名, uid)。macOS 走 libproc,Linux 读 /proc。
#[cfg(target_os = "macos")]
fn pid_identity(pid: i32) -> Option<(String, Option<u32>)> {
    unsafe {
        let mut pathbuf = [0u8; 4096];
        let n = proc_pidpath(pid, pathbuf.as_mut_ptr(), pathbuf.len() as u32);
        let name = if n > 0 {
            // proc_pidpath 返回长度不含结尾 NUL,缓冲区已清零,从头读即可
            std::ffi::CStr::from_bytes_until_nul(&pathbuf)
                .ok()?
                .to_string_lossy()
                .into_owned()
        } else {
            return None;
        };
        let display = name.rsplit('/').next().unwrap_or(name.as_str()).to_string();
        // proc_bsdinfo 实际 136 字节(CC 实测),缓冲区必须给足
        let mut bsd = [0u8; 256];
        let got = proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            bsd.as_mut_ptr().cast(),
            bsd.len() as i32,
        );
        // proc_bsdinfo.pbi_uid 偏移 20(CC 实测)
        let uid =
            (got as usize >= 24).then(|| u32::from_ne_bytes([bsd[20], bsd[21], bsd[22], bsd[23]]));
        Some((display, uid))
    }
}

#[cfg(target_os = "linux")]
fn pid_identity(pid: i32) -> Option<(String, Option<u32>)> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()?
        .trim()
        .to_string();
    let uid = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|u| u.parse::<u32>().ok())
        });
    Some((comm, uid))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn pid_identity(_pid: i32) -> Option<(String, Option<u32>)> {
    None
}

// ---- macOS libproc FFI ------------------------------------------------------

#[cfg(target_os = "macos")]
mod macos_ffi {
    pub const PROC_PIDLISTFDS: i32 = 1;
    pub const PROC_PIDTBSDINFO: i32 = 3;
    pub const PROC_PIDFDVNODEPATHINFO: i32 = 2;
    pub const PROX_FDTYPE_VNODE: i32 = 1;
    /// 路径在 vnode_fdinfowithpath 中的偏移(CC 实测 offsetof)
    pub const VNODE_PATH_OFF: usize = 176;

    // proc_pidinfo/proc_pidfdinfo/proc_pidpath 均由 libSystem 导出,无需额外链接库
    extern "C" {
        pub fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut core::ffi::c_void,
            buffersize: i32,
        ) -> i32;
        pub fn proc_pidfdinfo(
            pid: i32,
            fd: i32,
            flavor: i32,
            buffer: *mut core::ffi::c_void,
            buffersize: i32,
        ) -> i32;
        pub fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
    }

    /// 用 sysctl KERN_PROC_ALL 枚举全部 PID。
    /// kinfo_proc 结构体大小用 KERN_PROC_PID(自身 pid) 动态测定作为步长;
    /// p_pid 位于结构体起始的 extern_proc 中 —— 新内核布局下在偏移 40
    /// (实测 macOS 26/arm64,老资料常写 12,已过时)。
    pub unsafe fn list_pids_sysctl() -> Vec<i32> {
        let self_pid = std::process::id() as i32;
        // 1) 测定 sizeof(kinfo_proc)
        let mut mib_one = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PID,
            self_pid,
        ];
        let mut need: libc::size_t = 0;
        if libc::sysctl(
            mib_one.as_mut_ptr(),
            4,
            std::ptr::null_mut(),
            &mut need,
            std::ptr::null_mut(),
            0,
        ) != 0
            || !(256..=16384).contains(&need)
        {
            return Vec::new();
        }
        let stride = need;
        let dbg = std::env::var_os("WJ_DEBUG").is_some();
        // 2) 取全量进程表
        let mut mib_all = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL];
        let mut len: libc::size_t = 0;
        if libc::sysctl(
            mib_all.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
            || len == 0
            || len > stride * 20_000
        {
            return Vec::new();
        }
        let mut buf = vec![0u8; len];
        if libc::sysctl(
            mib_all.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Vec::new();
        }
        const PID_OFFSET: usize = 40;
        let pids: Vec<i32> = buf
            .chunks_exact(stride)
            .filter_map(|c| {
                let pid = i32::from_ne_bytes([
                    c[PID_OFFSET],
                    c[PID_OFFSET + 1],
                    c[PID_OFFSET + 2],
                    c[PID_OFFSET + 3],
                ]);
                (pid > 0).then_some(pid)
            })
            .collect();
        if dbg {
            eprintln!("[attr] stride={stride} 表长={} pid数={}", len, pids.len());
        }
        pids
    }
}

#[cfg(target_os = "macos")]
use macos_ffi::*;

/// 从路径布局推断所属应用名(纯启发式)。
/// 覆盖 macOS ~/Library、Linux XDG、Windows AppData 下的常见应用目录。
pub fn infer_app(path: &str) -> Option<String> {
    #[cfg(target_os = "macos")]
    const MARKERS: [&str; 7] = [
        "/Application Support/",
        "/Containers/",
        "/Caches/",
        "/Preferences/",
        "/Logs/",
        "/WebKit/",
        "/Saved Application State/",
    ];
    #[cfg(target_os = "linux")]
    const MARKERS: [&str; 3] = ["/.config/", "/.cache/", "/.local/share/"];
    #[cfg(target_os = "windows")]
    const MARKERS: [&str; 2] = ["/AppData/Roaming/", "/AppData/Local/"];
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    const MARKERS: [&str; 0] = [];

    for m in MARKERS {
        if let Some(i) = path.find(m) {
            let rest = &path[i + m.len()..];
            let seg = rest.split(['/', '\\']).next().unwrap_or("");
            if seg.is_empty() || seg.len() > 64 {
                continue;
            }
            let name = seg.strip_suffix(".plist").unwrap_or(seg);
            // bundle id(如 com.apple.Safari)取最后一段做展示名
            let display = name.rsplit('.').next().unwrap_or(name);
            if display.len() >= 2 {
                return Some(display.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn infer_from_container_paths() {
        assert_eq!(
            infer_app("/Users/a/Library/Containers/com.apple.Safari/Data/x"),
            Some("Safari".into())
        );
        assert_eq!(
            infer_app("/Users/a/Library/Application Support/ZCode/cache.db"),
            Some("ZCode".into())
        );
        assert_eq!(
            infer_app("/Users/a/Library/Preferences/com.tencent.qq.plist"),
            Some("qq".into())
        );
        assert_eq!(infer_app("/Users/a/Documents/notes.txt"), None);
    }
}

#[cfg(test)]
mod fd_tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn fd_scan_finds_self_open_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let mut a = Attributor::default();
        a.scan_open_files();
        let canon = dunce::canonicalize(f.path()).unwrap();
        eprintln!("fd_map 大小: {}", a.fd_map.len());
        for (k, v) in a.fd_map.iter().take(5) {
            eprintln!("  样本: {v} -> {k:?}");
        }
        eprintln!("期望路径: {canon:?}");
        if let Some(pid) = a.fd_map.get(&canon).copied() {
            eprintln!("命中 pid={pid}, identity={:?}", a.pid_info(pid));
        }
        assert!(
            a.fd_map.contains_key(&canon),
            "fd 扫描未发现自身持有的文件; fd_map.len={}",
            a.fd_map.len()
        );
    }
}

#[cfg(test)]
mod probe_tests {
    #[test]
    #[cfg(target_os = "macos")]
    fn probe_sysctl_kernproc() {
        unsafe {
            let pid = std::process::id() as i32;
            let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
            let mut need: libc::size_t = 0;
            let rc = libc::sysctl(
                mib.as_mut_ptr(),
                4,
                std::ptr::null_mut(),
                &mut need,
                std::ptr::null_mut(),
                0,
            );
            eprintln!(
                "KERN_PROC_PID rc={rc} errno={} need={need}",
                std::io::Error::last_os_error()
            );
            let mut mib2 = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL];
            let mut need2: libc::size_t = 0;
            let rc2 = libc::sysctl(
                mib2.as_mut_ptr(),
                3,
                std::ptr::null_mut(),
                &mut need2,
                std::ptr::null_mut(),
                0,
            );
            eprintln!(
                "KERN_PROC_ALL rc={rc2} errno={} need={need2}",
                std::io::Error::last_os_error()
            );
        }
    }
}

#[cfg(test)]
mod offset_tests {
    #[test]
    #[cfg(target_os = "macos")]
    fn find_pid_offset() {
        unsafe {
            let self_pid = std::process::id() as i32;
            let mut mib_all = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL];
            let mut len: libc::size_t = 0;
            libc::sysctl(
                mib_all.as_mut_ptr(),
                3,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            );
            let mut buf = vec![0u8; len];
            assert_eq!(
                libc::sysctl(
                    mib_all.as_mut_ptr(),
                    3,
                    buf.as_mut_ptr().cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0
                ),
                0
            );
            // 在每个 entry 的前 256 字节里找 self pid 出现的偏移
            let stride = 3888usize;
            let n = len / stride;
            let mut hits = std::collections::HashMap::new();
            for i in 0..n.min(40) {
                let e = &buf[i * stride..];
                for off in (0..256 - 3).step_by(4) {
                    let v = i32::from_ne_bytes([e[off], e[off + 1], e[off + 2], e[off + 3]]);
                    if v == self_pid && i * stride + off < len {
                        // 确认仅当该 pid 确实是第 i 个进程(用暴力:统计该偏移下所有 entry 的值>0 比例)
                        *hits.entry(off).or_insert(0) += 1;
                    }
                }
            }
            eprintln!("self_pid={self_pid} 命中偏移(前40项): {:?}", hits);
            // 打印第一个 entry 的前 80 字节 hex
            let e = &buf[..80];
            eprintln!(
                "entry[0] 前80字节: {}",
                e.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            // 验证:用偏移 12 读出全部 pid,看有多少 >0
            let c12 = buf
                .chunks_exact(stride)
                .filter(|c| i32::from_ne_bytes([c[12], c[13], c[14], c[15]]) > 0)
                .count();
            eprintln!("偏移12读出>0的pid数: {c12}/{n}");
        }
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    #[test]
    #[cfg(target_os = "macos")]
    fn self_identity() {
        let pid = std::process::id() as i32;
        let id = pid_identity(pid);
        eprintln!("identity({pid}) = {id:?}");
        assert!(id.is_some());
        assert!(
            id.as_ref().unwrap().0.contains("famtool") || !id.as_ref().unwrap().0.is_empty()
        );
    }
}

#[cfg(unix)]
/// uid → 用户名(getpwuid_r 查询目录服务,可供审计辅助进程复用)
pub fn uid_to_name(uid: u32) -> Option<String> {
unsafe {
    let mut pwd: libc::passwd = std::mem::zeroed();
    let mut buf = [0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    if libc::getpwuid_r(
        uid as libc::uid_t,
        &mut pwd,
        buf.as_mut_ptr().cast(),
        buf.len(),
        &mut result,
    ) == 0 && !result.is_null()
    {
        return Some(
            std::ffi::CStr::from_ptr(pwd.pw_name)
                .to_string_lossy()
                .into_owned(),
        );
    }
    None
}
}
