//! Windows 系统审计采集通道:SACL + 安全日志对象访问审核(事件 4663/4660)。
//!
//! 运行形态:管理员(auxiliary elevated)辅助进程连接 GUI 命名管道接收器,
//! 复用 `audit_pipe` 的 JSON 行协议推送事件。
//!
//! 机制:
//!   1. `auditpol /set /subcategory:"File System" /success:enable`
//!      开启对象访问审核(记录原状态,退出时尽力恢复);
//!   2. 对每个监控根用 PowerShell 向 SACL 追加 Everyone 的 Write/Delete
//!      成功审核 ACE(ContainerInherit/ObjectInherit);
//!   3. wevtapi `EvtSubscribe` 订阅 Security 日志中 4663/4660,XML 渲染后:
//!      - 4663 携带 ObjectName/ProcessName/ProcessID/SubjectUserName/AccessMask,
//!        写入类访问 → "modified";DELETE 意向 → 挂起等待确认;
//!      - 4660(句柄以删除关闭)按 HandleID 与挂起的 4663 关联 → "removed";
//!      进程全路径由内核写入事件,天然满足"关联应用进程"。
//!   4. 退出(Drop)时移除自建 SACL ACE 并恢复审核策略。
//!
//! 局限(如实呈现):4663 表达"访问意向",创建与修改无法精确区分(统一记
//! 为 modified,普通 notify 通道仍准确记录 created);重命名由 notify 通道
//! 呈现;读取事件(track_access)不产生 4663 审核,不支持。
//!
//! XML 解析、时间/数字解析、NT 设备路径翻译均为纯函数,可在任意平台测试。

use std::time::{SystemTime, UNIX_EPOCH};

// ---- 访问掩码位(grouping: 4663 AccessMask) ----
pub const ACCESS_DELETE: u64 = 0x0001_0000;
pub const ACCESS_WRITE_DATA: u64 = 0x0000_0002;
pub const ACCESS_APPEND_DATA: u64 = 0x0000_0004;
pub const ACCESS_WRITE_EA: u64 = 0x0000_0010;
pub const ACCESS_WRITE_ATTR: u64 = 0x0000_0100;
pub const ACCESS_GENERIC_WRITE: u64 = 0x4000_0000;
pub const ACCESS_MAXIMUM: u64 = 0x2000_0000;

/// 删除意向(挂起等待 4660 确认)
pub fn delete_intent(mask: u64) -> bool {
    mask & ACCESS_DELETE != 0
}
/// 写入类访问(创建/修改统一归为 modified)
pub fn write_intent(mask: u64) -> bool {
    !delete_intent(mask)
        && mask
            & (ACCESS_WRITE_DATA
                | ACCESS_APPEND_DATA
                | ACCESS_WRITE_EA
                | ACCESS_WRITE_ATTR
                | ACCESS_GENERIC_WRITE
                | ACCESS_MAXIMUM)
            != 0
}

/// Security 日志事件的通用抽取结果
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEvent {
    pub event_id: u32,
    /// 事件产生时刻(Unix 毫秒)
    pub time_ms: i64,
    pub fields: Vec<(String, String)>,
}

impl SecurityEvent {
    /// 按候选名依次查找 EventData 字段
    pub fn field(&self, names: &[&str]) -> Option<&str> {
        names
            .iter()
            .find_map(|n| self.fields.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str()))
    }
}

/// 渲染后的事件 XML → 结构化字段(非严格 XML:仅取需要的三类节点)
pub fn parse_event_xml(xml: &str) -> Option<SecurityEvent> {
    let event_id = parse_number(&between_tags(xml, "EventID")?).unwrap_or(0) as u32;
    if event_id == 0 {
        return None;
    }
    let time_ms = match attr_value(xml, "SystemTime").as_deref().and_then(parse_system_time) {
        Some(t) => t,
            // 时间异常时退回当前时刻不影响归因正确性
        None => now_ms(),
    };
    let mut fields = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Data ") {
        let head = &rest[start..];
        let Some(name) = quoted_attr(head, "Name") else { break };
        let Some(content_start) = find_gt(head) else { break };
        let after = &head[content_start..];
        let Some(end) = after.find("</Data>") else { break };
        fields.push((unescape(&name), unescape(&after[..end])));
        rest = &after[end + 7..];
    }
    Some(SecurityEvent { event_id, time_ms, fields })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `<Tag ...>value</Tag>` 抽取(取第一个匹配)
fn between_tags(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}");
    let start = xml.find(&open)?;
    let content_start = find_gt(&xml[start..])? + start;
    let close = format!("</{tag}>");
    let end = xml[content_start..].find(&close)? + content_start;
    Some(xml[content_start..end].to_string())
}

/// 属性值(引号可为 ' 或 ")
fn quoted_attr(text: &str, attr: &str) -> Option<String> {
    let needle = format!("{attr}=");
    let pos = text.find(&needle)? + needle.len();
    let rest = &text[pos..];
    let quote = rest.as_bytes().first().copied()?;
    if quote != b'\'' && quote != b'"' {
        return None;
    }
    let rest = &rest[1..];
    let end = rest.find(quote as char)?;
    Some(rest[..end].to_string())
}
fn attr_value(xml: &str, attr: &str) -> Option<String> {
    quoted_attr(xml, attr)
}
fn find_gt(text: &str) -> Option<usize> {
    text.find('>').map(|i| i + 1)
}

/// 十进制或 0x 十六进制
pub fn parse_number(text: &str) -> Option<u64> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    t.parse::<u64>().ok()
}

/// W3C/ISO8601 时间("2026-09-24T04:05:06.1234567Z" 或带 ±hh:mm)→ Unix 毫秒
pub fn parse_system_time(text: &str) -> Option<i64> {
    // 分数秒截到 6 位(微秒),再交给 rfc3339 解析
    let normalized = match text.find('.') {
        Some(dot) => {
            let tail = &text[dot + 1..];
            let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
            let rest = &tail[digits.len()..];
            let keep = &digits[..digits.len().min(6)];
            format!("{}.{keep}{rest}", &text[..dot])
        }
        None => text.to_string(),
    };
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&normalized) {
        return Some(dt.timestamp_millis());
    }
    chrono::NaiveDateTime::parse_from_str(&normalized, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .map(|n| n.and_utc().timestamp_millis())
}

/// NT 设备路径 → 驱动器路径("\Device\HarddiskVolume2\Users\a" + map → "C:\Users\a")
pub fn translate_object_name(name: &str, devmap: &[(String, String)]) -> String {
    for (device, drive) in devmap {
        if name.len() > device.len() && name[..device.len()].eq_ignore_ascii_case(device) {
            let mut out = String::with_capacity(name.len());
            out.push_str(drive);
            let tail = &name[device.len()..];
            for c in tail.chars() {
                out.push(if c == '\\' { '\\' } else { c });
            }
            return out;
        }
    }
    name.to_string()
}

/// 4663 → 候选事件(带进程与路径)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub path: String,
    pub exe: Option<String>,
    pub pid: u64,
    pub user: String,
    pub mask: u64,
    pub handle_id: u64,
    pub object_type: String,
}

pub fn extract_4663(ev: &SecurityEvent, devmap: &[(String, String)]) -> Option<Candidate> {
    if ev.event_id != 4663 {
        return None;
    }
    let object = ev.field(&["ObjectName", "Object Name"])?;
    let path = translate_object_name(object, devmap);
    // 目录对象审核规则同样命中文件目录本身;仅接受绝对路径形态
    if !(path.starts_with("\\\\") || (path.len() >= 3 && path.as_bytes()[1] == b':')) {
        return None;
    }
    let exe = ev
        .field(&["ProcessName", "Process Name"])
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let pid = ev.field(&["ProcessID", "Process ID", "ProcessId"]).and_then(parse_number)?;
    let user = ev.field(&["SubjectUserName", "Subject User Name"]).unwrap_or("").to_string();
    let mask = ev.field(&["AccessMask", "Access Mask", "AccessList"]).and_then(parse_number)?;
    let handle_id =
        ev.field(&["HandleID", "Handle Id", "HandleId"]).and_then(parse_number).unwrap_or(0);
    let object_type =
        ev.field(&["ObjectType", "Object Type"]).unwrap_or("File").to_string();
    Some(Candidate { path, exe, pid, user, mask, handle_id, object_type })
}

/// 4660 → (HandleID, 被删除对象路径)
pub fn extract_4660(ev: &SecurityEvent, devmap: &[(String, String)]) -> Option<(u64, String)> {
    if ev.event_id != 4660 {
        return None;
    }
    let handle_id =
        ev.field(&["HandleID", "Handle Id", "HandleId"]).and_then(parse_number)?;
    let path = ev
        .field(&["ObjectName", "Object Name"])
        .map(|s| translate_object_name(s, devmap))
        .unwrap_or_default();
    Some((handle_id, path))
}

fn unescape(text: &str) -> String {
    text.replace("&apos;", "'")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

// ---- Windows 运行时:wevtapi 订阅 + SACL/策略管理 -----------------------------

#[cfg(target_os = "windows")]
mod windows_rt {
    #![allow(dead_code)]
    // Win32 API 常量/类型保持官方命名
   #![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
    use super::*;
    use crate::audit_pipe::{Collector, EventBits, Scope};
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    type HANDLE = *mut core::ffi::c_void;
    type BOOL = i32;
    type DWORD = u32;
    type EVT_HANDLE = HANDLE;

    const INFINITE: DWORD = u32::MAX;
    const WAIT_OBJECT_0: DWORD = 0;
    const WAIT_TIMEOUT: DWORD = 258;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const TOKEN_QUERY: DWORD = 0x0008;
    const TOKEN_ELEVATION_CLASS: DWORD = 20;
    const EvtQueryChannelPath: DWORD = 0x1;
    const EvtQueryForwardDirection: DWORD = 0x100;
    const EvtSubscribeToFutureEvents: DWORD = 1;
    const EvtRenderEventXml: DWORD = 1;

    #[link(name = "kernel32")]
    extern "system" {
        fn CloseHandle(h: HANDLE) -> BOOL;
        fn CreateEventW(
            sa: *const core::ffi::c_void,
            manual_reset: BOOL,
            initial: BOOL,
            name: *const u16,
        ) -> HANDLE;
        fn WaitForSingleObject(h: HANDLE, ms: DWORD) -> DWORD;
        fn GetCurrentProcess() -> HANDLE;
        fn GetLastError() -> DWORD;
        fn GetLogicalDrives() -> DWORD;
    }
    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(process: HANDLE, access: DWORD, token: *mut HANDLE) -> BOOL;
        fn GetTokenInformation(
            token: HANDLE,
            class: DWORD,
            info: *mut core::ffi::c_void,
            len: DWORD,
            returned: *mut DWORD,
        ) -> BOOL;
        fn QueryDosDeviceW(
            device_name: *const u16,
            target_path: *mut u16,
            size: DWORD,
        ) -> DWORD;
    }
    #[link(name = "wevtapi")]
    extern "system" {
        fn EvtSubscribe(
            session: EVT_HANDLE,
            signal_event: HANDLE,
            path: *const u16,
            query: *const u16,
            bookmark: EVT_HANDLE,
            context: *mut core::ffi::c_void,
            callback: *const core::ffi::c_void,
            flags: DWORD,
        ) -> EVT_HANDLE;
        fn EvtNext(
            results: EVT_HANDLE,
            count: DWORD,
            handles: *mut EVT_HANDLE,
            timeout: DWORD,
            returned: *mut DWORD,
        ) -> BOOL;
        fn EvtRender(
            context: EVT_HANDLE,
            fragment: EVT_HANDLE,
            render_type: DWORD,
            buffer_size: DWORD,
            buffer: *mut core::ffi::c_void,
            used: *mut DWORD,
            property_count: *mut DWORD,
        ) -> BOOL;
        fn EvtClose(object: EVT_HANDLE) -> BOOL;
    }

    fn wide(text: &str) -> Vec<u16> {
        OsStr::new(text).encode_wide().chain(std::iter::once(0)).collect()
    }
    fn null_handle() -> HANDLE {
        std::ptr::null_mut()
    }

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: DWORD,
    }

    /// 当前进程是否已提权(管理员)
    pub fn self_elevated() -> bool {
        unsafe {
            let mut token = null_handle();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elev = TokenElevation { token_is_elevated: 0 };
            let mut ret = 0;
            let ok = GetTokenInformation(
                token,
                TOKEN_ELEVATION_CLASS,
                (&mut elev as *mut TokenElevation).cast(),
                std::mem::size_of::<TokenElevation>() as DWORD,
                &mut ret,
            );
            CloseHandle(token);
            ok != 0 && elev.token_is_elevated != 0
        }
    }

    /// 盘符 → NT 设备路径映射(翻译 4663 的 \Device\HarddiskVolumeN 前缀)
    pub fn device_map() -> Vec<(String, String)> {
        let mut out = Vec::new();
        let drives = unsafe { GetLogicalDrives() };
        for i in 0..26 {
            if drives & (1 << i) == 0 {
                continue;
            }
            let letter = (b'A' + i) as u16;
            let dev = wide(&format!("{}:", letter as u8 as char));
            let mut buf = [0u16; 256];
            let n = unsafe { QueryDosDeviceW(dev.as_ptr(), buf.as_mut_ptr(), buf.len() as DWORD) };
            if n != 0 {
                let target = String::from_utf16_lossy(
                    &buf[..buf.iter().position(|c| *c == 0).unwrap_or(0)],
                );
                out.push((target, format!("{}:", letter as u8 as char)));
            }
        }
        out
    }

    fn run(cmd: &str, args: &[&std::ffi::OsStr]) -> std::io::Result<std::process::Output> {
        std::process::Command::new(cmd).args(args).output()
    }
    fn powershell(script: &str, arg: &PathBuf) -> std::io::Result<std::process::Output> {
        run(
            "powershell.exe",
            &[
                std::ffi::OsStr::new("-NoProfile"),
                std::ffi::OsStr::new("-NonInteractive"),
                std::ffi::OsStr::new("-Command"),
                std::ffi::OsStr::new(script),
                std::ffi::OsStr::new("famtool"), // $args[0] 占位
                arg.as_os_str(),                 // $args[1]
            ],
        )
    }

    const AUDIT_RIGHTS: &str = "Write,Delete,DeleteSubdirectoriesAndFiles";
    fn acl_script(op: &str) -> String {
        // $args[0]=famtool $args[1]=路径;脚本为固定文本,路径仅经参数传入
        format!(
            "$ErrorActionPreference='Stop';$p=$args[1];$r=New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','{AUDIT_RIGHTS}','ContainerInherit,ObjectInherit','None','Success');$a=Get-Acl -LiteralPath $p;{};Set-Acl -LiteralPath $p -AclObject $a",
            match op {
                "add" => "$a.SetAuditRule($r)",
                "remove" => "$a.RemoveAuditRuleSpecific($r)",
                _ => "",
            }
        )
    }

    pub struct SecurityLogCollector {
        subscription: EVT_HANDLE,
        signal: HANDLE,
        devmap: Vec<(String, String)>,
        /// HandleID → 删除意向(等待 4660 确认;超时即丢弃)
        pending: HashMap<u64, (Candidate, Instant)>,
        /// 审核策略是否由本进程开启(退出时恢复)
        policy_enabled_by_us: bool,
        sacl_roots: Vec<PathBuf>,
        dropped: u64,
        buf: Vec<u16>,
        handles: Vec<EVT_HANDLE>,
    }

    impl SecurityLogCollector {
        pub fn open(scope: &Scope) -> Result<Self, String> {
            if !self_elevated() {
                return Err("当前进程未提权".into());
            }
            // 1) 对象访问审核策略
            let before = audit_policy_state()?;
            let mut policy_enabled_by_us = false;
            if !before {
                let out = run(
                    "auditpol.exe",
                    &[
                        std::ffi::OsStr::new("/set"),
                        std::ffi::OsStr::new("/subcategory:File System"),
                        std::ffi::OsStr::new("/success:enable"),
                    ],
                )
                .map_err(|e| format!("无法执行 auditpol: {e}"))?;
                if !out.status.success() {
                    return Err(format!(
                        "auditpol 开启对象访问审核失败: {}",
                        String::from_utf8_lossy(&out.stderr).trim()
                    ));
                }
                policy_enabled_by_us = true;
            }
            // 2) 监控根 SACL
            let mut roots = Vec::new();
            for root in &scope.roots {
                match powershell(&acl_script("add"), root) {
                    Ok(o) if o.status.success() => roots.push(root.clone()),
                    Ok(o) => eprintln!(
                        "audit: 设置 SACL 失败 {}: {}",
                        root.display(),
                        String::from_utf8_lossy(&o.stderr).trim()
                    ),
                    Err(e) => eprintln!("audit: powershell 不可用: {e}"),
                }
            }
            if roots.is_empty() {
                return Err("没有可配置 SACL 的监控根路径".into());
            }
            // 3) 订阅 Security 日志
            let signal = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
            if signal.is_null() {
                return Err("无法创建订阅事件对象".into());
            }
            let subscription = unsafe {
                EvtSubscribe(
                    null_handle(),
                    signal,
                    wide("Security").as_ptr(),
                    wide("*[System[(EventID=4660 or EventID=4663)]]").as_ptr(),
                    null_handle(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    EvtSubscribeToFutureEvents,
                )
            };
            if subscription.is_null() {
                unsafe { CloseHandle(signal) };
                return Err(format!(
                    "无法订阅 Security 日志(需要读取安全日志权限): GetLastError={}",
                    unsafe { GetLastError() }
                ));
            }
            Ok(Self {
                subscription,
                signal,
                devmap: device_map(),
                pending: HashMap::new(),
                policy_enabled_by_us,
                sacl_roots: roots,
                dropped: 0,
                buf: vec![0u16; 16 * 1024],
                handles: Vec::new(),
            })
        }

        fn render_xml(&mut self, event: EVT_HANDLE) -> Option<String> {
            loop {
                let mut used = 0u32;
                let ok = unsafe {
                    EvtRender(
                        null_handle(),
                        event,
                        EvtRenderEventXml,
                        (self.buf.len() * 2) as DWORD,
                        self.buf.as_mut_ptr().cast(),
                        &mut used,
                        std::ptr::null_mut(),
                    )
                };
                if ok != 0 {
                    let len = self.buf.iter().position(|c| *c == 0).unwrap_or(used as usize / 2);
                    return Some(String::from_utf16_lossy(&self.buf[..len]));
                }
                if unsafe { GetLastError() } == ERROR_INSUFFICIENT_BUFFER && used > 0 {
                            self.buf = vec![0u16; used as usize / 2 + 1024];
                    continue;
                }
                return None;
            }
        }

        fn emit(
            bits: &EventBits,
            sequence: &mut u64,
            out: &mut Vec<Vec<u8>>,
        ) {
            *sequence += 1;
            out.push(crate::audit_pipe::wire_line(bits, *sequence));
        }

        fn bits_for(
            cand: &Candidate,
            event: &'static str,
            path: String,
        ) -> EventBits {
            let folder = cand.object_type.eq_ignore_ascii_case("Directory")
                || std::fs::metadata(&path).is_ok_and(|m| m.is_dir());
            EventBits {
                event,
                from: None,
                object: if folder { "folder" } else { "file" },
                path,
                user: cand.user.clone(),
                owner: String::new(),
                event_type: (cand.mask & u32::MAX as u64) as u32,
                pid: cand.pid as u32,
                exe: cand.exe.clone().unwrap_or_default(),
                uid: u32::MAX,
                real_uid: u32::MAX,
                audit_uid: u32::MAX,
                parent: None,
                source: "security_log",
            }
        }
    }

    impl Collector for SecurityLogCollector {
        fn collect(
            &mut self,
            scope: &Scope,
            sequence: &mut u64,
            out: &mut Vec<Vec<u8>>,
        ) -> Result<(), String> {
            // 挂起删除 5 秒未获 4660 确认即过期(删除可能实际失败)
            self.pending.retain(|_, (_, at)| at.elapsed() < Duration::from_secs(5));
            loop {
                let mut returned = 0u32;
                self.handles.clear();
                let cap = 64u32;
                self.handles.clear();
                self.handles.resize(cap as usize, null_handle());
                let ok = unsafe {
                    EvtNext(
                        self.subscription,
                        cap,
                        self.handles.as_mut_ptr(),
                        0,
                        &mut returned,
                    )
                };
                if ok == 0 || returned == 0 {
                    break;
                }
                for i in 0..returned as usize {
                    let event = self.handles[i];
                    let xml = self.render_xml(event);
                    unsafe { EvtClose(event) };
                    let Some(xml) = xml else {
                        self.dropped += 1;
                        continue;
                    };
                    let Some(ev) = parse_event_xml(&xml) else { continue };
                    match ev.event_id {
                        4663 => {
                            let Some(cand) = extract_4663(&ev, &self.devmap) else {
                                continue;
                            };
                            if delete_intent(cand.mask) {
                                if !scope.includes(&cand.path) {
                                    continue;
                                }
                                if cand.handle_id != 0 {
                                    self.pending.insert(cand.handle_id, (cand, Instant::now()));
                                }
                            } else if write_intent(cand.mask)
                                && scope.includes(&cand.path)
                                && cand.exe.is_some()
                            {
                                Self::emit(
                                    &Self::bits_for(&cand, "modified", cand.path.clone()),
                                    sequence,
                                    out,
                                );
                            }
                        }
                        4660 => {
                            let Some((handle_id, path)) = extract_4660(&ev, &self.devmap) else {
                                continue;
                            };
                            if let Some((cand, _)) = self.pending.remove(&handle_id) {
                                let path = if path.is_empty() { cand.path.clone() } else { path };
                                if !scope.includes(&path) || cand.exe.is_none() {
                                    continue;
                                }
                                Self::emit(
                                    &Self::bits_for(&cand, "removed", path),
                                    sequence,
                                    out,
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(())
        }
        fn dropped(&mut self) -> u64 {
            self.dropped
        }
    }

    impl Drop for SecurityLogCollector {
        fn drop(&mut self) {
            unsafe {
                EvtClose(self.subscription);
                CloseHandle(self.signal);
            }
            for root in &self.sacl_roots {
                let _ = powershell(&acl_script("remove"), root);
            }
            if self.policy_enabled_by_us {
                let _ = run(
                    "auditpol.exe",
                    &[
                        std::ffi::OsStr::new("/set"),
                        std::ffi::OsStr::new("/subcategory:File System"),
                        std::ffi::OsStr::new("/success:disable"),
                    ],
                );
            }
        }
    }

    /// `auditpol /get /subcategory:"File System" /r` → Success 是否已开启
    fn audit_policy_state() -> Result<bool, String> {
        let out = run(
            "auditpol.exe",
            &[
                std::ffi::OsStr::new("/get"),
                std::ffi::OsStr::new("/subcategory:File System"),
                std::ffi::OsStr::new("/r"),
            ],
        )
        .map_err(|e| format!("无法执行 auditpol: {e}"))?;
        if !out.status.success() {
            return Err("auditpol /get 失败(可能缺少安全策略读取权限)".into());
        }
        // 结果列取值:No Auditing / Success / Failure / Success and Failure
        let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
        Ok(text.contains("success"))
    }

    pub fn teardown(roots: &[PathBuf]) -> Result<(), String> {
        for root in roots {
            let _ = powershell(&acl_script("remove"), root);
        }
        Ok(())
    }

    pub fn probe() -> (bool, String) {
        if !self_elevated() {
            return (false, "当前进程未提权:安全日志审计需要管理员授权启动".into());
        }
        let signal = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        if signal.is_null() {
            return (false, "无法创建事件对象".into());
        }
        let sub = unsafe {
            EvtSubscribe(
                null_handle(),
                signal,
                wide("Security").as_ptr(),
                wide("*[System[(EventID=4660 or EventID=4663)]]").as_ptr(),
                null_handle(),
                std::ptr::null_mut(),
                std::ptr::null(),
                EvtSubscribeToFutureEvents,
            )
        };
        unsafe { CloseHandle(signal) };
        if sub.is_null() {
            return (false, "无法订阅 Security 日志(需要读取安全日志权限)".into());
        }
        unsafe { EvtClose(sub) };
        (true, "Security 日志订阅可用".into())
    }
}

#[cfg(target_os = "windows")]
pub use windows_rt::{probe, self_elevated, SecurityLogCollector, teardown};

#[cfg(not(target_os = "windows"))]
pub fn probe() -> (bool, String) {
    (false, "安全日志审计仅适用于 Windows".into())
}
#[cfg(not(target_os = "windows"))]
pub fn self_elevated() -> bool {
    false
}
#[cfg(not(target_os = "windows"))]
pub fn teardown(_roots: &[std::path::PathBuf]) -> Result<(), String> {
    Err("安全日志审计仅适用于 Windows".into())
}

// ---- 纯解析单元测试(任意平台可跑) -------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_4663: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4663</EventID><Version>1</Version><Level>0</Level><Task>12800</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-24T04:05:06.1234567Z'/><EventRecordID>123456</EventRecordID><Correlation/><Execution ProcessID='1234' ThreadID='5678'/><Channel>Security</Channel><Computer>PC.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-1</Data><Data Name='SubjectUserName'>akhs</Data><Data Name='SubjectDomainName'>PC</Data><Data Name='SubjectLogonId'>0x3e7</Data><Data Name='ObjectServer'>Security</Data><Data Name='ObjectType'>File</Data><Data Name='ObjectName'>\Device\HarddiskVolume3\watched\报告.docx</Data><Data Name='HandleID'>0x12ac</Data><Data Name='ProcessID'>0xac4</Data><Data Name='ProcessName'>C:\Program Files\App\app.exe</Data><Data Name='AccessList'>%%4417</Data><Data Name='AccessMask'>0x10000</Data><Data Name='PrivilegeList'>-</Data><Data Name='ResourceAttributes'>-</Data></EventData><RenderingInfo Culture='en-US'><Level>信息</Level><Task>详细文件共享</Task><Opcode>信息</Opcode><Channel>Security</Channel><Provider>Microsoft-Windows-Security-Auditing</Provider><EventID>4663</EventID><Keywords><Keyword>审核成功</Keyword></Keywords></RenderingInfo></Event>"#;

    fn devmap() -> Vec<(String, String)> {
        vec![("\\Device\\HarddiskVolume3".into(), "C:".into())]
    }

    #[test]
    fn xml_extraction_yields_identity_and_path() {
        let ev = parse_event_xml(SAMPLE_4663).unwrap();
        assert_eq!(ev.event_id, 4663);
        assert_eq!(
            ev.time_ms,
            parse_system_time("2026-09-24T04:05:06.123Z").unwrap()
        );
        assert_eq!(ev.field(&["SubjectUserName", "Subject User Name"]), Some("akhs"));
        let cand = extract_4663(&ev, &devmap()).unwrap();
        assert_eq!(cand.path, r"C:\watched\报告.docx");
        assert_eq!(cand.exe.as_deref(), Some(r"C:\Program Files\App\app.exe"));
        assert_eq!(cand.pid, 0xac4);
        assert_eq!(cand.handle_id, 0x12ac);
        assert_eq!(cand.user, "akhs");
        assert!(delete_intent(cand.mask));
        assert!(!write_intent(cand.mask));
    }

    #[test]
    fn write_masks_classify_as_modified_intent() {
        assert!(write_intent(ACCESS_GENERIC_WRITE));
        assert!(write_intent(ACCESS_WRITE_DATA));
        assert!(write_intent(ACCESS_APPEND_DATA | ACCESS_WRITE_ATTR));
        assert!(!write_intent(ACCESS_DELETE));
        assert!(!write_intent(0x8000_0000 /*READ*/));
        assert!(!delete_intent(ACCESS_WRITE_DATA));
    }

    #[test]
    fn numbers_and_times_are_lenient() {
        assert_eq!(parse_number("0x1f4"), Some(500));
        assert_eq!(parse_number("500"), Some(500));
        assert_eq!(parse_number(" 0Xff "), Some(255));
        assert_eq!(parse_number(""), None);
        // 7 位分数秒与 3 位一致(毫秒精度)
        assert_eq!(
            parse_system_time("2026-09-24T04:05:06.1234567Z"),
            parse_system_time("2026-09-24T04:05:06.123Z")
        );
        assert!(parse_system_time("garbage").is_none());
    }

    #[test]
    fn confirm_4660_pops_pending_by_handle() {
        let xml = SAMPLE_4663.replace("4663</EventID>", "4660</EventID>");
        let ev = parse_event_xml(&xml).unwrap();
        assert_eq!(ev.event_id, 4660);
        // 4663 抽取器必须拒绝 4660
        assert!(extract_4663(&ev, &devmap()).is_none());
        let (handle, path) = extract_4660(&ev, &devmap()).unwrap();
        assert_eq!(handle, 0x12ac);
        assert_eq!(path, r"C:\watched\报告.docx");
    }

    #[test]
    fn device_translation_is_case_insensitive_and_safe() {
        let map = devmap();
        assert_eq!(
            translate_object_name(r"\device\harddiskvolume3\a\b.txt", &map),
            r"C:\a\b.txt"
        );
        // 未知设备前缀原样返回
        assert_eq!(
            translate_object_name(r"\Device\Mailslot\X", &map),
            r"\Device\Mailslot\X"
        );
        // 前缀恰等于设备路径(无尾部)不改写
        assert_eq!(
            translate_object_name(r"\Device\HarddiskVolume3", &map),
            r"\Device\HarddiskVolume3"
        );
    }

    #[test]
    fn non_file_objects_rejected() {
        let ev = parse_event_xml(SAMPLE_4663).unwrap();
        // ObjectName 非绝对路径形态(如注册表 Key)→ 拒绝
        let xml2 = SAMPLE_4663.replace(
            r"\Device\HarddiskVolume3\watched\报告.docx",
            r"\REGISTRY\MACHINE\SOFTWARE",
        );
        let ev2 = parse_event_xml(&xml2).unwrap();
        assert!(extract_4663(&ev2, &devmap()).is_none());
        let _ = ev;
    }

    #[test]
    fn entities_unescaped() {
        assert_eq!(unescape("a&amp;b&apos;c"), "a&b'c");
        let xml = SAMPLE_4663.replace("报告.docx", "R&amp;D&aposs.txt".replace("&aposs", "&apos;").as_str());
        let ev = parse_event_xml(&xml).unwrap();
        let cand = extract_4663(&ev, &devmap()).unwrap();
        assert_eq!(cand.path, r"C:\watched\R&D'.txt");
    }
}
