#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod audit_permissions;
mod service;
use fs2::FileExt;
use service::{DeleteResult, Desktop, SearchRequest, Snapshot};
use std::{path::PathBuf, sync::atomic::Ordering};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager,
};
use famtool_core::{
    config::{self, Config},
    search::NumberedPage,
};

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn snapshot(app: tauri::AppHandle) -> Result<Snapshot, String> {
    blocking(move || Ok(app.state::<Desktop>().snapshot())).await
}
#[tauri::command]
async fn set_monitoring(app: tauri::AppHandle, running: bool) -> Result<(), String> {
    blocking(move || app.state::<Desktop>().set_running(running)).await
}
#[tauri::command]
async fn save_settings(app: tauri::AppHandle, config: Config) -> Result<(), String> {
    blocking(move || app.state::<Desktop>().apply(config)).await
}
#[tauri::command]
async fn search_history(
    app: tauri::AppHandle,
    request: SearchRequest,
) -> Result<NumberedPage, String> {
    blocking(move || {
        let id = request.request_id.clone();
        app.state::<Desktop>().search(request, |scanned, matched| {
            let _ = app.emit(
                "history-progress",
                serde_json::json!({"request_id":id,"scanned":scanned,"matched":matched}),
            );
        })
    })
    .await
}
#[tauri::command]
async fn history_page(
    app: tauri::AppHandle,
    request_id: String,
    page: usize,
) -> Result<NumberedPage, String> {
    blocking(move || app.state::<Desktop>().history_page(&request_id, page)).await
}
#[tauri::command]
fn cancel_search(app: tauri::AppHandle, request_id: String) {
    app.state::<Desktop>().cancel_search(Some(&request_id));
}
#[tauri::command]
async fn delete_logs(app: tauri::AppHandle, confirmation: String) -> Result<DeleteResult, String> {
    blocking(move || app.state::<Desktop>().delete(&confirmation)).await
}
#[tauri::command]
fn clear_display(app: tauri::AppHandle) {
    app.state::<Desktop>().clear_display();
}
#[tauri::command]
async fn open_location(app: tauri::AppHandle, which: String) -> Result<(), String> {
    blocking(move || open_path(app.state::<Desktop>().location(&which)?, false)).await
}
#[tauri::command]
async fn reveal_file(path: String) -> Result<(), String> {
    blocking(move || open_path(PathBuf::from(path), true)).await
}
#[tauri::command]
async fn audit_probe(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    blocking(move || {
        #[cfg(target_os = "macos")]
        {
            let helper = app
                .path()
                .resource_dir()
                .map_err(|e| e.to_string())?
                .join("../MacOS/audit-helper");
            if !helper.is_file() {
                return Err("未找到原生审计辅助程序，请使用完整 macOS 应用包".into());
            }
            let output = std::process::Command::new(&helper)
                .arg("--check")
                .output()
                .map_err(|e| e.to_string())?;
            let mut result: serde_json::Value = serde_json::from_slice(&output.stdout)
                .map_err(|_| "辅助程序未返回有效检查结果；请检查签名及系统日志".to_string())?;
            result["helper_path"] = helper.display().to_string().into();
            let socket = app.state::<Desktop>().snapshot().audit.socket_path;
            result["socket_path"] = socket.into();
            Ok(result)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let helper = audit_helper_path()
                .ok_or_else(|| "未找到审计辅助程序 audit-pipe，请使用完整应用包".to_string())?;
            let output = std::process::Command::new(&helper)
                .arg("--check")
                .output()
                .map_err(|e| e.to_string())?;
            let mut result: serde_json::Value = serde_json::from_slice(&output.stdout)
                .map_err(|_| "辅助程序未返回有效检查结果".to_string())?;
            result["helper_path"] = helper.display().to_string().into();
            let socket = app.state::<Desktop>().snapshot().audit.socket_path;
            result["socket_path"] = socket.into();
            Ok(result)
        }
    })
    .await
}

/// 随应用打包的审计辅助程序路径:优先同目录 `audit-pipe`,
/// 兼容 externalBin 的目标三元组命名(`audit-pipe-x86_64-pc-windows-msvc.exe` 等)
fn audit_helper_path() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    #[cfg(windows)]
    let suffix = ".exe";
    #[cfg(not(windows))]
    let suffix = "";
    let exact = dir.join(format!("audit-pipe{suffix}"));
    if exact.is_file() {
        return Some(exact);
    }
    let mut fallback = None;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("audit-pipe") || !name.ends_with(suffix) {
                continue;
            }
            let path = entry.path();
            // 跳过开发占位文件(真实辅助程序远大于此)与非普通文件
            if path.is_file() && entry.metadata().map(|m| m.len() > 4096).unwrap_or(false) {
                fallback = Some(path);
                break;
            }
        }
    }
    fallback
}

#[tauri::command]
async fn audit_enable(app: tauri::AppHandle) -> Result<audit_permissions::PermissionReply, String> {
    let preflight = audit_permissions::operation(app.clone(), "preflight").await?;
    if preflight.state != "eligible" {
        return Ok(preflight);
    }
    let worker = app.clone();
    blocking(move || worker.state::<Desktop>().prepare_audit()).await?;
    audit_permissions::operation(app, "enable").await
}

#[tauri::command]
async fn audit_pipe_launch(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    blocking(move || {
        // 1) 准备审计接收通道:启用审计、启动监控、发布接收位置
        app.state::<Desktop>().prepare_audit()?;
        // 2) 定位随应用打包的审计辅助程序
        let helper =
            audit_helper_path().ok_or_else(|| "未找到 audit-pipe 辅助程序，请使用完整应用包".to_string())?;
        // 3) 以系统授权方式启动辅助进程(密码/同意由操作系统处理,本程序不经手凭据)
        let log = std::env::temp_dir().join("famtool-audit-pipe.log");
        #[cfg(not(target_os = "macos"))]
        let socket = app.state::<Desktop>().snapshot().audit.socket_path;
        #[cfg(target_os = "macos")]
        {
            // osascript 的管理 shell 无控制终端,nohup 会失败;用子壳后台 + stdin 重定向脱离
            let script = format!(
                "do shell script \"('{}' > '{}' 2>&1 < /dev/null &)\" with administrator privileges",
                helper.display(),
                log.display()
            );
            let out = std::process::Command::new("osascript")
                .arg("-e")
                .arg(&script)
                .output()
                .map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(format!(
                    "管理员授权未完成: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        #[cfg(target_os = "linux")]
        {
            // polkit 授权对话框;授权进程独立于 GUI 生命周期
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .map_err(|e| e.to_string())?;
            let err = std::process::Command::new("pkexec")
                .arg(&helper)
                .arg("--socket")
                .arg(&socket)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::from(
                    file.try_clone().map_err(|e| e.to_string())?,
                ))
                .stderr(std::process::Stdio::from(file))
                .spawn()
                .err()
                .map(|e| e.to_string());
            if let Some(e) = err {
                return Err(format!("无法启动 pkexec: {e}"));
            }
        }
        #[cfg(target_os = "windows")]
        {
            // UAC 提权;脚本为固定文本,路径仅经 $args 传入避免注入
            let script = "Start-Process -FilePath $args[0] -ArgumentList '--socket', $args[2] -WindowStyle Hidden -Verb RunAs";
            let out = std::process::Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    script,
                    "famtool",
                ])
                .arg(&helper)
                .arg(&socket)
                .output()
                .map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(format!(
                    "管理员授权未完成: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = (&helper, &log);
            return Err("当前平台没有系统审计采集通道".to_string());
        }
        Ok(serde_json::json!({
            "launched": true,
            "helper": helper.display().to_string(),
            "log": log.display().to_string()
        }))
    })
    .await
}

#[tauri::command]
async fn audit_service_status(
    app: tauri::AppHandle,
) -> Result<audit_permissions::PermissionReply, String> {
    audit_permissions::operation(app, "status").await
}
#[tauri::command]
async fn audit_service_stop(
    app: tauri::AppHandle,
) -> Result<audit_permissions::PermissionReply, String> {
    audit_permissions::operation(app, "stop").await
}
#[tauri::command]
async fn audit_open_privacy(
    app: tauri::AppHandle,
) -> Result<audit_permissions::PermissionReply, String> {
    audit_permissions::operation(app, "privacy").await
}
fn open_path(path: PathBuf, reveal: bool) -> Result<(), String> {
    if !path.is_absolute() || !path.exists() {
        return Err("路径不存在或已删除".into());
    }
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        if reveal {
            c.arg("-R");
        }
        c.arg(path);
        c
    };
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("explorer");
        if reveal {
            c.arg(format!("/select,{}", path.display()));
        } else {
            c.arg(path);
        }
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        let p = if reveal && path.is_file() {
            path.parent().unwrap_or(&path)
        } else {
            &path
        };
        c.arg(p);
        c
    };
    cmd.spawn().map_err(|e| e.to_string())?;
    Ok(())
}
fn show(app: &tauri::AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}
fn hide(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
}
fn quit(app: &tauri::AppHandle) {
    if app.state::<Desktop>().quitting.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        app.state::<Desktop>().shutdown();
        app.exit(0);
    });
}
fn icon() -> tauri::image::Image<'static> {
    let size = 32usize;
    let mut data = vec![0u8; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let d = ((x as f32 - 15.5).powi(2) + (y as f32 - 15.5).powi(2)).sqrt();
            let i = (y * size + x) * 4;
            let color = if d < 4.0 {
                [255, 255, 255, 255]
            } else if d < 14.0 {
                [30, 116, 105, 255]
            } else {
                [0, 0, 0, 0]
            };
            data[i..i + 4].copy_from_slice(&color);
        }
    }
    tauri::image::Image::new_owned(data, size as u32, size as u32)
}
/// 距离下一次每日 10:30(本地时间)的秒数
fn seconds_until_daily_check() -> u64 {
    use chrono::Timelike;
    let now = chrono::Local::now();
    let mut target = now
        .with_hour(10)
        .and_then(|t| t.with_minute(30))
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(now);
    if target <= now {
        target += chrono::Duration::days(1);
    }
    // +1 向上取整,避免截断使触发时间落在 10:29
    ((target - now).num_seconds() + 1).clamp(60, 86400 * 2) as u64
}

const RELEASES_API: &str = "https://api.github.com/repos/sulab999/FAMTool/releases/latest";

fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    let out = std::process::Command::new("curl")
        .args(["-sSf", "--max-time", "20", "-H", "Accept: application/vnd.github+json", url])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "网络请求失败: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("响应解析失败: {e}"))
}

/// 比较点分版本号:a 是否大于 b
fn version_newer(a: &str, b: &str) -> bool {
    let num = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v')
            .split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (va, vb) = (num(a), num(b));
    for i in 0..va.len().max(vb.len()) {
        let (x, y) = (va.get(i).copied().unwrap_or(0), vb.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    false
}

/// 按当前系统与架构挑选安装包:dmg / exe / deb / rpm
fn pick_installer(assets: &serde_json::Value) -> Option<(String, String)> {
    let arch = std::env::consts::ARCH; // aarch64 / x86_64
    let mut names: Vec<String> = Vec::new();
    if let Some(list) = assets.as_array() {
        for a in list {
            if let Some(n) = a.get("name").and_then(|v| v.as_str()) {
                names.push(n.to_string());
            }
        }
    }
    let find = |pred: &dyn Fn(&str) -> bool| -> Option<(String, String)> {
        for a in assets.as_array()? {
            let n = a.get("name")?.as_str()?;
            if pred(n) {
                let u = a.get("browser_download_url")?.as_str()?;
                return Some((n.to_string(), u.to_string()));
            }
        }
        None
    };
    if cfg!(target_os = "macos") {
        let exact = find(&|n| n.ends_with(&format!("_macos_{arch}.dmg")));
        exact.or_else(|| find(&|n| n.ends_with(".dmg")))
    } else if cfg!(target_os = "windows") {
        find(&|n| n.ends_with("-setup.exe") || n.ends_with(".exe"))
    } else {
        // Linux:deb 系优先 deb,rpm 系用 rpm
        let is_deb = std::path::Path::new("/etc/debian_version").exists()
            || std::fs::read_to_string("/etc/os-release")
                .map(|t| {
                    t.lines().any(|l| {
                        l.starts_with("ID=")
                            && l.contains(|c| c == 'e' || c == 'u')
                    })
                })
                .unwrap_or(true);
        let (deb_arch, rpm_arch) = if arch == "aarch64" {
            ("arm64", "aarch64")
        } else {
            ("amd64", "x86_64")
        };
        if is_deb {
            find(&move |n| n.ends_with(&format!("_{deb_arch}.deb")))
                .or_else(|| find(&|n| n.ends_with(".deb")))
        } else {
            find(&move |n| n.contains(&format!(".{rpm_arch}.rpm")) || n.ends_with(".rpm"))
        }
    }
}

struct ReleaseInfo {
    version: String,
    current: String,
    notes: String,
    asset_name: String,
    asset_url: String,
}

fn fetch_latest_release(current: &str) -> Result<Option<ReleaseInfo>, String> {
    let release = http_get_json(RELEASES_API)?;
    let tag = release
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or("发布信息缺少 tag_name")?;
    let version = tag.trim_start_matches('v').to_string();
    if !version_newer(&version, current) {
        return Ok(None);
    }
    let (asset_name, asset_url) = pick_installer(
        release.get("assets").ok_or("发布信息缺少资产列表")?,
    )
    .ok_or("该版本没有适配当前系统的安装包(dmg/exe/deb/rpm)")?;
    Ok(Some(ReleaseInfo {
        version,
        current: current.to_string(),
        notes: release
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .chars()
            .take(300)
            .collect(),
        asset_name,
        asset_url,
    }))
}

#[tauri::command]
async fn update_check(app: tauri::AppHandle) -> Result<Option<serde_json::Value>, String> {
    blocking(move || {
        let current = app.package_info().version.to_string();
        fetch_latest_release(&current).map(|info| {
            info.map(|i| {
                serde_json::json!({
                    "version": i.version,
                    "currentVersion": i.current,
                    "body": i.notes,
                    "assetName": i.asset_name,
                    "assetUrl": i.asset_url,
                })
            })
        })
    })
    .await
}

/// 下载安装包到系统"下载"目录,返回保存路径
#[tauri::command]
async fn update_download(
    app: tauri::AppHandle,
    url: String,
    filename: String,
) -> Result<String, String> {
    blocking(move || {
        if !url.starts_with("https://") || filename.contains("..") || filename.contains('/') {
            return Err("非法的下载地址或文件名".into());
        }
        use tauri::Manager;
        let dir = app
            .path()
            .download_dir()
            .or_else(|_| app.path().home_dir().map(|h| h.join("Downloads")))
            .map_err(|e| format!("无法确定下载目录: {e}"))?;
        let dest = dir.join(filename);
        let status = std::process::Command::new("curl")
            .args(["-Lsf", "--max-time", "600", "-o"])
            .arg(&dest)
            .arg(&url)
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            let _ = std::fs::remove_file(&dest);
            return Err("下载失败,请检查网络后重试".into());
        }
        Ok(dest.display().to_string())
    })
    .await
}

/// 打开安装包,由系统安装流程接管(dmg 挂载 / NSIS 向导 / 系统包安装器)
#[tauri::command]
async fn update_open(path: String) -> Result<(), String> {
    blocking(move || {
        let p = std::path::PathBuf::from(&path);
        if !p.is_absolute() || !p.exists() {
            return Err("安装包不存在或路径无效".into());
        }
        #[cfg(target_os = "macos")]
        let ok = std::process::Command::new("open").arg(&p).spawn().is_ok();
        #[cfg(target_os = "windows")]
        let ok = std::process::Command::new("cmd")
            .args(["/C", "start", "", &path])
            .spawn()
            .is_ok();
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let ok = std::process::Command::new("xdg-open").arg(&p).spawn().is_ok();
        if ok {
            Ok(())
        } else {
            Err("无法打开安装包,请手动运行".into())
        }
    })
    .await
}

fn spawn_update_scheduler(app: tauri::AppHandle) {
    std::thread::Builder::new()
        .name("update-scheduler".into())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(seconds_until_daily_check()));
            let current = app.package_info().version.to_string();
            if let Ok(Some(info)) = fetch_latest_release(&current) {
                let payload = serde_json::json!({
                    "version": info.version,
                    "currentVersion": info.current,
                    "body": info.notes,
                    "assetName": info.asset_name,
                    "assetUrl": info.asset_url,
                });
                // 驻留后台(窗口隐藏)时也要让用户看到提示
                show(&app);
                let _ = app.emit("update-available", payload);
            }
        })
        .expect("无法启动更新调度线程");
}

fn main() {
    let hidden = std::env::args().any(|a| a == "--start-hidden" || a == "--hidden");
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| show(app)))
        .setup(move |app| {
            let mut error = None;
            let lock = (|| {
                std::fs::create_dir_all(config::data_dir())?;
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(config::data_dir().join("instance.lock"))?;
                f.try_lock_exclusive()?;
                Ok::<_, std::io::Error>(f)
            })();
            let lock = match lock {
                Ok(f) => Some(f),
                Err(e) => {
                    error = Some(format!("无法取得单实例锁，请退出旧版应用: {e}"));
                    None
                }
            };
            let cfg = match config::load() {
                Ok(c) => c,
                Err(e) => {
                    error = Some(format!("读取加密配置失败: {e}"));
                    Config::default()
                }
            };
            let can_start = error.is_none();
            app.manage(Desktop::new(cfg, lock, error));
            app.state::<Desktop>().enable_managed_discovery();
            spawn_update_scheduler(app.handle().clone());
            let show_item = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
            let start = MenuItem::with_id(app, "start", "开始监控", true, None::<&str>)?;
            let pause = MenuItem::with_id(app, "pause", "暂停监控", true, None::<&str>)?;
            let history = MenuItem::with_id(app, "history", "历史搜索", true, None::<&str>)?;
            let delete = MenuItem::with_id(app, "delete", "删除日志…", true, None::<&str>)?;
            let exit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
            let menu =
                Menu::with_items(app, &[&show_item, &start, &pause, &history, &delete, &exit])?;
            TrayIconBuilder::with_id("monitor-tray")
                .icon(icon())
                .tooltip("文件监控")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show(app),
                    "history" => {
                        show(app);
                        let _ = app.emit("navigate", "history");
                    }
                    "delete" => {
                        show(app);
                        let _ = app.emit("request-delete", ());
                    }
                    "quit" => quit(app),
                    "start" | "pause" => {
                        let running = event.id.as_ref() == "start";
                        let app = app.clone();
                        tauri::async_runtime::spawn_blocking(move || {
                            if let Err(e) = app.state::<Desktop>().set_running(running) {
                                let _ = app.emit("operation-error", e);
                            }
                        });
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        }
                    ) {
                        show(tray.app_handle());
                    }
                })
                .build(app)?;
            if hidden {
                hide(app.handle());
            } else {
                show(app.handle());
            }
            if can_start {
                let app = app.handle().clone();
                tauri::async_runtime::spawn_blocking(move || {
                    let _ = app.state::<Desktop>().set_running(true);
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| match event {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                api.prevent_close();
                hide(window.app_handle());
            }
            tauri::WindowEvent::Focused(false) if window.is_minimized().unwrap_or(false) => {
                hide(window.app_handle())
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            snapshot,
            set_monitoring,
            save_settings,
            search_history,
            history_page,
            cancel_search,
            delete_logs,
            clear_display,
            audit_probe,
            audit_enable,
            audit_pipe_launch,
            update_check,
            update_download,
            update_open,
            audit_service_status,
            audit_service_stop,
            audit_open_privacy,
            open_location,
            reveal_file
        ])
        .build(tauri::generate_context!())
        .expect("无法启动 Tauri 文件监控");
    app.run(|app, event| match event {
        tauri::RunEvent::ExitRequested { api, code, .. } if code.is_none() => {
            api.prevent_exit();
            quit(app);
        }
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen { .. } => show(app),
        _ => {}
    });
}

#[cfg(test)]
mod pick_tests {
    use super::*;
    fn assets() -> serde_json::Value {
        serde_json::json!([
            {"name": "FAMTool-1.0.0-1.aarch64.rpm", "browser_download_url": "https://x/rpm-arm"},
            {"name": "FAMTool-1.0.0-1.x86_64.rpm", "browser_download_url": "https://x/rpm-x64"},
            {"name": "FAMTool_1.0.0_amd64.deb", "browser_download_url": "https://x/deb-amd64"},
            {"name": "FAMTool_1.0.0_arm64.deb", "browser_download_url": "https://x/deb-arm64"},
            {"name": "FAMTool_1.0.0_macos_aarch64.dmg", "browser_download_url": "https://x/dmg-arm"},
            {"name": "FAMTool_1.0.0_macos_x86_64.dmg", "browser_download_url": "https://x/dmg-x64"},
            {"name": "FAMTool_1.0.0_x64-setup.exe", "browser_download_url": "https://x/exe"},
        ])
    }
    #[test]
    #[cfg(target_os = "macos")]
    fn macos_picks_matching_dmg() {
        let (name, url) = pick_installer(&assets()).unwrap();
        let arch = std::env::consts::ARCH;
        assert!(name.contains(arch), "应选本机架构 dmg: {name}");
        assert!(name.ends_with(".dmg"));
        assert!(url.contains("dmg"));
    }
    #[test]
    fn version_compare() {
        assert!(version_newer("1.0.3", "1.0.2"));
        assert!(version_newer("v2.0", "1.9.9"));
        assert!(!version_newer("1.0.0", "1.0.0"));
        assert!(!version_newer("0.9", "1.0"));
    }
}

#[cfg(test)]
mod update_tests {
    #[test]
    fn daily_check_targets_1030_local() {
        use chrono::{Duration, Local, Timelike};
        let now = Local::now();
        let secs = super::seconds_until_daily_check();
        assert!(secs >= 60 && secs <= 86400 * 2, "超出合理范围: {secs}");
        let target = now + Duration::seconds(secs as i64);
        assert_eq!((target.hour(), target.minute()), (10, 30), "目标不是 10:30");
        assert!(target > now);
    }
}
