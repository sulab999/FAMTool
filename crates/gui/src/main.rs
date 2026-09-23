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
            let _ = app;
            Err("系统审计接入目前仅支持 macOS".into())
        }
    })
    .await
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
        // 1) 准备审计接收通道:启用审计、启动监控、发布接收位置(不涉及 ES/签名)
        app.state::<Desktop>().prepare_audit()?;
        // 2) 定位随应用打包的 OpenBSM 辅助程序
        let helper = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("audit-pipe")))
            .filter(|p| p.is_file())
            .ok_or_else(|| "未找到 audit-pipe 辅助程序，请使用完整应用包".to_string())?;
        // 3) 系统密码框以管理员启动辅助进程(nohup 后台常驻,密码由 macOS 处理)
        let log = std::env::temp_dir().join("famtool-audit-pipe.log");
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
