//! OS-managed privileged service registration; never handles passwords or shell commands.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Serialize)]
pub struct PermissionReply {
    pub state: String,
    pub message: String,
    pub helper_path: Option<String>,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn wj_audit_service_operation(operation: *const std::ffi::c_char) -> *mut std::ffi::c_char;
    fn wj_audit_service_free(data: *mut std::ffi::c_char);
}
pub async fn operation(
    app: tauri::AppHandle,
    operation: &'static str,
) -> Result<PermissionReply, String> {
    #[cfg(target_os = "macos")]
    {
        let (tx, rx) = std::sync::mpsc::channel();
        app.run_on_main_thread(move || {
            let text = std::ffi::CString::new(operation).unwrap();
            let result = unsafe {
                let ptr = wj_audit_service_operation(text.as_ptr());
                if ptr.is_null() {
                    Err("系统权限接口没有返回结果".into())
                } else {
                    let bytes = std::ffi::CStr::from_ptr(ptr).to_bytes();
                    let result =
                        serde_json::from_slice(bytes).map_err(|e| format!("权限状态格式错误: {e}"));
                    wj_audit_service_free(ptr);
                    result
                }
            };
            let _ = tx.send(result);
        })
        .map_err(|e| e.to_string())?;
        tauri::async_runtime::spawn_blocking(move || rx.recv().map_err(|e| e.to_string())?)
            .await
            .map_err(|e| e.to_string())?
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (app, operation);
        Ok(PermissionReply {
            state: "unsupported".into(),
            message: "自动系统审计授权仅支持 macOS 13 及以上版本".into(),
            helper_path: None,
        })
    }
}
#[derive(Serialize, Deserialize)]
struct Endpoint {
    protocol: u32,
    uid: u32,
    socket: PathBuf,
}

pub fn publish_endpoint(socket: &Path) -> Result<PathBuf, String> {
    #[cfg(target_os = "macos")]
    {
        let path = famtool_core::config::data_dir().join("audit-endpoint.json");
        write_endpoint(&path, socket, unsafe { libc::geteuid() })?;
        Ok(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = socket;
        Err("当前系统不支持托管审计服务".into())
    }
}
#[cfg(any(target_os = "macos", test))]
fn write_endpoint(path: &Path, socket: &Path, uid: u32) -> Result<(), String> {
    if uid == 0 || !socket.is_absolute() {
        return Err("主界面必须以普通用户运行，并提供绝对套接字路径".into());
    }
    let parent = path.parent().ok_or("无效连接位置")?;
    famtool_core::crypto::private_dir(parent).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(&Endpoint {
        protocol: 1,
        uid,
        socket: socket.into(),
    })
    .map_err(|e| e.to_string())?;
    famtool_core::crypto::atomic_write(path, &bytes).map_err(|e| e.to_string())
}
pub fn clear_endpoint(path: &Path, socket: &Path) {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return;
    };
    let mut bytes = Vec::new();
    if file.take(8193).read_to_end(&mut bytes).is_err() || bytes.len() > 8192 {
        return;
    }
    if serde_json::from_slice::<Endpoint>(&bytes)
        .is_ok_and(|e| e.protocol == 1 && e.socket == socket)
    {
        let _ = std::fs::remove_file(path);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_is_private_and_does_not_execute_or_accept_root_gui() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit-endpoint.json");
        let socket = dir.path().join("audit.sock");
        assert!(write_endpoint(&path, &socket, 0).is_err());
        assert!(!path.exists());
        write_endpoint(&path, &socket, 501).unwrap();
        let value: Endpoint = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value.uid, 501);
        assert_eq!(value.socket, socket);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        clear_endpoint(&path, &dir.path().join("other.sock"));
        assert!(path.exists());
        clear_endpoint(&path, &socket);
        assert!(!path.exists());
    }
}
