//! OpenBSM 审计管道辅助进程:连接主界面审计接收器并推送带权威进程身份的事件。
//! 用法:
//!   audit-pipe [--socket <path>]        (root;由主界面以管理员方式启动)
//! 非独立运行时报告 not_privileged 后退出。
fn main() {
    #[cfg(target_os = "macos")]
    {
        let mut socket = None;
        let mut args = std::env::args().skip(1);
        while let Some(a) = args.next() {
            if a == "--socket" {
                socket = args.next().map(std::path::PathBuf::from);
            }
        }
        if let Err(e) = famtool_core::audit_pipe::run_helper(socket) {
            eprintln!("audit-pipe: {e}");
            std::process::exit(1);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("audit-pipe 仅支持 macOS,当前平台没有 OpenBSM 审计管道");
        std::process::exit(1);
    }
}
