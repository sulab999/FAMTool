//! 系统审计辅助进程:以 root(macOS/Linux)或管理员(Windows)运行,
//! 连接主界面审计接收器并推送带权威进程身份的事件。
//!
//! 用法:
//!   audit-pipe                     (自动发现 audit-endpoint.json)
//!   audit-pipe --socket <地址>     (unix 套接字路径 / Windows 命名管道名)
//!   audit-pipe --check             (以当前身份探测采集通道能力,输出 JSON)
//!   audit-pipe --teardown          (Windows:移除本工具添加的 SACL 审核项)
//! 非管理员运行时向主界面报告 not_privileged 后退出。
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--check") {
        println!("{}", famtool_core::audit_pipe::run_check());
        return;
    }
    if args.iter().any(|a| a == "--teardown") {
        let roots = famtool_core::config::load()
            .map(|c| c.roots)
            .unwrap_or_else(|_| famtool_core::config::default_roots());
        match famtool_core::audit_pipe::run_teardown(&roots) {
            Ok(message) => println!("{message}"),
            Err(e) => {
                eprintln!("audit-pipe teardown: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    let mut socket = None;
    let mut iter = args.into_iter();
    while let Some(a) = iter.next() {
        if a == "--socket" {
            socket = iter.next().map(std::path::PathBuf::from);
        }
    }
    if let Err(e) = famtool_core::audit_pipe::run_helper(socket) {
        eprintln!("audit-pipe: {e}");
        std::process::exit(1);
    }
}
