// 调试用:打印 notify 原始事件,观察各平台后端的真实事件序列
use notify::{Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::time::Duration;

fn main() {
    let path = std::env::args().nth(1).expect("usage: raw <dir>");
    let mut watcher: RecommendedWatcher =
        notify::recommended_watcher(|res: Result<Event, notify::Error>| match res {
            Ok(ev) => println!("{:?}\t{:?}", ev.kind, ev.paths),
            Err(e) => println!("ERR {e:?}"),
        })
        .unwrap();
    watcher
        .watch(Path::new(&path), RecursiveMode::Recursive)
        .unwrap();
    println!("watching {path}");
    loop {
        std::thread::sleep(Duration::from_millis(500));
    }
}
