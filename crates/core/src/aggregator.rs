//! 事件聚合:把 notify 的原始事件按时间窗口分批,同一路径在同一批内的多个事件
//! 收敛为一条记录。
//!
//! 为什么要聚合:macOS FSEvents 对一次物理操作往往同时置多个标志位,notify 会
//! 为每个标志各发一个事件(例如 `rm` 会产生 Create + Remove + Modify 三条);
//! 而 Linux inotify / Windows ReadDirectoryChangesW 一般一次操作一个事件。
//! 统一在此按"删除 > 重命名 > 创建/修改"的优先级收敛,保证:
//!   - 删除永远被记录,不会被同批的创建/修改事件淹没;
//!   - 同批内"源路径消失 + 目标路径出现"配对成一条重命名(带原路径);
//!   - 同批内 Create+Modify 并存时,用文件出生时间区分是新建还是编辑。

use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use chrono::{DateTime, Local};
use notify::event::{CreateKind, RemoveKind};
use notify::{Event, EventKind};

use crate::record::{Actor, Record};

pub struct Options {
    /// 聚合窗口长度
    pub debounce: Duration,
    /// 是否记录"访问"事件
    pub track_access: bool,
    /// 需要跳过的路径(程序自身日志文件,避免写日志触发事件造成循环)
    pub skip_path: PathBuf,
    /// 监控根路径 → 抑制截止时刻。启动初期 FSEvents 可能重放根目录在监控开始前
    /// 的历史变化(标志位不可靠),宽限期内根路径自身仍存在的记录直接丢弃。
    pub root_grace: HashMap<PathBuf, Instant>,
}

pub fn run(rx: mpsc::Receiver<Event>, tx: mpsc::SyncSender<Vec<Record>>, opts: Options) {
    let mut batch: Option<Batch> = None;
    // 本进程已确认存在过的路径,用于区分"新建后被写入"与"编辑已有文件"。
    // 上限保护:超出后清空,退化为仅按文件出生时间判断。
    let mut seen: HashSet<PathBuf> = HashSet::new();
    // 操作者归因(fd 扫描 + 路径推断 + 属主)
    let mut attributor = crate::attributor::Attributor::default();
    let mut flush = |batch: &mut Option<Batch>, seen: &mut HashSet<PathBuf>| {
        let Some(done) = batch.take() else {
            return true;
        };
        let mut recs = done.finalize(&opts, seen);
        attributor.attribute(&mut recs);
        for chunk in recs.chunks(128) {
            if tx.send(chunk.to_vec()).is_err() {
                return false;
            }
        }
        if seen.len() > 100_000 {
            seen.clear();
        }
        true
    };
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ev) => {
                if batch.is_none() {
                    batch = Some(Batch::new(opts.debounce));
                }
                batch.as_mut().unwrap().ingest(ev);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if let Some(b) = &batch {
            let ready = Instant::now() >= b.deadline
                || b.actors.len() >= 10_000
                || b.paths.len() >= 10_000
                || b.both.len() >= 10_000;
            if ready && !flush(&mut batch, &mut seen) {
                return;
            }
        }
    }
    // 退出前把未到期的批次也结算掉
    flush(&mut batch, &mut seen);
}

#[derive(Clone, Copy, PartialEq)]
enum NameFlag {
    From,
    To,
    Any,
}

#[derive(Default)]
struct PathState {
    create: Option<CreateKind>,
    remove: Option<RemoveKind>,
    /// 内容或元数据被修改
    data: bool,
    access: bool,
    name: Option<NameFlag>,
}

struct Batch {
    deadline: Instant,
    /// 窗口开始时刻,用于区分"新建后被写入"与"编辑已有文件"
    window_start: SystemTime,
    wall_time: DateTime<Local>,
    /// 路径到达顺序,保证输出稳定
    order: Vec<PathBuf>,
    paths: HashMap<PathBuf, PathState>,
    /// 后端直接给出的成对重命名(Windows): (原路径, 新路径)
    both: Vec<(PathBuf, PathBuf)>,
    actors: HashMap<PathBuf, Actor>,
}

impl Batch {
    fn new(debounce: Duration) -> Self {
        Batch {
            deadline: Instant::now() + debounce,
            window_start: SystemTime::now(),
            wall_time: Local::now(),
            order: Vec::new(),
            paths: HashMap::new(),
            both: Vec::new(),
            actors: HashMap::new(),
        }
    }

    fn entry(&mut self, path: PathBuf) -> &mut PathState {
        if !self.paths.contains_key(&path) {
            self.order.push(path.clone());
        }
        self.paths.entry(path).or_default()
    }

    fn ingest(&mut self, ev: Event) {
        let actor = Actor {
            process_id: ev.attrs.process_id(),
            ..Actor::default()
        };
        for p in &ev.paths {
            self.actors
                .entry(p.clone())
                .and_modify(|old| {
                    if *old != actor {
                        *old = Actor::default();
                    }
                })
                .or_insert_with(|| actor.clone());
        }

        match ev.kind {
            EventKind::Create(k) => {
                for p in ev.paths {
                    self.entry(p).create = Some(k);
                }
            }
            EventKind::Remove(k) => {
                for p in ev.paths {
                    self.entry(p).remove = Some(k);
                }
            }
            EventKind::Modify(notify::event::ModifyKind::Name(mode)) => match mode {
                notify::event::RenameMode::Both => {
                    if ev.paths.len() >= 2 {
                        self.both.push((ev.paths[0].clone(), ev.paths[1].clone()));
                    }
                }
                other => {
                    let flag = match other {
                        notify::event::RenameMode::From => NameFlag::From,
                        notify::event::RenameMode::To => NameFlag::To,
                        _ => NameFlag::Any,
                    };
                    if let Some(p) = ev.paths.last() {
                        self.entry(p.clone()).name = Some(flag);
                    }
                }
            },
            EventKind::Modify(_) => {
                for p in ev.paths {
                    self.entry(p).data = true;
                }
            }
            EventKind::Access(_) => {
                for p in ev.paths {
                    self.entry(p).access = true;
                }
            }
            _ => {}
        }
    }

    fn finalize(mut self, opts: &Options, seen: &mut HashSet<PathBuf>) -> Vec<Record> {
        let mut out = Vec::new();
        let skip = &opts.skip_path;

        // 判断路径是否属于启动宽限期内的根路径伪事件:目录根一律抑制;
        // 文件根只抑制纯结构事件(无写入的 created / removed / renamed),
        // 内容修改和"伴随写入的 created"是真实观测,正常记录;
        // 根路径实际已不存在的是真实事件,不抑制
        let root_artifact = |p: &Path, event: &str, data: bool| {
            opts.root_grace.iter().any(|(root, until)| {
                if p != root || Instant::now() >= *until {
                    return false;
                }
                match fs::symlink_metadata(root) {
                    Ok(md) if md.is_file() => {
                        if matches!(event, "modified" | "accessed") {
                            return false;
                        }
                        !(event == "created" && data)
                    }
                    Ok(_) => true,
                    Err(_) => false,
                }
            })
        };

        // 1) 后端直接给出的成对重命名
        self.both.dedup();
        let boths = std::mem::take(&mut self.both);
        for (from, to) in boths {
            self.paths.remove(&from);
            self.paths.remove(&to);
            if from == *skip
                || to == *skip
                || root_artifact(&from, "renamed", false)
                || root_artifact(&to, "renamed", false)
            {
                continue;
            }
            out.push(self.record("renamed", stat_object(&to), to, Some(from)));
        }

        // 2) 同批内配对重命名:源(From 或路径已消失) ↔ 目标(To 或路径仍存在)
        let order = std::mem::take(&mut self.order);
        let mut sources: Vec<PathBuf> = Vec::new();
        let mut targets: Vec<PathBuf> = Vec::new();
        for p in &order {
            let Some(st) = self.paths.get(p) else {
                continue;
            };
            if st.remove.is_some() {
                continue; // 删除优先,不参与配对
            }
            match st.name {
                Some(NameFlag::From) => sources.push(p.clone()),
                Some(NameFlag::To) => targets.push(p.clone()),
                Some(NameFlag::Any) => {
                    if fs::symlink_metadata(p).is_ok() {
                        targets.push(p.clone());
                    } else {
                        sources.push(p.clone());
                    }
                }
                None => {}
            }
        }
        let paired = sources.len().min(targets.len());
        for i in 0..paired {
            let (from, to) = (sources[i].clone(), targets[i].clone());
            self.paths.remove(&from);
            self.paths.remove(&to);
            if from == *skip || to == *skip {
                continue;
            }
            out.push(self.record("renamed", stat_object(&to), to, Some(from)));
        }
        for p in &sources[paired..] {
            self.paths.remove(p);
            if *p == *skip || root_artifact(p, "renamed_out", false) {
                continue;
            }
            out.push(self.record("renamed_out", "unknown", p.clone(), None));
        }
        for p in &targets[paired..] {
            self.paths.remove(p);
            if *p == *skip || root_artifact(p, "renamed_in", false) {
                continue;
            }
            out.push(self.record("renamed_in", stat_object(p), p.clone(), None));
        }

        // 3) 其余路径按优先级输出
        for p in order {
            let Some(st) = self.paths.get(&p) else {
                continue;
            };
            if p == *skip {
                continue;
            }
            let rec = if st.remove.is_some() {
                let object = match st.remove {
                    Some(RemoveKind::Folder) => "folder",
                    Some(RemoveKind::File) => "file",
                    _ => stat_object(&p),
                };
                self.record("removed", object, p.clone(), None)
            } else if st.create.is_some() && st.data {
                // Create 与 Modify 并存:本进程见过的路径,或出生时间明显早于窗口
                // 开始(留出事件投递延迟的容差)→ 编辑已有文件;否则视为新建
                let tol = Duration::from_secs(2) + opts.debounce;
                let is_edit = seen.contains(&p)
                    || fs::symlink_metadata(&p)
                        .and_then(|m| m.created())
                        .map(|born| self.window_start.checked_sub(tol).is_some_and(|t| born < t))
                        .unwrap_or(false);
                let event = if is_edit { "modified" } else { "created" };
                let object = create_object(st.create, &p);
                self.record(event, object, p.clone(), None)
            } else if st.create.is_some() {
                self.record("created", create_object(st.create, &p), p.clone(), None)
            } else if st.data {
                self.record("modified", stat_object(&p), p.clone(), None)
            } else if st.access && opts.track_access {
                self.record("accessed", stat_object(&p), p.clone(), None)
            } else {
                continue;
            };
            if root_artifact(&p, &rec.event, st.data) {
                continue;
            }
            out.push(rec);
        }

        // 根据本批结论维护"已见过路径"集合,供后续批次判断新建/编辑
        for rec in &out {
            let path = PathBuf::from(&rec.path);
            match rec.event.as_str() {
                "removed" | "renamed_out" => {
                    seen.remove(&path);
                }
                "renamed" => {
                    if let Some(f) = &rec.from {
                        seen.remove(Path::new(f));
                    }
                    seen.insert(path);
                }
                _ => {
                    seen.insert(path);
                }
            }
        }
        out
    }

    fn record(
        &self,
        event: &'static str,
        object: &'static str,
        path: PathBuf,
        from: Option<PathBuf>,
    ) -> Record {
        Record {
            time: self.wall_time,
            event: event.into(),
            object: object.into(),
            actor: self.actors.get(&path).cloned().unwrap_or_default(),
            owner: None,
            diagnostic: None,
            audit: None,
            path: path.to_string_lossy().into_owned(),
            from: from.map(|p| p.to_string_lossy().into_owned()),
        }
    }
}

fn create_object(kind: Option<CreateKind>, path: &Path) -> &'static str {
    match kind {
        Some(CreateKind::Folder) => "folder",
        Some(CreateKind::File) => "file",
        _ => stat_object(path),
    }
}

fn stat_object(path: &Path) -> &'static str {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => "folder",
        Ok(_) => "file",
        Err(_) => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shutdown_flushes_pending_batch() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("tail");
        let (tx, rx) = mpsc::sync_channel(10);
        let (out_tx, out_rx) = mpsc::sync_channel(10);
        tx.send(Event::new(EventKind::Create(CreateKind::File)).add_path(path))
            .unwrap();
        drop(tx);
        run(
            rx,
            out_tx,
            Options {
                debounce: Duration::from_secs(60),
                track_access: false,
                skip_path: PathBuf::new(),
                root_grace: HashMap::new(),
            },
        );
        let rec = out_rx.recv().unwrap().remove(0);
        assert_eq!(rec.event, "created");
        assert_eq!(rec.actor, Actor::default());
        assert!(out_rx.recv().is_err());
    }
}
