//! 配置:默认全盘监控 + 各平台系统路径排除,持久化为 JSON。

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    /// 监控根路径列表
    pub roots: Vec<PathBuf>,
    /// 排除路径(按前缀匹配,事件路径以其开头即忽略)
    pub excludes: Vec<PathBuf>,
    /// 加密日志位置（实际存储在同名 .store 目录）
    pub log_file: PathBuf,
    /// 事件聚合窗口(毫秒)
    pub debounce_ms: u64,
    /// 是否记录"访问"事件
    pub track_access: bool,
    /// 是否递归监控子目录
    pub recursive: bool,
    pub retention_days: u32,
    pub audit_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            roots: default_roots(),
            excludes: default_excludes(),
            log_file: data_dir().join("famtool.log"),
            debounce_ms: 1000,
            track_access: false,
            recursive: true,
            retention_days: 30,
            audit_enabled: cfg!(any(
                target_os = "macos",
                target_os = "linux",
                target_os = "windows"
            )),
        }
    }
}

/// 默认监控整个磁盘
pub fn default_roots() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        vec![PathBuf::from(r"C:\")]
    }
    #[cfg(not(target_os = "windows"))]
    {
        vec![PathBuf::from("/")]
    }
}

/// 各平台默认排除的高噪音系统路径
pub fn default_excludes() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        vec![
            PathBuf::from("/System"),
            PathBuf::from("/private/var/db"),
            PathBuf::from("/private/var/folders"),
            PathBuf::from("/private/var/vm"),
            PathBuf::from("/System/Volumes/VM"),
            PathBuf::from("/.fseventsd"),
            PathBuf::from("/.Spotlight-V100"),
            PathBuf::from("/.DocumentRevisions-V100"),
            PathBuf::from("/.TemporaryDirectories"),
            PathBuf::from("/dev"),
        ]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
            PathBuf::from("/run"),
        ]
    }
    #[cfg(target_os = "windows")]
    {
        vec![
            PathBuf::from(r"C:\$Recycle.Bin"),
            PathBuf::from(r"C:\Windows\Temp"),
            PathBuf::from(r"C:\pagefile.sys"),
            PathBuf::from(r"C:\swapfile.sys"),
        ]
    }
}

/// 程序数据/配置目录(配置、日志默认存放处)
pub fn data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir().join("Library/Application Support/famtool")
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join("AppData").join("Roaming"))
            .join("famtool")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".config"))
            .join("famtool")
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn config_path() -> PathBuf {
    data_dir().join("config.json")
}

/// Missing configuration uses defaults; corruption is reported, never silently overwritten.
pub fn load() -> std::io::Result<Config> {
    let p = config_path();
    let data = match std::fs::read(&p) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(e),
    };
    let encrypted = crate::crypto::Crypto::is_encrypted(&data);
    let bytes = if encrypted {
        crate::crypto::Crypto::open(&data_dir().join("config.key"), false)?.open_bytes(&data)?
    } else {
        data
    };
    let cfg: Config = serde_json::from_slice(&bytes).map_err(crate::crypto::error)?;
    cfg.validate()?;
    if !encrypted {
        cfg.save()?;
    }
    Ok(cfg)
}

impl Config {
    pub fn validate(&self) -> std::io::Result<()> {
        if self.roots.is_empty()
            || self.log_file.as_os_str().is_empty()
            || !(1..=36500).contains(&self.retention_days)
            || !(1..=60000).contains(&self.debounce_ms)
        {
            return Err(crate::crypto::error(
                "路径不能为空，保留天数须为 1–36500，聚合窗口须为 1–60000 ms",
            ));
        }
        Ok(())
    }
    pub fn save(&self) -> std::io::Result<()> {
        self.validate()?;
        let p = config_path();
        crate::crypto::private_dir(&data_dir())?;
        let existing_encrypted = std::fs::read(&p)
            .map(|b| crate::crypto::Crypto::is_encrypted(&b))
            .unwrap_or(false);
        let crypto =
            crate::crypto::Crypto::open(&data_dir().join("config.key"), !existing_encrypted)?;
        let data = crypto.seal(&serde_json::to_vec(self).map_err(crate::crypto::error)?)?;
        crate::crypto::atomic_write(&p, &data)
    }
}
