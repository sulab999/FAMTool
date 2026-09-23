//! Authenticated encryption. Keys are separate from ciphertext and owner-readable on Unix.
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use fs2::FileExt;
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

const MAGIC: &[u8] = b"WJENC1\0";
pub fn error(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

pub fn private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(data)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub struct Crypto(Aes256Gcm);
impl Crypto {
    /// Read-only access for history queries; never creates directories or lock files.
    pub fn read(key_path: &Path) -> io::Result<Self> {
        let key = fs::read(key_path)?;
        if key.len() != 32 {
            return Err(error("加密密钥长度错误"));
        }
        Ok(Self(Aes256Gcm::new_from_slice(&key).map_err(error)?))
    }

    pub fn open(key_path: &Path, allow_create: bool) -> io::Result<Self> {
        let parent = key_path.parent().ok_or_else(|| error("密钥路径无父目录"))?;
        private_dir(parent)?;
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(parent.join("key.lock"))?;
        lock.lock_exclusive()?;
        let key = match fs::read(key_path) {
            Ok(key) => key,
            Err(e) if e.kind() == io::ErrorKind::NotFound && allow_create => {
                let key = Aes256Gcm::generate_key(OsRng);
                atomic_write(key_path, &key)?;
                key.to_vec()
            }
            Err(e) => return Err(error(format!("无法读取加密密钥，请恢复原密钥: {e}"))),
        };
        if key.len() != 32 {
            return Err(error("加密密钥长度错误"));
        }
        Ok(Self(Aes256Gcm::new_from_slice(&key).map_err(error)?))
    }
    pub fn seal(&self, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&nonce);
        out.extend(self.0.encrypt(&nonce, plaintext).map_err(error)?);
        Ok(out)
    }
    pub fn open_bytes(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        if !data.starts_with(MAGIC) || data.len() < MAGIC.len() + 12 + 16 {
            return Err(error("加密数据格式损坏或版本不受支持"));
        }
        self.0
            .decrypt(
                Nonce::from_slice(&data[MAGIC.len()..MAGIC.len() + 12]),
                &data[MAGIC.len() + 12..],
            )
            .map_err(|_| error("解密认证失败：密钥不匹配或数据已损坏"))
    }
    pub fn is_encrypted(data: &[u8]) -> bool {
        data.starts_with(MAGIC)
    }
}
