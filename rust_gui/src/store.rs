//! Хранилища: secret.key, identity.key, TOFU (tofu.json), приём файлов.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn candidate_paths(name: &str) -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from(name)];
    for up in 1..=4 {
        v.push(PathBuf::from(format!("{}{}", "../".repeat(up), name)));
    }
    v
}

pub fn write_file_secure(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

pub fn load_shared_key() -> [u8; 32] {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(e) = std::env::var("MESH_SHARED_KEY") {
        paths.push(PathBuf::from(e));
    }
    paths.extend(candidate_paths("secret.key"));
    for p in &paths {
        if let Ok(data) = std::fs::read_to_string(p) {
            if let Ok(key) = B64.decode(data.trim()) {
                if let Ok(k) = <[u8; 32]>::try_from(key) {
                    return k;
                }
            }
        }
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    if let Some(last) = paths.last() {
        let _ = write_file_secure(last, B64.encode(key).as_bytes());
    }
    key
}

/// (приватный ключ, публичный ключ b64). Создаётся при первом запуске.
pub fn load_or_create_identity() -> (StaticSecret, String) {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(e) = std::env::var("MESH_IDENTITY_FILE") {
        paths.push(PathBuf::from(e));
    }
    paths.extend(candidate_paths("identity.key"));
    for p in &paths {
        if let Ok(data) = std::fs::read_to_string(p) {
            let parts: Vec<&str> = data.split_whitespace().collect();
            if parts.len() == 2 {
                if let (Ok(seed), Ok(_)) = (B64.decode(parts[0]), B64.decode(parts[1])) {
                    if let Ok(s) = <[u8; 32]>::try_from(seed) {
                        return (
                            StaticSecret::from(s),
                            B64.encode(PublicKey::from(s).as_bytes()),
                        );
                    }
                }
            }
        }
    }
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let pub_bytes = PublicKey::from(seed).to_bytes();
    if let Some(last) = paths.last() {
        let _ = write_file_secure(
            last,
            format!("{} {}\n", B64.encode(seed), B64.encode(pub_bytes)).as_bytes(),
        );
    }
    (StaticSecret::from(seed), B64.encode(pub_bytes))
}

// ── TOFU ────────────────────────────────────────────────

static TOFU: std::sync::OnceLock<std::sync::Mutex<HashMap<String, String>>> =
    std::sync::OnceLock::new();

/// Глобальное TOFU-хранилище (лениво загружается из tofu.json).
pub fn tofu() -> &'static std::sync::Mutex<HashMap<String, String>> {
    TOFU.get_or_init(|| std::sync::Mutex::new(load_tofu()))
}

pub fn load_tofu() -> HashMap<String, String> {
    for p in candidate_paths("tofu.json") {
        if let Ok(data) = std::fs::read_to_string(&p) {
            if let Ok(map) = serde_json::from_str::<HashMap<String, String>>(&data) {
                return map;
            }
        }
    }
    HashMap::new()
}

pub fn save_tofu(map: &HashMap<String, String>) {
    if let Ok(json) = serde_json::to_string_pretty(map) {
        for p in candidate_paths("tofu.json") {
            let _ = std::fs::write(&p, json.as_bytes());
            break;
        }
    }
}

pub fn safe_file_name(raw: &str) -> String {
    let file = Path::new(raw.trim())
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let name = file.trim();
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return String::new();
    }
    name.to_string()
}

pub fn save_received_file(base: &str, raw: &[u8]) -> bool {
    let dir = match std::env::current_dir().map(|p| p.join("downloads")) {
        Ok(d) => d,
        Err(_) => return false,
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let final_path = dir.join(base);
    final_path.starts_with(&dir) && write_file_secure(&final_path, raw).is_ok()
}
