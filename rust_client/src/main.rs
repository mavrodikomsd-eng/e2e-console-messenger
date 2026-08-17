use std::collections::HashMap;
use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const TYPE_MESSAGE: u8 = b'M';
const TYPE_COMMAND: u8 = b'C';
const TYPE_FILE: u8 = b'F';
const TYPE_REGISTER: u8 = b'R';
const MAX_FILE: usize = 400_000;

static PRINT_LOCK: Mutex<()> = Mutex::new(());

fn pprint(line: &str) {
    let _g = PRINT_LOCK.lock().unwrap();
    print!("\r{} \n>>> ", line);
    let _ = io::stdout().flush();
}

fn send_frame(stream: &mut TcpStream, ftype: u8, payload: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(ftype);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)
}

fn recv_frame(stream: &mut TcpStream) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0u8; 5];
    match stream.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(Some((header[0], payload)))
}

fn load_shared_key() -> [u8; 32] {
    let path = std::env::var("MESH_SHARED_KEY").unwrap_or_else(|_| "secret.key".into());
    if let Ok(data) = std::fs::read_to_string(&path) {
        if let Ok(key) = B64.decode(data.trim()) {
            if let Ok(k) = <[u8; 32]>::try_from(key) {
                return k;
            }
        }
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let _ = std::fs::write(&path, B64.encode(key));
    key
}

fn load_or_create_identity() -> (StaticSecret, Vec<u8>) {
    let path = std::env::var("MESH_IDENTITY_FILE").unwrap_or_else(|_| "identity.key".into());
    if let Ok(data) = std::fs::read_to_string(&path) {
        let parts: Vec<&str> = data.split_whitespace().collect();
        if parts.len() == 2 {
            if let (Ok(seed), Ok(pubk)) = (B64.decode(parts[0]), B64.decode(parts[1])) {
                if let Ok(s) = <[u8; 32]>::try_from(seed) {
                    return (StaticSecret::from(s), pubk);
                }
            }
        }
    }
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    let pub_bytes = PublicKey::from(&secret).to_bytes().to_vec();
    let _ = std::fs::write(&path, format!("{} {}\n", B64.encode(seed), B64.encode(&pub_bytes)));
    (secret, pub_bytes)
}

fn derive_key(our: &StaticSecret, peer_pub: &[u8; 32]) -> [u8; 32] {
    let shared = our.diffie_hellman(&PublicKey::from(*peer_pub));
    let mut h = Sha256::new();
    h.update(shared.as_bytes());
    let d = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&d);
    key
}

fn gcm_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> String {
    let cipher = Aes256Gcm::new_from_slice(key).expect("bad key");
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("encrypt failed");
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    B64.encode(out)
}

fn gcm_decrypt(key: &[u8; 32], encoded: &str, aad: &[u8]) -> Option<String> {
    let data = B64.decode(encoded).ok()?;
    if data.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let pt = cipher
        .decrypt(Nonce::from_slice(&data[..12]), Payload { msg: &data[12..], aad })
        .ok()?;
    String::from_utf8(pt).ok()
}

fn encrypt_to_peer(text: &str, peer_pub_b64: &str, self_pub_b64: &str, our: &StaticSecret) -> String {
    let peer_pub: [u8; 32] = B64.decode(peer_pub_b64).expect("bad peer pub").try_into().expect("peer pub len");
    let key = derive_key(our, &peer_pub);
    gcm_encrypt(&key, text.as_bytes(), self_pub_b64.as_bytes())
}

fn decrypt_from_peer(encoded: &str, sender_pub_b64: &str, our: &StaticSecret) -> Option<String> {
    let sender_pub: [u8; 32] = B64.decode(sender_pub_b64).ok()?.try_into().ok()?;
    let key = derive_key(our, &sender_pub);
    gcm_decrypt(&key, encoded, sender_pub_b64.as_bytes())
}

struct State {
    known: Mutex<HashMap<String, String>>,
    pending: Mutex<Option<mpsc::Sender<String>>>,
}

fn insert_keys(state: &State, text: &str) {
    let body = match text.find(']') {
        Some(i) => &text[i + 1..],
        None => text,
    };
    let mut known = state.known.lock().unwrap();
    for item in body.split(';') {
        let item = item.trim();
        if let Some(idx) = item.find(':') {
            known.insert(item[..idx].to_string(), item[idx + 1..].to_string());
        }
    }
}

fn request(stream: &mut TcpStream, state: &State, shared_key: &[u8; 32], cmd: &str) -> Option<String> {
    let (tx, rx) = mpsc::channel();
    *state.pending.lock().unwrap() = Some(tx);
    let enc = gcm_encrypt(shared_key, cmd.as_bytes(), b"");
    if send_frame(stream, TYPE_COMMAND, enc.as_bytes()).is_err() {
        return None;
    }
    rx.recv_timeout(Duration::from_secs(3)).ok()
}

fn handle_message(state: &State, our: &StaticSecret, payload: &[u8]) {
    let parts: Vec<&[u8]> = payload.split(|&b| b == 0).collect();
    if parts.len() < 3 {
        pprint("[ОШИБКА] Повреждённый кадр сообщения");
        return;
    }
    let sender = String::from_utf8_lossy(parts[0]).to_string();
    let ct = String::from_utf8_lossy(parts[2]).to_string();
    match state.known.lock().unwrap().get(&sender).cloned() {
        None => pprint(&format!("[{}]: (неизвестный публичный ключ)", sender)),
        Some(pk) => match decrypt_from_peer(&ct, &pk, our) {
            Some(plain) => pprint(&format!("[{}]: {}", sender, plain.trim_end())),
            None => pprint(&format!("[{}]: (не удалось расшифровать — подмена/ключ)", sender)),
        },
    }
}

fn handle_file(state: &State, our: &StaticSecret, payload: &[u8]) {
    let parts: Vec<&[u8]> = payload.split(|&b| b == 0).collect();
    if parts.len() < 4 {
        pprint("[ОШИБКА] Повреждённый кадр файла");
        return;
    }
    let sender = String::from_utf8_lossy(parts[0]).to_string();
    let fname = String::from_utf8_lossy(parts[2]).to_string();
    let data = String::from_utf8_lossy(parts[3]).to_string();
    match state.known.lock().unwrap().get(&sender).cloned() {
        None => pprint(&format!("[{}] отправил файл: {}, но ключ неизвестен", sender, fname)),
        Some(pk) => match decrypt_from_peer(&data, &pk, our) {
            Some(b64) => match B64.decode(b64.trim()) {
                Ok(raw) => match std::fs::write(&fname, &raw) {
                    Ok(()) => pprint(&format!("[{}] отправил файл: {} ({} байт) — сохранён", sender, fname, raw.len())),
                    Err(_) => pprint(&format!("[{}] отправил файл: {}, но сохранить не удалось", sender, fname)),
                },
                Err(_) => pprint(&format!("[{}] отправил файл: {}, но расшифровать не удалось", sender, fname)),
            },
            None => pprint(&format!("[{}] отправил файл: {}, но расшифровать не удалось", sender, fname)),
        },
    }
}

fn reader_loop(mut stream: TcpStream, state: Arc<State>, our: Arc<StaticSecret>, shared_key: [u8; 32]) {
    loop {
        match recv_frame(&mut stream) {
            Ok(Some((ftype, payload))) => {
                if ftype == TYPE_COMMAND {
                    let enc = String::from_utf8_lossy(&payload).to_string();
                    if let Some(text) = gcm_decrypt(&shared_key, &enc, b"") {
                        let text = text.trim().to_string();
                        if let Some(rest) = text.strip_prefix("[RESP]") {
                            if let Some(tx) = state.pending.lock().unwrap().take() {
                                let _ = tx.send(rest.trim().to_string());
                            }
                            continue;
                        }
                        if text.starts_with("[ПУБКЛЮЧИ]") || text.starts_with("[НОВЫЙ]") {
                            insert_keys(&state, &text);
                            continue;
                        }
                        pprint(&text);
                    }
                } else if ftype == TYPE_MESSAGE {
                    handle_message(&state, &our, &payload);
                } else if ftype == TYPE_FILE {
                    handle_file(&state, &our, &payload);
                }
            }
            _ => break,
        }
    }
}

fn recipient_pub(stream: &mut TcpStream, state: &State, shared_key: &[u8; 32], name: &str) -> Option<String> {
    if let Some(p) = state.known.lock().unwrap().get(name).cloned() {
        return Some(p);
    }
    if let Some(resp) = request(stream, state, shared_key, &format!("/pubkey {}", name)) {
        if resp != "ERR" {
            state.known.lock().unwrap().insert(name.to_string(), resp.clone());
            return Some(resp);
        }
    }
    None
}

fn send_to(stream: &mut TcpStream, state: &State, shared_key: &[u8; 32], our: &StaticSecret, self_pub_b64: &str, username: &str, target: &str, text: &str) -> bool {
    let pubk = match recipient_pub(stream, state, shared_key, target) {
        Some(p) => p,
        None => {
            pprint(&format!("[ОШИБКА] Не знаю публичный ключ для {}", target));
            return false;
        }
    };
    let ct = encrypt_to_peer(text, &pubk, self_pub_b64, our);
    let payload = format!("{}\x00{}\x00{}", username, target, ct);
    send_frame(stream, TYPE_MESSAGE, payload.as_bytes()).is_ok()
}

fn room_targets(stream: &mut TcpStream, state: &State, shared_key: &[u8; 32], username: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(resp) = request(stream, state, shared_key, "/roommembers") {
        if resp != "ERR" {
            let mut known = state.known.lock().unwrap();
            for item in resp.split(';') {
                if let Some(idx) = item.find(':') {
                    let n = item[..idx].to_string();
                    let p = item[idx + 1..].to_string();
                    known.insert(n.clone(), p.clone());
                    if n != username {
                        out.push((n, p));
                    }
                }
            }
        }
    }
    out
}

fn send_to_room(stream: &mut TcpStream, state: &State, shared_key: &[u8; 32], our: &StaticSecret, self_pub_b64: &str, username: &str, text: &str) {
    let targets = room_targets(stream, state, shared_key, username);
    for (name, pubk) in &targets {
        let ct = encrypt_to_peer(text, pubk, self_pub_b64, our);
        let payload = format!("{}\x00{}\x00{}", username, name, ct);
        let _ = send_frame(stream, TYPE_MESSAGE, payload.as_bytes());
    }
    pprint(&format!("[Я]: {}", text));
}

fn send_file_to_room(stream: &mut TcpStream, state: &State, shared_key: &[u8; 32], our: &StaticSecret, self_pub_b64: &str, username: &str, path: &str) {
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(_) => {
            pprint(&format!("[ОШИБКА] Файл не найден: {}", path));
            return;
        }
    };
    if raw.len() > MAX_FILE {
        pprint(&format!("[ОШИБКА] Файл слишком большой (до {} КБ)", MAX_FILE / 1000));
        return;
    }
    let fname = path.rsplit(['/', '\\']).next().unwrap_or(path).to_string();
    let b64 = B64.encode(&raw);
    let targets = room_targets(stream, state, shared_key, username);
    for (name, pubk) in &targets {
        let data = encrypt_to_peer(&b64, pubk, self_pub_b64, our);
        let payload = format!("{}\x00{}\x00{}\x00{}", username, name, fname, data);
        let _ = send_frame(stream, TYPE_FILE, payload.as_bytes());
    }
    pprint(&format!("[Я] файл: {} отправлен в комнату", fname));
}

fn main() {
    let host = std::env::var("MESH_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("MESH_PORT").unwrap_or_else(|_| "1301".into());
    let shared_key = load_shared_key();

    let (our_secret, pub_bytes) = load_or_create_identity();
    let our = Arc::new(our_secret);
    let pub_b64 = B64.encode(&pub_bytes);

    let mut stream = match TcpStream::connect(format!("{}:{}", host, port)) {
        Ok(s) => s,
        Err(e) => {
            pprint(&format!("[ОШИБКА] Не удалось подключиться: {}", e));
            return;
        }
    };
    let _ = stream.set_nodelay(true);

    pprint("Введи своё имя:");
    let mut name = String::new();
    let _ = io::stdin().lock().read_line(&mut name);
    let username = if name.trim().is_empty() { "Аноним".to_string() } else { name.trim().to_string() };

    let _ = send_frame(&mut stream, TYPE_MESSAGE, username.as_bytes());
    let reg = format!("{}\x00{}", username, pub_b64);
    let _ = send_frame(&mut stream, TYPE_REGISTER, reg.as_bytes());

    let state = Arc::new(State {
        known: Mutex::new(HashMap::new()),
        pending: Mutex::new(None),
    });

    let reader_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let r_state = Arc::clone(&state);
    let r_our = Arc::clone(&our);
    let _handle = std::thread::spawn(move || reader_loop(reader_stream, r_state, r_our, shared_key));

    pprint(&format!("Добро пожаловать, {}!", username));
    pprint("Команды: /join <комната>, /msg Имя текст, /file <путь>, /users, /rooms, /roommembers, /help, /exit");

    let auto_exit_ms: Option<u64> = std::env::var("MESH_AUTOEXIT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&m| m > 0);

    let stdin = io::stdin();
    loop {
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => {
                if let Some(ms) = auto_exit_ms {
                    std::thread::sleep(Duration::from_millis(ms));
                }
                break;
            }
            Err(_) => break,
            _ => {}
        }
        let msg = line.trim().to_string();
        if msg.is_empty() {
            continue;
        }
        if let Some(rest) = msg.strip_prefix("/msg ") {
            let mut it = rest.splitn(2, ' ');
            let target = it.next().unwrap_or("").to_string();
            let text = it.next().unwrap_or("").to_string();
            if target.is_empty() || text.is_empty() {
                pprint("[ОШИБКА] Формат: /msg Имя текст");
                continue;
            }
            if send_to(&mut stream, &state, &shared_key, &our, &pub_b64, &username, &target, &text) {
                pprint(&format!("[Я] -> {}: {}", target, text));
            }
        } else if let Some(rest) = msg.strip_prefix("/file ") {
            send_file_to_room(&mut stream, &state, &shared_key, &our, &pub_b64, &username, rest.trim());
        } else if msg.starts_with('/') {
            let enc = gcm_encrypt(&shared_key, msg.as_bytes(), b"");
            let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
        } else {
            send_to_room(&mut stream, &state, &shared_key, &our, &pub_b64, &username, &msg);
        }
    }
}