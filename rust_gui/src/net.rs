//! Сетевой поток: владеет TcpStream, общается с GUI через каналы.

use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use x25519_dalek::StaticSecret;

use crate::crypto::{decrypt_from_peer, encrypt_to_peer, fingerprint, gcm_decrypt, gcm_encrypt};
use crate::proto::*;
use crate::store::*;

pub enum UiCmd {
    Raw(String),
    Register { pass: String },
    Login { pass: String },
    ProfileSet { nick: String, bio: String, hide: bool },
    SetUsername(String),
    SetPassword { old: String, new: String },
    Whois(String),
    RefreshUsers,
    RefreshRooms,
    Join { room: String, pass: String },
    CreateRoom { room: String, pass: String },
    Leave,
    Typing(String),
    Room(String),
    Priv { target: String, text: String },
    File(String),
    Trust(String),
}

pub enum Ev {
    Line(String),
    Warn(String),
    Error(String),
    Authed,
    /// (ник, @username, онлайн)
    UserList(Vec<(String, String, bool)>),
    Presence { user: String, online: bool, nick: String },
    /// Чужой профиль: @user, nick, онлайн, bio
    Profile { user: String, nick: String, online: bool, bio: String },
    /// Свой профиль сохранён: nick, bio, hide
    ProfileSaved { nick: String, bio: String, hide: bool },
    UsernameChanged(String),
    PasswordChanged,
    /// Мы вошли в комнату
    RoomChanged(String),
    /// Список комнат (сырой текст сервера)
    Rooms(String),
    /// @user печатает
    Typing { from: String },
    /// Личное/комнатное сообщение от пира (уже расшифровано).
    Msg { from: String, text: String },
    /// Входящий файл.
    FileMsg { from: String, name: String },
}

struct NetState {
    known: Mutex<HashMap<String, String>>,
    pending: Mutex<Option<Sender<String>>>,
    tx: Sender<Ev>,
}

fn emit(tx: &Sender<Ev>, line: impl Into<String>) {
    let _ = tx.send(Ev::Line(line.into()));
}

fn check_tofu(tx: &Sender<Ev>, name: &str, pubk: &str) -> &'static str {
    let fp = fingerprint(pubk);
    let status = {
        let mut map = tofu().lock().unwrap();
        match map.get(name) {
            None => {
                map.insert(name.to_string(), fp.clone());
                "new"
            }
            Some(old) if *old == fp => "ok",
            _ => "changed",
        }
    };
    if status == "changed" {
        let old = tofu().lock().unwrap().get(name).cloned().unwrap_or_default();
        let _ = tx.send(Ev::Warn(format!(
            "⚠ ВНИМАНИЕ! Публичный ключ '{}' ИЗМЕНИЛСЯ! Был: {} Стал: {}. Возможен MITM. Если это ожидаемо — /trust {}",
            name, old, fp, name
        )));
    }
    status
}

fn insert_keys(st: &NetState, text: &str) {
    let body = match text.find(']') {
        Some(i) => &text[i + 1..],
        None => text,
    };
    let mut known = st.known.lock().unwrap();
    for item in body.split(';') {
        let item = item.trim();
        if let Some(idx) = item.find(':') {
            let n = item[..idx].trim().to_string();
            let p = item[idx + 1..].trim().to_string();
            check_tofu(&st.tx, &n, &p);
            known.insert(n, p);
        }
    }
}

fn request(stream: &mut TcpStream, st: &NetState, shared_key: &[u8; 32], cmd: &str) -> Option<String> {
    let (tx, rx) = mpsc::channel();
    *st.pending.lock().unwrap() = Some(tx);
    let enc = gcm_encrypt(shared_key, cmd.as_bytes(), b"")?;
    send_frame(stream, TYPE_COMMAND, enc.as_bytes()).ok()?;
    rx.recv_timeout(Duration::from_secs(3)).ok()
}

fn recipient_pub(stream: &mut TcpStream, st: &NetState, shared_key: &[u8; 32], name: &str) -> Option<String> {
    if let Some(p) = st.known.lock().unwrap().get(name).cloned() {
        return Some(p);
    }
    let resp = request(stream, st, shared_key, &format!("/pubkey {}", name))?;
    if resp != "ERR" {
        check_tofu(&st.tx, name, &resp);
        st.known.lock().unwrap().insert(name.to_string(), resp.clone());
        return Some(resp);
    }
    None
}

fn room_targets(stream: &mut TcpStream, st: &NetState, shared_key: &[u8; 32], username: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(resp) = request(stream, st, shared_key, "/roommembers") {
        if resp != "ERR" {
            let mut known = st.known.lock().unwrap();
            for item in resp.split(';') {
                if let Some(idx) = item.find(':') {
                    let n = item[..idx].trim().to_string();
                    let p = item[idx + 1..].trim().to_string();
                    check_tofu(&st.tx, &n, &p);
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

fn handle_message(st: &NetState, our: &StaticSecret, payload: &[u8]) {
    let parts: Vec<&[u8]> = payload.split(|&b| b == 0).collect();
    if parts.len() < 3 {
        return;
    }
    let sender = String::from_utf8_lossy(parts[0]).to_string();
    let ct = String::from_utf8_lossy(parts[2]).to_string();
    match st.known.lock().unwrap().get(&sender).cloned() {
        None => emit(&st.tx, format!("[{}]: (неизвестный публичный ключ)", sender)),
        Some(pk) => match decrypt_from_peer(&ct, &pk, our) {
            Some(plain) => {
                let _ = st.tx.send(Ev::Msg { from: sender, text: plain.trim_end().to_string() });
            }
            None => {
                let _ = st.tx.send(Ev::Error(format!("[{}]: не удалось расшифровать (подмена/ключ)", sender)));
            }
        },
    }
}

fn handle_file(st: &NetState, our: &StaticSecret, payload: &[u8]) {
    let parts: Vec<&[u8]> = payload.split(|&b| b == 0).collect();
    if parts.len() < 4 {
        return;
    }
    let sender = String::from_utf8_lossy(parts[0]).to_string();
    let fname = String::from_utf8_lossy(parts[2]).to_string();
    let data = String::from_utf8_lossy(parts[3]).to_string();
    match st.known.lock().unwrap().get(&sender).cloned() {
        None => emit(&st.tx, format!("[{}] отправил файл {}, но ключ неизвестен", sender, fname)),
        Some(pk) => {
            let got = decrypt_from_peer(&data, &pk, our)
                .and_then(|b64| B64.decode(b64.trim()).ok())
                .and_then(|raw| {
                    let base = safe_file_name(&fname);
                    if base.is_empty() {
                        None
                    } else if save_received_file(&base, &raw) {
                        Some(base)
                    } else {
                        None
                    }
                });
            match got {
                Some(base) => {
                    let _ = st.tx.send(Ev::FileMsg { from: sender, name: base });
                }
                None => {
                    let _ = st.tx.send(Ev::Error(format!("[{}] файл {} получить не удалось", sender, fname)));
                }
            }
        }
    }
}

fn reader_loop(
    mut stream: TcpStream,
    st: Arc<NetState>,
    our: Arc<StaticSecret>,
    shared_key: [u8; 32],
    username: String,
    pub_b64: String,
) {
    loop {
        match recv_frame(&mut stream) {
            Ok(Some((ftype, payload))) => {
                if ftype == TYPE_COMMAND {
                    let enc = String::from_utf8_lossy(&payload).to_string();
                    if let Some(text) = gcm_decrypt(&shared_key, &enc, b"") {
                        let text = text.trim().to_string();
                        if let Some(rest) = text.strip_prefix("[RESP]") {
                            if let Some(tx) = st.pending.lock().unwrap().take() {
                                let _ = tx.send(rest.trim().to_string());
                            }
                            continue;
                        }
                        if text.starts_with("[ПУБКЛЮЧИ]") || text.starts_with("[НОВЫЙ]") {
                            insert_keys(&st, &text);
                            continue;
                        }
                        if text.starts_with("[AUTH]OK") {
                            // После входа повторно регистрируем публичный ключ.
                            let reg = format!("{}\x00{}", username, pub_b64);
                            let _ = send_frame(&mut stream, TYPE_REGISTER, reg.as_bytes());
                            let _ = st.tx.send(Ev::Authed);
                            continue;
                        }
                        // ── Сервер v2 ──
                        if let Some(rest) = text.strip_prefix("[ПОЛЬЗОВАТЕЛИ2]") {
                            let mut users = Vec::new();
                            for item in rest.split(';') {
                                let p: Vec<&str> = item.split('|').collect();
                                if p.len() >= 3 {
                                    users.push((p[1].to_string(), p[0].to_string(), p[2] == "1"));
                                }
                            }
                            let _ = st.tx.send(Ev::UserList(users));
                            continue;
                        }
                        if let Some(rest) = text.strip_prefix("[ПРИСУТСТВИЕ]") {
                            let p: Vec<&str> = rest.split('|').collect();
                            if p.len() >= 2 {
                                let online = p[1] == "online";
                                let nick = p.get(2).unwrap_or(&"").to_string();
                                let _ = st.tx.send(Ev::Presence { user: p[0].to_string(), online, nick });
                            }
                            continue;
                        }
                        if let Some(rest) = text.strip_prefix("[ПРОФИЛЬOK]") {
                            let p: Vec<&str> = rest.splitn(4, '|').collect();
                            if p.len() >= 4 {
                                let _ = st.tx.send(Ev::ProfileSaved {
                                    nick: p[1].to_string(),
                                    bio: p[2].to_string(),
                                    hide: p[3] == "1",
                                });
                            }
                            continue;
                        }
                        if let Some(rest) = text.strip_prefix("[ПРОФИЛЬ]") {
                            let p: Vec<&str> = rest.splitn(4, '|').collect();
                            if p.len() >= 4 {
                                let _ = st.tx.send(Ev::Profile {
                                    user: p[0].to_string(),
                                    nick: p[1].to_string(),
                                    online: p[2] == "online",
                                    bio: p[3].to_string(),
                                });
                            }
                            continue;
                        }
                        if let Some(rest) = text.strip_prefix("[ЮЗЕРOK]") {
                            let _ = st.tx.send(Ev::UsernameChanged(rest.trim().to_string()));
                            continue;
                        }
                        if text.starts_with("[ПАРОЛЬOK]") {
                            let _ = st.tx.send(Ev::PasswordChanged);
                            continue;
                        }
                        if let Some(rest) = text.strip_prefix("[ПЕЧАТАЕТ]") {
                            let _ = st.tx.send(Ev::Typing { from: rest.trim().to_string() });
                            continue;
                        }
                        if let Some(rest) = text.strip_prefix("[КОМНАТА] Вы в комнате:") {
                            let _ = st.tx.send(Ev::RoomChanged(rest.trim().to_string()));
                            continue;
                        }
                        if let Some(rest) = text.strip_prefix("[КОМНАТЫ]") {
                            let _ = st.tx.send(Ev::Rooms(rest.trim().to_string()));
                            continue;
                        }
                        if text.starts_with("[ОШИБКА]") {
                            let _ = st.tx.send(Ev::Error(text));
                            continue;
                        }
                        emit(&st.tx, text);
                    }
                } else if ftype == TYPE_MESSAGE {
                    handle_message(&st, &our, &payload);
                } else if ftype == TYPE_FILE {
                    handle_file(&st, &our, &payload);
                }
            }
            _ => {
                let _ = st.tx.send(Ev::Error("Соединение с сервером потеряно.".into()));
                let _ = st.tx.send(Ev::Line("__DISCONNECTED__".into()));
                break;
            }
        }
    }
}

/// Точка входа сетевого потока: подключается и обрабатывает команды GUI.
pub fn net_loop(
    host: String,
    port: String,
    username: String,
    shared_key: [u8; 32],
    our: Arc<StaticSecret>,
    pub_b64: String,
    ui_rx: Receiver<UiCmd>,
    ev_tx: Sender<Ev>,
) {
    let mut stream = match TcpStream::connect(format!("{}:{}", host, port)) {
        Ok(s) => s,
        Err(e) => {
            let _ = ev_tx.send(Ev::Error(format!("Не удалось подключиться к {}:{}. {}", host, port, e)));
            let _ = ev_tx.send(Ev::Line("__DISCONNECTED__".into()));
            return;
        }
    };
    let _ = stream.set_nodelay(true);

    let _ = send_frame(&mut stream, TYPE_MESSAGE, username.as_bytes());
    let _ = send_frame(&mut stream, TYPE_VERSION, PROTOCOL_VERSION.as_bytes());
    let reg = format!("{}\x00{}", username, pub_b64);
    let _ = send_frame(&mut stream, TYPE_REGISTER, reg.as_bytes());

    let st = Arc::new(NetState {
        known: Mutex::new(HashMap::new()),
        pending: Mutex::new(None),
        tx: ev_tx,
    });

    if let Ok(rs) = stream.try_clone() {
        let r_st = Arc::clone(&st);
        let r_our = Arc::clone(&our);
        let r_user = username.clone();
        let r_pub = pub_b64.clone();
        std::thread::spawn(move || reader_loop(rs, r_st, r_our, shared_key, r_user, r_pub));
    }

    emit(&st.tx, format!("Добро пожаловать, {}!", username));

    while let Ok(cmd) = ui_rx.recv() {
        match cmd {
            UiCmd::Raw(slash_cmd) => {
                if slash_cmd == "/exit" {
                    break;
                }
                if let Some(enc) = gcm_encrypt(&shared_key, slash_cmd.as_bytes(), b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::Trust(name) => match st.known.lock().unwrap().get(&name).cloned() {
                Some(p) => {
                    let fp = fingerprint(&p);
                    tofu().lock().unwrap().insert(name.clone(), fp.clone());
                    save_tofu(&tofu().lock().unwrap());
                    emit(&st.tx, format!("✅ Новый ключ {} подтверждён: {}", name, fp));
                }
                None => {
                    let _ = st.tx.send(Ev::Error(format!("Ключ для {} неизвестен", name)));
                }
            },
            UiCmd::Register { pass } => {
                let s = format!("/register {} {}", pass, pass);
                if let Some(enc) = gcm_encrypt(&shared_key, s.as_bytes(), b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::Login { pass } => {
                let s = format!("/login {} {}", username, pass);
                if let Some(enc) = gcm_encrypt(&shared_key, s.as_bytes(), b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::ProfileSet { nick, bio, hide } => {
                let s = format!("/profile set nick={} bio={} hide={}", nick, bio, if hide { 1 } else { 0 });
                if let Some(enc) = gcm_encrypt(&shared_key, s.as_bytes(), b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::SetUsername(new_user) => {
                let s = format!("/setusername {}", new_user);
                if let Some(enc) = gcm_encrypt(&shared_key, s.as_bytes(), b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::SetPassword { old, new } => {
                let s = format!("/setpassword {} {}", old, new);
                if let Some(enc) = gcm_encrypt(&shared_key, s.as_bytes(), b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::Whois(name) => {
                let s = format!("/whois {}", name);
                if let Some(enc) = gcm_encrypt(&shared_key, s.as_bytes(), b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::RefreshUsers => {
                if let Some(enc) = gcm_encrypt(&shared_key, b"/users", b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::RefreshRooms => {
                if let Some(enc) = gcm_encrypt(&shared_key, b"/rooms", b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::Join { room, pass } => {
                let s = if pass.is_empty() {
                    format!("/join {}", room)
                } else {
                    format!("/join {} {}", room, pass)
                };
                if let Some(enc) = gcm_encrypt(&shared_key, s.as_bytes(), b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::CreateRoom { room, pass } => {
                let s = if pass.is_empty() {
                    format!("/createroom {}", room)
                } else {
                    format!("/createroom {} {}", room, pass)
                };
                if let Some(enc) = gcm_encrypt(&shared_key, s.as_bytes(), b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::Leave => {
                if let Some(enc) = gcm_encrypt(&shared_key, b"/leave", b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::Typing(target) => {
                let s = format!("/typing {}", target);
                if let Some(enc) = gcm_encrypt(&shared_key, s.as_bytes(), b"") {
                    let _ = send_frame(&mut stream, TYPE_COMMAND, enc.as_bytes());
                }
            }
            UiCmd::Priv { target, text } => {
                let sent = recipient_pub(&mut stream, &st, &shared_key, &target)
                    .and_then(|pubk| encrypt_to_peer(&text, &pubk, &pub_b64, &our))
                    .map(|ct| format!("{}\x00{}\x00{}", username, target, ct))
                    .map(|payload| send_frame(&mut stream, TYPE_MESSAGE, payload.as_bytes()).is_ok())
                    .unwrap_or(false);
                if sent {
                    emit(&st.tx, format!("[Я → {}]: {}", target, text));
                } else {
                    let _ = st.tx.send(Ev::Error(format!(
                        "Не удалось отправить сообщение для {} (нет ключа?)",
                        target
                    )));
                }
            }
            UiCmd::Room(text) => {
                for (name, pubk) in room_targets(&mut stream, &st, &shared_key, &username) {
                    if let Some(ct) = encrypt_to_peer(&text, &pubk, &pub_b64, &our) {
                        let payload = format!("{}\x00{}\x00{}", username, name, ct);
                        let _ = send_frame(&mut stream, TYPE_MESSAGE, payload.as_bytes());
                    }
                }
                emit(&st.tx, format!("[Я]: {}", text));
            }
            UiCmd::File(path) => match std::fs::read(&path) {
                Err(_) => {
                    let _ = st.tx.send(Ev::Error(format!("Файл не найден: {}", path)));
                }
                Ok(raw) if raw.len() > MAX_FILE => {
                    let _ = st.tx.send(Ev::Error(format!(
                        "Файл слишком большой (до {} КБ)",
                        MAX_FILE / 1000
                    )));
                }
                Ok(raw) => {
                    let fname = path.rsplit(['/', '\\']).next().unwrap_or(&path).to_string();
                    let b64 = B64.encode(&raw);
                    for (name, pubk) in room_targets(&mut stream, &st, &shared_key, &username) {
                        if let Some(ct) = encrypt_to_peer(&b64, &pubk, &pub_b64, &our) {
                            let payload = format!("{}\x00{}\x00{}\x00{}", username, name, fname, ct);
                            let _ = send_frame(&mut stream, TYPE_FILE, payload.as_bytes());
                        }
                    }
                    emit(&st.tx, format!("[Я] файл {} отправлен в комнату", fname));
                }
            },
        }
    }
}