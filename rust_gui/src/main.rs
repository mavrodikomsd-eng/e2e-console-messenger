//! MeshMessenger — GUI-клиент в стиле Telegram Desktop (Rust + egui).
//! Протокол v2: @username + nick + bio + приватность статуса, комнаты, typing.
//! X25519 ECDH + AES-256-GCM (E2E), общий secret.key для команд, TOFU.

mod crypto;
mod net;
mod proto;
mod store;

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui;

use net::{Ev, UiCmd};
use store::{load_or_create_identity, load_shared_key, tofu};

// ── Сохранённые аккаунты ──
#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct SavedAccount {
    username: String,
    password: String,
    host: String,
    port: String,
}

fn accounts_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("MeshMessenger")
        .join("accounts.json")
}

fn load_accounts() -> Vec<SavedAccount> {
    std::fs::read_to_string(accounts_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_accounts(accounts: &[SavedAccount]) {
    let path = accounts_path();
    let _ = std::fs::create_dir_all(path.parent().unwrap());
    let _ = std::fs::write(&path, serde_json::to_string_pretty(accounts).unwrap());
}

fn save_account(acc: &SavedAccount) {
    let mut accounts = load_accounts();
    accounts.retain(|a| !(a.username == acc.username && a.host == acc.host && a.port == acc.port));
    accounts.insert(0, acc.clone());
    if accounts.len() > 10 {
        accounts.truncate(10);
    }
    save_accounts(&accounts);
}

// ── Палитра Telegram Desktop (тёмная) ───────────────────
const CHAT_BG: egui::Color32 = egui::Color32::from_rgb(14, 22, 33); // #0e1621 — фон ленты
const SIDEBAR: egui::Color32 = egui::Color32::from_rgb(23, 33, 43); // #17212b — сайдбар/шапки
const PANEL_2: egui::Color32 = egui::Color32::from_rgb(32, 43, 54); // #202b36 — hover/вторичное
const INPUT_BG: egui::Color32 = egui::Color32::from_rgb(36, 47, 61); // #242f3d — поля ввода
const INPUT_STROKE: egui::Color32 = egui::Color32::from_rgb(52, 66, 82);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(80, 162, 233); // #50a2e9
const ACCENT_HOVER: egui::Color32 = egui::Color32::from_rgb(106, 179, 243);
const BUBBLE_ME: egui::Color32 = egui::Color32::from_rgb(43, 82, 120); // #2b5278
const BUBBLE_OTHER: egui::Color32 = egui::Color32::from_rgb(24, 37, 51); // #182533
const TEXT: egui::Color32 = egui::Color32::from_rgb(233, 239, 245);
const TEXT_DIM: egui::Color32 = egui::Color32::from_rgb(112, 132, 153); // #708499
const DIVIDER: egui::Color32 = egui::Color32::from_rgb(16, 25, 33);
const ONLINE: egui::Color32 = egui::Color32::from_rgb(77, 205, 94); // #4dcd5e
const TIME_IN_BUBBLE: egui::Color32 = egui::Color32::from_rgb(160, 180, 200);

const SYS_CHAT: &str = "\u{1f4e1} Сервер";
const ROOM_CHAT: &str = "# Общая комната";

#[derive(Clone)]
struct Msg {
    mine: bool,
    sender: String,
    text: String,
    kind: u8, // 0 текст, 2 ошибка, 3 предупреждение, 4 файл
    time: String,
    date: String, // "2026-08-25"
    reactions: Vec<(String, usize)>, // (emoji, count)
    read: bool,
}

/// Windows toast-уведомление через PowerShell
#[cfg(target_os = "windows")]
fn toast_notify(title: &str, body: &str) {
    let script = format!(
        r#"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; \
         [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, ContentType = WindowsRuntime] | Out-Null; \
         $template = '<toast><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual></toast>'; \
         $xml = New-Object Windows.Data.Xml.Dom.XmlDocument; \
         $xml.LoadXml($template); \
         $toast = [Windows.UI.Notifications.ToastNotification]::new($xml); \
         [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("MeshMessenger").Show($toast)"#,
        title.replace('<', "&lt;").replace('>', "&gt;"),
        body.replace('<', "&lt;").replace('>', "&gt;")
    );
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
        .spawn();
}

#[cfg(not(target_os = "windows"))]
fn toast_notify(_title: &str, _body: &str) {}

fn now_hhmm() -> String {
    chrono::Local::now().format("%H:%M").to_string()
}

fn now_date() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

fn date_label(d: &str) -> String {
    let today = now_date();
    let yesterday = (chrono::Local::now() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
    if d == today {
        "Сегодня".to_string()
    } else if d == yesterday {
        "Вчера".to_string()
    } else {
        d.to_string()
    }
}

struct Chat {
    id: String, // для личных: "@user"
    msgs: Vec<Msg>,
    unread: usize,
    is_room: bool,
    last_activity: std::time::Instant, // время последнего сообщения для сортировки
}

impl Chat {
    fn new(id: String, is_room: bool) -> Self {
        Self { id, msgs: Vec::new(), unread: 0, is_room, last_activity: std::time::Instant::now() }
    }
    fn last_preview(&self) -> String {
        match self.msgs.last() {
            None => "Нет сообщений".to_string(),
            Some(m) => {
                let prefix = if m.mine { "Вы: " } else if m.kind != 0 { "" } else { &m.sender[..] };
                if m.kind == 4 {
                    format!("{}📎 {}", if m.mine { "Вы: " } else { "" }, m.text)
                } else if m.kind != 0 {
                    m.text.clone()
                } else {
                    format!("{}: {}", prefix.trim_end_matches(':'), m.text)
                }
            }
        }
    }
}

/// Пользователь из списка онлайна.
#[derive(Clone)]
struct User {
    nick: String,
    at: String, // "@username"
    online: bool,
}

impl User {
    fn display(&self) -> &str {
        if self.nick.is_empty() { &self.at } else { &self.nick }
    }
}

#[derive(serde::Deserialize)]
struct CfgFile {
    server: Option<CfgServer>,
}
#[derive(serde::Deserialize)]
struct CfgServer {
    host: Option<String>,
    port: Option<u16>,
}

fn load_config() -> (String, String) {
    let mut host = String::from("127.0.0.1");
    let mut port = String::from("1301");
    for path in ["config.json", "../config.json"] {
        if let Ok(data) = std::fs::read_to_string(path) {
            if let Ok(cfg) = serde_json::from_str::<CfgFile>(&data) {
                if let Some(s) = cfg.server {
                    if let Some(h) = s.host {
                        if !h.is_empty() {
                            host = h;
                        }
                    }
                    if let Some(p) = s.port {
                        if p > 0 {
                            port = p.to_string();
                        }
                    }
                }
                break;
            }
        }
    }
    if let Ok(h) = std::env::var("MESH_HOST") {
        if !h.is_empty() {
            host = h;
        }
    }
    if let Ok(p) = std::env::var("MESH_PORT") {
        if !p.is_empty() {
            port = p;
        }
    }
    (host, port)
}

struct MeshApp {
    screen: Screen,
    // ── Экран входа ──
    host: String,
    port: String,
    at_user: String, // "@username"
    password: String,
    reg_nick: String,
    reg_bio: String,
    auth_mode_register: bool,
    // ── Сеть/состояние ──
    ui_tx: Option<Sender<UiCmd>>,
    ev_rx: Option<Receiver<Ev>>,
    authed: bool,
    connected: bool,
    me: String, // мой @username
    my_nick: String,
    my_bio: String,
    // ── Чаты ──
    chats: Vec<Chat>,
    active: usize,
    search: String,
    search_in_chat: String,
    input: String,
    users: Vec<User>,
    typing_from: Option<(String, Instant)>,
    last_typing_sent: Option<Instant>,
    // ── Окна ──
    show_fingerprints: bool,
    show_profile: bool,
    show_create_room: bool,
    show_join_room: bool,
    // профиль (редактирование)
    p_nick: String,
    p_bio: String,
    p_hide: bool,
    p_new_user: String,
    p_old_pass: String,
    p_new_pass: String,
    // комнаты
    cr_name: String,
    cr_pass: String,
    jr_name: String,
    jr_pass: String,
    // карточка чужого профиля: @user, nick, online, bio
    whois: Option<(String, String, bool, String)>,
    // Ошибка прямо на экране входа (видно, даже если чат не открыт)
    connect_error: Option<String>,
    // сохранённые аккаунты для быстрого входа
    saved_accounts: Vec<SavedAccount>,
}

enum Screen {
    Connect,
    Chat,
}

impl Default for MeshApp {
    fn default() -> Self {
        let (host, port) = load_config();
        let mut chats = Vec::new();
        chats.push(Chat::new(ROOM_CHAT.to_string(), true));
        chats.push(Chat::new(SYS_CHAT.to_string(), false));
        let mut app = Self {
            screen: Screen::Connect,
            host,
            port,
            at_user: String::new(),
            password: String::new(),
            reg_nick: String::new(),
            reg_bio: String::new(),
            auth_mode_register: true,
            ui_tx: None,
            ev_rx: None,
            authed: false,
            connected: false,
            me: String::new(),
            my_nick: String::new(),
            my_bio: String::new(),
            chats,
            active: 0,
            search: String::new(),
            search_in_chat: String::new(),
            input: String::new(),
            users: Vec::new(),
            typing_from: None,
            last_typing_sent: None,
            show_fingerprints: false,
            show_profile: false,
            show_create_room: false,
            show_join_room: false,
            p_nick: String::new(),
            p_bio: String::new(),
            p_hide: false,
            p_new_user: String::new(),
            p_old_pass: String::new(),
            p_new_pass: String::new(),
            cr_name: String::new(),
            cr_pass: String::new(),
            jr_name: String::new(),
            jr_pass: String::new(),
            whois: None,
            connect_error: None,
            saved_accounts: load_accounts(),
        };
        // Демо-сообщения, чтобы видеть вёрстку пузырей до подключения.
        let t = now_hhmm();
        for (mine, sender, text) in [
            (false, "Алиса", "Привет! 👋 Это тестовое сообщение — проверяем вёрстку пузырей."),
            (true, "Я", "Привет, Алиса! Выглядит отлично, как в Telegram 🙂"),
            (false, "Боб", "И у меня всё читается. Шифрование E2E работает 🔒"),
        ] {
            if let Some(room) = app.chats.first_mut() {
                room.msgs.push(Msg { mine, sender: sender.to_string(), text: text.to_string(), kind: 0, time: t.clone(), date: now_date(), reactions: vec![], read: true });
            }
        }
        app
    }
}

impl MeshApp {
    fn chat_index(&mut self, id: &str, is_room: bool) -> usize {
        if let Some(pos) = self.chats.iter().position(|c| c.id == id) {
            return pos;
        }
        self.chats.push(Chat::new(id.to_string(), is_room));
        self.chats.len() - 1
    }

    fn push_msg(&mut self, chat_id: &str, is_room: bool, mine: bool, sender: &str, text: &str, kind: u8) {
        let idx = self.chat_index(chat_id, is_room);
        let active = self.active == idx;
        let chat = &mut self.chats[idx];
        chat.msgs.push(Msg { mine, sender: sender.to_string(), text: text.to_string(), kind, time: now_hhmm(), date: now_date(), reactions: vec![], read: active });
        chat.last_activity = std::time::Instant::now();
        if !active {
            chat.unread += 1;
        }
        if chat.msgs.len() > 3000 {
            chat.msgs.drain(..1000);
        }
        // Поднять чат наверх если он не активный и не первый
        if !active && idx != 0 {
            let was_active_id = self.chats[self.active].id.clone();
            let chat_obj = self.chats.remove(idx);
            self.chats.insert(0, chat_obj);
            // Пересчитать active чтобы не сбился выбранный чат
            self.active = self.chats.iter().position(|c| c.id == was_active_id).unwrap_or(0);
        }
    }

    fn open_private(&mut self, at: &str) {
        let idx = self.chat_index(at, false);
        self.active = idx;
        self.chats[idx].unread = 0;
        self.chats[idx].last_activity = std::time::Instant::now();
    }

    fn display_name(&self, at: &str) -> String {
        if at == self.me {
            return self.my_nick.clone();
        }
        self.users
            .iter()
            .find(|u| &u.at == at)
            .map(|u| u.display().to_string())
            .unwrap_or_else(|| at.trim_start_matches('@').to_string())
    }

    fn start_connect(&mut self) {
        let (ui_tx, ui_rx) = mpsc::channel::<UiCmd>();
        let (ev_tx, ev_rx) = mpsc::channel::<Ev>();
        let shared_key = load_shared_key();
        let (secret, pub_b64) = load_or_create_identity();
        let user = if self.at_user.trim().is_empty() {
            "@anon".to_string()
        } else {
            let u = self.at_user.trim().to_lowercase();
            self.at_user = u.clone();
            u
        };
        if !user.starts_with('@') {
            self.at_user = format!("@{}", user);
        }
        self.me = self.at_user.clone();
        self.my_nick = if self.reg_nick.trim().is_empty() {
            self.at_user.trim_start_matches('@').to_string()
        } else {
            self.reg_nick.trim().to_string()
        };
        self.my_bio = self.reg_bio.trim().to_string();
        let host = self.host.clone();
        let port = self.port.clone();
        let register = self.auth_mode_register;
        let pass = self.password.clone();
        std::thread::spawn(move || {
            net::net_loop(host, port, user, shared_key, std::sync::Arc::new(secret), pub_b64, ui_rx, ev_tx)
        });
        self.ui_tx = Some(ui_tx);
        self.ev_rx = Some(ev_rx);
        self.connected = true;
        self.push_msg(SYS_CHAT, false, false, "система", "Подключаемся…", 0);
        // Авторизация уходит в канал: net_loop обработает её сразу после подключения.
        let cmd = if register { UiCmd::Register { pass } } else { UiCmd::Login { pass } };
        if let Some(tx) = &self.ui_tx {
            let _ = tx.send(cmd);
        }
    }

    fn send_ui(&self, cmd: UiCmd) {
        if let Some(tx) = &self.ui_tx {
            let _ = tx.send(cmd);
        }
    }

    fn poll_events(&mut self) {
        let mut events = Vec::new();
        if let Some(rx) = &self.ev_rx {
            while let Ok(ev) = rx.try_recv() {
                events.push(ev);
            }
        } else {
            return;
        }
        for ev in events {
            match ev {
                Ev::Line(t) => {
                    if t == "__DISCONNECTED__" {
                        self.connected = false;
                        self.authed = false;
                        self.push_msg(SYS_CHAT, false, false, "система", "⛔ Соединение потеряно.", 2);
                    } else {
                        self.push_msg(SYS_CHAT, false, false, "сервер", &t, 0);
                    }
                }
                Ev::Warn(t) => self.push_msg(SYS_CHAT, false, false, "⚠ TOFU", &t, 3),
                Ev::Error(t) => {
                    if matches!(self.screen, Screen::Connect) {
                        self.connect_error = Some(t);
                    } else {
                        self.push_msg(SYS_CHAT, false, false, "ошибка", &t, 2);
                    }
                }
                Ev::Authed => {
                    self.authed = true;
                    self.connect_error = None;
                    self.screen = Screen::Chat;
                    // Сохраняем аккаунт для быстрого входа
                    let pass = self.password.clone();
                    self.password.clear();
                    save_account(&SavedAccount {
                        username: self.me.clone(),
                        password: pass,
                        host: self.host.clone(),
                        port: self.port.clone(),
                    });
                    self.saved_accounts = load_accounts();
                    self.push_msg(SYS_CHAT, false, false, "система", "✅ Вход выполнен. Можно общаться!", 0);
                    self.send_ui(UiCmd::RefreshUsers);
                    self.send_ui(UiCmd::RefreshRooms);
                }
                Ev::UserList(users) => {
                    self.users = users
                        .into_iter()
                        .map(|(nick, at, online)| User { nick, at, online })
                        .filter(|u| u.at != self.me)
                        .collect();
                }
                Ev::Presence { user, online, nick } => {
                    if user == self.me {
                        continue;
                    }
                    match self.users.iter_mut().find(|u| u.at == user) {
                        Some(u) => {
                            u.online = online;
                            if !nick.is_empty() {
                                u.nick = nick;
                            }
                        }
                        None if online => self.users.push(User { nick, at: user, online: true }),
                        _ => {}
                    }
                }
                Ev::Profile { user, nick, online, bio } => {
                    self.whois = Some((user, nick, online, bio));
                }
                Ev::ProfileSaved { nick, bio, hide } => {
                    self.my_nick = nick.clone();
                    self.p_nick = nick;
                    self.p_bio = bio.clone();
                    self.p_hide = hide;
                    self.my_bio = bio;
                    self.push_msg(SYS_CHAT, false, false, "система", "✅ Профиль сохранён", 0);
                }
                Ev::UsernameChanged(nu) => {
                    let old = self.me.clone();
                    self.me = nu.clone();
                    self.at_user = nu.clone();
                    for c in &mut self.chats {
                        if c.id == old {
                            c.id = nu.clone();
                        }
                    }
                    self.push_msg(SYS_CHAT, false, false, "система", &format!("✅ @username сменён на {}", nu), 0);
                }
                Ev::PasswordChanged => {
                    self.p_old_pass.clear();
                    self.p_new_pass.clear();
                    self.push_msg(SYS_CHAT, false, false, "система", "✅ Пароль изменён", 0);
                }
                Ev::RoomChanged(room) => {
                    let id = format!("# {}", room);
                    let idx = self.chat_index(&id, true);
                    self.active = idx;
                    self.chats[idx].unread = 0;
                    self.push_msg(SYS_CHAT, false, false, "система", &format!("Вы вошли в комнату {}", room), 0);
                }
                Ev::Rooms(_) => {}
                Ev::Typing { from } => {
                    self.typing_from = Some((from, Instant::now()));
                }
                Ev::Msg { from, text } => {
                    if from == self.me {
                        continue;
                    }
                    let name = self.display_name(&from);
                    let is_active = self.chats.iter().any(|c| c.id == from && {
                        let idx = self.chats.iter().position(|c2| c2.id == from).unwrap_or(0);
                        self.active == idx
                    });
                    if !is_active {
                        toast_notify(&name, &text);
                    }
                    self.push_msg(&from, false, false, &name, &text, 0);
                }
                Ev::FileMsg { from, name } => {
                    let fname = self.display_name(&from);
                    self.push_msg(&from, false, false, &fname, &format!("📎 файл «{}» сохранён в downloads/", name), 4);
                }
            }
        }
        // «Печатает…» исчезает через 4 секунды
        if let Some((_, t)) = &self.typing_from {
            if t.elapsed() > Duration::from_secs(4) {
                self.typing_from = None;
            }
        }
    }

    fn submit_input(&mut self) {
        let msg = self.input.trim().to_string();
        if msg.is_empty() {
            return;
        }
        self.input.clear();
        if !self.connected {
            self.push_msg(SYS_CHAT, false, false, "ошибка", "Нет соединения.", 2);
            return;
        }
        if msg.starts_with('/') {
            // Слэш-команды — скрытая возможность для опытных пользователей
            if msg == "/fingerprints" {
                self.show_fingerprints = true;
            } else {
                self.send_ui(UiCmd::Raw(msg));
            }
            return;
        }
        let chat = &self.chats[self.active];
        if chat.is_room {
            let text = msg.clone();
            let nick = self.my_nick.clone();
            self.push_msg(ROOM_CHAT, true, true, &nick, &msg, 0);
            self.send_ui(UiCmd::Room(text));
        } else {
            let target = chat.id.clone();
            let nick = self.my_nick.clone();
            self.push_msg(&target, false, true, &nick, &msg, 0);
            self.send_ui(UiCmd::Priv { target, text: msg });
        }
    }

    fn export_chat(&self) {
        let chat = &self.chats[self.active];
        let header = format!("MeshMessenger — Экспорт чата «{}»\n{}\n{}", chat.id, "=".repeat(40), "");
        let lines: Vec<String> = chat.msgs.iter().map(|m| {
            let prefix = if m.mine { "Вы" } else { &m.sender };
            format!("[{} {}] {}: {}", m.date, m.time, prefix, m.text)
        }).collect();
        let content = format!("{}\n{}", header, lines.join("\n"));

        // Сохраняем в downloads/
        let filename = format!("mesh_export_{}_{}.txt",
            chat.id.replace(' ', "_").replace('#', ""),
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        );
        let downloads = dirs::download_dir().unwrap_or_else(|| PathBuf::from("."));
        let path = downloads.join(&filename);
        let _ = std::fs::write(&path, &content);
        // Открываем в проводнике
        let _ = std::process::Command::new("explorer").arg("/select,").arg(&path).spawn();
    }

    fn maybe_send_typing(&mut self, changed: bool) {
        // «Печатает…» — не чаще раза в 3 секунды, только в личных чатах
        if !changed || self.chats[self.active].is_room || !self.authed {
            return;
        }
        let now = Instant::now();
        let ok = match self.last_typing_sent {
            None => true,
            Some(t) => now.duration_since(t) > Duration::from_secs(3),
        };
        if ok {
            self.last_typing_sent = Some(now);
            let target = self.chats[self.active].id.clone();
            self.send_ui(UiCmd::Typing(target));
        }
    }
}

impl eframe::App for MeshApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();
        ctx.request_repaint_after(Duration::from_millis(80));

        match self.screen {
            Screen::Connect => self.draw_connect(ctx),
            Screen::Chat => {
                self.draw_sidebar(ctx);
                self.draw_chat_view(ctx);
                self.draw_profile_window(ctx);
                self.draw_create_room_window(ctx);
                self.draw_join_room_window(ctx);
                self.draw_whois_window(ctx);
                self.draw_fingerprints(ctx);
            }
        }
    }
}

impl MeshApp {
    fn draw_connect(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(CHAT_BG).inner_margin(egui::Margin::same(32.0)))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(24.0);
                    ui.heading(egui::RichText::new("🛡 MeshMessenger").size(30.0).color(TEXT));
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("X25519 · AES-256-GCM · Argon2id · TOFU")
                            .size(12.5)
                            .color(TEXT_DIM),
                    );
                    ui.add_space(28.0);
                });
                ui.vertical_centered(|ui| {
                    egui::Frame::default()
                        .fill(SIDEBAR)
                        .rounding(14.0)
                        .inner_margin(egui::Margin::same(24.0))
                        .show(ui, |ui| {
                            ui.set_min_width(420.0);
                            self.draw_auth_toggle(ui);
                            ui.add_space(16.0);
                            self.draw_auth_fields(ui);
                            ui.add_space(14.0);
                            self.draw_server_collapse(ui);
                            ui.add_space(12.0);
                            if let Some(err) = &self.connect_error {
                                ui.horizontal(|ui| {
                                    ui.add_space(8.0);
                                    ui.label(
                                        egui::RichText::new(format!("⚠ {err}"))
                                            .color(egui::Color32::from_rgb(250, 180, 100))
                                            .size(12.0),
                                    );
                                });
                                ui.add_space(8.0);
                            }
                            self.draw_auth_button(ui);
                            // Сохранённые аккаунты
                            if !self.saved_accounts.is_empty() {
                                ui.add_space(14.0);
                                ui.separator();
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new("Быстрый вход").size(12.0).color(TEXT_DIM));
                                ui.add_space(6.0);
                                let saved = self.saved_accounts.clone();
                                let mut remove_idx: Option<usize> = None;
                                let mut clicked_idx: Option<usize> = None;
                                for (i, acc) in saved.iter().enumerate() {
                                    ui.horizontal(|ui| {
                                        ui.add_space(8.0);
                                        ui.label(egui::RichText::new(&acc.username).size(13.0).color(TEXT));
                                        ui.label(egui::RichText::new(format!("({}:{})", acc.host, acc.port)).size(10.5).color(TEXT_DIM));
                                        if ui.small_button("✕").on_hover_text("Удалить").clicked() {
                                            remove_idx = Some(i);
                                        } else {
                                            let row_resp = ui.interact(ui.available_rect_before_wrap(), egui::Id::new(format!("saved_{}", i)), egui::Sense::click());
                                            if row_resp.clicked() {
                                                clicked_idx = Some(i);
                                            }
                                        }
                                    });
                                }
                                if let Some(i) = remove_idx {
                                    self.saved_accounts.remove(i);
                                    save_accounts(&self.saved_accounts);
                                }
                                if let Some(i) = clicked_idx {
                                    let acc = self.saved_accounts[i].clone();
                                    self.at_user = acc.username;
                                    self.password = acc.password;
                                    self.host = acc.host;
                                    self.port = acc.port;
                                    self.auth_mode_register = false;
                                    self.start_connect();
                                }
                            }
                        });
                    ui.add_space(16.0);
                    ui.label(
                        egui::RichText::new("Сервер видит только маршрутные имена — содержимое сообщений защищено E2E-шифрованием")
                            .size(11.5)
                            .color(TEXT_DIM),
                    );
                });
            });
    }

    fn draw_auth_toggle(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let w = ui.available_width() / 2.0 - 4.0;
            let sel = egui::Button::new(egui::RichText::new("Регистрация").color(
                if self.auth_mode_register { egui::Color32::WHITE } else { TEXT_DIM },
            ))
            .fill(if self.auth_mode_register { ACCENT } else { egui::Color32::TRANSPARENT })
            .rounding(8.0)
            .min_size(egui::vec2(w, 32.0));
            if ui.add(sel).clicked() {
                self.auth_mode_register = true;
            }
            let log = egui::Button::new(egui::RichText::new("Вход").color(
                if !self.auth_mode_register { egui::Color32::WHITE } else { TEXT_DIM },
            ))
            .fill(if !self.auth_mode_register { ACCENT } else { egui::Color32::TRANSPARENT })
            .rounding(8.0)
            .min_size(egui::vec2(ui.available_width() - 4.0, 32.0));
            if ui.add(log).clicked() {
                self.auth_mode_register = false;
            }
        });
    }
}

impl MeshApp {
    fn user_valid(at: &str) -> bool {
        let u = at.trim().trim_start_matches('@');
        u.len() >= 3
            && u.len() <= 19
            && u.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }

    fn draw_auth_fields(&mut self, ui: &mut egui::Ui) {
        let user_ok = Self::user_valid(&self.at_user);
        egui::Grid::new("auth_grid")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label(egui::RichText::new("Юзернейм").color(TEXT_DIM));
                ui.add_sized(
                    [260.0, 24.0],
                    egui::TextEdit::singleline(&mut self.at_user).hint_text("username (a-z, 0-9, _)"),
                );
                ui.end_row();
                ui.label(egui::RichText::new("Пароль").color(TEXT_DIM));
                ui.add_sized(
                    [260.0, 24.0],
                    egui::TextEdit::singleline(&mut self.password).password(true).hint_text("••••••••"),
                );
                ui.end_row();
                if self.auth_mode_register {
                    ui.label(egui::RichText::new("Имя").color(TEXT_DIM));
                    ui.add_sized(
                        [260.0, 24.0],
                        egui::TextEdit::singleline(&mut self.reg_nick).hint_text("Как вас показывать (необязательно)"),
                    );
                    ui.end_row();
                    ui.label(egui::RichText::new("О себе").color(TEXT_DIM));
                    ui.add_sized(
                        [260.0, 24.0],
                        egui::TextEdit::singleline(&mut self.reg_bio).hint_text("Пара слов (необязательно)"),
                    );
                    ui.end_row();
                }
            });
        if !self.at_user.is_empty() && !user_ok {
            ui.label(
                egui::RichText::new("⚠ username: 3–19 символов a-z, 0-9, _")
                    .size(11.5)
                    .color(egui::Color32::from_rgb(250, 180, 100)),
            );
        }
    }

    fn draw_server_collapse(&mut self, ui: &mut egui::Ui) {
        ui.collapsing(egui::RichText::new("Сервер").size(12.0).color(TEXT_DIM), |ui| {
            egui::Grid::new("srv_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                ui.label(egui::RichText::new("Хост").color(TEXT_DIM));
                ui.add_sized([260.0, 22.0], egui::TextEdit::singleline(&mut self.host));
                ui.end_row();
                ui.label(egui::RichText::new("Порт").color(TEXT_DIM));
                ui.add_sized([260.0, 22.0], egui::TextEdit::singleline(&mut self.port));
                ui.end_row();
            });
        });
    }

    fn draw_auth_button(&mut self, ui: &mut egui::Ui) {
        let can = Self::user_valid(&self.at_user) && !self.password.is_empty();
        let btn = egui::Button::new(
            egui::RichText::new(if self.auth_mode_register { "🔒  Создать аккаунт" } else { "🔑  Войти" })
                .color(egui::Color32::WHITE)
                .size(15.0),
        )
        .fill(if can { ACCENT } else { ACCENT.gamma_multiply(0.4) })
        .rounding(10.0)
        .min_size(egui::vec2(ui.available_width(), 38.0));
        if ui.add_enabled(can, btn).clicked() {
            self.start_connect();
        }
    }
}

impl MeshApp {
    /// Аватарка: цветной круг с инициалами.
    fn avatar(ui: &mut egui::Ui, title: &str, size: f32) {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), size / 2.0, avatar_color(title));
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            initials_of(title),
            egui::FontId::proportional(size * 0.42),
            TEXT,
        );
    }

    fn draw_sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("chats")
            .exact_width(300.0)
            .frame(egui::Frame::default().fill(SIDEBAR))
            .show(ctx, |ui| {
                // ── Шапка: мой аватар, имя, шестерёнка профиля, ключи ──
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    Self::avatar(ui, &format!("{}{}", self.my_nick, self.me), 34.0);
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(&self.my_nick).size(15.0).color(TEXT));
                        ui.label(
                            egui::RichText::new(if self.authed { &self.me } else { "не в сети" })
                                .size(11.0)
                                .color(if self.authed { ONLINE } else { TEXT_DIM }),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        if ui.button("🔑").on_hover_text("TOFU-отпечатки ключей").clicked() {
                            self.show_fingerprints = !self.show_fingerprints;
                        }
                        if ui.button("⚙").on_hover_text("Мой профиль").clicked() {
                            self.p_nick = self.my_nick.clone();
                            self.p_bio = self.my_bio.clone();
                            self.show_profile = true;
                        }
                    });
                });
                ui.add_space(6.0);
                // ── Поиск ──
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    egui::Frame::default()
                        .fill(INPUT_BG)
                        .rounding(18.0)
                        .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                        .show(ui, |ui| {
                            ui.add_sized(
                                [258.0, 18.0],
                                egui::TextEdit::singleline(&mut self.search).hint_text("🔍  Поиск людей и комнат"),
                            );
                        });
                });
                ui.add_space(4.0);
                // ── Кнопки комнат ──
                ui.horizontal(|ui| {
                    ui.add_space(10.0);
                    if ui.button("➕ Создать комнату").clicked() {
                        self.cr_name.clear();
                        self.cr_pass.clear();
                        self.show_create_room = true;
                    }
                    if ui.button("🚪 Присоединиться").clicked() {
                        self.jr_name.clear();
                        self.jr_pass.clear();
                        self.send_ui(UiCmd::RefreshRooms);
                        self.show_join_room = true;
                    }
                });
                ui.add_space(4.0);
                ui.separator();
                self.draw_sidebar_list(ui);
            });
    }

    fn draw_sidebar_list(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().show(ui, |ui| {
            let query = self.search.to_lowercase();
            let mut switch: Option<usize> = None;
            // ── Комнаты (сортируем по активности) ──
            ui.label(egui::RichText::new("  КОМНАТЫ").size(10.5).color(TEXT_DIM).strong());
            let room_indices: Vec<usize> = (0..self.chats.len())
                .filter(|&i| self.chats[i].is_room)
                .filter(|&i| query.is_empty() || self.chats[i].id.to_lowercase().contains(&query))
                .collect();
            let mut sorted_rooms = room_indices;
            sorted_rooms.sort_by(|&a, &b| self.chats[b].last_activity.cmp(&self.chats[a].last_activity));
            for i in sorted_rooms {
                if self.chat_row(ui, i) {
                    switch = Some(i);
                }
            }
            ui.add_space(6.0);
            // ── Личные чаты (ВСЕГДА показываем, сортируем по активности) ──
            ui.label(egui::RichText::new("  ЛИЧНЫЕ ЧАТЫ").size(10.5).color(TEXT_DIM).strong());
            let private_indices: Vec<usize> = (0..self.chats.len())
                .filter(|&i| !self.chats[i].is_room)
                .filter(|&i| query.is_empty()
                    || self.chats[i].id.to_lowercase().contains(&query)
                    || self.display_name(&self.chats[i].id).to_lowercase().contains(&query))
                .collect();
            if private_indices.is_empty() {
                ui.label(egui::RichText::new("  Нет чатов. Нажмите на человека ниже →")
                    .size(11.5).color(TEXT_DIM));
            } else {
                let mut sorted_priv = private_indices;
                sorted_priv.sort_by(|&a, &b| self.chats[b].last_activity.cmp(&self.chats[a].last_activity));
                for i in sorted_priv {
                    if self.chat_row(ui, i) {
                        switch = Some(i);
                    }
                }
            }
            ui.add_space(6.0);
            // ── Все пользователи (создают личные чаты) ──
            ui.label(egui::RichText::new("  ПОЛЬЗОВАТЕЛИ").size(10.5).color(TEXT_DIM).strong());
            let mut users: Vec<User> = self
                .users
                .iter()
                .filter(|u| {
                    query.is_empty()
                        || u.nick.to_lowercase().contains(&query)
                        || u.at.to_lowercase().contains(&query)
                })
                .cloned()
                .collect();
            users.sort_by(|a, b| b.online.cmp(&a.online));
            for u in &users {
                let at = u.at.clone();
                if self.user_row(ui, &at, &u.nick, u.online) {
                    if self.chats.iter().any(|c| c.id == at) {
                        let i = self.chats.iter().position(|c| c.id == at).unwrap();
                        switch = Some(i);
                    } else {
                        self.open_private(&at);
                        self.send_ui(UiCmd::Whois(at));
                    }
                }
            }
            if users.is_empty() {
                ui.label(
                    egui::RichText::new("  Пока никого. Люди появятся, когда подключатся.")
                        .size(11.5)
                        .color(TEXT_DIM),
                );
            }
            if let Some(i) = switch {
                self.active = i;
                self.chats[i].unread = 0;
            }
        });
    }
}

impl MeshApp {
    /// Строка комнаты в сайдбаре. true — кликнули.
    fn chat_row(&self, ui: &mut egui::Ui, i: usize) -> bool {
        let chat = &self.chats[i];
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 56.0), egui::Sense::click());
        let selected = i == self.active;
        let fill = if selected {
            ACCENT.gamma_multiply(0.25)
        } else if resp.hovered() {
            PANEL_2
        } else {
            egui::Color32::TRANSPARENT
        };
        let pill = rect.shrink2(egui::vec2(6.0, 1.0));
        ui.painter().rect_filled(pill, 8.0, fill);
        let av = egui::Rect::from_min_size(rect.left_top() + egui::vec2(10.0, 10.0), egui::vec2(36.0, 36.0));
        ui.painter().circle_filled(av.center(), 18.0, avatar_color(&chat.id));
        ui.painter().text(
            av.center(),
            egui::Align2::CENTER_CENTER,
            initials_of(&chat.id),
            egui::FontId::proportional(14.0),
            TEXT,
        );
        ui.painter().text(
            rect.left_top() + egui::vec2(58.0, 14.0),
            egui::Align2::LEFT_CENTER,
            if chat.is_room { chat.id.clone() } else { self.display_name(&chat.id) },
            egui::FontId::proportional(15.0),
            TEXT,
        );
        ui.painter().text(
            rect.left_top() + egui::vec2(58.0, 38.0),
            egui::Align2::LEFT_CENTER,
            truncate(&chat.last_preview(), 32),
            egui::FontId::proportional(12.5),
            TEXT_DIM,
        );
        if chat.unread > 0 {
            let c = rect.right_center() - egui::vec2(16.0, 0.0);
            ui.painter().circle_filled(c, 11.0, ACCENT);
            ui.painter().text(
                c,
                egui::Align2::CENTER_CENTER,
                format!("{}", chat.unread.min(99)),
                egui::FontId::proportional(11.0),
                egui::Color32::WHITE,
            );
        }
        resp.clicked()
    }

    /// Строка пользователя в сайдбаре. true — кликнули.
    fn user_row(&self, ui: &mut egui::Ui, at: &str, nick: &str, online: bool) -> bool {
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 56.0), egui::Sense::click());
        let selected = self.chats[self.active].id == at;
        let fill = if selected {
            ACCENT.gamma_multiply(0.25)
        } else if resp.hovered() {
            PANEL_2
        } else {
            egui::Color32::TRANSPARENT
        };
        let pill = rect.shrink2(egui::vec2(6.0, 1.0));
        ui.painter().rect_filled(pill, 8.0, fill);
        let av = egui::Rect::from_min_size(rect.left_top() + egui::vec2(10.0, 10.0), egui::vec2(36.0, 36.0));
        ui.painter().circle_filled(av.center(), 18.0, avatar_color(at));
        ui.painter().text(
            av.center(),
            egui::Align2::CENTER_CENTER,
            initials_of(nick),
            egui::FontId::proportional(14.0),
            TEXT,
        );
        // Зелёная точка онлайна на краю аватарки
        if online {
            let dot = av.right_bottom() - egui::vec2(2.0, 2.0);
            ui.painter().circle_filled(dot, 5.5, SIDEBAR);
            ui.painter().circle_filled(dot, 4.0, ONLINE);
        }
        ui.painter().text(
            rect.left_top() + egui::vec2(58.0, 14.0),
            egui::Align2::LEFT_CENTER,
            nick.to_string(),
            egui::FontId::proportional(15.0),
            TEXT,
        );
        ui.painter().text(
            rect.left_top() + egui::vec2(58.0, 38.0),
            egui::Align2::LEFT_CENTER,
            format!("{} · {}", at, if online { "в сети" } else { "не в сети" }),
            egui::FontId::proportional(12.0),
            TEXT_DIM,
        );
        resp.clicked()
    }
}

impl MeshApp {
    fn draw_chat_view(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default()
            .frame(egui::Frame::default().fill(CHAT_BG))
            .show(ctx, |ui| {
                let title = self.chats[self.active].id.clone();
                let is_room = self.chats[self.active].is_room;
                let n = self.chats[self.active].msgs.len();

                // ── Шапка чата ──
                egui::TopBottomPanel::top("chat_header")
                    .frame(egui::Frame::default().fill(SIDEBAR).inner_margin(egui::Margin::symmetric(12.0, 8.0)))
                    .show_inside(ui, |ui| {
                        ui.horizontal(|ui| {
                            Self::avatar(ui, &title, 34.0);
                            ui.vertical(|ui| {
                                let display = if is_room { title.clone() } else { self.display_name(&title) };
                                ui.label(egui::RichText::new(display).size(16.0).color(TEXT));
                                let typing = self.typing_from.as_ref().map(|(f, _)| f == &title).unwrap_or(false);
                                let status = if is_room {
                                    "комната · E2E 🔒".to_string()
                                } else if typing {
                                    "печатает…".to_string()
                                } else {
                                    match self.users.iter().find(|u| u.at == title) {
                                        Some(u) if u.online => "в сети".to_string(),
                                        _ => "не в сети".to_string(),
                                    }
                                };
                                let color = if !is_room && typing { ACCENT_HOVER } else { TEXT_DIM };
                                ui.label(egui::RichText::new(status).size(11.0).color(color));
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button("📥").on_hover_text("Экспорт чата в файл").clicked() {
                                    self.export_chat();
                                }
                                if ui.button("🔍").on_hover_text("Поиск в чате").clicked() {
                                    self.search_in_chat.clear();
                                }
                            });
                        });
                        // Поле поиска (показывается если есть текст)
                        if !self.search_in_chat.is_empty() || ui.memory(|m| m.focused().map_or(false, |f| f == egui::Id::new("chat_search"))) {
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.add(egui::TextEdit::singleline(&mut self.search_in_chat)
                                    .hint_text("Поиск в чате…")
                                    .desired_width(ui.available_width() - 30.0));
                                if ui.small_button("✕").clicked() {
                                    self.search_in_chat.clear();
                                }
                            });
                        }
                        ui.add_space(4.0);
                        ui.separator();
                    });

                // ── Лента сообщений ──
                egui::CentralPanel::default()
                    .frame(egui::Frame::default().fill(CHAT_BG))
                    .show_inside(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .stick_to_bottom(true)
                            .auto_shrink(false)
                            .show(ui, |ui| {
                                ui.add_space(10.0);
                                if n == 0 {
                                    ui.vertical_centered(|ui| {
                                        ui.add_space(40.0);
                                        let hint = if is_room {
                                            "Напишите сообщение — его получат все участники комнаты"
                                        } else {
                                            "Выберите, кому хотели бы написать"
                                        };
                                        ui.label(egui::RichText::new(hint).color(TEXT_DIM));
                                    });
                                }
                                let max_w = (ui.available_width() * 0.72).max(220.0);
                                let msgs = self.chats[self.active].msgs.clone();
                                let search_q = self.search_in_chat.to_lowercase();
                                let mut prev_sender: Option<String> = None;
                                let mut prev_mine = false;
                                let mut prev_date = String::new();
                                for (i, m) in msgs.iter().enumerate() {
                                    // Фильтр поиска
                                    if !search_q.is_empty() && !m.text.to_lowercase().contains(&search_q) && !m.sender.to_lowercase().contains(&search_q) {
                                        continue;
                                    }
                                    // Разделитель по датам
                                    if m.date != prev_date {
                                        ui.add_space(8.0);
                                        ui.vertical_centered(|ui| {
                                            egui::Frame::default()
                                                .fill(PANEL_2)
                                                .rounding(10.0)
                                                .inner_margin(egui::Margin::symmetric(12.0, 4.0))
                                                .show(ui, |ui| {
                                                    ui.label(egui::RichText::new(date_label(&m.date)).size(11.0).color(TEXT_DIM));
                                                });
                                        });
                                        ui.add_space(4.0);
                                        prev_date = m.date.clone();
                                        prev_sender = None;
                                        prev_mine = false;
                                    }
                                    let same = prev_sender.as_deref() == Some(m.sender.as_str()) && m.mine == prev_mine;
                                    let first_of_group = !same;
                                    let last_of_group = msgs
                                        .get(i + 1)
                                        .map(|nx| nx.sender != m.sender || nx.mine != m.mine || nx.date != m.date)
                                        .unwrap_or(true);
                                    ui.add_space(if same { 3.0 } else { 12.0 });
                                    draw_bubble(ui, m, max_w, &self.me, first_of_group, last_of_group, i);
                                    prev_sender = Some(m.sender.clone());
                                    prev_mine = m.mine;
                                }
                                ui.add_space(10.0);
                            });
                    });

                self.draw_input_bar(ui, is_room);
            });
    }
}

impl MeshApp {
    fn draw_input_bar(&mut self, ui: &mut egui::Ui, is_room: bool) {
        egui::TopBottomPanel::bottom("inputbar")
            .frame(egui::Frame::default().fill(SIDEBAR).inner_margin(egui::Margin::symmetric(10.0, 8.0)))
            .show_inside(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("📎").on_hover_text("Отправить файл в комнату").clicked() {
                        if let Some(path) = pick_file() {
                            self.send_ui(UiCmd::File(path.to_string_lossy().to_string()));
                        }
                    }
                    let avail = (ui.available_width() - 130.0).max(150.0);
                    let hint = if is_room { "Сообщение в комнату…" } else { "Личное сообщение…" };
                    let before = self.input.clone();
                    let resp = ui.add_sized(
                        [avail, 22.0],
                        egui::TextEdit::singleline(&mut self.input).hint_text(hint),
                    );
                    self.maybe_send_typing(self.input != before);
                    let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    let send_btn = egui::Button::new(egui::RichText::new("Отправить").color(egui::Color32::WHITE))
                        .fill(ACCENT)
                        .rounding(18.0);
                    let send = ui.add_enabled(self.connected, send_btn).clicked();
                    if send || enter {
                        self.submit_input();
                    }
                });
            });
    }
}

impl MeshApp {
    /// Окно «Мой профиль»: nick, bio, скрытие статуса, смена @username и пароля.
    fn draw_profile_window(&mut self, ctx: &egui::Context) {
        if !self.show_profile {
            return;
        }
        let mut open = true;
        egui::Window::new(egui::RichText::new("⚙ Мой профиль").color(TEXT))
            .open(&mut open)
            .frame(egui::Frame::default().fill(SIDEBAR).rounding(12.0).inner_margin(egui::Margin::same(16.0)))
            .show(ctx, |ui| {
                ui.set_min_width(360.0);
                ui.horizontal(|ui| {
                    Self::avatar(ui, &format!("{}{}", self.my_nick, self.me), 48.0);
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(&self.my_nick).size(17.0).color(TEXT));
                        ui.label(egui::RichText::new(&self.me).size(12.0).color(TEXT_DIM));
                    });
                });
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);

                egui::Grid::new("prof_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                    ui.label(egui::RichText::new("Имя").color(TEXT_DIM));
                    ui.add_sized([250.0, 22.0], egui::TextEdit::singleline(&mut self.p_nick));
                    ui.end_row();
                    ui.label(egui::RichText::new("О себе").color(TEXT_DIM));
                    ui.add_sized([250.0, 22.0], egui::TextEdit::singleline(&mut self.p_bio).hint_text("Пара слов о себе"));
                    ui.end_row();
                });
                ui.checkbox(&mut self.p_hide, "Скрывать статус «в сети»");
                ui.add_space(6.0);
                if ui
                    .add(egui::Button::new(egui::RichText::new("Сохранить профиль").color(egui::Color32::WHITE)).fill(ACCENT).rounding(8.0))
                    .clicked()
                {
                    self.send_ui(UiCmd::ProfileSet {
                        nick: self.p_nick.clone(),
                        bio: self.p_bio.clone(),
                        hide: self.p_hide,
                    });
                }
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);
                ui.label(egui::RichText::new("Смена @username (войдёте под новым именем)").size(12.0).color(TEXT_DIM));
                ui.horizontal(|ui| {
                    ui.add_sized([250.0, 22.0], egui::TextEdit::singleline(&mut self.p_new_user).hint_text("@new_username"));
                    if ui.button("Сменить").clicked() {
                        let u = self.p_new_user.trim().to_lowercase();
                        if !u.is_empty() {
                            let u = if u.starts_with('@') { u } else { format!("@{}", u) };
                            self.send_ui(UiCmd::SetUsername(u));
                            self.p_new_user.clear();
                        }
                    }
                });
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Смена пароля").size(12.0).color(TEXT_DIM));
                egui::Grid::new("pwd_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                    ui.label(egui::RichText::new("Старый").color(TEXT_DIM));
                    ui.add_sized([250.0, 22.0], egui::TextEdit::singleline(&mut self.p_old_pass).password(true));
                    ui.end_row();
                    ui.label(egui::RichText::new("Новый").color(TEXT_DIM));
                    ui.add_sized([250.0, 22.0], egui::TextEdit::singleline(&mut self.p_new_pass).password(true));
                    ui.end_row();
                });
                if ui.button("Сменить пароль").clicked() {
                    self.send_ui(UiCmd::SetPassword {
                        old: self.p_old_pass.clone(),
                        new: self.p_new_pass.clone(),
                    });
                }
            });
        self.show_profile = open;
    }

    /// Окно создания комнаты: имя + опциональный пароль.
    fn draw_create_room_window(&mut self, ctx: &egui::Context) {
        if !self.show_create_room {
            return;
        }
        let mut open = true;
        egui::Window::new(egui::RichText::new("➕ Создать комнату").color(TEXT))
            .open(&mut open)
            .frame(egui::Frame::default().fill(SIDEBAR).rounding(12.0).inner_margin(egui::Margin::same(16.0)))
            .show(ctx, |ui| {
                ui.set_min_width(320.0);
                egui::Grid::new("cr_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                    ui.label(egui::RichText::new("Название").color(TEXT_DIM));
                    ui.add_sized([220.0, 22.0], egui::TextEdit::singleline(&mut self.cr_name).hint_text("например, work"));
                    ui.end_row();
                    ui.label(egui::RichText::new("Пароль").color(TEXT_DIM));
                    ui.add_sized(
                        [220.0, 22.0],
                        egui::TextEdit::singleline(&mut self.cr_pass).password(true).hint_text("необязательно"),
                    );
                    ui.end_row();
                });
                ui.add_space(8.0);
                ui.label(egui::RichText::new("🔒 Комната с паролем войдёт только по паролю").size(11.0).color(TEXT_DIM));
                ui.add_space(8.0);
                let can = !self.cr_name.trim().is_empty();
                if ui.add_enabled(can, egui::Button::new(egui::RichText::new("Создать").color(egui::Color32::WHITE)).fill(ACCENT).rounding(8.0)).clicked() {
                    self.send_ui(UiCmd::CreateRoom {
                        room: self.cr_name.trim().to_string(),
                        pass: self.cr_pass.clone(),
                    });
                    self.show_create_room = false;
                }
            });
        self.show_create_room = open;
    }
}

impl MeshApp {
    /// Окно присоединения к комнате: имя + пароль (для закрытых).
    fn draw_join_room_window(&mut self, ctx: &egui::Context) {
        if !self.show_join_room {
            return;
        }
        let mut open = true;
        egui::Window::new(egui::RichText::new("🚪 Присоединиться к комнате").color(TEXT))
            .open(&mut open)
            .frame(egui::Frame::default().fill(SIDEBAR).rounding(12.0).inner_margin(egui::Margin::same(16.0)))
            .show(ctx, |ui| {
                ui.set_min_width(320.0);
                egui::Grid::new("jr_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                    ui.label(egui::RichText::new("Комната").color(TEXT_DIM));
                    ui.add_sized([220.0, 22.0], egui::TextEdit::singleline(&mut self.jr_name).hint_text("название комнаты"));
                    ui.end_row();
                    ui.label(egui::RichText::new("Пароль").color(TEXT_DIM));
                    ui.add_sized(
                        [220.0, 22.0],
                        egui::TextEdit::singleline(&mut self.jr_pass).password(true).hint_text("если комната 🔒"),
                    );
                    ui.end_row();
                });
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new("🔒 Закрытые комнаты — только с паролем. Список комнат: чат «📡 Сервер».")
                        .size(11.0)
                        .color(TEXT_DIM),
                );
                ui.add_space(8.0);
                let can = !self.jr_name.trim().is_empty();
                let btn = egui::Button::new(egui::RichText::new("Войти").color(egui::Color32::WHITE))
                    .fill(ACCENT)
                    .rounding(8.0);
                if ui.add_enabled(can, btn).clicked() {
                    self.send_ui(UiCmd::Join {
                        room: self.jr_name.trim().to_string(),
                        pass: self.jr_pass.clone(),
                    });
                    self.show_join_room = false;
                }
            });
        self.show_join_room = open;
    }
}

impl MeshApp {
    /// Карточка чужого профиля (по клику на человека в сайдбаре).
    fn draw_whois_window(&mut self, ctx: &egui::Context) {
        let data = match &self.whois {
            Some(d) => d.clone(),
            None => return,
        };
        let mut open = true;
        egui::Window::new(egui::RichText::new("Профиль").color(TEXT))
            .open(&mut open)
            .frame(egui::Frame::default().fill(SIDEBAR).rounding(12.0).inner_margin(egui::Margin::same(16.0)))
            .show(ctx, |ui| {
                let (at, nick, online, bio) = &data;
                ui.set_min_width(300.0);
                ui.horizontal(|ui| {
                    Self::avatar(ui, &format!("{}{}", nick, at), 56.0);
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(nick).size(18.0).color(TEXT));
                        ui.label(egui::RichText::new(at).size(12.5).color(TEXT_DIM));
                        ui.label(
                            egui::RichText::new(if *online { "🟢 в сети" } else { "⚪ не в сети" })
                                .size(11.5)
                                .color(if *online { ONLINE } else { TEXT_DIM }),
                        );
                    });
                });
                if !bio.is_empty() {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new(bio).size(13.0).color(TEXT));
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("✉ Написать").clicked() {
                        self.open_private(at);
                        self.whois = None;
                    }
                    if ui.button("🔑 Ключи").clicked() {
                        self.show_fingerprints = true;
                    }
                });
            });
        if !open {
            self.whois = None;
        }
    }

    fn draw_fingerprints(&mut self, ctx: &egui::Context) {
        if !self.show_fingerprints {
            return;
        }
        let mut open = true;
        egui::Window::new(egui::RichText::new("🔑 TOFU-отпечатки ключей").color(TEXT))
            .open(&mut open)
            .frame(egui::Frame::default().fill(SIDEBAR).rounding(12.0))
            .show(ctx, |ui| {
                let map = tofu().lock().unwrap().clone();
                if map.is_empty() {
                    ui.label(egui::RichText::new("Пока никого. Ключи появятся после первого обмена.").color(TEXT_DIM));
                } else {
                    egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                        for (n, fp) in map.iter() {
                            ui.horizontal(|ui| {
                                Self::avatar(ui, n, 26.0);
                                ui.vertical(|ui| {
                                    let display = if n == &self.me {
                                        format!("{} (вы)", self.my_nick)
                                    } else {
                                        self.display_name(n)
                                    };
                                    ui.label(egui::RichText::new(display).color(TEXT).size(13.0));
                                    ui.monospace(egui::RichText::new(fp).color(TEXT_DIM).size(10.5));
                                });
                                if ui.small_button("доверять").clicked() {
                                    self.send_ui(UiCmd::Trust(n.to_string()));
                                }
                            });
                            ui.add_space(2.0);
                        }
                    });
                }
            });
        self.show_fingerprints = open;
    }
}

/// Простой markdown: **жирный**, `код`, ```блок кода```, ссылки
fn render_rich_text(ui: &mut egui::Ui, text: &str, base_color: egui::Color32) {
    let lines: Vec<&str> = text.split('\n').collect();
    for line in &lines {
        if line.starts_with("```") && line.len() > 3 {
            // Блок кода — пропускаем закрывающие ```
            continue;
        }
        // Простой рендер: ищем **жирный** и `код`
        let mut segments: Vec<(String, bool, bool)> = Vec::new(); // (text, bold, code)
        let mut current = String::new();
        let mut in_bold = false;
        let mut in_code = false;
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '*' {
                if !current.is_empty() {
                    segments.push((current.clone(), in_bold, in_code));
                    current.clear();
                }
                in_bold = !in_bold;
                i += 2;
                continue;
            }
            if chars[i] == '`' {
                if !current.is_empty() {
                    segments.push((current.clone(), in_bold, in_code));
                    current.clear();
                }
                in_code = !in_code;
                i += 1;
                continue;
            }
            current.push(chars[i]);
            i += 1;
        }
        if !current.is_empty() {
            segments.push((current, in_bold, in_code));
        }
        if segments.is_empty() {
            ui.label(egui::RichText::new(*line).color(base_color).size(14.5));
        } else {
            ui.horizontal_wrapped(|ui| {
                for (seg, bold, code) in &segments {
                    let mut rt = egui::RichText::new(seg).size(14.5);
                    if *bold {
                        rt = rt.strong();
                    }
                    if *code {
                        rt = rt.color(ACCENT).family(egui::FontFamily::Monospace);
                    } else {
                        rt = rt.color(base_color);
                    }
                    ui.label(rt);
                }
            });
        }
    }
}

/// Пузырь сообщения в стиле Telegram: хвостик только у первого сообщения группы.
fn draw_bubble(ui: &mut egui::Ui, m: &Msg, max_w: f32, me: &str, first_of_group: bool, _last_of_group: bool, _msg_idx: usize) {
    let _ = me;
    let is_me = m.mine;
    let (fill, align_right, text_color) = match m.kind {
        2 => (egui::Color32::from_rgb(80, 45, 45), false, egui::Color32::from_rgb(255, 150, 150)),
        3 => (egui::Color32::from_rgb(80, 68, 32), false, egui::Color32::from_rgb(250, 220, 130)),
        _ if is_me => (BUBBLE_ME, true, TEXT),
        _ => (BUBBLE_OTHER, false, TEXT),
    };
    // Скругление: у первого в группе «хвост» (острый угол), у остальных — ровно
    let r = 12.0;
    let tail = if first_of_group { 3.0 } else { r };
    let rounding = if align_right {
        egui::Rounding { nw: r, ne: r, sw: r, se: tail }
    } else {
        egui::Rounding { nw: r, ne: r, sw: tail, se: r }
    };

    ui.horizontal(|ui| {
        if align_right {
            let w = ui.available_width();
            if w > max_w + 40.0 {
                ui.allocate_space(egui::vec2(w - max_w - 40.0, 0.0));
            }
        } else {
            ui.add_space(6.0);
        }
        egui::Frame::default()
            .fill(fill)
            .rounding(rounding)
            .inner_margin(egui::Margin::symmetric(12.0, 7.0))
            .show(ui, |ui| {
                ui.set_max_width(max_w);
                ui.vertical(|ui| {
                    // Ник отправителя — для чужих обычных сообщений, только в начале группы
                    if !is_me && m.kind == 0 && !m.sender.is_empty() && first_of_group {
                        ui.label(
                            egui::RichText::new(&m.sender)
                                .size(12.0)
                                .strong()
                                .color(avatar_color(&m.sender).linear_multiply(2.2)),
                        );
                    }
                    // Текст с простым markdown
                    render_rich_text(ui, &m.text, text_color);
                    // Реакции
                    if !m.reactions.is_empty() {
                        ui.add_space(2.0);
                        ui.horizontal(|ui| {
                            for (emoji, count) in &m.reactions {
                                egui::Frame::default()
                                    .fill(PANEL_2)
                                    .rounding(10.0)
                                    .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new(format!("{} {}", emoji, count)).size(11.0).color(TEXT_DIM));
                                    });
                                ui.add_space(2.0);
                            }
                        });
                    }
                    // Время + галочка — мелким в углу пузыря, прижато вправо
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                        if is_me && m.kind == 0 {
                            let check = if m.read { "✓✓" } else { "✓" };
                            let check_color = if m.read {
                                egui::Color32::from_rgb(100, 200, 100)
                            } else {
                                egui::Color32::from_rgba_unmultiplied(200, 225, 255, 180)
                            };
                            ui.label(egui::RichText::new(check).size(9.5).color(check_color));
                        }
                        ui.label(egui::RichText::new(&m.time).size(9.5).color(
                            if is_me && m.kind == 0 {
                                egui::Color32::from_rgba_unmultiplied(200, 225, 255, 150)
                            } else {
                                TIME_IN_BUBBLE
                            },
                        ));
                    });
                });
            });
        // Контекстное меню (правый клик)
        let resp = ui.interact(ui.max_rect(), egui::Id::new(format!("bubble_{}", _msg_idx)), egui::Sense::click());
        if resp.secondary_clicked() {
            ui.memory_mut(|mem| mem.open_popup(egui::Id::new("reaction_menu")));
        }
    });
    // Popup меню реакций
    egui::Area::new(egui::Id::new("reaction_menu"))
        .fixed_pos(ui.input(|i| i.pointer.interact_pos().unwrap_or(egui::pos2(0.0, 0.0))))
        .show(ui.ctx(), |ui| {
            egui::Frame::default().fill(SIDEBAR).rounding(8.0).inner_margin(egui::Margin::same(6.0)).show(ui, |ui| {
                ui.horizontal(|ui| {
                    for emoji in &["👍", "❤️", "😂", "😮", "😢", "🔥"] {
                        if ui.add(egui::Button::new(egui::RichText::new(*emoji).size(18.0)).fill(egui::Color32::TRANSPARENT)).clicked() {
                            // TODO: отправить реакцию через сеть
                            ui.memory_mut(|mem| mem.close_popup());
                        }
                    }
                });
            });
        });
}

fn pick_file() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Add-Type -AssemblyName System.Windows.Forms; \
                 $d = New-Object System.Windows.Forms.OpenFileDialog; \
                 if ($d.ShowDialog() -eq 'OK') { $d.FileName }",
            ])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if s.is_empty() { None } else { Some(PathBuf::from(s)) }
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// Обёртка MeshApp + трей-иконка
struct AppWithTray {
    app: MeshApp,
    _tray_icon: Option<tray_icon::TrayIcon>,
}

impl eframe::App for AppWithTray {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.app.update(ctx, frame);
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([800.0, 560.0])
            .with_title("MeshMessenger"),
        ..Default::default()
    };
    eframe::run_native(
        "MeshMessenger",
        options,
        Box::new(|cc| {
            apply_custom_theme(&cc.egui_ctx);

            // Трей — пытаемся загрузить иконку, если нет файла — просто без иконки
            let icon_path = std::env::current_dir().ok().map(|p| p.join("icon.ico"));
            let tray_icon = icon_path
                .filter(|p| p.exists())
                .and_then(|p| tray_icon::Icon::from_path(p, None).ok())
                .and_then(|icon| {
                    let menu = muda::Menu::new();
                    let _show = muda::MenuItem::new("Показать", true, None);
                    let _quit = muda::MenuItem::new("Выход", true, None);
                    menu.append(&_show).ok()?;
                    menu.append(&_quit).ok()?;
                    tray_icon::TrayIconBuilder::new()
                        .with_menu(Box::new(menu))
                        .with_tooltip("MeshMessenger — E2E мессенджер")
                        .with_icon(icon)
                        .build()
                        .ok()
                });

            Ok(Box::new(AppWithTray { app: MeshApp::default(), _tray_icon: tray_icon }))
        }),
    )
}

/// Единая тема всего приложения в стиле Telegram Desktop.
fn apply_custom_theme(ctx: &egui::Context) {
    // Шрифт: пробуем Segoe UI (есть на всех Windows, отличная кириллица)
    if let Ok(bytes) = std::fs::read("C:\\Windows\\Fonts\\segoeui.ttf") {
        let mut fonts = egui::FontDefinitions::default();
        fonts.font_data.insert(
            "segoe_ui".into(),
            egui::FontData::from_owned(bytes).into(),
        );
        if let Some(prop) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            prop.insert(0, "segoe_ui".into());
        }
        if let Ok(bold) = std::fs::read("C:\\Windows\\Fonts\\segoeuib.ttf") {
            fonts.font_data.insert("segoe_ui_bold".into(), egui::FontData::from_owned(bold).into());
            fonts
                .families
                .entry(egui::FontFamily::Name("Bold".into()))
                .or_default()
                .push("segoe_ui_bold".into());
        }
        ctx.set_fonts(fonts);
    }

    let mut style = (*ctx.style()).clone();
    let v = &mut style.visuals;

    v.dark_mode = true;
    v.override_text_color = Some(TEXT);
    v.panel_fill = SIDEBAR;
    v.window_fill = SIDEBAR;
    v.extreme_bg_color = INPUT_BG;
    v.faint_bg_color = PANEL_2;

    v.window_rounding = egui::Rounding::same(12.0);
    v.menu_rounding = egui::Rounding::same(10.0);

    v.selection.bg_fill = ACCENT.gamma_multiply(0.55);
    v.selection.stroke = egui::Stroke::new(1.0_f32, TEXT);
    v.hyperlink_color = ACCENT_HOVER;

    v.widgets.inactive.bg_fill = INPUT_BG;
    v.widgets.inactive.weak_bg_fill = INPUT_BG;
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0_f32, INPUT_STROKE);
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.2_f32, TEXT);
    v.widgets.inactive.rounding = egui::Rounding::same(8.0);

    v.widgets.hovered.bg_fill = PANEL_2;
    v.widgets.hovered.weak_bg_fill = PANEL_2;
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.5_f32, ACCENT_HOVER);
    v.widgets.hovered.fg_stroke = egui::Stroke::new(1.2_f32, TEXT);
    v.widgets.hovered.rounding = egui::Rounding::same(8.0);

    v.widgets.active.bg_fill = ACCENT.gamma_multiply(0.8);
    v.widgets.active.weak_bg_fill = ACCENT.gamma_multiply(0.8);
    v.widgets.active.bg_stroke = egui::Stroke::new(1.5_f32, ACCENT);
    v.widgets.active.fg_stroke = egui::Stroke::new(1.2_f32, egui::Color32::WHITE);
    v.widgets.active.rounding = egui::Rounding::same(8.0);

    v.widgets.open.bg_fill = PANEL_2;
    v.widgets.open.weak_bg_fill = PANEL_2;
    v.widgets.open.bg_stroke = egui::Stroke::new(1.0_f32, INPUT_STROKE);
    v.widgets.open.fg_stroke = egui::Stroke::new(1.2_f32, TEXT);
    v.widgets.open.rounding = egui::Rounding::same(8.0);

    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.menu_margin = egui::Margin::same(8.0);
    style.spacing.indent = 18.0;

    ctx.set_style(style);
}

fn avatar_color(title: &str) -> egui::Color32 {
    let hash: u32 = title.bytes().map(|b| (b as u32).wrapping_mul(31)).fold(5381u32, |a, b| a.wrapping_add(b));
    // Палитра аватарок Telegram
    const PALETTE: [[u8; 3]; 7] = [
        [226, 68, 92],   // красный
        [244, 144, 50],  // оранжевый
        [70, 178, 90],   // зелёный
        [46, 170, 220],  // голубой
        [130, 106, 224], // фиолетовый
        [226, 98, 176],  // розовый
        [80, 162, 233],  // акцент
    ];
    let c = PALETTE[(hash as usize) % PALETTE.len()];
    egui::Color32::from_rgb(c[0], c[1], c[2])
}

fn initials_of(title: &str) -> String {
    let clean = title.trim_start_matches(['#', '@', '👤', '📡', '\u{1f4e1}']).trim();
    let mut it = clean.split_whitespace();
    match (it.next(), it.next()) {
        (Some(a), Some(b)) => {
            format!("{}{}", a.chars().next().unwrap_or('?').to_uppercase(), b.chars().next().unwrap_or(' ').to_uppercase())
        }
        (Some(a), None) => a.chars().take(2).map(|c| c.to_ascii_uppercase()).collect(),
        _ => "?".to_string(),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cut: String = s.chars().take(n.saturating_sub(1)).collect();
        format!("{}…", cut)
    }
}

// __PART3__
