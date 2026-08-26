//! MeshMessenger Server v2 — аккаунты @username + nick + bio + приватность статуса.
//! Копия server.go с переделкой: профиль управляется из GUI (без видимых команд).
//! Протокол: тот же фрейминг, PROTOCOL_VERSION = 2.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"golang.org/x/crypto/argon2"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Server struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"server"`
	Crypto struct {
		Key string `json:"key"`
	} `json:"crypto"`
}

type Client struct {
	conn          net.Conn
	address       string
	username      string // @username (уникальный адрес)
	room          string
	pubkey        string
	authed        bool
	activated     bool
	loginAttempts int
	protoVersion  int
	msgTimes      []time.Time
}

var (
	clients       []*Client
	clientsMutex  sync.Mutex
	logMu         sync.Mutex
	encryptKey    []byte
	roomPasswords = map[string]string{}
	accounts      = map[string]Account{}
	startTime     = time.Now()
)

const accountsFile = "accounts.json"

// Account v2: ключ карты — "@username". Nick/Bio/HideStatus — новые поля.
type Account struct {
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Alg        string `json:"alg"`
	Memory     uint32 `json:"memory"`
	Time       uint32 `json:"time"`
	Threads    uint8  `json:"threads"`
	Nick       string `json:"nick,omitempty"`        // отображаемое имя (неуникальное)
	Bio        string `json:"bio,omitempty"`         // описание профиля
	HideStatus bool   `json:"hide_status,omitempty"` // скрывать «в сети»
}

// loadAccounts читает accounts.json и мигрирует старый формат (без @, без профиля).
// Старый файл сохраняется в accounts.json.bak перед перезаписью.
func loadAccounts() map[string]Account {
	raw := map[string]Account{}
	data, err := os.ReadFile(accountsFile)
	if err != nil {
		return raw
	}
	json.Unmarshal(data, &raw)

	migrated := false
	m := map[string]Account{}
	for key, acc := range raw {
		u := key
		if !strings.HasPrefix(u, "@") {
			u = "@" + strings.ToLower(u)
			migrated = true
		}
		if acc.Nick == "" {
			acc.Nick = strings.TrimPrefix(u, "@")
			migrated = true
		}
		m[u] = acc
	}
	if migrated {
		_ = os.WriteFile(accountsFile+".bak", data, 0600)
		out, _ := json.MarshalIndent(m, "", "  ")
		_ = os.WriteFile(accountsFile, out, 0600)
		fmt.Println("[МИГРАЦИЯ] accounts.json переведён на формат @username (бэкап: accounts.json.bak)")
	}
	return m
}

func saveAccounts() {
	data, _ := json.MarshalIndent(accounts, "", "  ")
	os.WriteFile(accountsFile, data, 0600)
}

const (
	nonceSize = 12
	tagSize   = 16
	keySize   = 32 // AES-256

	maxMessageSize = 1 << 20 // 1 МБ

	typeMessage  = byte('M')
	typeCommand  = byte('C')
	typeFile     = byte('F')
	typeRegister = byte('R')
	typeVersion  = byte('V')
	protoVersion = 2 // v2: @username-аккаунты, профили, статусы, typing
	headerSize   = 5

	keyFile = "secret.key"
)

// checkRate — анти-флуд: не более rateMaxMessages кадров за rateWindowSeconds.
var (
	rateMu          sync.Mutex
	userMsgTimes    = map[string][]time.Time{}
	rateMaxMessages = 30
	rateWindowSec   = 5
)

func checkRate(username string) bool {
	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()
	times := userMsgTimes[username][:0]
	for _, t := range userMsgTimes[username] {
		if now.Sub(t) < time.Duration(rateWindowSec)*time.Second {
			times = append(times, t)
		}
	}
	times = append(times, now)
	userMsgTimes[username] = times
	return len(times) > rateMaxMessages
}

func cleanupRate(username string) {
	rateMu.Lock()
	delete(userMsgTimes, username)
	rateMu.Unlock()
}

func logMessage(username, messagePreview string) {
	logMu.Lock()
	defer logMu.Unlock()
	if st, err := os.Stat("messages.log"); err == nil && st.Size() > 1_000_000 {
		_ = os.Rename("messages.log", "messages.log.1")
	}
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s: %s\n", timestamp, username, messagePreview)
	f, err := os.OpenFile("messages.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(logEntry)
}

// ── TCP-фрейминг с типом кадра ─────────────────────────
// Формат: [1 байт тип][4 байта длина (BE)][payload]

func sendFrame(conn net.Conn, frameType byte, payload []byte) error {
	if len(payload) > maxMessageSize {
		return fmt.Errorf("сообщение слишком большое: %d байт", len(payload))
	}
	frame := make([]byte, headerSize+len(payload))
	frame[0] = frameType
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	copy(frame[headerSize:], payload)
	_, err := conn.Write(frame)
	return err
}

func sendFrameString(conn net.Conn, frameType byte, payload string) error {
	return sendFrame(conn, frameType, []byte(payload))
}

func recvFrame(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	frameType := header[0]
	length := binary.BigEndian.Uint32(header[1:])
	if length > maxMessageSize {
		return 0, nil, fmt.Errorf("недопустимая длина сообщения: %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return frameType, payload, nil
}

// ── AES-256-GCM ───────────────────────────────────────

func encryptMessage(plaintext string) string {
	payload, err := aesGcmEncrypt([]byte(plaintext))
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(payload)
}

func decryptMessage(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	plaintext, err := aesGcmDecrypt(data)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func aesGcmEncrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func aesGcmDecrypt(payload []byte) ([]byte, error) {
	if len(payload) < nonceSize+tagSize {
		return nil, fmt.Errorf("слишком короткий шифротекст")
	}
	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("невалидный шифротекст: %v", err)
	}
	return plaintext, nil
}

// ── Обработка клиентов ────────────────────────────────

func broadcastFrame(frameType byte, payload []byte, senderConn net.Conn) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()
	for _, client := range clients {
		if client.conn != senderConn {
			sendFrame(client.conn, frameType, payload)
		}
	}
}

// sendToUsername доставляет кадр только клиенту с указанным @username.
func sendToUsername(frameType byte, payload []byte, senderConn net.Conn, target string) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()
	for _, client := range clients {
		if client.conn != senderConn && client.username == target && client.authed {
			sendFrame(client.conn, frameType, payload)
			return
		}
	}
}

func broadcastToRoom(frameType byte, payload []byte, senderConn net.Conn, room string) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()
	for _, client := range clients {
		if client.conn != senderConn && client.room == room {
			sendFrame(client.conn, frameType, payload)
		}
	}
}

func findClient(conn net.Conn) *Client {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()
	for _, c := range clients {
		if c.conn == conn {
			return c
		}
	}
	return nil
}

func pubKeysTable() string {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()
	var parts []string
	for _, c := range clients {
		if c.authed && c.pubkey != "" {
			parts = append(parts, c.username+":"+c.pubkey)
		}
	}
	return strings.Join(parts, ";")
}

func hashPassword(pwd string) string {
	h := sha256.Sum256([]byte(pwd))
	return hex.EncodeToString(h[:])
}

const (
	argonMemory  = 64 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
)

func newArgon2Account(pwd string) Account {
	salt := make([]byte, 16)
	rand.Read(salt)
	key := argon2.IDKey([]byte(pwd), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return Account{
		Salt:    base64.RawStdEncoding.EncodeToString(salt),
		Hash:    base64.RawStdEncoding.EncodeToString(key),
		Alg:     "argon2id",
		Memory:  argonMemory,
		Time:    argonTime,
		Threads: argonThreads,
	}
}

func verifyArgon2(acc Account, pwd string) bool {
	salt, err := base64.RawStdEncoding.DecodeString(acc.Salt)
	if err != nil {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(acc.Hash)
	if err != nil {
		return false
	}
	key := argon2.IDKey([]byte(pwd), salt, acc.Time, acc.Memory, acc.Threads, argonKeyLen)
	return subtle.ConstantTimeCompare(key, expected) == 1
}

func verifyLegacy(acc Account, pwd string) bool {
	return acc.Hash != "" && hashPassword(acc.Salt+pwd) == acc.Hash
}

// ── Профили и статусы (v2) ────────────────────────────

// validAtUsername: "@", затем 3–19 символов [a-z0-9_].
func validAtUsername(name string) bool {
	if !strings.HasPrefix(name, "@") || len(name) < 4 || len(name) > 20 {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// sanitizeProfileField убирает символы, ломающие протокол-разделители.
func sanitizeProfileField(s string, maxLen int) string {
	s = strings.Map(func(r rune) rune {
		switch r {
		case '|', ';', ':', '\n', '\r', 0:
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	return s
}

// getAccount возвращает копию аккаунта (под clientsMutex).
func getAccount(u string) (Account, bool) {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()
	acc, ok := accounts[u]
	return acc, ok
}

// isOnline: подключён, авторизован и не скрывает статус.
func isOnline(u string) bool {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()
	for _, c := range clients {
		if c.username == u && c.authed {
			if acc, ok := accounts[u]; ok && acc.HideStatus {
				return false
			}
			return true
		}
	}
	return false
}

// presenceBroadcast рассылает всем изменение присутствия.
// Формат: [ПРИСУТСТВИЕ]@user|online|Nick / [ПРИСУТСТВИЕ]@user|offline
func presenceBroadcast(u string, online bool) {
	var text string
	if online {
		nick := strings.TrimPrefix(u, "@")
		if acc, ok := getAccount(u); ok && acc.Nick != "" {
			nick = acc.Nick
		}
		text = "[ПРИСУТСТВИЕ]" + u + "|online|" + nick
	} else {
		text = "[ПРИСУТСТВИЕ]" + u + "|offline"
	}
	broadcastFrame(typeCommand, []byte(encryptMessage(text)), nil)
}

func activate(c *Client) {
	if c.activated {
		return
	}
	c.activated = true
	sendFrameString(c.conn, typeCommand, encryptMessage("[ПУБКЛЮЧИ]"+pubKeysTable()))
	broadcastFrame(typeCommand, []byte(encryptMessage("[НОВЫЙ]"+c.username+":"+c.pubkey)), c.conn)
	broadcastToRoom(typeCommand, []byte(encryptMessage("\n[СИСТЕМА] "+c.username+" присоединился к чату")), c.conn, c.room)
	presenceBroadcast(c.username, true)
	fmt.Printf("[АВТОРИЗАЦИЯ] %s вошёл в систему\n", c.username)
}

func handleClient(conn net.Conn, address string) {
	defer conn.Close()
	var username string

	// Первый кадр — @username (без шифрования)
	frameType, nameData, err := recvFrame(conn)
	if err != nil {
		return
	}
	if frameType != typeMessage {
		return
	}
	username = strings.TrimSpace(string(nameData))
	if !validAtUsername(username) {
		sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Недопустимый @username (нужен: @ + 3–19 символов a-z, 0-9, _)"))
		return
	}

	clientsMutex.Lock()
	taken := false
	for _, c := range clients {
		if c.username == username {
			taken = true
			break
		}
	}
	if taken {
		clientsMutex.Unlock()
		sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Имя уже занято, выбери другое"))
		return
	}
	clients = append(clients, &Client{conn: conn, address: address, username: username, room: "main", msgTimes: make([]time.Time, 0, 32)})
	clientsMutex.Unlock()

	fmt.Printf("[ПОДКЛЮЧЕНИЕ] %s подключился с %s\n", username, address)

	hint := "[AUTH]Новый аккаунт — зарегистрируйся: /register пароль пароль"
	if _, ok := getAccount(username); ok {
		hint = "[AUTH]Аккаунт есть — войди: /login @username пароль"
	}
	sendFrameString(conn, typeCommand, encryptMessage(hint))

	for {
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
		frameType, payload, err := recvFrame(conn)
		if err != nil {
			break
		}

		if checkRate(username) {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Слишком много сообщений. Соединение закрыто (анти-флуд)."))
			fmt.Printf("[АНТИ-ФЛУД] %s отключён (превышен лимит)\n", username)
			break
		}

		room := "main"
		self := findClient(conn)
		if self != nil {
			room = self.room
		}

		if (frameType == typeMessage || frameType == typeFile) && (self == nil || !self.authed) {
			sendFrameString(conn, typeCommand, encryptMessage("[AUTH]Сначала авторизуйтесь"))
			continue
		}

		if frameType == typeMessage {
			parts := bytes.Split(payload, []byte{0})
			if len(parts) >= 3 && len(parts[1]) > 0 {
				target := strings.TrimSpace(string(parts[1]))
				logMessage(username, "(личное для "+target+")")
				sendToUsername(typeMessage, payload, conn, target)
				continue
			}
			logMessage(username, "(E2E сообщение в "+room+")")
			dbSaveMessage(username, room, string(payload), "text")
			broadcastToRoom(typeMessage, payload, conn, room)
			fmt.Printf("[%s]: (E2E сообщение → комната %s)\n", username, room)
		} else if frameType == typeFile {
			logMessage(username, "(файл)")
			dbSaveMessage(username, room, string(payload), "file")
			broadcastToRoom(typeFile, payload, conn, room)
			fmt.Printf("[%s]: (файл → комната %s)\n", username, room)
		} else if frameType == typeCommand {
			decrypted, err := decryptMessage(string(payload))
			if err != nil {
				fmt.Printf("[!!] %s отправил невалидную команду\n", username)
				sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Не удалось расшифровать команду. Проверьте, что у клиента и сервера одинаковый secret.key"))
				continue
			}
			handleCommand(decrypted, findClient(conn))
		} else if frameType == typeVersion {
			if self != nil && strings.TrimSpace(string(payload)) != strconv.Itoa(protoVersion) {
				sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Неподдерживаемая версия протокола (нужна v2)"))
				conn.Close()
				break
			}
		} else if frameType == typeRegister {
			if self == nil || !self.authed {
				continue
			}
			parts := bytes.Split(payload, []byte{0})
			if len(parts) >= 2 {
				wasEmpty := self.pubkey == ""
				self.pubkey = string(parts[1])
				if !self.activated {
					activate(self)
				} else if wasEmpty {
					sendFrameString(conn, typeCommand, encryptMessage("[ПУБКЛЮЧИ]"+pubKeysTable()))
					broadcastFrame(typeCommand, []byte(encryptMessage("[НОВЫЙ]"+self.username+":"+self.pubkey)), conn)
				}
			}
		}
	}

	clientsMutex.Lock()
	room := "main"
	for i, c := range clients {
		if c.conn == conn {
			room = c.room
			clients = append(clients[:i], clients[i+1:]...)
			break
		}
	}
	clientsMutex.Unlock()

	leaveText := fmt.Sprintf("\n[СИСТЕМА] %s покинул чат", username)
	broadcastToRoom(typeCommand, []byte(encryptMessage(leaveText)), nil, room)
	presenceBroadcast(username, false)
	cleanupRate(username)
	fmt.Printf("[ОТКЛЮЧЕНИЕ] %s отключился\n", username)
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// parseProfilePairs разбирает "key=value" парами; значения могут содержать пробелы:
// новая пара начинается с токена, содержащего '='.
func parseProfilePairs(rest string) map[string]string {
	out := map[string]string{}
	var key string
	var val strings.Builder
	first := true
	flush := func() {
		if key != "" {
			out[key] = strings.TrimSpace(val.String())
		}
		val.Reset()
	}
	for _, tok := range strings.Fields(rest) {
		if idx := strings.Index(tok, "="); idx > 0 {
			flush()
			key = tok[:idx]
			val.WriteString(tok[idx+1:])
		} else if !first && key != "" {
			val.WriteString(" " + tok)
		}
		first = false
	}
	flush()
	return out
}

func handleCommand(command string, self *Client) {
	if self == nil {
		return
	}
	conn := self.conn
	command = strings.TrimSpace(command)

	if !self.authed && !strings.HasPrefix(command, "/register") && !strings.HasPrefix(command, "/login") {
		sendFrameString(conn, typeCommand, encryptMessage("[AUTH]Сначала вход"))
		return
	}

	switch {
	// ── Регистрация: /register пароль пароль (nick = @username подключения) ──
	case strings.HasPrefix(command, "/register"):
		fields := strings.Fields(command)
		if len(fields) != 3 {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Формат: /register пароль пароль"))
			break
		}
		p1, p2 := fields[1], fields[2]
		u := self.username
		clientsMutex.Lock()
		if _, ok := accounts[u]; ok {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] @username уже зарегистрирован"))
			break
		}
		if p1 != p2 {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Пароли не совпадают"))
			break
		}
		acc := newArgon2Account(p1)
		acc.Nick = strings.TrimPrefix(u, "@")
		accounts[u] = acc
		saveAccounts()
		dbSaveAccount(u, acc)
		clientsMutex.Unlock()
		self.authed = true
		sendFrameString(conn, typeCommand, encryptMessage("[AUTH]OK"))
		activate(self)

	// ── Вход: /login [пароль] или /login @username пароль ──
	case strings.HasPrefix(command, "/login"):
		fields := strings.Fields(command)
		if len(fields) < 2 {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Формат: /login @username пароль"))
			break
		}
		u, pwd := self.username, fields[1]
		if len(fields) >= 3 {
			u = strings.ToLower(fields[1])
		}
		clientsMutex.Lock()
		acc, ok := accounts[u]
		clientsMutex.Unlock()
		valid := false
		if ok {
			if acc.Alg == "" {
				valid = verifyLegacy(acc, pwd)
				if valid {
				upd := newArgon2Account(pwd)
				upd.Nick, upd.Bio, upd.HideStatus = acc.Nick, acc.Bio, acc.HideStatus
				clientsMutex.Lock()
				accounts[u] = upd
				saveAccounts()
				dbSaveAccount(u, upd)
				clientsMutex.Unlock()
				}
			} else {
				valid = verifyArgon2(acc, pwd)
			}
		}
		if !valid {
			self.loginAttempts++
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Неверные учётные данные"))
			if self.loginAttempts >= 5 {
				conn.Close()
			}
			break
		}
		if u != self.username {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] @username должен совпадать с именем подключения"))
			break
		}
		self.authed = true
		self.loginAttempts = 0
		sendFrameString(conn, typeCommand, encryptMessage("[AUTH]OK"))
		activate(self)

	// ── Профиль: /profile set nick=… bio=… hide=0|1 ──
	case strings.HasPrefix(command, "/profile set "):
		pairs := parseProfilePairs(strings.TrimPrefix(command, "/profile set "))
		if len(pairs) == 0 {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Нечего менять"))
			break
		}
		clientsMutex.Lock()
		acc, ok := accounts[self.username]
		if !ok {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Аккаунт не найден"))
			break
		}
		changedNick, changedHide := false, false
		if v, ok := pairs["nick"]; ok {
			acc.Nick = sanitizeProfileField(v, 32)
			if acc.Nick == "" {
				acc.Nick = strings.TrimPrefix(self.username, "@")
			}
			changedNick = true
		}
		if v, ok := pairs["bio"]; ok {
			acc.Bio = sanitizeProfileField(v, 200)
		}
		if v, ok := pairs["hide"]; ok && (v == "0" || v == "1") {
			acc.HideStatus = v == "1"
			changedHide = true
		}
		accounts[self.username] = acc
		saveAccounts()
		dbSaveAccount(self.username, acc)
		clientsMutex.Unlock()
		if changedNick || changedHide {
			presenceBroadcast(self.username, isOnline(self.username))
		}
		sendFrameString(conn, typeCommand, encryptMessage("[ПРОФИЛЬOK]"+self.username+"|"+acc.Nick+"|"+acc.Bio+"|"+boolStr(acc.HideStatus)))

	// ── Смена @username: /setusername @new ──
	case strings.HasPrefix(command, "/setusername "):
		nu := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(command, "/setusername ")))
		if !validAtUsername(nu) {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Недопустимый @username (нужен: @ + 3–19 символов a-z, 0-9, _)"))
			break
		}
		old := self.username
		if nu == old {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Это уже ваше имя"))
			break
		}
		clientsMutex.Lock()
		if _, exists := accounts[nu]; exists {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] @username уже занят"))
			break
		}
		busy := false
		for _, c := range clients {
			if c.username == nu {
				busy = true
				break
			}
		}
		if busy {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] @username уже используется в сети"))
			break
		}
		acc, ok := accounts[old]
		if !ok {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Аккаунт не найден"))
			break
		}
		delete(accounts, old)
		accounts[nu] = acc
		saveAccounts()
		dbSaveAccount(nu, acc)
		dbDeleteAccount(old)
		self.username = nu
		clientsMutex.Unlock()
		presenceBroadcast(nu, true)
		broadcastToRoom(typeCommand, []byte(encryptMessage("\n[СИСТЕМА] "+old+" теперь "+nu)), conn, self.room)
		sendFrameString(conn, typeCommand, encryptMessage("[ЮЗЕРOK]"+nu))
		fmt.Printf("[ПРОФИЛЬ] %s сменил имя на %s\n", old, nu)

	// ── Смена пароля: /setpassword old new ──
	case strings.HasPrefix(command, "/setpassword "):
		fields := strings.Fields(command)
		if len(fields) != 3 {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Формат: /setpassword старый новый"))
			break
		}
		oldPwd, newPwd := fields[1], fields[2]
		if len(newPwd) < 4 {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Новый пароль слишком короткий (мин. 4)"))
			break
		}
		clientsMutex.Lock()
		acc, ok := accounts[self.username]
		if !ok {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Аккаунт не найден"))
			break
		}
		valid := false
		if acc.Alg == "" {
			valid = verifyLegacy(acc, oldPwd)
		} else {
			valid = verifyArgon2(acc, oldPwd)
		}
		if !valid {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Старый пароль неверен"))
			break
		}
		upd := newArgon2Account(newPwd)
		upd.Nick, upd.Bio, upd.HideStatus = acc.Nick, acc.Bio, acc.HideStatus
		accounts[self.username] = upd
		saveAccounts()
		dbSaveAccount(self.username, upd)
		clientsMutex.Unlock()
		sendFrameString(conn, typeCommand, encryptMessage("[ПАРОЛЬOK]"))

	// ── Чужой профиль: /whois @user → [ПРОФИЛЬ]@user|Nick|online|bio ──
	case strings.HasPrefix(command, "/whois "):
		u := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(command, "/whois ")))
		acc, ok := getAccount(u)
		if !ok {
			sendFrameString(conn, typeCommand, encryptMessage("[RESP]ERR"))
			break
		}
		status := "offline"
		if isOnline(u) {
			status = "online"
		}
		sendFrameString(conn, typeCommand, encryptMessage("[ПРОФИЛЬ]"+u+"|"+acc.Nick+"|"+status+"|"+acc.Bio))

	// ── Список пользователей (v2): [ПОЛЬЗОВАТЕЛИ2]@user|Nick|1;… ──
	case command == "/users":
		clientsMutex.Lock()
		var parts []string
		for _, c := range clients {
			if !c.authed {
				continue
			}
			acc, ok := accounts[c.username]
			nick := strings.TrimPrefix(c.username, "@")
			if ok && acc.Nick != "" {
				nick = acc.Nick
			}
			on := "1"
			if ok && acc.HideStatus {
				on = "0"
			}
			parts = append(parts, c.username+"|"+nick+"|"+on)
		}
		clientsMutex.Unlock()
		sendFrameString(conn, typeCommand, encryptMessage("[ПОЛЬЗОВАТЕЛИ2]"+strings.Join(parts, ";")))

	// ── «Печатает…»: /typing @user → получателю [ПЕЧАТАЕТ]@from ──
	case strings.HasPrefix(command, "/typing "):
		target := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(command, "/typing ")))
		if target != self.username {
			sendToUsername(typeCommand, []byte(encryptMessage("[ПЕЧАТАЕТ]"+self.username)), conn, target)
		}

	case command == "/rooms":
		clientsMutex.Lock()
		counts := map[string]int{}
		for _, c := range clients {
			counts[c.room]++
		}
		var parts []string
		for r, p := range roomPasswords {
			mark := "🔒"
			if p == "" {
				mark = "открыта"
			}
			parts = append(parts, fmt.Sprintf("%s(%s,%d)", r, mark, counts[r]))
		}
		clientsMutex.Unlock()
		sendFrameString(conn, typeCommand, encryptMessage("\n[КОМНАТЫ] "+strings.Join(parts, ", ")))

	case strings.HasPrefix(command, "/createroom "):
		fields := strings.Fields(command)
		if len(fields) < 2 {
			break
		}
		room := fields[1]
		pwd := ""
		if len(fields) >= 3 {
			pwd = fields[2]
		}
		clientsMutex.Lock()
		if _, ok := roomPasswords[room]; ok {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Комната уже существует: "+room))
			break
		}
		if pwd != "" {
			rsalt := make([]byte, 16)
			rand.Read(rsalt)
			rsaltHex := hex.EncodeToString(rsalt)
			roomPasswords[room] = rsaltHex + ":" + hashPassword(rsaltHex+pwd)
		} else {
			roomPasswords[room] = ""
		}
		clientsMutex.Unlock()
		self.room = room
		sendFrameString(conn, typeCommand, encryptMessage("\n[КОМНАТА] Создана комната "+room))
		sendFrameString(conn, typeCommand, encryptMessage("\n[КОМНАТА] Вы в комнате: "+room))

	case strings.HasPrefix(command, "/join "):
		fields := strings.Fields(command)
		if len(fields) < 2 {
			break
		}
		room := fields[1]
		pwd := ""
		if len(fields) >= 3 {
			pwd = fields[2]
		}
		clientsMutex.Lock()
		if room == "main" {
			self.room = room
		} else if existing, ok := roomPasswords[room]; ok {
			okPass := existing == ""
			if !okPass {
				if idx := strings.Index(existing, ":"); idx >= 0 {
					okPass = hashPassword(existing[:idx]+pwd) == existing[idx+1:]
				} else {
					okPass = hashPassword(pwd) == existing
				}
			}
			if !okPass {
				clientsMutex.Unlock()
				sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Неверный пароль для "+room))
				break
			}
			self.room = room
		} else {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Комнаты нет: "+room))
			break
		}
		clientsMutex.Unlock()
		sendFrameString(conn, typeCommand, encryptMessage("\n[КОМНАТА] Вы в комнате: "+room))
		fmt.Printf("[%s] перешёл в комнату %s\n", self.username, room)

	case command == "/leave":
		self.room = "main"
		sendFrameString(conn, typeCommand, encryptMessage("\n[КОМНАТА] Вы вернулись в main"))

	case command == "/time":
		sendFrameString(conn, typeCommand, encryptMessage("\n[ВРЕМЯ] "+time.Now().Format("2006-01-02 15:04:05")))

	case command == "/ping":
		sendFrameString(conn, typeCommand, encryptMessage("\n[PING] pong"))

	case command == "/status":
		clientsMutex.Lock()
		total := len(clients)
		clientsMutex.Unlock()
		sendFrameString(conn, typeCommand, encryptMessage(fmt.Sprintf("\n[СТАТУС] Онлайн: %d, комната: %s", total, self.room)))

	case strings.HasPrefix(command, "/pubkey "):
		name := strings.TrimSpace(strings.TrimPrefix(command, "/pubkey "))
		pub := ""
		clientsMutex.Lock()
		for _, c := range clients {
			if c.username == name && c.authed && c.pubkey != "" {
				pub = c.pubkey
				break
			}
		}
		clientsMutex.Unlock()
		if pub == "" {
			pub = "ERR"
		}
		sendFrameString(conn, typeCommand, encryptMessage("[RESP]"+pub))

	case command == "/roommembers":
		clientsMutex.Lock()
		var parts []string
		for _, c := range clients {
			if c.room == self.room && c.authed && c.pubkey != "" {
				parts = append(parts, c.username+":"+c.pubkey)
			}
		}
		clientsMutex.Unlock()
		sendFrameString(conn, typeCommand, encryptMessage("[RESP]"+strings.Join(parts, ";")))

	case command == "/about":
		sendFrameString(conn, typeCommand, encryptMessage("\n[О ПРОЕКТЕ] MeshMessenger v2\nЗащищённый мессенджер с E2E-шифрованием (X25519 + AES-256-GCM).\nАккаунты: @username + nick + bio + приватность статуса."))

	case strings.HasPrefix(command, "/history"):
		fields := strings.Fields(command)
		historyRoom := self.room
		historyLimit := 50
		if len(fields) >= 2 {
			historyRoom = fields[1]
		}
		if len(fields) >= 3 {
			fmt.Sscanf(fields[2], "%d", &historyLimit)
		}
		msgs := dbLoadHistory(historyRoom, historyLimit)
		if len(msgs) == 0 {
			sendFrameString(conn, typeCommand, encryptMessage("[ИСТОРИЯ] Нет сообщений в комнате "+historyRoom))
		} else {
			var lines []string
			lines = append(lines, fmt.Sprintf("[ИСТОРИЯ] Комната %s (%d сообщений):", historyRoom, len(msgs)))
			for _, m := range msgs {
				lines = append(lines, fmt.Sprintf("  [%s] %s: (E2E сообщение)", m["time"], m["sender"]))
			}
			sendFrameString(conn, typeCommand, encryptMessage(strings.Join(lines, "\n")))
		}

	case command == "/serverstats":
		stats := dbGetStats()
		line := fmt.Sprintf("[СТАТИСТИКА] Аккаунтов: %v, Сообщений: %v, Комнат: %v, БД: %v, Аптайм: %v",
			stats["total_accounts"], stats["total_messages"], stats["total_rooms"], stats["db_size"], stats["uptime"])
		sendFrameString(conn, typeCommand, encryptMessage(line))

	case command == "/clear":
		sendFrameString(conn, typeCommand, encryptMessage(strings.Repeat("\n", 50)))

	case command == "/exit":
		conn.Close()

	case command == "/help", command == "/h":
		sendFrameString(conn, typeCommand, encryptMessage("[КОМАНДЫ]\n/register пароль пароль\n/login @user пароль\n/msg @user текст\n/file путь\n/history [комната] [лимит]\n/users /rooms /roommembers\n/join комната [пароль] /leave\n/profile set nick=… bio=… hide=0|1\n/whois @user /pubkey @user\n/trust @user /fingerprints\n/serverstats /time /ping /status\n/about /clear /exit /help"))

	default:
		if command != "" {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Неизвестная команда. /help — список"))
		}
	}
}

// loadConfig читает config.json; если его нет — fallback на legacy configs.json
func loadConfig() *Config {
	for _, filename := range []string{"config.json", "configs.json"} {
		if data, err := os.ReadFile(filename); err == nil {
			var cfg Config
			if err := json.Unmarshal(data, &cfg); err != nil {
				fmt.Printf("Ошибка парсинга JSON (%s): %v\n", filename, err)
				os.Exit(1)
			}
			return &cfg
		}
	}
	fmt.Println("Ошибка: не найден ни config.json, ни configs.json")
	os.Exit(1)
	return nil
}

func startServer(cfg *Config) {
	host := cfg.Server.Host
	port := cfg.Server.Port
	if h := os.Getenv("MESH_HOST"); h != "" {
		host = h
	}
	if p := os.Getenv("MESH_PORT"); p != "" {
		port, _ = strconv.Atoi(p)
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()

	fmt.Printf("[СЕРВЕР v2] Запущен на %s:%d\n", host, port)
	fmt.Println("[СЕРВЕР v2] Аккаунты: @username + nick + bio + приватность статуса")
	fmt.Println("[СЕРВЕР v2] Режим: E2E шифрование (сервер НЕ видит содержимое сообщений)")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}
		go handleClient(conn, conn.RemoteAddr().String())
	}
}

// readKeyFile ищет secret.key в текущей директории и до 4 уровней вверх.
func readKeyFile() []byte {
	candidates := []string{keyFile, "../secret.key", "../../secret.key", "../../../secret.key", "../../../../secret.key"}
	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil {
			if key, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data))); derr == nil && len(key) == keySize {
				return key
			}
		}
	}
	return nil
}

// writeKeyFile сохраняет ключ в первую доступную из candidates позицию (или текущую).
func writeKeyFile(key []byte) {
	encoded := base64.StdEncoding.EncodeToString(key)
	for _, p := range []string{keyFile, "../secret.key"} {
		if err := os.WriteFile(p, []byte(encoded), 0600); err == nil {
			return
		}
	}
	_ = os.WriteFile(keyFile, []byte(encoded), 0600)
}

// loadOrCreateKey возвращает AES-256 ключ: secret.key → конфиг (миграция) → генерация.
func loadOrCreateKey(cfg *Config) []byte {
	if key := readKeyFile(); key != nil {
		return key
	}
	if cfg.Crypto.Key != "" {
		if key, derr := base64.StdEncoding.DecodeString(cfg.Crypto.Key); derr == nil && len(key) == keySize {
			writeKeyFile(key)
			fmt.Printf("[ВНИМАНИЕ] Ключ перенесён из configs.json в %s\n", keyFile)
			return key
		}
	}
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		fmt.Println("Ошибка генерации ключа:", err)
		os.Exit(1)
	}
	writeKeyFile(key)
	fmt.Printf("[СОЗДАНИЕ] Ключ AES-256 сгенерирован и сохранён в %s\n", keyFile)
	return key
}

func main() {
	cfg := loadConfig()
	encryptKey = loadOrCreateKey(cfg)
	accounts = loadAccounts()
	initDB()
	migrateAccountsToDB()
	startServer(cfg)
}
