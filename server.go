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
	conn           net.Conn
	address        string
	username       string
	room           string
	pubkey         string
	authed         bool
	activated      bool
	loginAttempts  int
		protoVersion   int
}

var (
	clients       []*Client
	clientsMutex  sync.Mutex
	logMu         sync.Mutex
	encryptKey    []byte
	roomPasswords = map[string]string{}
	accounts      = map[string]Account{}
)

const accountsFile = "accounts.json"

type Account struct {
	Salt    string `json:"salt"`
	Hash    string `json:"hash"`
	Alg     string `json:"alg"`
	Memory  uint32 `json:"memory"`
	Time    uint32 `json:"time"`
	Threads uint8  `json:"threads"`
}

func loadAccounts() map[string]Account {
	m := map[string]Account{}
	data, err := os.ReadFile(accountsFile)
	if err == nil {
		json.Unmarshal(data, &m)
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
		protoVersion = 1
	headerSize   = 5

	keyFile = "secret.key"
)

func logMessage(username, messagePreview string) {
	logMu.Lock()
	defer logMu.Unlock()
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

// sendToUsername доставляет кадр только клиенту с указанным именем.
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

// newArgon2Account creates a salted argon2id(password) hash with params
// stored alongside, in a format shared with server.py.
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

// verifyLegacy checks the pre-argon2 accounts.json format (salted SHA-256).
func verifyLegacy(acc Account, pwd string) bool {
	return acc.Hash != "" && hashPassword(acc.Salt+pwd) == acc.Hash
}

func activate(c *Client) {
	if c.activated {
		return
	}
	c.activated = true
	sendFrameString(c.conn, typeCommand, encryptMessage("[ПУБКЛЮЧИ]" + pubKeysTable()))
	broadcastFrame(typeCommand, []byte(encryptMessage("[НОВЫЙ]" + c.username + ":" + c.pubkey)), c.conn)
	broadcastToRoom(typeCommand, []byte(encryptMessage("\n[СИСТЕМА] "+c.username+" присоединился к чату")), c.conn, c.room)
	fmt.Printf("[АВТОРИЗАЦИЯ] %s вошёл в систему\n", c.username)
}

func validUsername(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == 0 || c == ';' || c == ':' || c == '\n' || c == '\r' {
			return false
		}
	}
	return true
}

func handleClient(conn net.Conn, address string) {
	defer conn.Close()
	var username string

	// Первый кадр — имя пользователя (без шифрования)
	frameType, nameData, err := recvFrame(conn)
	if err != nil {
		return
	}
	if frameType != typeMessage {
		return
	}
	username = strings.TrimSpace(string(nameData))
	if !validUsername(username) {
		sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Недопустимое имя пользователя"))
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
	clients = append(clients, &Client{conn: conn, address: address, username: username, room: "main"})
	clientsMutex.Unlock()

	fmt.Printf("[ПОДКЛЮЧЕНИЕ] %s подключился с %s\n", username, address)

	hint := "[AUTH]Новый ник — зарегистрируйся: /register ник пароль пароль"
	if _, ok := accounts[username]; ok {
		hint = "[AUTH]Аккаунт есть — войди: /login ник пароль"
	}
	sendFrameString(conn, typeCommand, encryptMessage(hint))

	for {
		frameType, payload, err := recvFrame(conn)
		if err != nil {
			break
		}

		room := "main"
		self := findClient(conn)
		if self != nil {
			room = self.room
		}

		if (frameType == typeMessage || frameType == typeFile) && (self == nil || !self.authed) {
			sendFrameString(conn, typeCommand, encryptMessage("[AUTH]Сначала авторизуйтесь: /login ник пароль или /register ник пароль пароль"))
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
			broadcastToRoom(typeMessage, payload, conn, room)
			fmt.Printf("[%s]: (E2E сообщение → комната %s)\n", username, room)
		} else if frameType == typeFile {
			logMessage(username, "(файл)")
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
				sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Неподдерживаемая версия протокола"))
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
					// Ключ пришёл после авторизации (клиент шлёт R ещё раз). Раздаём обновлённый ключ.
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
	fmt.Printf("[ОТКЛЮЧЕНИЕ] %s отключился\n", username)
}

func handleCommand(command string, self *Client) {
	if self == nil {
		return
	}
	conn := self.conn
	command = strings.TrimSpace(command)

	if !self.authed && !strings.HasPrefix(command, "/register") && !strings.HasPrefix(command, "/login") {
		sendFrameString(conn, typeCommand, encryptMessage("[AUTH]Сначала вход: /login ник пароль"))
		return
	}

	switch {
	case strings.HasPrefix(command, "/register"):
		fields := strings.Fields(command)
		if len(fields) != 4 {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Формат: /register ник пароль пароль"))
			break
		}
		nick, p1, p2 := fields[1], fields[2], fields[3]
		if nick != self.username {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Ник должен совпадать с именем подключения"))
			break
		}
		clientsMutex.Lock()
		if _, ok := accounts[nick]; ok {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Ник уже зарегистрирован"))
			break
		}
		if p1 != p2 {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Пароли не совпадают"))
			break
		}
		accounts[nick] = newArgon2Account(p1)
		saveAccounts()
		clientsMutex.Unlock()
		self.authed = true
		sendFrameString(conn, typeCommand, encryptMessage("[AUTH]OK"))
		activate(self)

	case strings.HasPrefix(command, "/login"):
		fields := strings.Fields(command)
		if len(fields) != 3 {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Формат: /login ник пароль"))
			break
		}
		nick, pwd := fields[1], fields[2]
		if nick != self.username {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Ник должен совпадать с именем подключения"))
			break
		}
		clientsMutex.Lock()
		acc, ok := accounts[nick]
		clientsMutex.Unlock()
		valid := false
		if ok {
			if acc.Alg == "" {
				valid = verifyLegacy(acc, pwd)
				if valid {
					accounts[nick] = newArgon2Account(pwd)
					saveAccounts()
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
		self.authed = true
		self.loginAttempts = 0
		sendFrameString(conn, typeCommand, encryptMessage("[AUTH]OK"))
		activate(self)

	case command == "/users":
		clientsMutex.Lock()
		var names []string
		for _, c := range clients {
			if c.room == self.room {
				names = append(names, c.username)
			}
		}
		clientsMutex.Unlock()
		response := fmt.Sprintf("\n[ПОЛЬЗОВАТЕЛИ] Комната %s (%d): %s", self.room, len(names), strings.Join(names, ", "))
		sendFrameString(conn, typeCommand, encryptMessage(response))

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
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Комната уже существует: " + room))
			break
		}
		if pwd != "" {
			rsalt := make([]byte, 16)
			rand.Read(rsalt)
			rsaltHex := hex.EncodeToString(rsalt)
			roomPasswords[room] = rsaltHex + ":" + hashPassword(rsaltHex + pwd)
		} else {
			roomPasswords[room] = ""
		}
		clientsMutex.Unlock()
		sendFrameString(conn, typeCommand, encryptMessage("\n[КОМНАТА] Создана комната " + room))

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
					okPass = hashPassword(existing[:idx] + pwd) == existing[idx+1:]
				} else {
					okPass = hashPassword(pwd) == existing
				}
			}
			if !okPass {
				clientsMutex.Unlock()
				sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Неверный пароль для " + room))
				break
			}
			self.room = room
		} else {
			clientsMutex.Unlock()
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Комнаты нет: " + room + ". Создай: /createroom <имя> [пароль]"))
			break
		}
		clientsMutex.Unlock()
		sendFrameString(conn, typeCommand, encryptMessage("\n[КОМНАТА] Вы в комнате: " + room))
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
		sendFrameString(conn, typeCommand, encryptMessage("[RESP]" + pub))

	case command == "/roommembers":
		clientsMutex.Lock()
		var parts []string
		for _, c := range clients {
			if c.room == self.room && c.authed && c.pubkey != "" {
				parts = append(parts, c.username+":"+c.pubkey)
			}
		}
		clientsMutex.Unlock()
		sendFrameString(conn, typeCommand, encryptMessage("[RESP]" + strings.Join(parts, ";")))

	case command == "/about":
		sendFrameString(conn, typeCommand, encryptMessage("\nMeshMessenger v0.2\nЗащищённый мессенджер с E2E-шифрованием.\nОсновной сервер: Go."))

	case command == "/clear":
		sendFrameString(conn, typeCommand, encryptMessage(strings.Repeat("\n", 50)))

	case command == "/help":
		sendFrameString(conn, typeCommand, encryptMessage("\n[КОМАНДЫ]\n/users /rooms - списки\n/join <комната> /leave\n/file <путь>\n/msg Имя текст - личное\n/time /status /ping /about\n/clear /exit /help"))

	case command == "/exit":
		conn.Close()
	default:
		if command != "" {
			sendFrameString(conn, typeCommand, encryptMessage("[ОШИБКА] Неизвестная команда: " + command + ". Список команд: /help"))
		}
	}
}

func loadConfig(filename string) *Config {
	data, err := os.ReadFile(filename)
	if err != nil {
		fmt.Printf("Ошибка загрузки конфига: %v\n", err)
		os.Exit(1)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Printf("Ошибка парсинга JSON: %v\n", err)
		os.Exit(1)
	}

	return &cfg
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

	fmt.Printf("[СЕРВЕР] Запущен на %s:%d\n", host, port)
	fmt.Println("[СЕРВЕР] Режим: E2E шифрование (сервер НЕ видит содержимое сообщений)\n")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		// Мгновенная доставка (без алгоритма Нейгла)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
		}
		go handleClient(conn, conn.RemoteAddr().String())
	}
}

// loadOrCreateKey возвращает AES-256 ключ в порядке приоритета:
//  1. файл secret.key        — основной источник секрета
//  2. конфиг (миграция со старой версии) — копируется в secret.key
//  3. генерация нового ключа при полном отсутствии секрета
func loadOrCreateKey(cfg *Config) []byte {
	// 1) Секретный файл
	if data, err := os.ReadFile(keyFile); err == nil {
		key, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr == nil && len(key) == keySize {
			return key
		}
	}

	// 2) Миграция из configs.json (свойство crypto.key)
	if cfg.Crypto.Key != "" {
		if key, derr := base64.StdEncoding.DecodeString(cfg.Crypto.Key); derr == nil && len(key) == keySize {
			_ = os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)), 0600)
			fmt.Printf("[ВНИМАНИЕ] Ключ перенесён из configs.json в %s\n", keyFile)
			return key
		}
	}

	// 3) Генерация нового ключа
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		fmt.Printf("Ошибка генерации ключа: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(key)), 0600); err != nil {
		fmt.Printf("Ошибка записи %s: %v\n", keyFile, err)
		os.Exit(1)
	}
	fmt.Printf("[СОЗДАНИЕ] Ключ AES-256 сгенерирован и сохранён в %s (поделись им с участниками чата)\n", keyFile)

	return key
}

func main() {
	cfg := loadConfig("configs.json")
	encryptKey = loadOrCreateKey(cfg)
	accounts = loadAccounts()

	startServer(cfg)
}
