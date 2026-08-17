package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
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
	conn     net.Conn
	address  string
	username string
	room     string
	pubkey   string
}

var (
	clients      []*Client
	clientsMutex sync.Mutex
	encryptKey   []byte
)

const (
	nonceSize = 12
	tagSize   = 16
	keySize   = 32 // AES-256

	maxMessageSize = 1 << 20 // 1 МБ

	typeMessage  = byte('M')
	typeCommand  = byte('C')
	typeFile     = byte('F')
	typeRegister = byte('R')
	headerSize   = 5

	keyFile = "secret.key"
)

func logMessage(username, messagePreview string) {
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
		if client.conn != senderConn && client.username == target {
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
		if c.pubkey != "" {
			parts = append(parts, c.username+":"+c.pubkey)
		}
	}
	return strings.Join(parts, ";")
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
	if username == "" {
		username = fmt.Sprintf("User_%s", address)
	}

	clientsMutex.Lock()
	clients = append(clients, &Client{conn: conn, address: address, username: username, room: "main"})
	clientsMutex.Unlock()

	fmt.Printf("[ПОДКЛЮЧЕНИЕ] %s подключился с %s (комната: main)\n", username, address)

	joinText := fmt.Sprintf("\n[СИСТЕМА] %s присоединился к чату", username)
	broadcastToRoom(typeCommand, []byte(encryptMessage(joinText)), conn, "main")

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
				continue
			}
			handleCommand(decrypted, findClient(conn))
		} else if frameType == typeRegister {
			parts := bytes.Split(payload, []byte{0})
			if len(parts) >= 2 {
				nm := strings.TrimSpace(string(parts[0]))
				pk := string(parts[1])
				if self != nil {
					self.pubkey = pk
				}
				table := pubKeysTable()
				sendFrameString(conn, typeCommand, encryptMessage("[ПУБКЛЮЧИ]" + table))
				broadcastFrame(typeCommand, []byte(encryptMessage("[НОВЫЙ]" + nm + ":" + pk)), conn)
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

	switch {
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
		clientsMutex.Unlock()
		var parts []string
		for r, n := range counts {
			parts = append(parts, fmt.Sprintf("%s(%d)", r, n))
		}
		sendFrameString(conn, typeCommand, encryptMessage("\n[КОМНАТЫ] "+strings.Join(parts, ", ")))

	case strings.HasPrefix(command, "/join "):
		room := strings.TrimSpace(strings.TrimPrefix(command, "/join "))
		if room == "" {
			break
		}
		self.room = room
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
			if c.username == name {
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
			if c.room == self.room && c.pubkey != "" {
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
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()

	fmt.Printf("[СЕРВЕР] Запущен на %s:%d\n", cfg.Server.Host, cfg.Server.Port)
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

	startServer(cfg)
}
