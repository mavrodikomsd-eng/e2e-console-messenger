package main

import (
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

	typeMessage = byte('M') // сообщение: имя + \x00 + шифротекст (сервер не читает)
	typeCommand = byte('C') // команда/системный ответ (зашифровано)
	headerSize  = 5         // 1 (тип) + 4 (длина)
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
	clients = append(clients, &Client{conn: conn, address: address, username: username})
	clientsMutex.Unlock()

	fmt.Printf("[ПОДКЛЮЧЕНИЕ] %s подключился с %s\n", username, address)

	// Системное сообщение о подключении — зашифровано (тип C)
	joinText := fmt.Sprintf("\n[СИСТЕМА] %s присоединился к чату", username)
	broadcastFrame(typeCommand, []byte(encryptMessage(joinText)), conn)

	for {
		frameType, payload, err := recvFrame(conn)
		if err != nil {
			break
		}

		if frameType == typeMessage {
			// ── E2E: сервер НЕ смотрит содержимое ──
			// Формат: имя + \x00 + шифротекст. Пересылаем как есть.
			logMessage(username, "(E2E сообщение)")
			broadcastFrame(typeMessage, payload, conn)
			fmt.Printf("[%s]: (E2E сообщение → переслано)\n", username)
		} else if frameType == typeCommand {
			// Команду расшифровываем (служебная информация)
			decrypted, err := decryptMessage(string(payload))
			if err != nil {
				fmt.Printf("[!!] %s отправил невалидную команду\n", username)
				continue
			}
			handleCommand(decrypted, username, conn)
		}
	}

	clientsMutex.Lock()
	for i, c := range clients {
		if c.conn == conn {
			clients = append(clients[:i], clients[i+1:]...)
			break
		}
	}
	clientsMutex.Unlock()

	leaveText := fmt.Sprintf("\n[СИСТЕМА] %s покинул чат", username)
	broadcastFrame(typeCommand, []byte(encryptMessage(leaveText)), nil)
	fmt.Printf("[ОТКЛЮЧЕНИЕ] %s отключился\n", username)
}

func handleCommand(command, username string, conn net.Conn) {
	command = strings.TrimSpace(command)

	switch command {
	case "/users":
		clientsMutex.Lock()
		userList := make([]string, len(clients))
		for i, c := range clients {
			userList[i] = c.username
		}
		clientsMutex.Unlock()

		response := fmt.Sprintf("\n[ПОЛЬЗОВАТЕЛИ] Онлайн (%d): %s", len(userList), strings.Join(userList, ", "))
		sendFrameString(conn, typeCommand, encryptMessage(response))

	case "/clear":
		response := strings.Repeat("\n", 50)
		sendFrameString(conn, typeCommand, encryptMessage(response))

	case "/help":
		helpText := "\n[КОМАНДЫ]\n/users - список пользователей\n/clear - очистить экран\n/exit - выход\n/help - справка"
		sendFrameString(conn, typeCommand, encryptMessage(helpText))

	case "/exit":
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

func main() {
	cfg := loadConfig("configs.json")

	key, err := base64.StdEncoding.DecodeString(cfg.Crypto.Key)
	if err != nil || len(key) != keySize {
		fmt.Printf("Ошибка: ключ должен быть base64 из %d байт (AES-256). Сгенерируй: openssl rand -base64 32\n", keySize)
		os.Exit(1)
	}
	encryptKey = key

	startServer(cfg)
}
