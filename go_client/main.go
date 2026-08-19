package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	typeMessage  = byte('M')
	typeCommand  = byte('C')
	typeFile     = byte('F')
	typeRegister = byte('R')
	typeVersion  = byte('V')
	protoVersion = 1
	headerSize   = 5
	maxFileSize  = 400000
)

var (
	printMu  sync.Mutex
	sharedKey [32]byte
)

func pprint(text string) {
	printMu.Lock()
	defer printMu.Unlock()
	fmt.Printf("\r%s \n>>> ", text)
}

func sendFrame(conn net.Conn, ftype byte, payload []byte) error {
	if len(payload) > 1<<20 {
		return fmt.Errorf("payload too big")
	}
	frame := make([]byte, headerSize+len(payload))
	frame[0] = ftype
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	copy(frame[headerSize:], payload)
	_, err := conn.Write(frame)
	return err
}

func recvFrame(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length > 1<<20 {
		return 0, nil, fmt.Errorf("payload too big")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}

func loadSharedKey() [32]byte {
	path := os.Getenv("MESH_SHARED_KEY")
	if path == "" {
		path = "secret.key"
	}
	if data, err := os.ReadFile(path); err == nil {
		key, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr == nil && len(key) == 32 {
			var k [32]byte
			copy(k[:], key)
			return k
		}
	}
	var key [32]byte
	rand.Read(key[:])
	os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key[:])), 0600)
	return key
}

func loadOrCreateIdentity() (*ecdh.PrivateKey, string) {
	path := os.Getenv("MESH_IDENTITY_FILE")
	if path == "" {
		path = "identity.key"
	}
	if data, err := os.ReadFile(path); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) == 2 {
			seed, err1 := base64.StdEncoding.DecodeString(parts[0])
			pub, err2 := base64.StdEncoding.DecodeString(parts[1])
			if err1 == nil && err2 == nil && len(seed) == 32 {
				if priv, err := ecdh.X25519().NewPrivateKey(seed); err == nil {
					return priv, base64.StdEncoding.EncodeToString(pub)
				}
			}
		}
	}
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	pub := priv.PublicKey().Bytes()
	seed := priv.Bytes()
	os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed)+" "+base64.StdEncoding.EncodeToString(pub)+"\n"), 0600)
	return priv, base64.StdEncoding.EncodeToString(pub)
}

func deriveKey(priv *ecdh.PrivateKey, peerPubB64 string) []byte {
	pubBytes, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil {
		return nil
	}
	peerPub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil
	}
	shared, err := priv.ECDH(peerPub)
	if err != nil {
		return nil
	}
	h := sha256.Sum256(shared)
	return h[:]
}

func gcmEncrypt(key []byte, plaintext []byte, aad []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return base64.StdEncoding.EncodeToString(append(nonce, ct...))
}

func gcmDecrypt(key []byte, encoded string, aad []byte) (string, bool) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) < 28 {
		return "", false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", false
	}
	pt, err := gcm.Open(nil, data[:12], data[12:], aad)
	if err != nil {
		return "", false
	}
	return string(pt), true
}

func encryptToPeer(text string, peerPubB64 string, selfPubB64 string, priv *ecdh.PrivateKey) string {
	key := deriveKey(priv, peerPubB64)
	if key == nil {
		return ""
	}
	return gcmEncrypt(key, []byte(text), []byte(selfPubB64))
}

func decryptFromPeer(encoded string, senderPubB64 string, priv *ecdh.PrivateKey) (string, bool) {
	key := deriveKey(priv, senderPubB64)
	if key == nil {
		return "", false
	}
	return gcmDecrypt(key, encoded, []byte(senderPubB64))
}

type Client struct {
	conn    net.Conn
	name    string
	priv    *ecdh.PrivateKey
	selfPub string
	known   map[string]string
	pending chan string
}

func (c *Client) insertKeys(text string) {
	body := text
	if i := strings.Index(text, "]"); i >= 0 {
		body = text[i+1:]
	}
	for _, item := range strings.Split(body, ";") {
		item = strings.TrimSpace(item)
		if i := strings.Index(item, ":"); i >= 0 {
			c.known[item[:i]] = item[i+1:]
		}
	}
}

func (c *Client) request(cmd string) string {
	select {
	case <-c.pending:
	default:
	}
	enc := gcmEncrypt(sharedKey[:], []byte(cmd), nil)
	if err := sendFrame(c.conn, typeCommand, []byte(enc)); err != nil {
		return ""
	}
	select {
	case resp := <-c.pending:
		return resp
	case <-time.After(3 * time.Second):
		return ""
	}
}

func splitZero(payload []byte) [][]byte {
	var parts [][]byte
	start := 0
	for i, b := range payload {
		if b == 0 {
			parts = append(parts, payload[start:i])
			start = i + 1
		}
	}
	return append(parts, payload[start:])
}

func (c *Client) handleMessage(payload []byte) {
	parts := splitZero(payload)
	if len(parts) < 3 {
		pprint("[ОШИБКА] Повреждённый кадр сообщения")
		return
	}
	sender := string(parts[0])
	ct := string(parts[2])
	pub, ok := c.known[sender]
	if !ok {
		pprint(fmt.Sprintf("[%s]: (неизвестный публичный ключ)", sender))
		return
	}
	if plain, ok := decryptFromPeer(ct, pub, c.priv); ok {
		pprint(fmt.Sprintf("[%s]: %s", sender, strings.TrimRight(plain, "\r\n")))
	} else {
		pprint(fmt.Sprintf("[%s]: (не удалось расшифровать — подмена/ключ)", sender))
	}
}
// sanitizeFileName reduces an incoming filename to a safe base name.
// It strips directory components and rejects empty / unsafe names.
func sanitizeFileName(raw string) string {
	lastSep := -1
	for i := 0; i < len(raw); i++ {
		if raw[i] == '/' || raw[i] == '\\' {
			lastSep = i
		}
	}
	name := raw
	if lastSep >= 0 {
		name = raw[lastSep+1:]
	}
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		return ""
	}
	// Defense in depth: no path separators may remain.
	if strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return ""
	}
	return name
}

// saveReceivedFile writes raw into downloads/<base>, creating the folder if
// needed. It refuses any target that escapes downloads/. Returns true on ok.
func saveReceivedFile(base string, raw []byte) bool {
	dir := filepath.Join("downloads")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return false
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	absFinal, err := filepath.Abs(filepath.Join(absDir, base))
	if err != nil {
		return false
	}
	if !strings.HasPrefix(absFinal, absDir+string(filepath.Separator)) {
		return false
	}
	if err := os.WriteFile(absFinal, raw, 0600); err != nil {
		return false
	}
	return true
}



func (c *Client) handleFile(payload []byte) {
	parts := splitZero(payload)
	if len(parts) < 4 {
		pprint("[ОШИБКА] Повреждённый кадр файла")
		return
	}
	sender := string(parts[0])
	fname := string(parts[2])
	data := string(parts[3])
	pub, ok := c.known[sender]
	if !ok {
		pprint(fmt.Sprintf("[%s] отправил файл: %s, но ключ неизвестен", sender, fname))
		return
	}
	plain, ok := decryptFromPeer(data, pub, c.priv)
	if !ok {
		pprint(fmt.Sprintf("[%s] отправил файл: %s, но расшифровать не удалось", sender, fname))
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(plain))
	if err != nil {
		pprint(fmt.Sprintf("[%s] отправил файл: %s, но расшифровать не удалось", sender, fname))
		return
	}
	base := sanitizeFileName(fname)
	if base == "" {
		pprint(fmt.Sprintf("[%s] отправил файл: %s, но имя недопустимо", sender, fname))
		return
	}
	if !saveReceivedFile(base, raw) {
		pprint(fmt.Sprintf("[%s] отправил файл: %s, но сохранить не удалось", sender, fname))
		return
	}
	pprint(fmt.Sprintf("[%s] отправил файл: %s (%d байт) — сохранён", sender, fname, len(raw)))
}

func (c *Client) reader() {
	for {
		ftype, payload, err := recvFrame(c.conn)
		if err != nil {
			return
		}
		switch ftype {
		case typeCommand:
			text, ok := gcmDecrypt(sharedKey[:], string(payload), nil)
			if !ok {
				continue
			}
			text = strings.TrimSpace(text)
			if strings.HasPrefix(text, "[RESP]") {
				resp := strings.TrimSpace(strings.TrimPrefix(text, "[RESP]"))
				select {
				case c.pending <- resp:
				default:
				}
				continue
			}
			if strings.HasPrefix(text, "[ПУБКЛЮЧИ]") || strings.HasPrefix(text, "[НОВЫЙ]") {
				c.insertKeys(text)
				continue
			}
			pprint(text)
		case typeMessage:
			c.handleMessage(payload)
		case typeFile:
			c.handleFile(payload)
		}
	}
}

func (c *Client) recipientPub(target string) string {
	if p, ok := c.known[target]; ok {
		return p
	}
	resp := c.request("/pubkey " + target)
	if resp != "" && resp != "ERR" {
		c.known[target] = resp
		return resp
	}
	return ""
}

func (c *Client) sendTo(target string, text string) bool {
	pub := c.recipientPub(target)
	if pub == "" {
		pprint(fmt.Sprintf("[ОШИБКА] Не знаю публичный ключ для %s", target))
		return false
	}
	ct := encryptToPeer(text, pub, c.selfPub, c.priv)
	payload := []byte(c.name + "\x00" + target + "\x00" + ct)
	return sendFrame(c.conn, typeMessage, payload) == nil
}

func (c *Client) roomTargets() [][2]string {
	var out [][2]string
	resp := c.request("/roommembers")
	if resp == "" || resp == "ERR" {
		return out
	}
	for _, item := range strings.Split(resp, ";") {
		item = strings.TrimSpace(item)
		if i := strings.Index(item, ":"); i >= 0 {
			n := item[:i]
			p := item[i+1:]
			c.known[n] = p
			if n != c.name {
				out = append(out, [2]string{n, p})
			}
		}
	}
	return out
}

func (c *Client) sendToRoom(text string) {
	for _, t := range c.roomTargets() {
		ct := encryptToPeer(text, t[1], c.selfPub, c.priv)
		payload := []byte(c.name + "\x00" + t[0] + "\x00" + ct)
		sendFrame(c.conn, typeMessage, payload)
	}
	pprint("[Я]: " + text)
}

func (c *Client) sendFileToRoom(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		pprint("[ОШИБКА] Файл не найден: " + path)
		return
	}
	if len(raw) > maxFileSize {
		pprint("[ОШИБКА] Файл слишком большой (до 400 КБ)")
		return
	}
	fname := path
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		fname = path[i+1:]
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	for _, t := range c.roomTargets() {
		data := encryptToPeer(b64, t[1], c.selfPub, c.priv)
		payload := []byte(c.name + "\x00" + t[0] + "\x00" + fname + "\x00" + data)
		sendFrame(c.conn, typeFile, payload)
	}
	pprint("[Я] файл: " + fname + " отправлен в комнату")
}

func loadHostPort() (string, string) {
	host := "127.0.0.1"
	port := "1301"
	var cfg struct {
		Server struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"server"`
	}
	for _, path := range []string{"config.json", "../config.json"} {
		if data, err := os.ReadFile(path); err == nil {
			if json.Unmarshal(data, &cfg) == nil {
				if cfg.Server.Host != "" {
					host = cfg.Server.Host
				}
				if cfg.Server.Port > 0 {
					port = strconv.Itoa(cfg.Server.Port)
				}
				break
			}
		}
	}
	if h := os.Getenv("MESH_HOST"); h != "" {
		host = h
	}
	if p := os.Getenv("MESH_PORT"); p != "" {
		port = p
	}
	return host, port
}

func main() {
	sharedKey = loadSharedKey()
	host, port := loadHostPort()
	priv, pubB64 := loadOrCreateIdentity()

	conn, err := net.Dial("tcp", host+":"+port)
	if err != nil {
		pprint("[ОШИБКА] Не удалось подключиться: " + err.Error())
		return
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	fmt.Print("Введи своё имя: ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	name := strings.TrimSpace(line)
	if name == "" {
		name = "Аноним"
	}

	sendFrame(conn, typeMessage, []byte(name))
	sendFrame(conn, typeVersion, []byte(strconv.Itoa(protoVersion)))
	c := &Client{
		conn:    conn,
		name:    name,
		priv:    priv,
		selfPub: pubB64,
		known:   map[string]string{},
		pending: make(chan string, 1),
	}
	sendFrame(conn, typeRegister, []byte(name+"\x00"+pubB64))

	go c.reader()

	pprint("Добро пожаловать, " + name + "!")
	pprint("Команды: /join <комната> [пароль], /msg Имя текст, /file <путь>, /users, /rooms, /roommembers, /help, /exit")

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if ms, ok := os.LookupEnv("MESH_AUTOEXIT_MS"); ok {
				if n, aerr := strconv.Atoi(ms); aerr == nil && n > 0 {
					time.Sleep(time.Duration(n) * time.Millisecond)
				}
			}
			break
		}
		msg := strings.TrimSpace(line)
		if msg == "" {
			continue
		}
		if strings.HasPrefix(msg, "/msg ") {
			rest := strings.TrimSpace(strings.TrimPrefix(msg, "/msg "))
			parts := strings.SplitN(rest, " ", 2)
			if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
				pprint("[ОШИБКА] Формат: /msg Имя текст")
				continue
			}
			target := strings.TrimSpace(parts[0])
			text := strings.TrimSpace(parts[1])
			if c.sendTo(target, text) {
				pprint("[Я] -> " + target + ": " + text)
			}
		} else if strings.HasPrefix(msg, "/file ") {
			path := strings.TrimSpace(strings.TrimPrefix(msg, "/file "))
			c.sendFileToRoom(path)
		} else if strings.HasPrefix(msg, "/") {
			enc := gcmEncrypt(sharedKey[:], []byte(msg), nil)
			sendFrame(conn, typeCommand, []byte(enc))
		} else {
			c.sendToRoom(msg)
		}
	}
}


