package main

import (
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMain уводит рабочую директорию тестов во временную, чтобы initDB
// не трогал настоящий data/mesh.db, и поднимает БД + ключ шифрования.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "meshv2-test-*")
	if err != nil {
		fmt.Println("tmpdir:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	oldWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		fmt.Println("chdir:", err)
		os.Exit(1)
	}

	initDB()
	migrateAccountsToDB()
	encryptKey = make([]byte, keySize)
	if _, err := rand.Read(encryptKey); err != nil {
		fmt.Println("key:", err)
		os.Exit(1)
	}

	testLn, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Println("listen:", err)
		os.Exit(1)
	}
	go func() {
		for {
			c, err := testLn.Accept()
			if err != nil {
				return
			}
			go handleClient(c, c.RemoteAddr().String())
		}
	}()

	code := m.Run()

	os.Chdir(oldWd)
	os.Exit(code)
}

var testLn net.Listener

// cleanupTestAccount удаляет аккаунт из глобального состояния между тестами.
func cleanupTestAccount(t *testing.T, username string) {
	t.Cleanup(func() {
		clientsMutex.Lock()
		delete(accounts, username)
		kept := clients[:0]
		for _, c := range clients {
			if c.username != username {
				kept = append(kept, c)
			}
		}
		clients = kept
		clientsMutex.Unlock()
		dbDeleteAccount(username)
	})
}

// dialClientRaw подключается и шлёт только M-кадр с именем (без V-кадра).
func dialClientRaw(t *testing.T, username string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", testLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := sendFrame(conn, typeMessage, []byte(username)); err != nil {
		t.Fatalf("username frame: %v", err)
	}
	return conn
}

// dialClient подключается к тестовому серверу и прогоняет v2-handshake:
// первый кадр M с @username, затем V с версией протокола.
func dialClient(t *testing.T, username string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", testLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if err := sendFrame(conn, typeMessage, []byte(username)); err != nil {
		t.Fatalf("username frame: %v", err)
	}
	if err := sendFrame(conn, typeVersion, []byte(strconv.Itoa(protoVersion))); err != nil {
		t.Fatalf("version frame: %v", err)
	}
	return conn
}

// readCommand читает один командный кадр и расшифровывает его.
func readCommand(t *testing.T, conn net.Conn) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	frameType, payload, err := recvFrame(conn)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if frameType != typeCommand {
		t.Fatalf("ожидался командный кадр, получен %q: %s", frameType, payload[:min(len(payload), 80)])
	}
	text, err := decryptMessage(string(payload))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return text
}

const testPassword = "correct-horse-battery"

// readUntil читает кадры (пропуская служебные подсказки сервера), пока match
// не сработает. Возвращает текст сработавшего командного кадра.
func readUntil(t *testing.T, conn net.Conn, match func(ftype byte, text string) bool) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		ftype, payload, err := recvFrame(conn)
		if err != nil {
			t.Fatalf("read frame: %v (последний матч не найден)", err)
		}
		var text string
		if ftype == typeCommand {
			text, err = decryptMessage(string(payload))
			if err != nil {
				text = string(payload)
			}
		}
		if match(ftype, text) {
			return text
		}
		if time.Now().After(deadline) {
			t.Fatalf("readUntil: условие не выполнено за 5с")
		}
	}
}

// authClient регистрирует (или входит под) аккаунт и возвращает соединение.
func authClient(t *testing.T, username string) net.Conn {
	t.Helper()
	conn := dialClient(t, username)

	cmd := fmt.Sprintf("/register %s %s", testPassword, testPassword)
	if _, ok := accounts[username]; ok {
		cmd = fmt.Sprintf("/login %s %s", username, testPassword)
	}
	if err := sendFrame(conn, typeCommand, []byte(encryptMessage(cmd))); err != nil {
		t.Fatalf("send %q: %v", cmd, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp := readCommand(t, conn)
		if strings.Contains(resp, "[AUTH]OK") {
			return conn
		}
		if strings.Contains(resp, "уже зарегистрирован") {
			// аккаунт остался от предыдущего прогона — входим
			if err := sendFrame(conn, typeCommand, []byte(encryptMessage(fmt.Sprintf("/login %s %s", username, testPassword)))); err != nil {
				t.Fatalf("send login: %v", err)
			}
			continue
		}
		if strings.Contains(resp, "[ОШИБКА]") {
			t.Fatalf("авторизация не удалась: %s", resp)
		}
		if time.Now().After(deadline) {
			t.Fatalf("таймаут авторизации, последний ответ: %s", resp)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Юнит-тесты ──────────────────────────────────────────────

func TestValidAtUsername(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"@abc", true},
		{"@user_1", true},
		{"@" + strings.Repeat("a", 19), true},
		{"ab", false},          // слишком короткий даже с @
		{"@ab", false},         // меньше 3 символов после @
		{"user", false},        // нет @
		{"@Test", false},       // заглавные
		{"@user name", false},  // пробел
		{"@user;name", false},  // инъекция-разделитель
		{"@" + strings.Repeat("a", 20), false}, // слишком длинный
	}
	for _, c := range cases {
		if got := validAtUsername(c.name); got != c.ok {
			t.Errorf("validAtUsername(%q) = %v, ожидалось %v", c.name, got, c.ok)
		}
	}
}

func TestArgon2Roundtrip(t *testing.T) {
	acc := newArgon2Account(testPassword)
	if !verifyArgon2(acc, testPassword) {
		t.Error("верный пароль не прошёл проверку")
	}
	if verifyArgon2(acc, "wrong-password") {
		t.Error("неверный пароль прошёл проверку")
	}
	if acc.Salt == acc.Hash {
		t.Error("salt не должен совпадать с hash")
	}
	// Каждый вызов даёт новую соль
	acc2 := newArgon2Account(testPassword)
	if acc.Salt == acc2.Salt {
		t.Error("соли двух регистраций совпали")
	}
}

// ── Интеграционные тесты (handleClient через net.Pipe) ─────

// Регрессия на баг e1475ec: /login @username пароль брал пароль
// из поля username и всегда отвечал «Неверные учётные данные».
func TestLoginAfterRegisterRegression(t *testing.T) {
	const user = "@testlogin"
	cleanupTestAccount(t, user)

	// 1. Регистрация
	conn := dialClient(t, user)
	defer conn.Close()
	reg := fmt.Sprintf("/register %s %s", testPassword, testPassword)
	if err := sendFrame(conn, typeCommand, []byte(encryptMessage(reg))); err != nil {
		t.Fatalf("register send: %v", err)
	}
	resp := readUntil(t, conn, func(ft byte, txt string) bool {
		return strings.Contains(txt, "[AUTH]OK") || strings.Contains(txt, "[ОШИБКА]")
	})
	if !strings.Contains(resp, "[AUTH]OK") {
		t.Fatalf("регистрация не прошла: %s", resp)
	}
	conn.Close()
	time.Sleep(100 * time.Millisecond)

	// 2. Вход в документированном формате "/login @username пароль"
	conn2 := dialClient(t, user)
	defer conn2.Close()
	login := fmt.Sprintf("/login %s %s", user, testPassword)
	if err := sendFrame(conn2, typeCommand, []byte(encryptMessage(login))); err != nil {
		t.Fatalf("login send: %v", err)
	}
	respLogin := readUntil(t, conn2, func(ft byte, txt string) bool {
		return strings.Contains(txt, "[AUTH]OK") || strings.Contains(txt, "[ОШИБКА]")
	})
	if !strings.Contains(respLogin, "[AUTH]OK") {
		t.Fatalf("регрессия логина: %s", respLogin)
	}
	conn2.Close() // освобождаем @username до следующего подключения
	time.Sleep(100 * time.Millisecond)

	// 3. Неверный пароль должен отклоняться
	conn3 := dialClient(t, user)
	defer conn3.Close()
	bad := fmt.Sprintf("/login %s wrong-password", user)
	if err := sendFrame(conn3, typeCommand, []byte(encryptMessage(bad))); err != nil {
		t.Fatalf("bad login send: %v", err)
	}
	respBad := readUntil(t, conn3, func(ft byte, txt string) bool {
		return strings.Contains(txt, "Неверные учётные данные") || strings.Contains(txt, "Имя уже занято")
	})
	if !strings.Contains(respBad, "Неверные учётные данные") {
		t.Fatalf("неверный пароль неожиданно принят: %s", respBad)
	}
}

// Личное сообщение доставляется адресату и не прилетает третьим.
func TestPrivateMessageRelay(t *testing.T) {
	const userA = "@testpriv_a"
	const userB = "@testpriv_b"
	cleanupTestAccount(t, userA)
	cleanupTestAccount(t, userB)

	a := authClient(t, userA)
	defer a.Close()
	time.Sleep(100 * time.Millisecond)
	b := authClient(t, userB)
	defer b.Close()
	time.Sleep(100 * time.Millisecond)

	// b отправляет личное a: payload = sender\0target\0ciphertext
	payload := []byte(userB + "\x00" + userA + "\x00ciphertext-from-b")
	if err := sendFrame(b, typeMessage, payload); err != nil {
		t.Fatalf("send private: %v", err)
	}

	a.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ftype byte
	var got []byte
	for {
		var err error
		ftype, got, err = recvFrame(a)
		if err != nil {
			t.Fatalf("a не получил сообщение: %v", err)
		}
		if ftype == typeMessage {
			break
		}
	}
	if string(got) != string(payload) {
		t.Fatalf("полезная нагрузка искажена:\n получено: %q\n ожидалось: %q", got, payload)
	}
}

// Слепой режим: сообщение уходит в комнату, но НЕ пишется в SQLite.
// Регрессия на коммит 70c3304 — если кто-то вернёт dbSaveMessage,
// тест это поймает.
func TestBlindModeNoHistoryStored(t *testing.T) {
	const userA = "@testblind_a"
	const userB = "@testblind_b"
	cleanupTestAccount(t, userA)
	cleanupTestAccount(t, userB)

	a := authClient(t, userA)
	defer a.Close()
	time.Sleep(100 * time.Millisecond)
	b := authClient(t, userB)
	defer b.Close()
	time.Sleep(100 * time.Millisecond)

	// Публичное сообщение в комнату (без target) и личное
	pub := []byte(userB + "\x00ciphertext-public")
	if err := sendFrame(b, typeMessage, pub); err != nil {
		t.Fatalf("send public: %v", err)
	}
	priv := []byte(userB + "\x00" + userA + "\x00ciphertext-private")
	if err := sendFrame(b, typeMessage, priv); err != nil {
		t.Fatalf("send private: %v", err)
	}

	// a должен получить только публичное (приватное адресовано a? нет — a
	// получает и приватное, но для теста достаточно факта доставки)
	a.SetReadDeadline(time.Now().Add(5 * time.Second))
	gotPublic := false
	for i := 0; i < 10; i++ {
		ftype, _, err := recvFrame(a)
		if err != nil {
			break
		}
		if ftype == typeMessage {
			gotPublic = true
			break
		}
	}
	if !gotPublic {
		t.Fatal("публичное сообщение не доставлено — релей сломан")
	}
	time.Sleep(300 * time.Millisecond) // дать серверу «успеть» записать, если бы умел

	var count int
	dbMu.Lock()
	err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&count)
	dbMu.Unlock()
	if err != nil {
		t.Fatalf("query messages: %v", err)
	}
	if count != 0 {
		t.Fatalf("слепой режим нарушен: в базе %d сообщений, ожидалось 0", count)
	}
}

// Клиент со старой версией протокола должен получить ошибку версии.
func TestVersionMismatchRejected(t *testing.T) {
	const user = "@testver"
	cleanupTestAccount(t, user)

	clientSide := dialClientRaw(t, user)
	defer clientSide.Close()

	_ = clientSide
	sendFrame(clientSide, typeVersion, []byte("1")) // старая версия

	resp := readUntil(t, clientSide, func(ft byte, txt string) bool {
		return strings.Contains(txt, "версия")
	})
	_ = resp

	// После ошибки сервер закрывает соединение
	if _, _, err := recvFrame(clientSide); err == nil {
		t.Error("соединение не было закрыто после несовпадения версии")
	}
}
