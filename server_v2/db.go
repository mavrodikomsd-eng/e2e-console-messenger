package main

import (
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

var (
	db   *sql.DB
	dbMu sync.Mutex
)

const dbFile = "data/mesh.db"

func initDB() {
	os.MkdirAll("data", 0755)
	var err error
	db, err = sql.Open("sqlite", dbFile+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		fmt.Printf("[БД] Ошибка открытия: %v\n", err)
		os.Exit(1)
	}

	db.Exec(`CREATE TABLE IF NOT EXISTS accounts (
		username TEXT PRIMARY KEY,
		salt TEXT, hash TEXT, alg TEXT,
		memory INTEGER, time_val INTEGER, threads INTEGER,
		nick TEXT, bio TEXT, hide_status INTEGER DEFAULT 0,
		banned INTEGER DEFAULT 0,
		created_at TEXT DEFAULT (datetime('now'))
	)`)

	db.Exec(`CREATE TABLE IF NOT EXISTS messages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sender TEXT NOT NULL,
		room TEXT NOT NULL DEFAULT 'main',
		encrypted TEXT NOT NULL,
		msg_type TEXT DEFAULT 'text',
		created_at TEXT DEFAULT (datetime('now'))
	)`)

	db.Exec(`CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room, id DESC)`)
	fmt.Println("[БД] SQLite инициализирован:", dbFile)
}

func migrateAccountsToDB() {
	dbMu.Lock()
	defer dbMu.Unlock()
	for username, acc := range accounts {
		hide := 0
		if acc.HideStatus {
			hide = 1
		}
		db.Exec(`INSERT OR IGNORE INTO accounts
			(username, salt, hash, alg, memory, time_val, threads, nick, bio, hide_status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			username, acc.Salt, acc.Hash, acc.Alg,
			acc.Memory, acc.Time, acc.Threads,
			acc.Nick, acc.Bio, hide)
	}
	var count int
	db.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&count)
	if count > 0 {
		fmt.Printf("[БД] Миграция: %d аккаунтов в SQLite\n", count)
	}
}

func dbSaveAccount(username string, acc Account) {
	dbMu.Lock()
	defer dbMu.Unlock()
	hide := 0
	if acc.HideStatus {
		hide = 1
	}
	db.Exec(`INSERT OR REPLACE INTO accounts
		(username, salt, hash, alg, memory, time_val, threads, nick, bio, hide_status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		username, acc.Salt, acc.Hash, acc.Alg,
		acc.Memory, acc.Time, acc.Threads,
		acc.Nick, acc.Bio, hide)
}

func dbDeleteAccount(username string) {
	dbMu.Lock()
	defer dbMu.Unlock()
	db.Exec(`DELETE FROM accounts WHERE username = ?`, username)
}

func dbSaveMessage(sender, room, encrypted, msgType string) {
	dbMu.Lock()
	defer dbMu.Unlock()
	db.Exec(`INSERT INTO messages (sender, room, encrypted, msg_type) VALUES (?, ?, ?, ?)`,
		sender, room, encrypted, msgType)
}

func dbLoadHistory(room string, limit int) []map[string]string {
	dbMu.Lock()
	defer dbMu.Unlock()
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := db.Query(`SELECT sender, encrypted, msg_type, created_at
		FROM messages WHERE room = ? ORDER BY id DESC LIMIT ?`, room, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var result []map[string]string
	for rows.Next() {
		var sender, enc, msgType, ts string
		rows.Scan(&sender, &enc, &msgType, &ts)
		result = append(result, map[string]string{
			"sender": sender, "encrypted": enc, "type": msgType, "time": ts,
		})
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return result
}

func dbGetStats() map[string]interface{} {
	dbMu.Lock()
	defer dbMu.Unlock()
	stats := map[string]interface{}{}

	var total int
	db.QueryRow(`SELECT COUNT(*) FROM accounts`).Scan(&total)
	stats["total_accounts"] = total

	var msgCount int
	db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&msgCount)
	stats["total_messages"] = msgCount

	var rooms int
	db.QueryRow(`SELECT COUNT(DISTINCT room) FROM messages`).Scan(&rooms)
	stats["total_rooms"] = rooms

	stats["db_size"] = func() string {
		if info, err := os.Stat(dbFile); err == nil {
			size := info.Size()
			if size > 1024*1024 {
				return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
			}
			return fmt.Sprintf("%.1f KB", float64(size)/1024)
		}
		return "N/A"
	}()

	stats["uptime"] = time.Since(startTime).Round(time.Second).String()
	return stats
}
