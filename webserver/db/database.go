package db

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

// InitDB initializes the SQLite database connection and creates tables
func InitDB() error {
	// Ensure directory exists
	if err := os.MkdirAll("/var/lib/kidos", 0755); err != nil {
		return err
	}

	var err error
	DB, err = sql.Open("sqlite3", "/var/lib/kidos/users.db")
	if err != nil {
		return err
	}

	// Enable foreign key enforcement
	if _, err := DB.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		return err
	}

	// Test connection
	if err := DB.Ping(); err != nil {
		return err
	}

	// Create tables if not exist
	if err := runMigrations(); err != nil {
		return err
	}

	log.Println("✓ Database initialized successfully (foreign keys ON)")
	return nil
}

// runMigrations creates the database schema
func runMigrations() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		display_name TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS user_devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		mac_address TEXT NOT NULL,
		ip_address TEXT,
		device_name TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(mac_address)
	);

	CREATE TABLE IF NOT EXISTS user_blocked_domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		domain TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(user_id, domain)
	);

	CREATE TABLE IF NOT EXISTS unregistered_devices (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		mac_address TEXT UNIQUE NOT NULL,
		ip_address TEXT,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		attempt_count INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS blocked_domain_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		user_name TEXT NOT NULL,
		device_mac TEXT NOT NULL,
		device_name TEXT,
		ip_address TEXT,
		blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_user_devices_mac ON user_devices(mac_address);
	CREATE INDEX IF NOT EXISTS idx_user_devices_user_id ON user_devices(user_id);
	CREATE INDEX IF NOT EXISTS idx_blocked_domains_user_id ON user_blocked_domains(user_id);
	CREATE INDEX IF NOT EXISTS idx_blocked_domains_lookup ON user_blocked_domains(user_id, domain);
	CREATE INDEX IF NOT EXISTS idx_unregistered_devices_mac ON unregistered_devices(mac_address);
	CREATE INDEX IF NOT EXISTS idx_blocked_logs_date ON blocked_domain_logs(blocked_at);
	CREATE INDEX IF NOT EXISTS idx_blocked_logs_user ON blocked_domain_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_blocked_logs_device ON blocked_domain_logs(device_mac);
	`

	_, err := DB.Exec(schema)
	if err != nil {
		log.Printf("Migration error: %v", err)
		return err
	}

	log.Println("✓ Database schema ready")
	return nil
}
