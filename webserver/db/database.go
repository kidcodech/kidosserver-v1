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

	CREATE TABLE IF NOT EXISTS user_ips (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		ip_address TEXT NOT NULL,
		device_name TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(ip_address)
	);

	CREATE INDEX IF NOT EXISTS idx_user_ips_ip ON user_ips(ip_address);
	CREATE INDEX IF NOT EXISTS idx_user_ips_user_id ON user_ips(user_id);
	`

	_, err := DB.Exec(schema)
	if err != nil {
		log.Printf("Migration error: %v", err)
		return err
	}

	log.Println("✓ Database schema ready")
	return nil
}
