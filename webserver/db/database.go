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

	// Ensure default admin exists
	if err := EnsureDefaultAdmin(); err != nil {
		log.Printf("Failed to ensure default admin: %v", err)
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
		query_type TEXT DEFAULT 'A',
		blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS admins (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS system_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS doh_providers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		ip_address TEXT NOT NULL,
		is_enabled BOOLEAN DEFAULT 1,
		is_system BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(ip_address)
	);

	CREATE TABLE IF NOT EXISTS blocked_encrypted_dns_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		device_mac TEXT NOT NULL,
		device_name TEXT,
		device_ip TEXT,
		user_id INTEGER,
		user_name TEXT,
		dns_server_ip TEXT NOT NULL,
		protocol TEXT NOT NULL,
		blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_user_devices_mac ON user_devices(mac_address);
	CREATE INDEX IF NOT EXISTS idx_user_devices_user_id ON user_devices(user_id);
	CREATE INDEX IF NOT EXISTS idx_blocked_domains_user_id ON user_blocked_domains(user_id);
	CREATE INDEX IF NOT EXISTS idx_blocked_domains_lookup ON user_blocked_domains(user_id, domain);
	CREATE INDEX IF NOT EXISTS idx_unregistered_devices_mac ON unregistered_devices(mac_address);
	CREATE INDEX IF NOT EXISTS idx_blocked_logs_date ON blocked_domain_logs(blocked_at);
	CREATE INDEX IF NOT EXISTS idx_blocked_logs_user ON blocked_domain_logs(user_id);
	CREATE INDEX IF NOT EXISTS idx_blocked_logs_device ON blocked_domain_logs(device_mac);
	CREATE INDEX IF NOT EXISTS idx_encrypted_logs_date ON blocked_encrypted_dns_logs(blocked_at);
	`

	_, err := DB.Exec(schema)
	if err != nil {
		log.Printf("Migration error: %v", err)
		return err
	}

	// Migration: Add query_type column to blocked_domain_logs if it doesn't exist
	// We ignore the error because SQLite doesn't support "IF NOT EXISTS" for ADD COLUMN
	DB.Exec("ALTER TABLE blocked_domain_logs ADD COLUMN query_type TEXT DEFAULT 'A'")

	// Migration: Add is_system column to doh_providers if it doesn't exist
	DB.Exec("ALTER TABLE doh_providers ADD COLUMN is_system BOOLEAN DEFAULT 0")

	// Migration: Add device_ip column to blocked_encrypted_dns_logs if it doesn't exist
	DB.Exec("ALTER TABLE blocked_encrypted_dns_logs ADD COLUMN device_ip TEXT")

	// Migration: Add enable_blocking column to users if it doesn't exist
	DB.Exec("ALTER TABLE users ADD COLUMN enable_blocking BOOLEAN DEFAULT 1")

	// Seed Data - System Settings
	DB.Exec("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('block_dot', 'true')")
	DB.Exec("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('block_doq', 'true')")
	DB.Exec("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('block_doh', 'true')")

	// Seed Data - DoH Providers
	seedDoH := `
	INSERT OR IGNORE INTO doh_providers (name, ip_address, is_system) VALUES 
		('Google', '8.8.8.8', 1), ('Google', '8.8.4.4', 1),
		('Cloudflare', '1.1.1.1', 1), ('Cloudflare', '1.0.0.1', 1), ('Cloudflare', '1.1.1.2', 1), ('Cloudflare', '1.0.0.2', 1), ('Cloudflare', '1.1.1.3', 1), ('Cloudflare', '1.0.0.3', 1),
		('Quad9', '9.9.9.9', 1), ('Quad9', '149.112.112.112', 1), ('Quad9', '9.9.9.10', 1), ('Quad9', '149.112.112.10', 1), ('Quad9', '9.9.9.11', 1), ('Quad9', '149.112.112.11', 1),
		('OpenDNS', '208.67.222.222', 1), ('OpenDNS', '208.67.220.220', 1), ('OpenDNS', '208.67.222.123', 1), ('OpenDNS', '208.67.220.123', 1),
		('AdGuard', '94.140.14.14', 1), ('AdGuard', '94.140.15.15', 1), ('AdGuard', '94.140.14.140', 1), ('AdGuard', '94.140.14.141', 1),
		('NextDNS', '45.90.28.0/24', 1), ('NextDNS', '45.90.30.0/24', 1),
		('Mullvad', '194.242.2.2', 1), ('Mullvad', '194.242.2.3', 1), ('Mullvad', '194.242.2.4', 1),
		('Control D', '76.76.2.0', 1), ('Control D', '76.76.10.0', 1),
		('CleanBrowsing', '185.228.168.9', 1), ('CleanBrowsing', '185.228.169.9', 1), ('CleanBrowsing', '185.228.168.10', 1), ('CleanBrowsing', '185.228.169.11', 1),
		('DNS.SB', '185.222.222.222', 1), ('DNS.SB', '45.11.45.11', 1);
	`
	if _, err := DB.Exec(seedDoH); err != nil {
		log.Printf("Seed DoH error: %v", err)
	}

	// Ensure system providers are marked as system (in case they existed before migration)
	updateSystem := `
	UPDATE doh_providers SET is_system = 1 WHERE ip_address IN (
		'8.8.8.8', '8.8.4.4',
		'1.1.1.1', '1.0.0.1', '1.1.1.2', '1.0.0.2', '1.1.1.3', '1.0.0.3',
		'9.9.9.9', '149.112.112.112', '9.9.9.10', '149.112.112.10', '9.9.9.11', '149.112.112.11',
		'208.67.222.222', '208.67.220.220', '208.67.222.123', '208.67.220.123',
		'94.140.14.14', '94.140.15.15', '94.140.14.140', '94.140.14.141',
		'45.90.28.0/24', '45.90.30.0/24',
		'194.242.2.2', '194.242.2.3', '194.242.2.4',
		'76.76.2.0', '76.76.10.0',
		'185.228.168.9', '185.228.169.9', '185.228.168.10', '185.228.169.11',
		'185.222.222.222', '45.11.45.11'
	);
	`
	if _, err := DB.Exec(updateSystem); err != nil {
		log.Printf("Update system providers error: %v", err)
	}

	log.Println("✓ Database schema and seed data applied")
	return nil
}
