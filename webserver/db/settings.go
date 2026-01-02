package db

import (
	"database/sql"
)

// GetSystemSetting returns the value of a system setting
func GetSystemSetting(key string) (string, error) {
	var value string
	err := DB.QueryRow("SELECT value FROM system_settings WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

// SetSystemSetting updates or inserts a system setting
func SetSystemSetting(key, value string) error {
	_, err := DB.Exec(`
		INSERT INTO system_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = ?
	`, key, value, value)
	return err
}
