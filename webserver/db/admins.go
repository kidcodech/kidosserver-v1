package db

import (
	"database/sql"
	"log"

	"golang.org/x/crypto/bcrypt"
)

// Admin represents an administrator account
type Admin struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
}

// EnsureDefaultAdmin checks if any admin exists, if not creates default admin:admin
func EnsureDefaultAdmin() error {
	var count int
	err := DB.QueryRow("SELECT COUNT(*) FROM admins").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		log.Println("No admins found, creating default admin account (admin:admin)")
		hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			return err
		}

		_, err = DB.Exec("INSERT INTO admins (username, password_hash) VALUES (?, ?)", "admin", string(hash))
		if err != nil {
			return err
		}
	}
	return nil
}

// VerifyAdminCredentials checks username and password
func VerifyAdminCredentials(username, password string) (bool, error) {
	var hash string
	err := DB.QueryRow("SELECT password_hash FROM admins WHERE username = ?", username).Scan(&hash)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false, nil // Invalid password
	}

	return true, nil
}

// ChangeAdminPassword updates the password for an admin
func ChangeAdminPassword(username, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = DB.Exec("UPDATE admins SET password_hash = ? WHERE username = ?", string(hash), username)
	return err
}
