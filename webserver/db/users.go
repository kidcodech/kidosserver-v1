package db

import (
	"database/sql"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User represents a family member being monitored
type User struct {
	ID          int       `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserIP represents an IP address assigned to a user
type UserIP struct {
	ID         int       `json:"id"`
	UserID     int       `json:"user_id"`
	IPAddress  string    `json:"ip_address"`
	DeviceName string    `json:"device_name,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// UserWithIPs represents a user with all their assigned IP addresses
type UserWithIPs struct {
	User
	IPs []UserIP `json:"ips"`
}

// GetAllUsers returns all users with their IP addresses
func GetAllUsers() ([]UserWithIPs, error) {
	rows, err := DB.Query("SELECT id, username, display_name, created_at, updated_at FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserWithIPs
	for rows.Next() {
		var u UserWithIPs
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}

		// Get IPs for this user
		u.IPs, err = GetUserIPs(u.ID)
		if err != nil {
			return nil, err
		}

		users = append(users, u)
	}
	return users, nil
}

// CreateUser creates a new user with hashed password
func CreateUser(username, displayName, password string) (*User, error) {
	// Hash password with bcrypt
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	result, err := DB.Exec(
		"INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)",
		username, string(passwordHash), displayName,
	)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()
	return GetUser(int(id))
}

// GetUser retrieves a user by ID
func GetUser(id int) (*User, error) {
	var u User
	err := DB.QueryRow(
		"SELECT id, username, display_name, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(&u.ID, &u.Username, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &u, err
}

// UpdateUser updates user information, optionally updating password if provided
func UpdateUser(id int, username, displayName string, password *string) error {
	if password != nil && *password != "" {
		// Hash new password
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		_, err = DB.Exec(
			"UPDATE users SET username = ?, password_hash = ?, display_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
			username, string(passwordHash), displayName, id,
		)
		return err
	}

	// Update without changing password
	_, err := DB.Exec(
		"UPDATE users SET username = ?, display_name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		username, displayName, id,
	)
	return err
}

// DeleteUser deletes a user (cascades to IPs)
func DeleteUser(id int) error {
	_, err := DB.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

// GetUserIPs returns all IP addresses assigned to a user
func GetUserIPs(userID int) ([]UserIP, error) {
	rows, err := DB.Query(
		"SELECT id, user_id, ip_address, COALESCE(device_name, ''), created_at FROM user_ips WHERE user_id = ? ORDER BY created_at",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []UserIP
	for rows.Next() {
		var ip UserIP
		if err := rows.Scan(&ip.ID, &ip.UserID, &ip.IPAddress, &ip.DeviceName, &ip.CreatedAt); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// AddUserIP adds an IP address to a user
func AddUserIP(userID int, ipAddress, deviceName string) (*UserIP, error) {
	result, err := DB.Exec(
		"INSERT INTO user_ips (user_id, ip_address, device_name) VALUES (?, ?, ?)",
		userID, ipAddress, deviceName,
	)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()

	var ip UserIP
	err = DB.QueryRow(
		"SELECT id, user_id, ip_address, COALESCE(device_name, ''), created_at FROM user_ips WHERE id = ?",
		id,
	).Scan(&ip.ID, &ip.UserID, &ip.IPAddress, &ip.DeviceName, &ip.CreatedAt)

	return &ip, err
}

// DeleteUserIP removes an IP address assignment
func DeleteUserIP(ipID int) error {
	_, err := DB.Exec("DELETE FROM user_ips WHERE id = ?", ipID)
	return err
}

// GetUserByIP returns user information for a given IP address
func GetUserByIP(ipAddress string) (*UserWithIPs, error) {
	var u UserWithIPs
	err := DB.QueryRow(`
		SELECT u.id, u.username, u.display_name, u.created_at, u.updated_at
		FROM users u
		JOIN user_ips ip ON u.id = ip.user_id
		WHERE ip.ip_address = ?
	`, ipAddress).Scan(&u.ID, &u.Username, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	u.IPs, err = GetUserIPs(u.ID)
	return &u, err
}
