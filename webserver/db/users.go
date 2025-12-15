package db

import (
	"database/sql"
	"strings"
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

// UserDevice represents a MAC address assigned to a user
type UserDevice struct {
	ID         int       `json:"id"`
	UserID     int       `json:"user_id"`
	MACAddress string    `json:"mac_address"`
	IPAddress  string    `json:"ip_address,omitempty"`
	DeviceName string    `json:"device_name,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// BlockedDomain represents a domain blocked for a specific user
type BlockedDomain struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Domain    string    `json:"domain"`
	CreatedAt time.Time `json:"created_at"`
}

// UnregisteredDevice represents a device trying to access internet without registration
type UnregisteredDevice struct {
	ID           int       `json:"id"`
	MACAddress   string    `json:"mac_address"`
	IPAddress    string    `json:"ip_address,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	AttemptCount int       `json:"attempt_count"`
}

// UserWithDevices represents a user with all their assigned devices
type UserWithDevices struct {
	User
	Devices []UserDevice `json:"devices"`
}

// GetAllUsers returns all users with their device MAC addresses
func GetAllUsers() ([]UserWithDevices, error) {
	rows, err := DB.Query("SELECT id, username, display_name, created_at, updated_at FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []UserWithDevices
	for rows.Next() {
		var u UserWithDevices
		if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}

		// Get devices for this user
		u.Devices, err = GetUserDevices(u.ID)
		if err != nil {
			return nil, err
		}

		users = append(users, u)
	}
	return users, nil
}

// GetUserWithDevices returns a single user with their device MAC addresses
func GetUserWithDevices(id int) (*UserWithDevices, error) {
	var u UserWithDevices
	err := DB.QueryRow(
		"SELECT id, username, display_name, created_at, updated_at FROM users WHERE id = ?",
		id,
	).Scan(&u.ID, &u.Username, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Get devices for this user
	u.Devices, err = GetUserDevices(u.ID)
	if err != nil {
		return nil, err
	}

	return &u, nil
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

// GetUserDevices returns all MAC addresses assigned to a user
func GetUserDevices(userID int) ([]UserDevice, error) {
	rows, err := DB.Query(
		"SELECT id, user_id, mac_address, COALESCE(ip_address, ''), COALESCE(device_name, ''), created_at FROM user_devices WHERE user_id = ? ORDER BY created_at",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []UserDevice
	for rows.Next() {
		var device UserDevice
		if err := rows.Scan(&device.ID, &device.UserID, &device.MACAddress, &device.IPAddress, &device.DeviceName, &device.CreatedAt); err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	return devices, nil
}

// AddUserDevice adds a MAC address to a user
func AddUserDevice(userID int, macAddress, ipAddress, deviceName string) (*UserDevice, error) {
	result, err := DB.Exec(
		"INSERT INTO user_devices (user_id, mac_address, ip_address, device_name) VALUES (?, ?, ?, ?)",
		userID, macAddress, ipAddress, deviceName,
	)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()

	var device UserDevice
	err = DB.QueryRow(
		"SELECT id, user_id, mac_address, COALESCE(ip_address, ''), COALESCE(device_name, ''), created_at FROM user_devices WHERE id = ?",
		id,
	).Scan(&device.ID, &device.UserID, &device.MACAddress, &device.IPAddress, &device.DeviceName, &device.CreatedAt)
	return &device, err
}

// DeleteUserDevice removes a device assignment
func DeleteUserDevice(deviceID int) error {
	_, err := DB.Exec("DELETE FROM user_devices WHERE id = ?", deviceID)
	return err
}

// GetUserByMAC returns user information for a given MAC address
func GetUserByMAC(macAddress string) (*UserWithDevices, error) {
	var u UserWithDevices
	err := DB.QueryRow(`
		SELECT u.id, u.username, u.display_name, u.created_at, u.updated_at
		FROM users u
		JOIN user_devices dev ON u.id = dev.user_id
		WHERE dev.mac_address = ?
	`, macAddress).Scan(&u.ID, &u.Username, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	u.Devices, err = GetUserDevices(u.ID)
	return &u, err
}

// AuthenticateUser verifies username and password, returns user if valid
func AuthenticateUser(username, password string) (*User, error) {
	var u User
	var passwordHash string

	err := DB.QueryRow(
		"SELECT id, username, password_hash, display_name, created_at, updated_at FROM users WHERE username = ?",
		username,
	).Scan(&u.ID, &u.Username, &passwordHash, &u.DisplayName, &u.CreatedAt, &u.UpdatedAt)

	if err == sql.ErrNoRows {
		return nil, err // User not found
	}
	if err != nil {
		return nil, err
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return nil, err // Invalid password
	}

	return &u, nil
}

// GetUserBlockedDomains returns all blocked domains for a user
func GetUserBlockedDomains(userID int) ([]BlockedDomain, error) {
	rows, err := DB.Query(
		"SELECT id, user_id, domain, created_at FROM user_blocked_domains WHERE user_id = ? ORDER BY domain",
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []BlockedDomain
	for rows.Next() {
		var d BlockedDomain
		if err := rows.Scan(&d.ID, &d.UserID, &d.Domain, &d.CreatedAt); err != nil {
			return nil, err
		}
		domains = append(domains, d)
	}
	return domains, nil
}

// AddBlockedDomain blocks a domain for a specific user
func AddBlockedDomain(userID int, domain string) (*BlockedDomain, error) {
	// Normalize domain: lowercase and remove trailing dot
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	result, err := DB.Exec(
		"INSERT INTO user_blocked_domains (user_id, domain) VALUES (?, ?)",
		userID, domain,
	)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()

	var d BlockedDomain
	err = DB.QueryRow(
		"SELECT id, user_id, domain, created_at FROM user_blocked_domains WHERE id = ?",
		id,
	).Scan(&d.ID, &d.UserID, &d.Domain, &d.CreatedAt)

	return &d, err
}

// RemoveBlockedDomain removes a blocked domain for a user
func RemoveBlockedDomain(domainID int) error {
	_, err := DB.Exec("DELETE FROM user_blocked_domains WHERE id = ?", domainID)
	return err
}

// IsBlockedForUser checks if a domain is blocked for a specific user
func IsBlockedForUser(userID int, domain string) (bool, error) {
	var count int
	err := DB.QueryRow(
		"SELECT COUNT(*) FROM user_blocked_domains WHERE user_id = ? AND domain = ?",
		userID, domain,
	).Scan(&count)

	return count > 0, err
}

// GetAllBlockedDomainsMap returns a map of userID -> map[domain]bool for fast lookup
func GetAllBlockedDomainsMap() (map[int]map[string]bool, error) {
	rows, err := DB.Query("SELECT user_id, domain FROM user_blocked_domains")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	blockedMap := make(map[int]map[string]bool)
	for rows.Next() {
		var userID int
		var domain string
		if err := rows.Scan(&userID, &domain); err != nil {
			return nil, err
		}

		if blockedMap[userID] == nil {
			blockedMap[userID] = make(map[string]bool)
		}
		// Normalize domain from DB
		normalized := strings.TrimSuffix(strings.ToLower(domain), ".")
		blockedMap[userID][normalized] = true
	}

	return blockedMap, nil
}

// RecordUnregisteredDevice records or updates an unregistered device attempt
func RecordUnregisteredDevice(macAddress, ipAddress string) error {
	// Try to insert, or update if exists
	_, err := DB.Exec(`
		INSERT INTO unregistered_devices (mac_address, ip_address, first_seen, last_seen, attempt_count)
		VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)
		ON CONFLICT(mac_address) DO UPDATE SET
			ip_address = ?,
			last_seen = CURRENT_TIMESTAMP,
			attempt_count = attempt_count + 1
	`, macAddress, ipAddress, ipAddress)
	return err
}

// GetUnregisteredDevices returns all unregistered devices
func GetUnregisteredDevices() ([]UnregisteredDevice, error) {
	rows, err := DB.Query(`
		SELECT id, mac_address, COALESCE(ip_address, ''), first_seen, last_seen, attempt_count
		FROM unregistered_devices
		WHERE mac_address NOT IN (SELECT mac_address FROM user_devices)
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []UnregisteredDevice
	for rows.Next() {
		var d UnregisteredDevice
		if err := rows.Scan(&d.ID, &d.MACAddress, &d.IPAddress, &d.FirstSeen, &d.LastSeen, &d.AttemptCount); err != nil {
			return nil, err
		}
		devices = append(devices, d)
	}
	return devices, nil
}

// ClearUnregisteredDevice removes a device from unregistered list (called when registered)
func ClearUnregisteredDevice(macAddress string) error {
	_, err := DB.Exec("DELETE FROM unregistered_devices WHERE mac_address = ?", macAddress)
	return err
}

// DeleteAllUnregisteredDevices removes all devices from unregistered list
func DeleteAllUnregisteredDevices() error {
	_, err := DB.Exec("DELETE FROM unregistered_devices")
	return err
}

// BlockedDomainLog represents a blocked domain attempt
type BlockedDomainLog struct {
	ID         int       `json:"id"`
	Domain     string    `json:"domain"`
	UserID     int       `json:"user_id"`
	UserName   string    `json:"user_name"`
	DeviceMAC  string    `json:"device_mac"`
	DeviceName string    `json:"device_name,omitempty"`
	IPAddress  string    `json:"ip_address,omitempty"`
	QueryType  string    `json:"query_type"`
	BlockedAt  time.Time `json:"blocked_at"`
}

// LogBlockedDomain logs a blocked domain attempt
func LogBlockedDomain(domain string, userID int, userName, deviceMAC, deviceName, ipAddress, queryType string) error {
	_, err := DB.Exec(`
		INSERT INTO blocked_domain_logs (domain, user_id, user_name, device_mac, device_name, ip_address, query_type)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, domain, userID, userName, deviceMAC, deviceName, ipAddress, queryType)
	return err
}

// GetBlockedDomainLogs retrieves blocked domain logs with optional filters
func GetBlockedDomainLogs(date string, userID int, deviceMAC string) ([]BlockedDomainLog, error) {
	query := `
		SELECT id, domain, user_id, user_name, device_mac, 
		       COALESCE(device_name, ''), COALESCE(ip_address, ''), COALESCE(query_type, 'A'), blocked_at
		FROM blocked_domain_logs
		WHERE 1=1
	`
	args := []interface{}{}

	if date != "" {
		// Use localtime to match the user's perspective (since UI converts UTC to local)
		query += " AND DATE(blocked_at, 'localtime') = ?"
		args = append(args, date)
	}

	if userID > 0 {
		query += " AND user_id = ?"
		args = append(args, userID)
	}

	if deviceMAC != "" {
		query += " AND device_mac = ?"
		args = append(args, deviceMAC)
	}

	query += " ORDER BY blocked_at DESC LIMIT 1000"

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []BlockedDomainLog
	for rows.Next() {
		var log BlockedDomainLog
		if err := rows.Scan(&log.ID, &log.Domain, &log.UserID, &log.UserName,
			&log.DeviceMAC, &log.DeviceName, &log.IPAddress, &log.QueryType, &log.BlockedAt); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

// ClearBlockedDomainLogs deletes all blocked domain logs
func ClearBlockedDomainLogs() error {
	_, err := DB.Exec("DELETE FROM blocked_domain_logs")
	return err
}
