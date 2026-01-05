package db

import (
	"database/sql"
	"time"
)

type EncryptedDNSLog struct {
	ID          int       `json:"id"`
	DeviceMAC   string    `json:"device_mac"`
	DeviceName  string    `json:"device_name"`
	DeviceIP    string    `json:"device_ip"`
	UserID      *int      `json:"user_id"`
	UserName    string    `json:"user_name"`
	DNSServerIP string    `json:"dns_server_ip"`
	Protocol    string    `json:"protocol"`
	BlockedAt   time.Time `json:"blocked_at"`
}

// LogBlockedEncryptedDNS adds a log entry for blocked encrypted DNS
func LogBlockedEncryptedDNS(mac, deviceName, deviceIP string, userID *int, userName, serverIP, protocol string) error {
	_, err := DB.Exec(`
		INSERT INTO blocked_encrypted_dns_logs 
		(device_mac, device_name, device_ip, user_id, user_name, dns_server_ip, protocol) 
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		mac, deviceName, deviceIP, userID, userName, serverIP, protocol)
	return err
}

// GetBlockedEncryptedDNSLogs returns logs with optional filtering
// GetBlockedEncryptedDNSLogs returns logs with optional filtering
func GetBlockedEncryptedDNSLogs(limit int, date string, userID *int, deviceMAC string) ([]EncryptedDNSLog, error) {
	query := `
		SELECT id, device_mac, device_name, device_ip, user_id, user_name, dns_server_ip, protocol, blocked_at 
		FROM blocked_encrypted_dns_logs 
		WHERE 1=1`

	args := []interface{}{}

	if date != "" {
		query += " AND DATE(blocked_at) = ?"
		args = append(args, date)
	}

	if userID != nil {
		query += " AND user_id = ?"
		args = append(args, *userID)
	}

	if deviceMAC != "" {
		query += " AND device_mac = ?"
		args = append(args, deviceMAC)
	}

	query += " ORDER BY blocked_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []EncryptedDNSLog
	for rows.Next() {
		var l EncryptedDNSLog
		var userID sql.NullInt64
		var userName sql.NullString
		var deviceName sql.NullString
		var deviceIP sql.NullString

		if err := rows.Scan(&l.ID, &l.DeviceMAC, &deviceName, &deviceIP, &userID, &userName, &l.DNSServerIP, &l.Protocol, &l.BlockedAt); err != nil {
			return nil, err
		}

		if userID.Valid {
			id := int(userID.Int64)
			l.UserID = &id
		}
		if userName.Valid {
			l.UserName = userName.String
		}
		if deviceName.Valid {
			l.DeviceName = deviceName.String
		}
		if deviceIP.Valid {
			l.DeviceIP = deviceIP.String
		}

		logs = append(logs, l)
	}
	return logs, nil
}

// ClearEncryptedDNSLogs deletes all encrypted DNS logs
func ClearEncryptedDNSLogs() error {
	_, err := DB.Exec("DELETE FROM blocked_encrypted_dns_logs")
	return err
}
