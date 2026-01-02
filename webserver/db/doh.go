package db

import "fmt"

type DoHProvider struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
	IsEnabled bool   `json:"is_enabled"`
	IsSystem  bool   `json:"is_system"`
}

// GetDoHProviders returns all DoH providers
func GetDoHProviders() ([]DoHProvider, error) {
	rows, err := DB.Query("SELECT id, name, ip_address, is_enabled, is_system FROM doh_providers ORDER BY name, ip_address")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []DoHProvider
	for rows.Next() {
		var p DoHProvider
		if err := rows.Scan(&p.ID, &p.Name, &p.IPAddress, &p.IsEnabled, &p.IsSystem); err != nil {
			return nil, err
		}
		providers = append(providers, p)
	}
	return providers, nil
}

// AddDoHProvider adds a new DoH provider
func AddDoHProvider(name, ip string) error {
	_, err := DB.Exec("INSERT INTO doh_providers (name, ip_address) VALUES (?, ?)", name, ip)
	return err
}

// DeleteDoHProvider deletes a DoH provider
func DeleteDoHProvider(id int) error {
	res, err := DB.Exec("DELETE FROM doh_providers WHERE id = ? AND is_system = 0", id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("cannot delete system provider or provider not found")
	}
	return nil
}

// ToggleDoHProvider toggles the enabled state of a DoH provider
func ToggleDoHProvider(id int, enabled bool) error {
	_, err := DB.Exec("UPDATE doh_providers SET is_enabled = ? WHERE id = ?", enabled, id)
	return err
}
