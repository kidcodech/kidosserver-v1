import { useState, useEffect } from 'react'

function IPManagementModal({ user, onClose, onSave }) {
  const [currentUser, setCurrentUser] = useState(user)
  const [newMAC, setNewMAC] = useState('')
  const [deviceName, setDeviceName] = useState('')
  const [error, setError] = useState('')

  // Fetch fresh user data
  const refreshUserData = async () => {
    try {
      const response = await fetch(`/api/users/${user.id}`)
      const data = await response.json()
      
      // Fetch devices separately
      const devicesResponse = await fetch(`/api/users/${user.id}/devices`)
      const devices = await devicesResponse.json()
      
      setCurrentUser({ ...data, devices })
    } catch (err) {
      console.error('Error refreshing user data:', err)
    }
  }

  const addDevice = async (e) => {
    e.preventDefault()
    setError('')

    // Validate MAC address format
    const macRegex = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/
    
    if (!macRegex.test(newMAC)) {
      setError('Invalid MAC address format. Use XX:XX:XX:XX:XX:XX')
      return
    }

    try {
      const response = await fetch(`/api/users/${user.id}/devices`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          mac_address: newMAC.trim().toLowerCase(), 
          device_name: deviceName.trim() 
        })
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(errorText || 'Failed to add MAC address')
      }

      setNewMAC('')
      setDeviceName('')
      await refreshUserData() // Refresh local data
      onSave() // Notify parent to refresh
    } catch (err) {
      setError(err.message)
    }
  }

  const deleteDevice = async (deviceId, macAddress) => {
    if (!confirm(`Remove MAC address ${macAddress}?`)) return

    try {
      await fetch(`/api/users/${user.id}/devices/${deviceId}`, { method: 'DELETE' })
      await refreshUserData() // Refresh local data
      onSave() // Notify parent to refresh
    } catch (err) {
      setError('Failed to delete MAC address')
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content modal-wide" onClick={e => e.stopPropagation()}>
        <h2>📱 Manage MAC Addresses for {currentUser.display_name}</h2>
        
        {error && <div className="error-message">{error}</div>}

        <div className="ip-list">
          <h3>Assigned MAC Addresses ({currentUser.devices?.length || 0})</h3>
          {currentUser.devices && currentUser.devices.length > 0 ? (
            currentUser.devices.map(device => (
              <div key={device.id} className="ip-item">
                <div className="ip-info">
                  <span className="domain-name">{device.mac_address}</span>
                  {device.ip_address && <span className="device-label" style={{color: '#888'}}>IP: {device.ip_address}</span>}
                  {device.device_name && <span className="device-label">{device.device_name}</span>}
                </div>
                <button 
                  onClick={() => deleteDevice(device.id, device.mac_address)} 
                  className="btn btn-small btn-danger"
                  title="Remove MAC"
                >
                  🗑️
                </button>
              </div>
            ))
          ) : (
            <div className="no-data">No MAC addresses assigned yet</div>
          )}
        </div>

        <div className="add-ip-section">
          <h3>Add New MAC Address</h3>
          <form onSubmit={addDevice} className="add-ip-form">
            <div className="form-row">
              <input
                type="text"
                value={newMAC}
                onChange={e => setNewMAC(e.target.value)}
                placeholder="MAC Address (e.g., aa:bb:cc:dd:ee:ff)"
                pattern="^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"
                required
                className="domain-input"
              />
              <input
                type="text"
                value={deviceName}
                onChange={e => setDeviceName(e.target.value)}
                placeholder="Device Name (optional)"
                maxLength={50}
                className="domain-input"
              />
              <button type="submit" className="btn btn-success">
                ➕ Add
              </button>
            </div>
            <small className="form-hint">Each MAC address can only be assigned to one user</small>
          </form>
        </div>

        <div className="form-actions">
          <button onClick={onClose} className="btn btn-primary">
            ✅ Done
          </button>
        </div>
      </div>
    </div>
  )
}

export default IPManagementModal
