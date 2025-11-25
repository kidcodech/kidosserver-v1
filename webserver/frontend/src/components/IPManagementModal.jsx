import { useState, useEffect } from 'react'

function IPManagementModal({ user, onClose, onSave }) {
  const [currentUser, setCurrentUser] = useState(user)
  const [newIP, setNewIP] = useState('')
  const [deviceName, setDeviceName] = useState('')
  const [error, setError] = useState('')

  // Fetch fresh user data
  const refreshUserData = async () => {
    try {
      const response = await fetch(`/api/users/${user.id}`)
      const data = await response.json()
      
      // Fetch IPs separately
      const ipsResponse = await fetch(`/api/users/${user.id}/ips`)
      const ips = await ipsResponse.json()
      
      setCurrentUser({ ...data, ips })
    } catch (err) {
      console.error('Error refreshing user data:', err)
    }
  }

  const addIP = async (e) => {
    e.preventDefault()
    setError('')

    // Validate IP address format
    const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
    const match = newIP.match(ipRegex)
    
    if (!match) {
      setError('Invalid IP address format')
      return
    }

    // Check each octet is 0-255
    for (let i = 1; i <= 4; i++) {
      const octet = parseInt(match[i])
      if (octet < 0 || octet > 255) {
        setError('IP address octets must be between 0 and 255')
        return
      }
    }

    try {
      const response = await fetch(`/api/users/${user.id}/ips`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          ip_address: newIP.trim(), 
          device_name: deviceName.trim() 
        })
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(errorText || 'Failed to add IP address')
      }

      setNewIP('')
      setDeviceName('')
      await refreshUserData() // Refresh local data
      onSave() // Notify parent to refresh
    } catch (err) {
      setError(err.message)
    }
  }

  const deleteIP = async (ipId, ipAddress) => {
    if (!confirm(`Remove IP address ${ipAddress}?`)) return

    try {
      await fetch(`/api/users/${user.id}/ips/${ipId}`, { method: 'DELETE' })
      await refreshUserData() // Refresh local data
      onSave() // Notify parent to refresh
    } catch (err) {
      setError('Failed to delete IP address')
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content modal-wide" onClick={e => e.stopPropagation()}>
        <h2>📱 Manage IP Addresses for {currentUser.display_name}</h2>
        
        {error && <div className="error-message">{error}</div>}

        <div className="ip-list">
          <h3>Assigned IP Addresses ({currentUser.ips?.length || 0})</h3>
          {currentUser.ips && currentUser.ips.length > 0 ? (
            currentUser.ips.map(ip => (
              <div key={ip.id} className="ip-item">
                <div className="ip-info">
                  <span className="domain-name">{ip.ip_address}</span>
                  {ip.device_name && <span className="device-label">{ip.device_name}</span>}
                </div>
                <button 
                  onClick={() => deleteIP(ip.id, ip.ip_address)} 
                  className="btn btn-small btn-danger"
                  title="Remove IP"
                >
                  🗑️
                </button>
              </div>
            ))
          ) : (
            <div className="no-data">No IP addresses assigned yet</div>
          )}
        </div>

        <div className="add-ip-section">
          <h3>Add New IP Address</h3>
          <form onSubmit={addIP} className="add-ip-form">
            <div className="form-row">
              <input
                type="text"
                value={newIP}
                onChange={e => setNewIP(e.target.value)}
                placeholder="IP Address (e.g., 192.168.1.7)"
                pattern="^(\d{1,3}\.){3}\d{1,3}$"
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
            <small className="form-hint">Each IP address can only be assigned to one user</small>
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
