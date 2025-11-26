import { useState, useEffect } from 'react'
import UserFormModal from './UserFormModal'
import IPManagementModal from './IPManagementModal'

function UserManagement() {
  const [users, setUsers] = useState([])
  const [showAddUser, setShowAddUser] = useState(false)
  const [editingUser, setEditingUser] = useState(null)
  const [showIPModal, setShowIPModal] = useState(null)

  useEffect(() => {
    fetchUsers()
  }, [])

  const fetchUsers = async () => {
    try {
      const res = await fetch('/api/users')
      const data = await res.json()
      setUsers(data || [])
    } catch (error) {
      console.error('Error fetching users:', error)
    }
  }

  const deleteUser = async (id, username) => {
    if (!confirm(`Delete user "${username}"? This will also remove all associated MAC addresses.`)) return
    
    try {
      await fetch(`/api/users/${id}`, { method: 'DELETE' })
      fetchUsers()
    } catch (error) {
      console.error('Error deleting user:', error)
    }
  }

  return (
    <div>
      <div className="controls">
        <button onClick={() => setShowAddUser(true)} className="btn btn-success">
          ➕ Add User
        </button>
        <button onClick={fetchUsers} className="btn btn-primary">
          🔄 Refresh
        </button>
      </div>

      <div className="stats-summary">
        <div className="stat-card">
          <h3>Total Users</h3>
          <p className="stat-value">{users.length}</p>
        </div>
        <div className="stat-card">
          <h3>Total Devices</h3>
          <p className="stat-value">
            {users.reduce((sum, u) => sum + (u.devices?.length || 0), 0)}
          </p>
        </div>
      </div>

      <div className="packet-table-container">
        <table className="packet-table user-table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Display Name</th>
              <th>Devices</th>
              <th>MAC Addresses</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.length === 0 ? (
              <tr>
                <td colSpan="5" className="no-data">No users configured yet</td>
              </tr>
            ) : (
              users.map(user => (
                <tr key={user.id}>
                  <td className="domain-name">{user.username}</td>
                  <td>{user.display_name}</td>
                  <td>{user.devices?.length || 0}</td>
                  <td>
                    <div className="ip-badges">
                      {user.devices?.length > 0 ? (
                        user.devices.map(device => (
                          <div key={device.id} className="user-ip-badge">
                            {device.mac_address}
                            {device.ip_address && <span className="device-name" style={{color: '#888'}}> ({device.ip_address})</span>}
                            {device.device_name && <span className="device-name"> - {device.device_name}</span>}
                          </div>
                        ))
                      ) : (
                        <span className="no-ips">No MACs assigned</span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="action-buttons">
                      <button 
                        onClick={() => setEditingUser(user)} 
                        className="btn btn-small btn-primary"
                        title="Edit user"
                      >
                        ✏️
                      </button>
                      <button 
                        onClick={() => setShowIPModal(user)} 
                        className="btn btn-small btn-success"
                        title="Manage MAC addresses"
                      >
                        📱
                      </button>
                      <button 
                        onClick={() => deleteUser(user.id, user.username)} 
                        className="btn btn-small btn-danger"
                        title="Delete user"
                      >
                        🗑️
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {showAddUser && (
        <UserFormModal
          onClose={() => setShowAddUser(false)}
          onSave={fetchUsers}
        />
      )}

      {editingUser && (
        <UserFormModal
          user={editingUser}
          onClose={() => setEditingUser(null)}
          onSave={fetchUsers}
        />
      )}

      {showIPModal && (
        <IPManagementModal
          user={showIPModal}
          onClose={() => setShowIPModal(null)}
          onSave={fetchUsers}
        />
      )}
    </div>
  )
}

export default UserManagement
