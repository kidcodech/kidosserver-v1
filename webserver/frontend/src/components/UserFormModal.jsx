import { useState } from 'react'

function UserFormModal({ user, onClose, onSave }) {
  const [username, setUsername] = useState(user?.username || '')
  const [displayName, setDisplayName] = useState(user?.display_name || '')
  const [password, setPassword] = useState('')
  const [passwordTouched, setPasswordTouched] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    // Validate username (alphanumeric, underscore, hyphen)
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
      setError('Username can only contain letters, numbers, underscores, and hyphens')
      return
    }

    if (username.length < 3 || username.length > 32) {
      setError('Username must be between 3 and 32 characters')
      return
    }

    if (!user && password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }
    if (user && passwordTouched && password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    const data = {
      username: username.trim(),
      display_name: displayName.trim(),
      password: passwordTouched || !user ? password : undefined
    }

    try {
      const response = user
        ? await fetch(`/api/users/${user.id}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
          })
        : await fetch('/api/users', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
          })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(errorText || 'Failed to save user')
      }

      onSave()
      onClose()
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <h2>{user ? '✏️ Edit User' : '➕ Add User'}</h2>
        
        {error && <div className="error-message">{error}</div>}
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Username *</label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              required
              pattern="[a-zA-Z0-9_-]+"
              minLength={3}
              maxLength={32}
              className="domain-input"
              placeholder="e.g., john_doe"
              autoFocus
            />
            <small className="form-hint">Letters, numbers, underscores, and hyphens only</small>
          </div>
          
          <div className="form-group">
            <label>Display Name *</label>
            <input
              type="text"
              value={displayName}
              onChange={e => setDisplayName(e.target.value)}
              required
              maxLength={100}
              className="domain-input"
              placeholder="e.g., John Doe"
            />
            <small className="form-hint">Friendly name for display</small>
          </div>
          
          <div className="form-group">
            <label>Password {user ? '(leave blank to keep unchanged)' : '*'}</label>
            <input
              type="password"
              value={password}
              onChange={e => { setPassword(e.target.value); setPasswordTouched(true); }}
              minLength={user ? 0 : 8}
              className="domain-input"
              placeholder={user ? "New password (optional)" : "At least 8 characters"}
              autoComplete="new-password"
            />
            <small className="form-hint">Minimum 8 characters. {user ? 'Leave blank to keep current password.' : ''}</small>
          </div>
          
          <div className="form-actions">
            <button type="submit" className="btn btn-success">
              {user ? '💾 Update' : '✅ Create'}
            </button>
            <button type="button" onClick={onClose} className="btn btn-danger">
              ❌ Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default UserFormModal
