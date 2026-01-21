import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

function AdminProfile() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState(''); // 'success' or 'error'
  const navigate = useNavigate();

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setMessage('New passwords do not match');
      setMessageType('error');
      return;
    }

    try {
      const response = await fetch('/api/admin/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
      });

      if (response.ok) {
        setMessage('Password changed successfully');
        setMessageType('success');
        setCurrentPassword('');
        setNewPassword('');
        setConfirmPassword('');
      } else {
        setMessage('Failed to change password. Check current password.');
        setMessageType('error');
      }
    } catch (err) {
      setMessage('Network error');
      setMessageType('error');
    }
  };

  const handleLogout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      navigate('/login');
    } catch (err) {
      console.error('Logout failed:', err);
    }
  };

  return (
    <div>
      <div className="card">
        <h3>Admin Settings</h3>
        
        <div style={{ marginBottom: '2rem' }}>
          <h4>Change Admin Password</h4>
          {message && (
            <div className={`alert ${messageType === 'success' ? 'alert-success' : 'alert-error'}`}>
              {message}
            </div>
          )}
          <form onSubmit={handlePasswordChange}>
            <div className="form-group">
              <label>Current Password</label>
              <input
                type="password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
                className="domain-input"
              />
            </div>
            <div className="form-group">
              <label>New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                className="domain-input"
              />
            </div>
             <div className="form-group">
              <label>Confirm New Password</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                className="domain-input"
              />
            </div>
            <button type="submit" className="btn btn-primary">Update Password</button>
          </form>
        </div>

        <div style={{ borderTop: '1px solid #2a2a3e', paddingTop: '2rem' }}>
          <button 
            onClick={handleLogout} 
            className="btn btn-danger"
          >
            Logout
          </button>
        </div>
      </div>
    </div>
  );
}

export default AdminProfile;
