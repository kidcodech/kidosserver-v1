import React, { useState, useEffect } from 'react';

function Auth() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [deviceName, setDeviceName] = useState('');
  const [message, setMessage] = useState(null);
  const [messageType, setMessageType] = useState(''); // 'success', 'error', 'info'
  const [loading, setLoading] = useState(false);
  const [clientIP, setClientIP] = useState('');

  useEffect(() => {
    // Fetch client IP on mount
    fetchClientIP();
  }, []);

  const fetchClientIP = async () => {
    try {
      const response = await fetch('/api/client-info');
      const data = await response.json();
      setClientIP(data.ip);
    } catch (error) {
      console.error('Error fetching client IP:', error);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!username || !password) {
      setMessage('Please enter username and password');
      setMessageType('error');
      return;
    }

    setLoading(true);
    setMessage(null);

    try {
      const response = await fetch('/api/auth/register-device', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          username,
          password,
          device_name: deviceName || navigator.userAgent.split(' ').slice(-1)[0] // Use browser as default device name
        }),
      });

      const data = await response.json();

      if (response.ok) {
        if (data.already_registered) {
          setMessage(data.message || 'This device is already registered to your account');
          setMessageType('info');
        } else {
          setMessage(data.message || 'Device registered successfully! You can now access the internet.');
          setMessageType('success');
        }
        // Clear password for security
        setPassword('');
      } else {
        setMessage(data.error || 'Authentication failed');
        setMessageType('error');
      }
    } catch (error) {
      setMessage('Network error. Please try again.');
      setMessageType('error');
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>Device Registration</h1>
        <p style={styles.subtitle}>
          Register this device to access the internet
        </p>
        
        {clientIP && (
          <div style={styles.ipInfo}>
            <strong>Your IP:</strong> {clientIP}
          </div>
        )}

        <form onSubmit={handleSubmit} style={styles.form}>
          <div style={styles.formGroup}>
            <label style={styles.label}>Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={styles.input}
              placeholder="Enter your username"
              autoComplete="username"
              disabled={loading}
            />
          </div>

          <div style={styles.formGroup}>
            <label style={styles.label}>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={styles.input}
              placeholder="Enter your password"
              autoComplete="current-password"
              disabled={loading}
            />
          </div>

          <div style={styles.formGroup}>
            <label style={styles.label}>
              Device Name <span style={styles.optional}>(optional)</span>
            </label>
            <input
              type="text"
              value={deviceName}
              onChange={(e) => setDeviceName(e.target.value)}
              style={styles.input}
              placeholder="e.g., John's iPhone"
              disabled={loading}
            />
          </div>

          {message && (
            <div style={{
              ...styles.message,
              ...(messageType === 'success' ? styles.messageSuccess : 
                  messageType === 'info' ? styles.messageInfo : 
                  styles.messageError)
            }}>
              {message}
            </div>
          )}

          <button
            type="submit"
            style={styles.button}
            disabled={loading}
          >
            {loading ? 'Registering...' : 'Register Device'}
          </button>
        </form>

        <div style={styles.footer}>
          <p style={styles.footerText}>
            Don't have an account? Contact your administrator.
          </p>
        </div>
      </div>
    </div>
  );
}

const styles = {
  container: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#f5f5f5',
    padding: '20px',
  },
  card: {
    backgroundColor: 'white',
    borderRadius: '8px',
    boxShadow: '0 2px 10px rgba(0,0,0,0.1)',
    padding: '40px',
    maxWidth: '450px',
    width: '100%',
  },
  title: {
    fontSize: '24px',
    fontWeight: 'bold',
    marginBottom: '8px',
    textAlign: 'center',
    color: '#333',
  },
  subtitle: {
    fontSize: '14px',
    color: '#666',
    textAlign: 'center',
    marginBottom: '20px',
  },
  ipInfo: {
    backgroundColor: '#f0f0f0',
    padding: '10px',
    borderRadius: '4px',
    marginBottom: '20px',
    textAlign: 'center',
    fontSize: '14px',
    color: '#555',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
  },
  formGroup: {
    display: 'flex',
    flexDirection: 'column',
  },
  label: {
    fontSize: '14px',
    fontWeight: '500',
    marginBottom: '6px',
    color: '#333',
  },
  optional: {
    fontSize: '12px',
    fontWeight: 'normal',
    color: '#999',
  },
  input: {
    padding: '10px 12px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    fontSize: '14px',
    transition: 'border-color 0.2s',
  },
  button: {
    backgroundColor: '#007bff',
    color: 'white',
    padding: '12px',
    border: 'none',
    borderRadius: '4px',
    fontSize: '16px',
    fontWeight: '500',
    cursor: 'pointer',
    marginTop: '8px',
    transition: 'background-color 0.2s',
  },
  message: {
    padding: '12px',
    borderRadius: '4px',
    fontSize: '14px',
    marginTop: '8px',
  },
  messageSuccess: {
    backgroundColor: '#d4edda',
    color: '#155724',
    border: '1px solid #c3e6cb',
  },
  messageInfo: {
    backgroundColor: '#d1ecf1',
    color: '#0c5460',
    border: '1px solid #bee5eb',
  },
  messageError: {
    backgroundColor: '#f8d7da',
    color: '#721c24',
    border: '1px solid #f5c6cb',
  },
  footer: {
    marginTop: '20px',
    paddingTop: '20px',
    borderTop: '1px solid #eee',
  },
  footerText: {
    fontSize: '12px',
    color: '#999',
    textAlign: 'center',
    margin: 0,
  },
};

export default Auth;
