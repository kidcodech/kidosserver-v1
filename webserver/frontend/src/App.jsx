import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [packets, setPackets] = useState([])
  const [dnsRequests, setDnsRequests] = useState([])
  const [blockedDomains, setBlockedDomains] = useState([])
  const [newDomain, setNewDomain] = useState('')
  const [activeTab, setActiveTab] = useState('packets')
  const [ws, setWs] = useState(null)

  useEffect(() => {
    // Fetch initial data
    fetchPackets()
    fetchDNSRequests()
    fetchBlockedDomains()

    // Auto-refresh every second
    const refreshInterval = setInterval(() => {
      fetchPackets()
      fetchDNSRequests()
      fetchBlockedDomains()
    }, 1000)

    // Setup WebSocket connection
    const websocket = new WebSocket(`ws://${window.location.host}/ws`)
    
    websocket.onopen = () => {
      console.log('WebSocket connected')
    }

    websocket.onmessage = (event) => {
      const message = JSON.parse(event.data)
      if (message.type === 'packet_stats') {
        setPackets(message.data)
      }
    }

    websocket.onerror = (error) => {
      console.error('WebSocket error:', error)
    }

    websocket.onclose = () => {
      console.log('WebSocket disconnected')
    }

    setWs(websocket)

    return () => {
      clearInterval(refreshInterval)
      if (websocket) {
        websocket.close()
      }
    }
  }, [])

  const fetchPackets = async () => {
    try {
      const response = await fetch('/api/packets/aggregate')
      const data = await response.json()
      setPackets(data || [])
    } catch (error) {
      console.error('Error fetching packets:', error)
    }
  }

  const fetchDNSRequests = async () => {
    try {
      const response = await fetch('/api/dns/requests')
      const data = await response.json()
      setDnsRequests(data || [])
    } catch (error) {
      console.error('Error fetching DNS requests:', error)
    }
  }

  const fetchBlockedDomains = async () => {
    try {
      const response = await fetch('/api/dns/blocked')
      const data = await response.json()
      setBlockedDomains(data || [])
    } catch (error) {
      console.error('Error fetching blocked domains:', error)
    }
  }

  const blockDomain = async (domain) => {
    try {
      await fetch('/api/dns/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      })
      fetchBlockedDomains()
    } catch (error) {
      console.error('Error blocking domain:', error)
    }
  }

  const unblockDomain = async (domain) => {
    try {
      await fetch('/api/dns/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      })
      fetchBlockedDomains()
    } catch (error) {
      console.error('Error unblocking domain:', error)
    }
  }

  const addDomain = async () => {
    const domain = newDomain.trim()
    if (!domain) {
      alert('Please enter a domain name')
      return
    }
    
    await blockDomain(domain)
    setNewDomain('')
  }

  const clearPackets = async () => {
    try {
      await fetch('/api/packets/clear', { method: 'POST' })
      setPackets([])
    } catch (error) {
      console.error('Error clearing packets:', error)
    }
  }

  const clearDNSRequests = async () => {
    try {
      await fetch('/api/dns/clear', { method: 'POST' })
      setDnsRequests([])
    } catch (error) {
      console.error('Error clearing DNS requests:', error)
    }
  }

  const formatBytes = (bytes) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
  }

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp)
    return date.toLocaleString()
  }

  return (
    <div className="App">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1>🔍 Kidos</h1>
          <div className="status">
            <span className={ws && ws.readyState === WebSocket.OPEN ? 'connected' : 'disconnected'}>
              {ws && ws.readyState === WebSocket.OPEN ? '● Live' : '○ Offline'}
            </span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <button 
            className={`nav-item ${activeTab === 'packets' ? 'active' : ''}`}
            onClick={() => setActiveTab('packets')}
          >
            <span className="nav-icon">📊</span>
            <span className="nav-text">Packet Statistics</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'dns' ? 'active' : ''}`}
            onClick={() => setActiveTab('dns')}
          >
            <span className="nav-icon">🌐</span>
            <span className="nav-text">DNS Requests</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'blocked' ? 'active' : ''}`}
            onClick={() => setActiveTab('blocked')}
          >
            <span className="nav-icon">🚫</span>
            <span className="nav-text">Blocked Domains</span>
          </button>
        </nav>
      </aside>

      <main className="main-content">

      {activeTab === 'packets' && (
        <>
          <div className="controls">
            <button onClick={fetchPackets} className="btn btn-primary">
              🔄 Refresh
            </button>
            <button onClick={clearPackets} className="btn btn-danger">
              🗑️ Clear All
            </button>
          </div>

          <div className="stats-summary">
            <div className="stat-card">
              <h3>Total Flows</h3>
              <p className="stat-value">{packets.length}</p>
            </div>
            <div className="stat-card">
              <h3>Total Packets</h3>
              <p className="stat-value">{packets.reduce((sum, p) => sum + p.count, 0)}</p>
            </div>
            <div className="stat-card">
              <h3>Total Bytes</h3>
              <p className="stat-value">{formatBytes(packets.reduce((sum, p) => sum + p.total_size, 0))}</p>
            </div>
          </div>

          <div className="packet-table-container">
            <table className="packet-table">
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Protocol</th>
                  <th>Packet Count ▼</th>
                  <th>Total Size</th>
                </tr>
              </thead>
              <tbody>
                {packets.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="no-data">No packets captured yet</td>
                  </tr>
                ) : (
                  [...packets]
                    .sort((a, b) => {
                      // Primary sort: packet count (descending)
                      if (b.count !== a.count) {
                        return b.count - a.count;
                      }
                      // Secondary sort: source IP (alphabetically)
                      if (a.src_ip !== b.src_ip) {
                        return a.src_ip.localeCompare(b.src_ip);
                      }
                      // Tertiary sort: destination IP (alphabetically)
                      return a.dst_ip.localeCompare(b.dst_ip);
                    })
                    .map((pkt, idx) => (
                      <tr key={idx}>
                        <td>
                          {pkt.src_ip}
                          {pkt.src_domain && <span className="domain"> ({pkt.src_domain})</span>}
                        </td>
                        <td>
                          {pkt.dst_ip}
                          {pkt.dst_domain && <span className="domain"> ({pkt.dst_domain})</span>}
                        </td>
                        <td>
                          <span className={`protocol protocol-${pkt.protocol.toLowerCase()}`}>
                            {pkt.protocol}
                          </span>
                        </td>
                        <td>{pkt.count}</td>
                        <td>{formatBytes(pkt.total_size)}</td>
                      </tr>
                    ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {activeTab === 'dns' && (
        <>
          <div className="controls">
            <button onClick={fetchDNSRequests} className="btn btn-primary">
              🔄 Refresh
            </button>
            <button onClick={clearDNSRequests} className="btn btn-danger">
              🗑️ Clear All
            </button>
          </div>

          <div className="stats-summary">
            <div className="stat-card">
              <h3>Total DNS Requests</h3>
              <p className="stat-value">{dnsRequests.length}</p>
            </div>
          </div>

          <div className="packet-table-container">
            <table className="packet-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Domain</th>
                  <th>Query Type</th>
                  <th>Query Class</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {dnsRequests.length === 0 ? (
                  <tr>
                    <td colSpan="6" className="no-data">No DNS requests captured yet</td>
                  </tr>
                ) : (
                  [...dnsRequests]
                    .reverse()
                    .map((req, idx) => (
                      <tr key={idx}>
                        <td>{formatTimestamp(req.timestamp)}</td>
                        <td>{req.src_ip}</td>
                        <td className="domain-name">{req.domain}</td>
                        <td>{req.query_type}</td>
                        <td>{req.query_class}</td>
                        <td>
                          <button 
                            onClick={() => blockDomain(req.domain)} 
                            className="btn btn-small btn-danger"
                            disabled={blockedDomains.includes(req.domain)}
                          >
                            {blockedDomains.includes(req.domain) ? '🚫 Blocked' : '🚫 Block'}
                          </button>
                        </td>
                      </tr>
                    ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}

      {activeTab === 'blocked' && (
        <>
          <div className="controls">
            <div className="add-domain-form">
              <input 
                type="text" 
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && addDomain()}
                placeholder="Enter domain to block (e.g., example.com)"
                className="domain-input"
              />
              <button onClick={addDomain} className="btn btn-success">
                ➕ Add Domain
              </button>
            </div>
            <button onClick={fetchBlockedDomains} className="btn btn-primary">
              🔄 Refresh
            </button>
          </div>

          <div className="stats-summary">
            <div className="stat-card">
              <h3>Total Blocked Domains</h3>
              <p className="stat-value">{blockedDomains.length}</p>
            </div>
          </div>

          <div className="packet-table-container">
            <table className="packet-table blocked-table">
              <thead>
                <tr>
                  <th style={{width: '80%'}}>Domain</th>
                  <th style={{width: '20%'}}>Action</th>
                </tr>
              </thead>
              <tbody>
                {blockedDomains.length === 0 ? (
                  <tr>
                    <td colSpan="2" className="no-data">No domains blocked yet</td>
                  </tr>
                ) : (
                  blockedDomains.map((domain, idx) => (
                    <tr key={idx}>
                      <td className="domain-name">{domain}</td>
                      <td>
                        <button 
                          onClick={() => unblockDomain(domain)} 
                          className="btn btn-small btn-primary"
                        >
                          ✅ Unblock
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
      </main>
    </div>
  )
}

export default App
