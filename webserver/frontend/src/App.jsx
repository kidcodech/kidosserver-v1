import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [packets, setPackets] = useState([])
  const [ws, setWs] = useState(null)

  useEffect(() => {
    // Fetch initial data
    fetchPackets()

    // Auto-refresh every second
    const refreshInterval = setInterval(() => {
      fetchPackets()
    }, 1000)

    // Setup WebSocket connection
    const websocket = new WebSocket('ws://localhost:8080/ws')
    
    websocket.onopen = () => {
      console.log('WebSocket connected')
    }

    websocket.onmessage = (event) => {
      const message = JSON.parse(event.data)
      if (message.type === 'packet_stats') {
        setPackets(JSON.parse(message.data))
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
      const response = await fetch('http://localhost:8080/api/packets/aggregate')
      const data = await response.json()
      setPackets(data || [])
    } catch (error) {
      console.error('Error fetching packets:', error)
    }
  }

  const clearPackets = async () => {
    try {
      await fetch('http://localhost:8080/api/packets/clear', { method: 'POST' })
      setPackets([])
    } catch (error) {
      console.error('Error clearing packets:', error)
    }
  }

  const formatBytes = (bytes) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB'
  }

  return (
    <div className="App">
      <header className="header">
        <h1>🔍 Kidos Network Monitor</h1>
        <div className="status">
          <span className={ws && ws.readyState === WebSocket.OPEN ? 'connected' : 'disconnected'}>
            {ws && ws.readyState === WebSocket.OPEN ? '● Live' : '○ Disconnected'}
          </span>
        </div>
      </header>

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
    </div>
  )
}

export default App
