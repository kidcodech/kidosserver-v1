import { useState, useEffect, useRef } from 'react'
import { useMediaQuery } from 'react-responsive'
import { useNavigate, useLocation, Routes, Route } from 'react-router-dom'
import './App.css'
import UserManagement from './components/UserManagement'

// Helper function to format bytes
const formatBytes = (bytes) => {
  if (bytes === 0) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

function TrafficGraph({ data, onWidthChange }) {
  const canvasRef = useRef(null)
  const containerRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    const container = containerRef.current
    if (!canvas || !container) return

    // Set canvas size to match container
    const containerWidth = container.clientWidth
    canvas.width = containerWidth
    canvas.height = 400
    
    // Notify parent of width change for history management
    if (onWidthChange) {
      onWidthChange(containerWidth)
    }

    const ctx = canvas.getContext('2d')
    const width = canvas.width
    const height = canvas.height

    // Clear canvas
    ctx.fillStyle = '#0f0f1e'
    ctx.fillRect(0, 0, width, height)

    if (data.length === 0) {
      // Show "No data" message
      ctx.fillStyle = '#666'
      ctx.font = '16px sans-serif'
      ctx.textAlign = 'center'
      ctx.fillText('Waiting for data... (Graph will appear as traffic flows)', width / 2, height / 2)
      return
    }

    console.log('Drawing graph with', data.length, 'data points, latest:', data[data.length - 1])

    // Padding for labels and graph boundaries
    const leftPadding = 70 // Space for Y-axis labels
    const rightPadding = 10
    const topPadding = 20
    const bottomPadding = 20
    
    // Calculate how many data points fit (account for left padding)
    const graphWidth = width - leftPadding - rightPadding
    const maxDataPoints = graphWidth
    const displayData = data.slice(-maxDataPoints)

    // Logarithmic scale: 1 KB/s to 1 Gbps with padding
    const minBytesPerSec = 1000 // 1 KB/s
    const maxBytesPerSec = 1000000000 // 1 Gbps (use full 1000 MB instead of 125 MB)
    const graphHeight = height - (topPadding + bottomPadding)
    
    const logScale = (value) => {
      if (value <= minBytesPerSec) return topPadding
      const logMin = Math.log10(minBytesPerSec)
      const logMax = Math.log10(maxBytesPerSec)
      const logValue = Math.log10(value)
      return topPadding + ((logValue - logMin) / (logMax - logMin)) * graphHeight
    }

    // Draw grid lines (logarithmic)
    ctx.strokeStyle = '#2a2a3e'
    ctx.lineWidth = 1
    const gridValues = [
      { value: 1000, label: '1 KB/s' },
      { value: 10000, label: '10 KB/s' },
      { value: 100000, label: '100 KB/s' },
      { value: 1000000, label: '1 MB/s' },
      { value: 10000000, label: '10 MB/s' },
      { value: 100000000, label: '100 MB/s' },
      { value: 1000000000, label: '1 Gb/s' }
    ]
    
    gridValues.forEach(({ value, label }) => {
      const y = height - logScale(value)
      ctx.beginPath()
      ctx.moveTo(leftPadding, y)
      ctx.lineTo(width - rightPadding, y)
      ctx.stroke()

      // Draw labels (aligned to the left)
      ctx.fillStyle = '#666'
      ctx.font = '10px monospace'
      ctx.textAlign = 'right'
      ctx.fillText(label, leftPadding - 5, y + 3)
    })

    // Draw graph line
    ctx.strokeStyle = '#646cff'
    ctx.lineWidth = 2
    ctx.beginPath()

    displayData.forEach((value, index) => {
      // 1-to-1 pixel mapping: one data point per pixel (offset by leftPadding)
      const x = leftPadding + index
      const y = height - logScale(value)
      
      if (index === 0) {
        ctx.moveTo(x, y)
      } else {
        ctx.lineTo(x, y)
      }
    })
    
    ctx.stroke()

    // Fill area under curve
    if (displayData.length > 0) {
      // Close from the last point's x-coordinate, not the full width
      ctx.lineTo(leftPadding + displayData.length - 1, height - bottomPadding)
      ctx.lineTo(leftPadding, height - bottomPadding)
      ctx.closePath()
      
      const gradient = ctx.createLinearGradient(0, 0, 0, height)
      gradient.addColorStop(0, 'rgba(100, 108, 255, 0.3)')
      gradient.addColorStop(1, 'rgba(100, 108, 255, 0.05)')
      ctx.fillStyle = gradient
      ctx.fill()
    }

  }, [data])

  return (
    <div ref={containerRef} style={{ width: '100%', height: '400px' }}>
      <canvas 
        ref={canvasRef}
        style={{ width: '100%', height: '100%', borderRadius: '12px', display: 'block' }}
      />
    </div>
  )
}

function App() {
  const navigate = useNavigate()
  const location = useLocation()
  const isMobile = useMediaQuery({ query: '(max-width: 768px)' })
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  
  // Determine active tab from URL
  const getActiveTab = () => {
    const path = location.pathname.replace('/admin/', '')
    if (path === '' || path === '/') return 'packets'
    return path
  }
  const [activeTab, setActiveTabState] = useState(getActiveTab())
  
  // Update activeTab when location changes
  useEffect(() => {
    const tab = getActiveTab()
    setActiveTabState(tab)
    if (tab === 'hotspot') {
      setHotspotLoading(true)
    }
  }, [location])
  
  // Function to change tab and update URL
  const setActiveTab = (tab) => {
    setActiveTabState(tab)
    if (tab === 'hotspot') {
      setHotspotLoading(true)
    }
    navigate(`/admin/${tab}`)
  }
  
  const [packets, setPackets] = useState([])
  const [dnsRequests, setDnsRequests] = useState([])
  const [blockedDomains, setBlockedDomains] = useState([])
  const [newDomain, setNewDomain] = useState('')
  const [blockedLogs, setBlockedLogs] = useState([])
  const [encryptedDNSLogs, setEncryptedDNSLogs] = useState([])
  // Default to today's date in local time
  const [logFilterDate, setLogFilterDate] = useState(() => {
    const now = new Date()
    const offset = now.getTimezoneOffset()
    const localDate = new Date(now.getTime() - (offset * 60 * 1000))
    return localDate.toISOString().split('T')[0]
  })
  const [logFilterType, setLogFilterType] = useState('') // 'user' or 'device'
  const [logFilterValue, setLogFilterValue] = useState('') // user_id or device_mac
  const [logsSubTab, setLogsSubTab] = useState('blocked')
  const [ws, setWs] = useState(null)
  const [trafficHistory, setTrafficHistory] = useState([])
  const [lastPacketCount, setLastPacketCount] = useState(0)
  const [lastUpdateTime, setLastUpdateTime] = useState(Date.now())
  const [maxHistoryLength, setMaxHistoryLength] = useState(1200) // Default, will be updated by canvas width
  const [clientIP, setClientIP] = useState('')
  const [userName, setUserName] = useState('')
  const [users, setUsers] = useState([])
  const [selectedUser, setSelectedUser] = useState(null)
  const [userBlockedDomains, setUserBlockedDomains] = useState([])
  const [newUserDomain, setNewUserDomain] = useState('')
  const [newUserMAC, setNewUserMAC] = useState('')
  const [usersSubTab, setUsersSubTab] = useState('manage')
  const [unregisteredDevices, setUnregisteredDevices] = useState([])
  const [showCreateUserModal, setShowCreateUserModal] = useState(false)
  const [newUser, setNewUser] = useState({ username: '', display_name: '', password: '' })
  const [newPassword, setNewPassword] = useState('')
  const [systemHealth, setSystemHealth] = useState(null)
  const [editingDeviceName, setEditingDeviceName] = useState(null)
  const [editDeviceNameValue, setEditDeviceNameValue] = useState('')
  const [blockDoT, setBlockDoT] = useState(true)
  const [blockDoQ, setBlockDoQ] = useState(true)
  const [blockDoH, setBlockDoH] = useState(true)
  const [dohProviders, setDohProviders] = useState([])
  const [newDoHProvider, setNewDoHProvider] = useState({ name: '', ip_address: '' })
  
  // Hotspot state
  const [hotspotConfig, setHotspotConfig] = useState({ 
    ssid: 'Kidos-Hotspot', 
    password: 'kidos12345', 
    channel: '6', 
    security: 'WPA2',
    interface: ''
  })
  const [hotspotStatus, setHotspotStatus] = useState({ running: false, clients: [] })
  const [wifiInterfaces, setWifiInterfaces] = useState([])
  const [showHotspotPassword, setShowHotspotPassword] = useState(false)
  const [isRestartingHotspot, setIsRestartingHotspot] = useState(false)
  const [hotspotLoading, setHotspotLoading] = useState(getActiveTab() === 'hotspot')

  // Setup WebSocket connection once
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const websocket = new WebSocket(`${protocol}//${window.location.host}/ws`)
    
    websocket.onopen = () => {
      // console.log('WebSocket connected')
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
      // console.log('WebSocket disconnected')
    }

    setWs(websocket)

    return () => {
      if (websocket) {
        websocket.close()
      }
    }
  }, [])

  // Initial data fetch
  useEffect(() => {
    if (activeTab === 'traffic') {
      fetchPackets()
    }
    if (activeTab === 'system') {
      fetchSystemHealth()
    }
    fetchDNSRequests()
    fetchBlockedDomains()
    fetchClientInfo()
    fetchUsers()
    fetchUnregisteredDevices()
    fetchSystemSettings()
    fetchDoHProviders()
    if (activeTab === 'hotspot') {
      setHotspotLoading(true)
      Promise.all([
        fetchWifiInterfaces(),
        fetchHotspotStatus(),
        fetchHotspotConfig()
      ]).finally(() => setHotspotLoading(false))
    }
  }, [activeTab])

  // Auto-refresh based on active tab
  useEffect(() => {
    const refreshInterval = setInterval(() => {
      if (activeTab === 'traffic') {
        fetchPackets()
      }
      if (activeTab === 'logs' && logsSubTab === 'dns') {
        fetchDNSRequests()
      }
      if (activeTab === 'users' && usersSubTab === 'devices') {
        fetchUnregisteredDevices()
      }
      if (activeTab === 'hotspot') {
        fetchHotspotStatus()
      }
    }, 1000)

    return () => {
      clearInterval(refreshInterval)
    }
  }, [activeTab, logsSubTab, usersSubTab])

  const fetchSystemSettings = async () => {
    try {
      const resDot = await fetch('/api/system/settings/block_dot')
      if (resDot.ok) {
        const data = await resDot.json()
        setBlockDoT(data.value !== 'false')
      }

      const resDoQ = await fetch('/api/system/settings/block_doq')
      if (resDoQ.ok) {
        const data = await resDoQ.json()
        setBlockDoQ(data.value !== 'false')
      }
      
      const resDoH = await fetch('/api/system/settings/block_doh')
      if (resDoH.ok) {
        const data = await resDoH.json()
        setBlockDoH(data.value !== 'false')
      }
    } catch (error) {
      console.error('Error fetching system settings:', error)
    }
  }

  const fetchDoHProviders = async () => {
    try {
      const response = await fetch('/api/doh/providers')
      if (response.ok) {
        const data = await response.json()
        setDohProviders(data || [])
      }
    } catch (error) {
      console.error('Error fetching DoH providers:', error)
    }
  }

  // Hotspot API functions
  const fetchWifiInterfaces = async () => {
    try {
      const response = await fetch('/api/hotspot/interfaces')
      if (response.ok) {
        const data = await response.json()
        setWifiInterfaces(data || [])
        
        if (data && data.length > 0) {
          setHotspotConfig(prev => {
            // Only set default interface if none is currently selected
            if (prev.interface) return prev
            
            const available = data.find(i => !i.has_ip)
            return { 
              ...prev, 
              interface: available ? available.name : data[0].name 
            }
          })
        }
      }
    } catch (error) {
      console.error('Error fetching wifi interfaces:', error)
    }
  }

  const fetchHotspotStatus = async () => {
    try {
      const response = await fetch('/api/hotspot/status')
      if (response.ok) {
        const data = await response.json()
        setHotspotStatus(data)
      }
    } catch (error) {
      console.error('Error fetching hotspot status:', error)
    }
  }

  const fetchHotspotConfig = async () => {
    try {
      const response = await fetch('/api/hotspot/config')
      if (response.ok) {
        const data = await response.json()
        if (data) setHotspotConfig(data)
      }
    } catch (error) {
      console.error('Error fetching hotspot config:', error)
    }
  }

  const saveHotspotConfig = async () => {
    if (!hotspotConfig.interface) {
        alert('Please select a Wi-Fi interface');
        return;
    }
    try {
      await fetch('/api/hotspot/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(hotspotConfig)
      })
      alert('Hotspot configuration saved')
    } catch (error) {
      console.error('Error saving hotspot config:', error)
      alert('Failed to save configuration')
    }
  }

  const startHotspot = async () => {
    if (!hotspotConfig.interface) {
        alert('Please select a Wi-Fi interface');
        return;
    }
    try {
      const response = await fetch('/api/hotspot/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(hotspotConfig)
      })
      if (response.ok) {
        alert('Hotspot started successfully')
        fetchHotspotStatus()
      } else {
        const error = await response.text()
        alert('Failed to start hotspot: ' + error)
      }
    } catch (error) {
      console.error('Error starting hotspot:', error)
      alert('Failed to start hotspot')
    }
  }

  const stopHotspot = async () => {
    try {
      await fetch('/api/hotspot/stop', { method: 'POST' })
      alert('Hotspot stopped')
      fetchHotspotStatus()
    } catch (error) {
      console.error('Error stopping hotspot:', error)
      alert('Failed to stop hotspot')
    }
  }

  const restartHotspot = async () => {
    setIsRestartingHotspot(true)
    try {
      const response = await fetch('/api/hotspot/restart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(hotspotConfig)
      })
      if (response.ok) {
        await fetchHotspotStatus()
        setTimeout(() => setIsRestartingHotspot(false), 500)
      } else {
        const error = await response.text()
        alert('Failed to restart hotspot: ' + error)
        setIsRestartingHotspot(false)
      }
    } catch (error) {
      console.error('Error restarting hotspot:', error)
      alert('Failed to restart hotspot')
      setIsRestartingHotspot(false)
    }
  }

  const toggleBlockDoT = async () => {
    const newValue = !blockDoT
    try {
      await fetch('/api/system/settings/block_dot', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: newValue ? 'true' : 'false' })
      })
      setBlockDoT(newValue)
    } catch (error) {
      console.error('Error updating block_dot setting:', error)
    }
  }

  const toggleBlockDoQ = async () => {
    const newValue = !blockDoQ
    try {
      await fetch('/api/system/settings/block_doq', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: newValue ? 'true' : 'false' })
      })
      setBlockDoQ(newValue)
    } catch (error) {
      console.error('Error updating block_doq setting:', error)
    }
  }

  const toggleBlockDoH = async () => {
    const newValue = !blockDoH
    try {
      await fetch('/api/system/settings/block_doh', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value: newValue ? 'true' : 'false' })
      })
      setBlockDoH(newValue)
    } catch (error) {
      console.error('Error updating block_doh setting:', error)
    }
  }

  const addDoHProvider = async () => {
    if (!newDoHProvider.name || !newDoHProvider.ip_address) {
      alert('Please enter both name and IP address')
      return
    }

    // IPv4 or CIDR validation
    const ipv4CidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:3[0-2]|[12]?[0-9]))?$/
    if (!ipv4CidrRegex.test(newDoHProvider.ip_address)) {
      alert('Please enter a valid IPv4 address or CIDR (e.g., 1.2.3.4 or 1.2.3.0/24)')
      return
    }

    try {
      await fetch('/api/doh/providers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newDoHProvider)
      })
      setNewDoHProvider({ name: '', ip_address: '' })
      fetchDoHProviders()
    } catch (error) {
      console.error('Error adding DoH provider:', error)
    }
  }

  const deleteDoHProvider = async (id) => {
    if (!confirm('Are you sure you want to delete this provider?')) return
    try {
      await fetch(`/api/doh/providers/${id}`, {
        method: 'DELETE'
      })
      fetchDoHProviders()
    } catch (error) {
      console.error('Error deleting DoH provider:', error)
    }
  }

  const toggleDoHProviderEnabled = async (id, currentStatus) => {
    try {
      await fetch(`/api/doh/providers/${id}/toggle`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !currentStatus })
      })
      fetchDoHProviders()
    } catch (error) {
      console.error('Error toggling DoH provider:', error)
    }
  }

  // Fetch logs when tab or filters change
  useEffect(() => {
    if (activeTab === 'logs') {
      // Ensure users are loaded for filtering
      if (users.length === 0) {
        fetchUsers()
      }
      
      if (logsSubTab === 'blocked') {
        fetchBlockedLogs()
      } else if (logsSubTab === 'dns') {
        fetchDNSRequests()
      } else if (logsSubTab === 'encrypted') {
        fetchEncryptedDNSLogs()
      }
    }
  }, [activeTab, logsSubTab, logFilterDate, logFilterType, logFilterValue])

  // Update traffic graph when packets change (only in traffic tab)
  useEffect(() => {
    if (activeTab !== 'traffic') return
    if (packets.length === 0) return
    
    const now = Date.now()
    const timeDelta = (now - lastUpdateTime) / 1000 // seconds
    
    if (timeDelta < 0.1) return // Ignore updates faster than 100ms
    
    const currentBytesCount = packets.reduce((sum, p) => sum + p.total_size, 0)
    const bytesDelta = Math.max(0, currentBytesCount - lastPacketCount)
    
    // Calculate bytes per second based on actual time elapsed
    const bytesPerSecond = Math.round(bytesDelta / timeDelta)
    
    console.log('Traffic update:', { 
      currentBytesCount, 
      lastPacketCount, 
      bytesDelta,
      timeDelta: timeDelta.toFixed(2) + 's',
      bytesPerSecond 
    })
    
    setLastPacketCount(currentBytesCount)
    setLastUpdateTime(now)
    
    setTrafficHistory(prev => {
      const newHistory = [...prev, bytesPerSecond]
      // Keep history based on canvas width (maxHistoryLength)
      if (newHistory.length > maxHistoryLength) {
        return newHistory.slice(-maxHistoryLength)
      }
      return newHistory
    })
  }, [packets, maxHistoryLength, activeTab])

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
      let url = '/api/dns/requests?'
      // If date is cleared, default to today
      const dateParam = logFilterDate || new Date().toLocaleDateString('en-CA') // YYYY-MM-DD
      url += `date=${dateParam}&`
      
      if (logFilterType === 'user' && logFilterValue) url += `user_id=${logFilterValue}&`
      if (logFilterType === 'device' && logFilterValue) url += `device_mac=${logFilterValue}&`

      const response = await fetch(url)
      const data = await response.json()
      setDnsRequests(data || [])
    } catch (error) {
      console.error('Error fetching DNS requests:', error)
    }
  }

  const fetchBlockedDomains = async () => {
    // Temporarily disabled - DNS inspector communication issues
    // try {
    //   const response = await fetch('/api/dns/blocked')
    //   const data = await response.json()
    //   setBlockedDomains(data || [])
    // } catch (error) {
    //   console.error('Error fetching blocked domains:', error)
    // }
  }

  const fetchBlockedLogs = async () => {
    try {
      let url = '/api/dns/blocked-logs?'
      // If date is cleared, default to today
      const dateParam = logFilterDate || new Date().toLocaleDateString('en-CA') // YYYY-MM-DD
      url += `date=${dateParam}&`
      
      if (logFilterType === 'user' && logFilterValue) url += `user_id=${logFilterValue}&`
      if (logFilterType === 'device' && logFilterValue) url += `device_mac=${logFilterValue}&`
      
      const response = await fetch(url)
      const data = await response.json()
      setBlockedLogs(data || [])
    } catch (error) {
      console.error('Error fetching blocked logs:', error)
    }
  }

  const clearBlockedLogs = async () => {
    if (!confirm('Are you sure you want to clear all blocked domain logs?')) {
      return
    }
    try {
      const response = await fetch('/api/dns/blocked-logs', {
        method: 'DELETE'
      })
      if (response.ok) {
        setBlockedLogs([])
      }
    } catch (error) {
      console.error('Error clearing blocked logs:', error)
    }
  }

  const clearEncryptedDNSLogs = async () => {
    if (!confirm('Are you sure you want to clear all encrypted DNS logs?')) {
      return
    }
    try {
      const response = await fetch('/api/logs/encrypted-dns', {
        method: 'DELETE'
      })
      if (response.ok) {
        setEncryptedDNSLogs([])
      }
    } catch (error) {
      console.error('Error clearing encrypted DNS logs:', error)
    }
  }

  const fetchClientInfo = async () => {
    try {
      const response = await fetch('/api/client/info')
      const data = await response.json()
      setClientIP(data.ip || '')
      if (data.user) {
        setUserName(data.user.display_name)
      } else {
        setUserName('')
      }
    } catch (error) {
      console.error('Error fetching client info:', error)
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

  const fetchUsers = async () => {
    try {
      const response = await fetch('/api/users')
      const data = await response.json()
      setUsers(data || [])
    } catch (error) {
      console.error('Error fetching users:', error)
    }
  }

  const fetchUserBlockedDomains = async (userId) => {
    try {
      const response = await fetch(`/api/users/${userId}/blocked-domains`)
      const data = await response.json()
      setUserBlockedDomains(data || [])
    } catch (error) {
      console.error('Error fetching user blocked domains:', error)
    }
  }

  const blockDomainForUser = async (userId, domain) => {
    try {
      await fetch(`/api/users/${userId}/blocked-domains`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      })
      fetchUserBlockedDomains(userId)
    } catch (error) {
      console.error('Error blocking domain for user:', error)
    }
  }

  const unblockDomainForUser = async (userId, domainId, domainName) => {
    if (!window.confirm(`Are you sure you want to unblock "${domainName}"?`)) {
      return
    }
    try {
      await fetch(`/api/users/${userId}/blocked-domains/${domainId}`, {
        method: 'DELETE'
      })
      fetchUserBlockedDomains(userId)
    } catch (error) {
      console.error('Error unblocking domain for user:', error)
    }
  }

  const unblockDomainByName = async (userId, domain) => {
    try {
      await fetch(`/api/users/${userId}/blocked-domains/unblock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      })
      fetchBlockedLogs() // Refresh logs
    } catch (error) {
      console.error('Error unblocking domain for user:', error)
    }
  }

  const addUserDomain = async () => {
    if (!selectedUser) {
      alert('Please select a user first')
      return
    }
    const domain = newUserDomain.trim()
    if (!domain) {
      alert('Please enter a domain name')
      return
    }
    
    await blockDomainForUser(selectedUser.id, domain)
    setNewUserDomain('')
  }

  const selectUser = (user) => {
    setSelectedUser(user)
    fetchUserBlockedDomains(user.id)
  }

  const addUserDevice = async (userId, macAddress) => {
    try {
      await fetch(`/api/users/${userId}/devices`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac_address: macAddress })
      })
      await fetchUsers()
      // Re-fetch the selected user's data
      if (selectedUser && selectedUser.id === userId) {
        const response = await fetch(`/api/users/${userId}`)
        const updatedUser = await response.json()
        setSelectedUser(updatedUser)
      }
    } catch (error) {
      console.error('Error adding MAC to user:', error)
    }
  }

  const removeUserMAC = async (userId, deviceId) => {
    if (!window.confirm('Are you sure you want to remove this device from the user?')) {
      return
    }
    try {
      await fetch(`/api/users/${userId}/devices/${deviceId}`, {
        method: 'DELETE'
      })
      await fetchUsers()
      // Re-fetch the selected user's data
      if (selectedUser && selectedUser.id === userId) {
        const response = await fetch(`/api/users/${userId}`)
        const updatedUser = await response.json()
        setSelectedUser(updatedUser)
      }
    } catch (error) {
      console.error('Error removing MAC from user:', error)
    }
  }

  const addUserMACAddress = async () => {
    if (!selectedUser) {
      alert('Please select a user first')
      return
    }
    const mac = newUserMAC.trim()
    if (!mac) {
      alert('Please enter a MAC address')
      return
    }
    
    // MAC address validation
    const macPattern = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/
    if (!macPattern.test(mac)) {
      alert('Please enter a valid MAC address (e.g., aa:bb:cc:dd:ee:ff)')
      return
    }
    
    await addUserDevice(selectedUser.id, mac.toLowerCase())
    setNewUserMAC('')
  }

  const fetchUnregisteredDevices = async () => {
    try {
      const response = await fetch('/api/devices/unregistered')
      const data = await response.json()
      setUnregisteredDevices(data || [])
    } catch (error) {
      console.error('Error fetching unregistered devices:', error)
    }
  }

  const fetchSystemHealth = async () => {
    try {
      const response = await fetch('/api/system/health')
      const data = await response.json()
      setSystemHealth(data)
    } catch (error) {
      console.error('Error fetching system health:', error)
    }
  }

  const registerDeviceToUser = async (mac, userId) => {
    try {
      // Find the device to get its IP address
      const device = unregisteredDevices.find(d => d.mac_address === mac)
      
      await fetch(`/api/users/${userId}/devices`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          mac_address: mac,
          ip_address: device?.ip_address || ''
        })
      })
      fetchUnregisteredDevices()
      fetchUsers()
    } catch (error) {
      console.error('Error registering device:', error)
    }
  }

  const createUser = async () => {
    if (!newUser.username || !newUser.display_name || !newUser.password) {
      alert('All fields are required')
      return
    }
    try {
      const response = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newUser)
      })
      if (response.ok) {
        setShowCreateUserModal(false)
        setNewUser({ username: '', display_name: '', password: '' })
        fetchUsers()
      } else {
        const error = await response.text()
        alert(`Failed to create user: ${error}`)
      }
    } catch (error) {
      console.error('Error creating user:', error)
    }
  }

  const deleteUser = async (userId, username) => {
    if (!confirm(`Are you sure you want to delete user "${username}"? This will remove all their IP addresses and blocked domains.`)) {
      return
    }
    try {
      await fetch(`/api/users/${userId}`, { method: 'DELETE' })
      if (selectedUser?.id === userId) {
        setSelectedUser(null)
      }
      fetchUsers()
    } catch (error) {
      console.error('Error deleting user:', error)
    }
  }

  const updateUserPassword = async () => {
    if (!selectedUser) return
    if (!newPassword) {
      alert('Please enter a new password')
      return
    }
    
    try {
      const response = await fetch(`/api/users/${selectedUser.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: selectedUser.username,
          display_name: selectedUser.display_name,
          password: newPassword
        })
      })
      
      if (response.ok) {
        alert('Password updated successfully')
        setNewPassword('')
      } else {
        const error = await response.text()
        alert(`Failed to update password: ${error}`)
      }
    } catch (error) {
      console.error('Error updating password:', error)
      alert('Failed to update password')
    }
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

  const forgetUnregisteredDevice = async (mac) => {
    if (!confirm(`Are you sure you want to forget device ${mac}?`)) return

    try {
      await fetch(`/api/devices/unregistered/${mac}`, {
        method: 'DELETE'
      })
      fetchUnregisteredDevices()
    } catch (error) {
      console.error('Error forgetting device:', error)
    }
  }

  const forgetAllUnregisteredDevices = async () => {
    if (!confirm('Are you sure you want to forget ALL unregistered devices?')) return

    try {
      await fetch('/api/devices/unregistered', {
        method: 'DELETE'
      })
      fetchUnregisteredDevices()
    } catch (error) {
      console.error('Error forgetting all devices:', error)
    }
  }

  const updateDeviceName = async (deviceId, newName) => {
    if (!selectedUser) return
    
    try {
      const response = await fetch(`/api/users/${selectedUser.id}/devices/${deviceId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_name: newName })
      })
      
      if (response.ok) {
        setEditingDeviceName(null)
        setEditDeviceNameValue('')
        fetchUsers()
        // Update selected user
        const updatedUser = await fetch(`/api/users/${selectedUser.id}`).then(r => r.json())
        setSelectedUser(updatedUser)
      }
    } catch (error) {
      console.error('Error updating device name:', error)
    }
  }

  const fetchEncryptedDNSLogs = async () => {
    try {
      let url = '/api/logs/encrypted-dns?'
      // If date is cleared, default to today
      const dateParam = logFilterDate || new Date().toLocaleDateString('en-CA') // YYYY-MM-DD
      url += `date=${dateParam}&`
      
      if (logFilterType === 'user' && logFilterValue) url += `user_id=${logFilterValue}&`
      if (logFilterType === 'device' && logFilterValue) url += `device_mac=${logFilterValue}&`

      const response = await fetch(url)
      if (response.ok) {
        const data = await response.json()
        setEncryptedDNSLogs(data || [])
      }
    } catch (error) {
      console.error('Error fetching encrypted DNS logs:', error)
    }
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
          {!isMobile && clientIP && (
            <div className="client-info">
              <span className="client-ip">📍 {clientIP}</span>
              {userName && <span className="client-user">👤 {userName}</span>}
            </div>
          )}
          {isMobile && (
            <button 
              className="mobile-menu-toggle"
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              aria-label="Toggle menu"
            >
              {isMobileMenuOpen ? '✕' : '☰'}
            </button>
          )}
        </div>

        <nav className={`sidebar-nav ${isMobileMenuOpen ? 'mobile-open' : ''}`}>
          <button 
            className={`nav-item ${activeTab === 'packets' ? 'active' : ''}`}
            onClick={() => { setActiveTab('packets'); setIsMobileMenuOpen(false); }}
          >
            <span className="nav-icon">📊</span>
            <span className="nav-text">Packet Statistics</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'traffic' ? 'active' : ''}`}
            onClick={() => { setActiveTab('traffic'); setIsMobileMenuOpen(false); }}
          >
            <span className="nav-icon">📈</span>
            <span className="nav-text">Traffic Monitor</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'logs' ? 'active' : ''}`}
            onClick={() => { setActiveTab('logs'); setIsMobileMenuOpen(false); }}
          >
            <span className="nav-icon">📋</span>
            <span className="nav-text">Logs</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'users' ? 'active' : ''}`}
            onClick={() => { setActiveTab('users'); setIsMobileMenuOpen(false); }}
          >
            <span className="nav-icon">👥</span>
            <span className="nav-text">Users</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'system' ? 'active' : ''}`}
            onClick={() => { setActiveTab('system'); fetchSystemHealth(); setIsMobileMenuOpen(false); }}
          >
            <span className="nav-icon">⚙️</span>
            <span className="nav-text">System Health</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => { setActiveTab('settings'); fetchSystemSettings(); setIsMobileMenuOpen(false); }}
          >
            <span className="nav-icon">🔧</span>
            <span className="nav-text">Settings</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'hotspot' ? 'active' : ''}`}
            onClick={() => { setActiveTab('hotspot'); setIsMobileMenuOpen(false); }}
          >
            <span className="nav-icon">📡</span>
            <span className="nav-text">Hotspot</span>
          </button>
        </nav>
        {!isMobile && (
          <div style={{
            textAlign: 'center',
            paddingTop: '1rem',
            paddingBottom: '1rem',
            borderTop: '1px solid #333'
          }}>
            <a 
              href="/"
              onClick={() => setIsMobileMenuOpen(false)}
              style={{
                color: '#646cff',
                textDecoration: 'none',
                fontWeight: 600
              }}
              onMouseEnter={(e) => e.target.style.textDecoration = 'underline'}
              onMouseLeave={(e) => e.target.style.textDecoration = 'none'}
            >
              Device Status
            </a>
          </div>
        )}
      </aside>

      <main className="main-content" style={isMobile ? { paddingBottom: '80px' } : {}}>

      {activeTab === 'traffic' && (
        <>
          <div className="stats-summary">
            <div className="stat-card">
              <h3>Current Rate</h3>
              <p className="stat-value">
                {trafficHistory.length > 0 ? formatBytes(trafficHistory[trafficHistory.length - 1]) : '0 B'}/s
              </p>
            </div>
            <div className="stat-card">
              <h3>Peak Rate</h3>
              <p className="stat-value">
                {trafficHistory.length > 0 ? formatBytes(Math.max(...trafficHistory)) : '0 B'}/s
              </p>
            </div>
            <div className="stat-card">
              <h3>Average Rate</h3>
              <p className="stat-value">
                {trafficHistory.length > 0 
                  ? formatBytes(Math.round(trafficHistory.reduce((a, b) => a + b, 0) / trafficHistory.length))
                  : '0 B'}/s
              </p>
            </div>
            <div className="stat-card">
              <h3>History</h3>
              <p className="stat-value">{trafficHistory.length}s</p>
            </div>
          </div>

          <div className="traffic-graph-container">
            <h2 style={{ color: '#646cff', marginBottom: '1rem' }}>Network Traffic Monitor</h2>
            <p style={{ color: '#888', marginBottom: '1rem', fontSize: '0.9rem' }}>
              Real-time download rate (bytes/second) - Logarithmic scale, Max: 1 Gbps
            </p>
            <TrafficGraph 
              data={trafficHistory} 
              onWidthChange={(width) => setMaxHistoryLength(width)}
            />
          </div>
        </>
      )}

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

      {activeTab === 'logs' && (
        <>
          <div className="controls">
            <div className="user-tabs">
              <button 
                className={`user-tab ${logsSubTab === 'blocked' ? 'active' : ''}`}
                onClick={() => setLogsSubTab('blocked')}
              >
                🚫 Blocked Domains
              </button>
              <button 
                className={`user-tab ${logsSubTab === 'encrypted' ? 'active' : ''}`}
                onClick={() => setLogsSubTab('encrypted')}
              >
                🔒 Encrypted DNS
              </button>
              <button 
                className={`user-tab ${logsSubTab === 'dns' ? 'active' : ''}`}
                onClick={() => setLogsSubTab('dns')}
              >
                🌐 DNS Requests
              </button>
            </div>
          </div>

          {logsSubTab === 'dns' && (
            <>
              <div className="controls">
                <div className="log-filters">
                  <input 
                    type="date" 
                    value={logFilterDate}
                    onChange={(e) => setLogFilterDate(e.target.value)}
                    className="filter-input"
                    placeholder="Filter by date"
                  />
                  <select 
                    value={logFilterType}
                    onChange={(e) => {
                      setLogFilterType(e.target.value)
                      setLogFilterValue('')
                    }}
                    className="filter-input"
                  >
                    <option value="">All Entries</option>
                    <option value="user">Filter by User</option>
                    <option value="device">Filter by Device</option>
                  </select>
                  {logFilterType === 'user' && (
                    <select 
                      value={logFilterValue}
                      onChange={(e) => setLogFilterValue(e.target.value)}
                      className="filter-input"
                    >
                      <option value="">Select User</option>
                      {users.map(user => (
                        <option key={user.id} value={user.id}>
                          {user.display_name} ({user.username})
                        </option>
                      ))}
                    </select>
                  )}
                  {logFilterType === 'device' && (
                    <select 
                      value={logFilterValue}
                      onChange={(e) => setLogFilterValue(e.target.value)}
                      className="filter-input"
                    >
                      <option value="">Select Device</option>
                      {users.flatMap(user => 
                        (user.devices || []).map(device => ({
                          mac: device.mac_address,
                          name: `${device.device_name || 'Unnamed'} (${user.display_name})`
                        }))
                      ).map((device, idx) => (
                        <option key={idx} value={device.mac}>
                          {device.name}
                        </option>
                      ))}
                    </select>
                  )}
                </div>
                <div style={{display: 'flex', gap: '10px'}}>
                  <button onClick={fetchDNSRequests} className="btn btn-primary">
                    🔄 Refresh
                  </button>
                  <button onClick={clearDNSRequests} className="btn btn-danger">
                    🗑️ Clear All
                  </button>
                </div>
              </div>

              <div className="stats-summary">
                <div className="stat-card">
                  <h3>Total DNS Requests</h3>
                  <p className="stat-value">{dnsRequests.length}</p>
                </div>
              </div>

              <div className="packet-table-container">
                <table className="packet-table dns-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Domain</th>
                      <th>Type</th>
                      <th>User</th>
                      <th>Device</th>
                      <th>MAC Address</th>
                      <th>IP Address</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dnsRequests.length === 0 ? (
                      <tr>
                        <td colSpan="8" className="no-data">No DNS requests captured yet</td>
                      </tr>
                    ) : (
                      [...dnsRequests]
                        .reverse()
                        .map((req, idx) => (
                          <tr key={idx}>
                            <td>{formatTimestamp(req.timestamp)}</td>
                            <td className="domain-name">{req.domain}</td>
                            <td><span className="protocol-badge">{req.query_type}</span></td>
                            <td>{req.user_name || 'Unknown'}</td>
                            <td>{req.device_name || 'Unnamed'}</td>
                            <td>{req.src_mac || '-'}</td>
                            <td>{req.src_ip}</td>
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

          {logsSubTab === 'blocked' && (
            <>
              <div className="controls">
                <div className="log-filters">
                  <input 
                    type="date" 
                    value={logFilterDate}
                    onChange={(e) => setLogFilterDate(e.target.value)}
                    className="filter-input"
                    placeholder="Filter by date"
                  />
                  <select 
                    value={logFilterType}
                    onChange={(e) => {
                      setLogFilterType(e.target.value)
                      setLogFilterValue('')
                    }}
                    className="filter-input"
                  >
                    <option value="">All Entries</option>
                    <option value="user">Filter by User</option>
                    <option value="device">Filter by Device</option>
                  </select>
                  {logFilterType === 'user' && (
                    <select 
                      value={logFilterValue}
                      onChange={(e) => setLogFilterValue(e.target.value)}
                      className="filter-input"
                    >
                      <option value="">Select User</option>
                      {users.map(user => (
                        <option key={user.id} value={user.id}>
                          {user.display_name} ({user.username})
                        </option>
                      ))}
                    </select>
                  )}
                  {logFilterType === 'device' && (
                    <select 
                      value={logFilterValue}
                      onChange={(e) => setLogFilterValue(e.target.value)}
                      className="filter-input"
                    >
                      <option value="">Select Device</option>
                      {users.flatMap(user => 
                        (user.devices || []).map(device => ({
                          mac: device.mac_address,
                          name: `${device.device_name || 'Unnamed'} (${user.display_name})`
                        }))
                      ).map((device, idx) => (
                        <option key={idx} value={device.mac}>
                          {device.name}
                        </option>
                      ))}
                    </select>
                  )}
                </div>
                <div style={{display: 'flex', gap: '10px'}}>
                  <button onClick={fetchBlockedLogs} className="btn btn-primary">
                    🔄 Refresh
                  </button>
                  <button onClick={clearBlockedLogs} className="btn btn-danger">
                    🗑️ Clear All
                  </button>
                </div>
              </div>

              <div className="stats-summary">
                <div className="stat-card">
                  <h3>Total Log Entries</h3>
                  <p className="stat-value">{blockedLogs.length}</p>
                </div>
              </div>

              <div className="packet-table-container">
                <table className="packet-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Domain</th>
                      <th>Type</th>
                      <th>User</th>
                      <th>Device</th>
                      <th>MAC Address</th>
                      <th>IP Address</th>
                    </tr>
                  </thead>
                  <tbody>
                    {blockedLogs.length === 0 ? (
                      <tr>
                        <td colSpan="7" className="no-data">No blocked domain logs found</td>
                      </tr>
                    ) : (
                      blockedLogs.map((log) => (
                        <tr key={log.id}>
                          <td>{new Date(log.blocked_at).toLocaleString()}</td>
                          <td className="domain-name">{log.domain}</td>
                          <td><span className="protocol-badge">{log.query_type || 'A'}</span></td>
                          <td>{log.user_name || 'Unknown'}</td>
                          <td>{log.device_name || 'Unnamed'}</td>
                          <td>{log.device_mac}</td>
                          <td>{log.ip_address || 'N/A'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {logsSubTab === 'encrypted' && (
            <>
              <div className="controls">
                <div className="log-filters">
                  <input 
                    type="date" 
                    value={logFilterDate}
                    onChange={(e) => setLogFilterDate(e.target.value)}
                    className="filter-input"
                    placeholder="Filter by date"
                  />
                  <select 
                    value={logFilterType}
                    onChange={(e) => {
                      setLogFilterType(e.target.value)
                      setLogFilterValue('')
                    }}
                    className="filter-input"
                  >
                    <option value="">All Entries</option>
                    <option value="user">Filter by User</option>
                    <option value="device">Filter by Device</option>
                  </select>
                  {logFilterType === 'user' && (
                    <select 
                      value={logFilterValue}
                      onChange={(e) => setLogFilterValue(e.target.value)}
                      className="filter-input"
                    >
                      <option value="">Select User</option>
                      {users.map(user => (
                        <option key={user.id} value={user.id}>
                          {user.display_name} ({user.username})
                        </option>
                      ))}
                    </select>
                  )}
                  {logFilterType === 'device' && (
                    <select 
                      value={logFilterValue}
                      onChange={(e) => setLogFilterValue(e.target.value)}
                      className="filter-input"
                    >
                      <option value="">Select Device</option>
                      {users.flatMap(user => 
                        (user.devices || []).map(device => ({
                          mac: device.mac_address,
                          name: `${device.device_name || 'Unnamed'} (${user.display_name})`
                        }))
                      ).map((device, idx) => (
                        <option key={idx} value={device.mac}>
                          {device.name}
                        </option>
                      ))}
                    </select>
                  )}
                </div>
                <div style={{display: 'flex', gap: '10px'}}>
                  <button onClick={fetchEncryptedDNSLogs} className="btn btn-primary">
                    🔄 Refresh
                  </button>
                  <button onClick={clearEncryptedDNSLogs} className="btn btn-danger">
                    🗑️ Clear All
                  </button>
                </div>
              </div>

              <div className="stats-summary">
                <div className="stat-card">
                  <h3>Total Encrypted DNS Blocks</h3>
                  <p className="stat-value">{encryptedDNSLogs.length}</p>
                </div>
              </div>

              <div className="packet-table-container">
                <table className="packet-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>DNS Server IP</th>
                      <th>Type</th>
                      <th>User</th>
                      <th>Device</th>
                      <th>Device IP</th>
                      <th>MAC Address</th>
                    </tr>
                  </thead>
                  <tbody>
                    {encryptedDNSLogs.length === 0 ? (
                      <tr>
                        <td colSpan="7" className="no-data">No encrypted DNS blocks captured yet</td>
                      </tr>
                    ) : (
                      encryptedDNSLogs.map((log, idx) => (
                        <tr key={idx}>
                          <td>{new Date(log.blocked_at).toLocaleString()}</td>
                          <td className="domain-name">{log.dns_server_ip}</td>
                          <td>
                            <span className="protocol protocol-tcp">{log.protocol}</span>
                          </td>
                          <td>{log.user_name || '-'}</td>
                          <td>{log.device_name || '-'}</td>
                          <td className="ip-address">{log.device_ip || '-'}</td>
                          <td className="ip-address">{log.device_mac}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}

      {activeTab === 'users' && (
        <>
          <div className="controls">
            <div className="user-tabs">
              <button 
                className={`user-tab ${usersSubTab === 'manage' ? 'active' : ''}`}
                onClick={() => setUsersSubTab('manage')}
              >
                👥 Manage Users
              </button>
              <button 
                className={`user-tab ${usersSubTab === 'devices' ? 'active' : ''}`}
                onClick={() => setUsersSubTab('devices')}
              >
                📱 Unregistered Devices
              </button>
            </div>
            <div style={{display: 'flex', gap: '0.5rem'}}>
              {usersSubTab === 'devices' && unregisteredDevices.length > 0 && (
                <button onClick={forgetAllUnregisteredDevices} className="btn btn-danger">
                  🗑️ Forget All
                </button>
              )}
              <button onClick={usersSubTab === 'manage' ? fetchUsers : fetchUnregisteredDevices} className="btn btn-primary">
                🔄 Refresh
              </button>
            </div>
          </div>

          {usersSubTab === 'manage' && (
          <div className="users-layout">
            <div className="users-list">
              <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem'}}>
                <h2>Users</h2>
                <button onClick={() => setShowCreateUserModal(true)} className="btn btn-success">
                  ➕ Create User
                </button>
              </div>
              <div className="user-cards">
                {users.length === 0 ? (
                  <div className="no-data">No users found</div>
                ) : (
                  users.map((user) => (
                    <div 
                      key={user.id} 
                      className={`user-card ${selectedUser?.id === user.id ? 'selected' : ''}`}
                      onClick={() => selectUser(user)}
                    >
                      <div className="user-card-header">
                        <span className="user-icon">👤</span>
                        <div className="user-details">
                          <div className="user-name">{user.display_name || user.username}</div>
                          <div className="user-username">@{user.username}</div>
                        </div>
                        <button 
                          onClick={(e) => { e.stopPropagation(); deleteUser(user.id, user.username); }}
                          className="btn btn-small btn-danger"
                          style={{marginLeft: 'auto'}}
                        >
                          🗑️
                        </button>
                      </div>
                      {user.devices && user.devices.length > 0 && (
                        <div className="user-ips">
                          {user.devices.map((device, idx) => (
                            <span key={idx} className="ip-badge">{device.mac_address}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="user-blocked-domains">
              {selectedUser ? (
                <>
                  <h2>Manage {selectedUser.display_name || selectedUser.username}</h2>
                  
                  {/* User Settings */}
                  <div className="user-section">
                    <h3>⚙️ User Settings</h3>
                    <div className="controls" style={{marginBottom: '1rem'}}>
                      <div className="add-domain-form">
                        <input 
                          type="password" 
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                          placeholder="New Password"
                          className="domain-input"
                        />
                        <button onClick={updateUserPassword} className="btn btn-primary">
                          🔑 Change Password
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* MAC Address Management */}
                  <div className="user-section">
                    <h3>📱 Registered Devices</h3>

                    <div className="ip-list">
                      {selectedUser.devices && selectedUser.devices.length > 0 ? (
                        selectedUser.devices.map((device) => (
                          <div key={device.id} className="ip-item device-item">
                            <div className="device-content">
                              <div className="device-main-info">
                                <span className="ip-address mac-address">{device.mac_address}</span>
                                {device.ip_address && (
                                  <span className="ip-address ip-addr">({device.ip_address})</span>
                                )}
                              </div>
                              
                              <div className="device-name-container">
                                {editingDeviceName === device.id ? (
                                  <div className="device-edit-form">
                                    <input 
                                      type="text"
                                      value={editDeviceNameValue}
                                      onChange={(e) => setEditDeviceNameValue(e.target.value)}
                                      onKeyPress={(e) => e.key === 'Enter' && updateDeviceName(device.id, editDeviceNameValue)}
                                      placeholder="Device name"
                                      className="domain-input device-name-input"
                                      autoFocus
                                    />
                                    <div className="device-edit-actions">
                                      <button 
                                        onClick={() => updateDeviceName(device.id, editDeviceNameValue)}
                                        className="btn btn-small btn-success"
                                      >
                                        ✓
                                      </button>
                                      <button 
                                        onClick={() => { setEditingDeviceName(null); setEditDeviceNameValue(''); }}
                                        className="btn btn-small btn-danger"
                                      >
                                        ✕
                                      </button>
                                    </div>
                                  </div>
                                ) : (
                                  <div className="device-name-display">
                                    <span className="device-name-text">
                                      {device.device_name || 'Unnamed device'}
                                    </span>
                                    <button 
                                      onClick={() => { 
                                        setEditingDeviceName(device.id); 
                                        setEditDeviceNameValue(device.device_name || ''); 
                                      }}
                                      className="btn btn-small btn-primary edit-btn"
                                    >
                                      ✏️
                                    </button>
                                  </div>
                                )}
                              </div>
                            </div>

                            <div className="device-meta">
                              <span className="ip-date">
                                Added: {new Date(device.created_at).toLocaleDateString()}
                              </span>
                              <button 
                                onClick={() => removeUserMAC(selectedUser.id, device.id)} 
                                className="btn btn-small btn-danger delete-btn"
                              >
                                🗑️
                              </button>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="no-data">No devices registered</div>
                      )}
                    </div>
                  </div>

                  {/* Blocked Domains Management */}
                  <div className="user-section">
                    <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem'}}>
                      <h3>🚫 Blocked Domains</h3>
                      <label className="switch">
                        <input 
                          type="checkbox" 
                          checked={selectedUser.enable_blocking}
                          onChange={async () => {
                            try {
                              const res = await fetch(`/api/users/${selectedUser.id}/blocking`, {
                                method: 'PUT',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ enable_blocking: !selectedUser.enable_blocking })
                              })
                              if (res.ok) {
                                // Fetch the full user with devices
                                await fetchUsers()
                                const userRes = await fetch(`/api/users/${selectedUser.id}`)
                                if (userRes.ok) {
                                  const fullUser = await userRes.json()
                                  setSelectedUser(fullUser)
                                }
                              }
                            } catch (error) {
                              console.error('Error toggling blocking:', error)
                            }
                          }}
                        />
                        <span className="slider round"></span>
                      </label>
                    </div>
                    <p className="setting-description" style={{marginBottom: '1rem'}}>
                      Enable or disable domain blocking for this user. When disabled, their blocked domain list is preserved but not enforced.
                      {selectedUser.enable_blocking ? <span style={{color: '#27ae60', fontWeight: 'bold', marginLeft: '0.5rem'}}>Currently Enabled</span> : <span style={{color: '#e74c3c', fontWeight: 'bold', marginLeft: '0.5rem'}}>Currently Disabled</span>}
                    </p>

                    {selectedUser.enable_blocking && (
                      <>
                        <div className="controls domain-controls-container" style={{marginBottom: '1rem'}}>
                          <div className="add-domain-form">
                            <input 
                              type="text" 
                              value={newUserDomain}
                              onChange={(e) => setNewUserDomain(e.target.value)}
                              onKeyPress={(e) => e.key === 'Enter' && addUserDomain()}
                              placeholder="Enter domain to block for this user"
                              className="domain-input"
                            />
                            <button onClick={addUserDomain} className="btn btn-success">
                              ➕ Add
                            </button>
                            <button onClick={() => fetchUserBlockedDomains(selectedUser.id)} className="btn btn-primary refresh-btn-mobile">
                              <span className="refresh-icon">🔄</span>
                              <span className="refresh-text">Refresh</span>
                            </button>
                          </div>
                        </div>

                        <div className="stats-summary">
                          <div className="stat-card">
                            <h3>Total Blocked Domains</h3>
                            <p className="stat-value">{userBlockedDomains.length}</p>
                          </div>
                        </div>

                        <div className="packet-table-container">
                          <table className="packet-table user-blocked-table">
                            <thead>
                              <tr>
                                <th className="col-domain">Domain</th>
                                <th className="col-action">Action</th>
                              </tr>
                            </thead>
                            <tbody>
                              {userBlockedDomains.length === 0 ? (
                                <tr>
                                  <td colSpan="2" className="no-data">No domains blocked for this user</td>
                                </tr>
                              ) : (
                                userBlockedDomains.map((item) => (
                                <tr key={item.id}>
                                  <td className="domain-name">{item.domain}</td>
                                  <td>
                                    <button 
                                      onClick={() => unblockDomainForUser(selectedUser.id, item.id, item.domain)} 
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
                </div>
              </>
            ) : (
              <div className="no-user-selected">
                <div className="no-user-icon">👈</div>
                <h3>Select a user to manage IP addresses and blocked domains</h3>
                <p>Choose a user from the list on the left to view and manage their settings</p>
              </div>
            )}
          </div>
          </div>
          )}

          {usersSubTab === 'devices' && (
            <div className="devices-section">
              <div className="stats-summary">
                <div className="stat-card">
                  <h3>Unregistered Devices</h3>
                  <p className="stat-value">{unregisteredDevices.length}</p>
                </div>
              </div>

              <div className="packet-table-container">
                <table className="packet-table">
                  <thead>
                    <tr>
                      <th>MAC Address</th>
                      <th>IP Address</th>
                      <th>First Seen</th>
                      <th>Last Seen</th>
                      <th>Attempts</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {unregisteredDevices.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="no-data">No unregistered devices detected</td>
                      </tr>
                    ) : (
                      unregisteredDevices.map((device, idx) => (
                        <tr key={idx}>
                          <td className="ip-address" style={{fontFamily: 'Courier New, monospace', color: '#f59e0b'}}>{device.mac_address}</td>
                          <td className="ip-address" style={{fontFamily: 'Courier New, monospace', color: '#888'}}>{device.ip_address || '-'}</td>
                          <td>{new Date(device.first_seen).toLocaleString()}</td>
                          <td>{new Date(device.last_seen).toLocaleString()}</td>
                          <td>{device.attempt_count}</td>
                          <td>
                            <div style={{display: 'flex', gap: '0.5rem'}}>
                              <select 
                                onChange={(e) => {
                                  if (e.target.value) {
                                    registerDeviceToUser(device.mac_address, parseInt(e.target.value))
                                    e.target.value = ''
                                  }
                                }}
                                className="user-select"
                                style={{flex: 1}}
                              >
                                <option value="">Assign to user...</option>
                                {users.map(user => (
                                  <option key={user.id} value={user.id}>{user.display_name}</option>
                                ))}
                              </select>
                              <button 
                                onClick={() => forgetUnregisteredDevice(device.mac_address)}
                                className="btn btn-danger"
                                style={{padding: '0.25rem 0.5rem', fontSize: '0.8rem'}}
                                title="Forget Device"
                              >
                                Forget
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {activeTab === 'system' && (
        <>
          <div className="controls">
            <h2>System Health</h2>
            <button onClick={fetchSystemHealth} className="btn btn-primary">
              🔄 Refresh
            </button>
          </div>

          {systemHealth ? (
            <div className="stats-summary">
              <div className="stat-card">
                <h3>CPU Usage</h3>
                <p className="stat-value">{systemHealth.cpu_usage || 'N/A'}%</p>
              </div>
              <div className="stat-card">
                <h3>Memory</h3>
                <p className="stat-value">{systemHealth.memory_usage || 'N/A'}%</p>
                <p style={{fontSize: '0.85rem', color: '#888', marginTop: '0.5rem'}}>
                  {systemHealth.memory_used} / {systemHealth.memory_total}
                </p>
              </div>
              <div className="stat-card">
                <h3>Disk Usage</h3>
                <p className="stat-value">{systemHealth.disk_usage || 'N/A'}</p>
                <p style={{fontSize: '0.85rem', color: '#888', marginTop: '0.5rem'}}>
                  {systemHealth.disk_used} / {systemHealth.disk_total}
                </p>
              </div>
              <div className="stat-card">
                <h3>Network Status</h3>
                <p className="stat-value">
                  {systemHealth.network_online ? '🟢 Online' : '🔴 Offline'}
                </p>
              </div>
              <div className="stat-card">
                <h3>System Uptime</h3>
                <p className="stat-value" style={{fontSize: '1rem'}}>
                  {systemHealth.uptime || 'N/A'}
                </p>
              </div>
            </div>
          ) : (
            <div className="no-data">Loading system information...</div>
          )}

          {systemHealth && systemHealth.namespaces && (
            <>
              <h3 style={{marginTop: '2rem', marginBottom: '1rem', color: '#888'}}>Network Topology</h3>
              <div className="network-diagram-container" style={{ padding: '20px', background: 'rgba(255,255,255,0.02)', borderRadius: '12px' }}>
                <svg width="1050" height="420" viewBox="0 0 1050 420">
                  <defs>
                    <marker id="arrow" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto" markerUnits="strokeWidth">
                      <path d="M0,0 L0,6 L9,3 z" fill="#666" />
                    </marker>
                    <marker id="arrow-start" markerWidth="10" markerHeight="10" refX="0" refY="3" orient="auto" markerUnits="strokeWidth">
                      <path d="M9,0 L9,6 L0,3 z" fill="#666" />
                    </marker>
                  </defs>

                  {/* 1. ethns (Internet) - x=100 (Shifted Right for Badge) */}
                    <rect x="100" y="20" width="180" height="160" rx="8" fill="#1a1a2e" stroke={systemHealth.namespaces['ethns']?.exists ? '#4cd964' : '#ff3b30'} strokeWidth="2" />
                    <text x="190" y="45" textAnchor="middle" fill="#fff" fontWeight="bold">Internet Gateway</text>
                    <text x="190" y="65" textAnchor="middle" fill="#aaa" fontSize="12" fontFamily="monospace">ns: ethns</text>
                    
                    {/* IP Field */}
                    {systemHealth.namespaces['ethns']?.ip_address && (
                        <>
                            <rect x="130" y="75" width="120" height="20" rx="4" fill="#000" stroke="#666" strokeWidth="1" />
                            <text x="190" y="89" textAnchor="middle" fill="#fff" fontSize="10" fontFamily="monospace">
                                {systemHealth.namespaces['ethns'].ip_address}
                            </text>
                        </>
                    )}

                    <rect x="130" y="105" width="120" height="25" rx="4" fill="rgba(255,255,255,0.05)" stroke="none" />
                    <text x="190" y="122" textAnchor="middle" fill="#ddd" fontSize="11">br0 / veth-eth</text>

                    {/* Interface Badge (Left Border - "Sticking Out") */}
                    {/* Main Box starts at 100. Badge Width 80. Overlap ~15px -> x = 100 - 80 + 15 = 35 */}
                    <rect x="35" y="135" width="80" height="24" rx="4" fill="#2c2c2e" stroke="#00D8FF" strokeWidth="1" style={{filter: 'drop-shadow(2px 2px 2px rgba(0,0,0,0.5))'}} />
                    <text x="75" y="151" textAnchor="middle" fill="#00D8FF" fontSize="11" fontWeight="bold">
                        {systemHealth.internet_interface || '?'}
                    </text>

                  {/* Arrow ethns -> kidosns (280 -> 330) */}
                  <line x1="280" y1="100" x2="330" y2="100" stroke="#666" strokeWidth="2" markerEnd="url(#arrow)" markerStart="url(#arrow-start)" />

                  {/* 2. kidosns (Core) - x=330 */}
                    <rect x="330" y="20" width="180" height="160" rx="8" fill="#1a1a2e" stroke={systemHealth.namespaces['kidosns']?.exists ? '#4cd964' : '#ff3b30'} strokeWidth="2" />
                    <text x="420" y="45" textAnchor="middle" fill="#fff" fontWeight="bold">Core Firewall</text>
                    <text x="420" y="65" textAnchor="middle" fill="#aaa" fontSize="12" fontFamily="monospace">ns: kidosns</text>
                    
                     {/* IP Field */}
                    {systemHealth.namespaces['kidosns']?.ip_address && (
                        <>
                            <rect x="360" y="75" width="120" height="20" rx="4" fill="#000" stroke="#666" strokeWidth="1" />
                            <text x="420" y="89" textAnchor="middle" fill="#fff" fontSize="10" fontFamily="monospace">
                                {systemHealth.namespaces['kidosns'].ip_address}
                            </text>
                        </>
                    )}

                    <rect x="345" y="105" width="150" height="25" rx="4" 
                          fill={systemHealth.namespaces['kidosns']?.xdp ? "rgba(76, 217, 100, 0.2)" : "rgba(255, 59, 48, 0.2)"} 
                          stroke={systemHealth.namespaces['kidosns']?.xdp ? "#4cd964" : "#ff3b30"} />
                    <text x="420" y="122" textAnchor="middle" fill={systemHealth.namespaces['kidosns']?.xdp ? "#4cd964" : "#ff3b30"} fontSize="11" fontWeight="bold">
                        XDP: {systemHealth.namespaces['kidosns']?.xdp ? 'ACTIVE' : 'INACTIVE'}
                    </text>
                   
                  
                   {/* Arrow kidosns -> switchns (510 -> 560) */}
                  <line x1="510" y1="100" x2="560" y2="100" stroke="#666" strokeWidth="2" markerEnd="url(#arrow)" markerStart="url(#arrow-start)" />

                  {/* 3. switchns (Switch) - x=560 */}
                    <rect x="560" y="20" width="180" height="160" rx="8" fill="#1a1a2e" stroke={systemHealth.namespaces['switchns']?.exists ? '#4cd964' : '#ff3b30'} strokeWidth="2" />
                    <text x="650" y="45" textAnchor="middle" fill="#fff" fontWeight="bold">Switch</text>
                    <text x="650" y="65" textAnchor="middle" fill="#aaa" fontSize="12" fontFamily="monospace">ns: switchns</text>
                    
                    {/* IP Field */}
                    {systemHealth.namespaces['switchns']?.ip_address && (
                        <>
                            <rect x="590" y="75" width="120" height="20" rx="4" fill="#000" stroke="#666" strokeWidth="1" />
                            <text x="650" y="89" textAnchor="middle" fill="#fff" fontSize="10" fontFamily="monospace">
                                {systemHealth.namespaces['switchns'].ip_address}
                            </text>
                        </>
                    )}

                  {/* Arrow switchns -> appsns (740 -> 790) */}
                  <line x1="740" y1="100" x2="790" y2="100" stroke="#666" strokeWidth="2" markerEnd="url(#arrow)" markerStart="url(#arrow-start)" />

                   {/* 4. appsns (Apps) - x=790 */}
                    <rect x="790" y="20" width="180" height="160" rx="8" fill="#1a1a2e" stroke={systemHealth.namespaces['appsns']?.exists ? '#4cd964' : '#ff3b30'} strokeWidth="2" />
                    <text x="880" y="45" textAnchor="middle" fill="#fff" fontWeight="bold">Applications</text>
                    <text x="880" y="65" textAnchor="middle" fill="#aaa" fontSize="12" fontFamily="monospace">ns: appsns</text>
                    
                    {/* IP Field */}
                     {systemHealth.namespaces['appsns']?.ip_address && (
                        <>
                            <rect x="820" y="75" width="120" height="20" rx="4" fill="#000" stroke="#666" strokeWidth="1" />
                            <text x="880" y="89" textAnchor="middle" fill="#fff" fontSize="10" fontFamily="monospace">
                                {systemHealth.namespaces['appsns'].ip_address}
                            </text>
                        </>
                    )}
                    
                    <circle cx="880" cy="115" r="6" fill={systemHealth.namespaces['appsns']?.exists ? '#4cd964' : '#ff3b30'} />

                  {/* 5. wifins (Hotspot) - Below Switch. x=560 */}
                  {systemHealth.namespaces['wifins']?.exists && (
                    <>
                      {/* Vertical line connection 650 -> 650 */}
                      <line x1="650" y1="180" x2="650" y2="230" stroke="#666" strokeWidth="2" markerEnd="url(#arrow)" markerStart="url(#arrow-start)" />
                      
                      <rect x="560" y="230" width="180" height="160" rx="8" fill="#1a1a2e" stroke="#4cd964" strokeWidth="2" style={{filter: 'drop-shadow(0 0 5px rgba(76,217,100,0.3))'}} />
                      <text x="650" y="255" textAnchor="middle" fill="#fff" fontWeight="bold">Wi-Fi Hotspot</text>
                      <text x="650" y="275" textAnchor="middle" fill="#aaa" fontSize="12" fontFamily="monospace">ns: wifins</text>
                      
                       {/* IP Field */}
                      {systemHealth.namespaces['wifins']?.ip_address && (
                        <>
                            <rect x="590" y="285" width="120" height="20" rx="4" fill="#000" stroke="#666" strokeWidth="1" />
                            <text x="650" y="299" textAnchor="middle" fill="#fff" fontSize="10" fontFamily="monospace">
                                {systemHealth.namespaces['wifins'].ip_address}
                            </text>
                        </>
                    )}
                      
                      {/* Interface Badge (Right Border - "Sticking Out") */}
                      {/* Box ends at 560+180=740. Badge Width 80. Overlap ~15px -> x = 740 - 15 = 725 */}
                      <rect x="725" y="315" width="80" height="24" rx="4" fill="#2c2c2e" stroke="#00D8FF" strokeWidth="1" style={{filter: 'drop-shadow(2px 2px 2px rgba(0,0,0,0.5))'}} />
                      <text x="765" y="331" textAnchor="middle" fill="#00D8FF" fontSize="11" fontWeight="bold">
                        {systemHealth.wifi_interface || '?'}
                      </text>
                      
                      <rect x="590" y="330" width="120" height="25" rx="4" 
                            fill={systemHealth.namespaces['wifins']?.hostapd ? "rgba(76, 217, 100, 0.2)" : "rgba(255, 59, 48, 0.2)"} 
                            stroke={systemHealth.namespaces['wifins']?.hostapd ? "#4cd964" : "#ff3b30"} />
                      <text x="650" y="347" textAnchor="middle" fill={systemHealth.namespaces['wifins']?.hostapd ? "#4cd964" : "#ff3b30"} fontSize="11" fontWeight="bold">
                          {systemHealth.namespaces['wifins']?.hostapd ? 'HOSTAPD RUNNING' : 'STOPPED'}
                      </text>
                    </>
                  )}
                </svg>
              </div>
            </>
          )}
        </>
      )}

      {activeTab === 'settings' && (
        <div className="settings-section">
          <h2>System Settings</h2>
          
          <div className="setting-card">
            <div className="setting-header">
              <h3>DNS over TLS (DoT)</h3>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={blockDoT} 
                  onChange={toggleBlockDoT}
                />
                <span className="slider round"></span>
              </label>
            </div>
            <p className="setting-description">
              Block DNS over TLS traffic on port 853. This prevents devices from bypassing DNS filtering by using encrypted DNS.
              {blockDoT ? <span className="status-blocked">Currently Blocked</span> : <span className="status-allowed">Currently Allowed</span>}
            </p>
          </div>

          <div className="setting-card">
            <div className="setting-header">
              <h3>DNS over QUIC (DoQ)</h3>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={blockDoQ} 
                  onChange={toggleBlockDoQ}
                />
                <span className="slider round"></span>
              </label>
            </div>
            <p className="setting-description">
              Block DNS over QUIC traffic on ports 853 and 784. This prevents devices from bypassing DNS filtering by using encrypted DNS over UDP.
              {blockDoQ ? <span className="status-blocked">Currently Blocked</span> : <span className="status-allowed">Currently Allowed</span>}
            </p>
          </div>

          <div className="setting-card">
            <div className="setting-header">
              <h3>DNS over HTTPS (DoH)</h3>
              <label className="switch">
                <input 
                  type="checkbox" 
                  checked={blockDoH} 
                  onChange={toggleBlockDoH}
                />
                <span className="slider round"></span>
              </label>
            </div>
            <p className="setting-description">
              Block known DNS over HTTPS providers on port 443. This prevents devices from bypassing DNS filtering by using encrypted DNS over HTTPS.
              {blockDoH ? <span className="status-blocked">Currently Blocked</span> : <span className="status-allowed">Currently Allowed</span>}
            </p>

            {blockDoH && (
              <div className="doh-providers-section" style={{marginTop: '1.5rem', borderTop: '1px solid #333', paddingTop: '1rem'}}>
                <h4>Blocked DoH Providers</h4>
                
                <div className="add-domain-form" style={{marginBottom: '1rem'}}>
                  <input 
                    type="text" 
                    value={newDoHProvider.name}
                    onChange={(e) => setNewDoHProvider({...newDoHProvider, name: e.target.value})}
                    placeholder="Provider Name"
                    className="domain-input"
                    style={{flex: 1}}
                  />
                  <input 
                    type="text" 
                    value={newDoHProvider.ip_address}
                    onChange={(e) => setNewDoHProvider({...newDoHProvider, ip_address: e.target.value})}
                    placeholder="IP Address or CIDR"
                    className="domain-input"
                    style={{flex: 2}}
                  />
                  <button onClick={addDoHProvider} className="btn btn-primary">
                    Add
                  </button>
                </div>

                <div className="ip-list doh-list">
                  {[...dohProviders].sort((a, b) => {
                    // Manual providers first (is_system: false < true)
                    if (a.is_system !== b.is_system) {
                      return a.is_system ? 1 : -1
                    }
                    return a.name.localeCompare(b.name)
                  }).map((provider) => (
                    <div key={provider.id} className="ip-item doh-item">
                      <div className="ip-info">
                        <span className="doh-name">{provider.name}</span>
                        <span className="doh-ip">{provider.ip_address}</span>
                        {provider.is_system && <span className="system-badge">System</span>}
                      </div>
                      <div className="action-buttons">
                        {!provider.is_system && (
                          <button 
                            onClick={() => deleteDoHProvider(provider.id)} 
                            className="btn btn-small btn-danger"
                            title="Delete custom provider"
                            style={{ marginRight: '0.5rem' }}
                          >
                            🗑️
                          </button>
                        )}
                        <label className="switch small-switch">
                          <input 
                            type="checkbox" 
                            checked={provider.is_enabled} 
                            onChange={() => toggleDoHProviderEnabled(provider.id, provider.is_enabled)}
                          />
                          <span className="slider round"></span>
                        </label>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'hotspot' && (
        <div className="settings-section">
          <h2>Wi-Fi Hotspot</h2>
          
          {hotspotLoading ? (
             <div style={{
                display: 'flex', 
                justifyContent: 'center', 
                alignItems: 'center', 
                height: '200px', 
                color: '#aaa', 
                fontSize: '1.2rem',
                backgroundColor: '#1a1a2e',
                borderRadius: '8px',
                border: '1px solid #2a2a3e'
             }}>
                Loading hotspot details...
             </div>
          ) : (
          <>
          <div className="setting-card">
            <div className="setting-header">
              <h3>Hotspot Status</h3>
              <span className={`status ${hotspotStatus.running ? 'connected' : 'disconnected'}`}>
                {hotspotStatus.running ? '● Running' : '○ Stopped'}
              </span>
            </div>
            {hotspotStatus.running && hotspotStatus.clients && hotspotStatus.clients.length > 0 && (
              <div style={{marginTop: '1rem'}}>
                <strong>Connected Clients: {hotspotStatus.clients.length}</strong>
                <ul style={{marginTop: '0.5rem', paddingLeft: '1.5rem'}}>
                  {hotspotStatus.clients.map((client, idx) => (
                    <li key={idx} style={{fontFamily: 'monospace'}}>{client}</li>
                  ))}
                </ul>
              </div>
            )}
            <div style={{marginTop: '1rem', display: 'flex', gap: '0.5rem'}}>
              <button 
                onClick={startHotspot} 
                className="btn btn-success"
                disabled={hotspotStatus.running}
              >
                Start Hotspot
              </button>
              <button 
                onClick={stopHotspot} 
                className="btn btn-danger"
              >
                Stop Hotspot
              </button>
              <button 
                onClick={restartHotspot} 
                className="btn btn-primary"
                disabled={!hotspotStatus.running}
              >
                Restart Hotspot
              </button>
            </div>
          </div>

          <div className="setting-card">
            <h3>{hotspotStatus.running || isRestartingHotspot ? "Hotspot Details" : "Hotspot Configuration"}</h3>
            
            {hotspotStatus.running || isRestartingHotspot ? (
               <div style={{
                 display: 'flex', 
                 flexDirection: 'column', 
                 gap: '1rem', 
                 padding: '1rem', 
                 backgroundColor: 'rgba(255,255,255,0.05)', 
                 borderRadius: '8px',
                 opacity: isRestartingHotspot ? 0.3 : 1,
                 transition: 'opacity 0.5s ease-in-out',
                 pointerEvents: isRestartingHotspot ? 'none' : 'auto'
               }}>
                <div style={{display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '0.5rem'}}>
                  <span style={{color: '#ddd'}}>SSID</span>
                  <span style={{fontWeight: 'bold', color: '#fff'}}>{hotspotConfig.ssid}</span>
                </div>
                <div style={{display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '0.5rem'}}>
                  <span style={{color: '#ddd'}}>Interface</span>
                  <span style={{fontFamily: 'monospace', color: '#fff'}}>{hotspotConfig.interface}</span>
                </div>
                <div style={{display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '0.5rem'}}>
                  <span style={{color: '#ddd'}}>Channel</span>
                  <span style={{color: '#fff'}}>{hotspotConfig.channel}</span>
                </div>
                <div style={{display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '0.5rem'}}>
                  <span style={{color: '#ddd'}}>Security</span>
                  <span style={{color: '#fff'}}>{hotspotConfig.security}</span>
                </div>
                <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center'}}>
                  <span style={{color: '#ddd'}}>Password</span>
                  <div style={{display: 'flex', alignItems: 'center', gap: '10px'}}>
                     <span style={{fontFamily: 'monospace', letterSpacing: '1px', color: '#fff'}}>
                        {showHotspotPassword ? hotspotConfig.password : '••••••••'}
                     </span>
                     <button 
                        className="btn btn-small"
                        onClick={() => setShowHotspotPassword(!showHotspotPassword)}
                        style={{padding: '4px 8px', fontSize: '0.75rem'}}
                     >
                        {showHotspotPassword ? 'Hide' : 'Show'}
                     </button>
                  </div>
                </div>
              </div>
            ) : (
              <div style={{display: 'flex', flexDirection: 'column', gap: '1rem', padding: '1rem', backgroundColor: 'rgba(255,255,255,0.05)', borderRadius: '8px'}}>
            <div className="form-group">
              <label>Wi-Fi Interface</label>
              <div style={{display: 'flex', flexDirection: 'column', gap: '0.5rem'}}>
              <div style={{display: 'flex', gap: '0.5rem', alignItems: 'center'}}>
                <select 
                  value={hotspotConfig.interface}
                  onChange={(e) => setHotspotConfig({...hotspotConfig, interface: e.target.value})}
                  className="domain-input"
                  style={{flex: 1}}
                >
                  <option value="">Select interface...</option>
                  {wifiInterfaces.map(iface => (
                    <option 
                        key={iface.name} 
                        value={iface.name}
                        disabled={iface.has_ip}
                        style={iface.has_ip ? {color: '#999'} : {}}
                    >
                        {iface.name} {iface.has_ip ? '(Has IP - In Use)' : ''}
                    </option>
                  ))}
                </select>
                <button onClick={fetchWifiInterfaces} className="btn btn-small">
                  🔄 Refresh
                </button>
              </div>
                <small style={{color: '#aaa', fontSize: '0.8rem'}}>
                    Note: Interfaces with an IP address are in use. Stop the interface before creating a hotspot.
                </small>
              </div>
            </div>

            <div className="form-group">
              <label>SSID (Network Name)</label>
              <input 
                type="text" 
                value={hotspotConfig.ssid}
                onChange={(e) => setHotspotConfig({...hotspotConfig, ssid: e.target.value})}
                placeholder="Kidos-Hotspot"
                className="domain-input"
              />
            </div>

            <div className="form-group">
              <label>Password</label>
              <div style={{display: 'flex', gap: '0.5rem'}}>
                  <input 
                    type={showHotspotPassword ? "text" : "password"}
                    value={hotspotConfig.password}
                    onChange={(e) => setHotspotConfig({...hotspotConfig, password: e.target.value})}
                    placeholder="Minimum 8 characters"
                    className="domain-input"
                    minLength="8"
                    style={{flex: 1}}
                  />
                   <button 
                      className="btn btn-small"
                      onClick={() => setShowHotspotPassword(!showHotspotPassword)}
                      type="button"
                    >
                      {showHotspotPassword ? 'Hide' : 'Show'}
                    </button>
              </div>
            </div>

            <div className="form-group">
              <label>Channel</label>
              <select 
                value={hotspotConfig.channel}
                onChange={(e) => setHotspotConfig({...hotspotConfig, channel: e.target.value})}
                className="domain-input"
              >
                {[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map(ch => (
                  <option key={ch} value={ch}>{ch}</option>
                ))}
              </select>
            </div>

            <div className="form-group">
              <label>Security</label>
              <select 
                value={hotspotConfig.security}
                onChange={(e) => setHotspotConfig({...hotspotConfig, security: e.target.value})}
                className="domain-input"
              >
                <option value="WPA2">WPA2</option>
                <option value="WPA3">WPA3</option>
                <option value="WPA2/WPA3">WPA2/WPA3 Mixed</option>
              </select>
            </div>

            <button onClick={saveHotspotConfig} className="btn btn-primary" style={{marginTop: '0.5rem'}}>
              Save Configuration
            </button>
            </div>
            )}
          </div>
          </>
          )}
        </div>
      )}

      </main>

      {showCreateUserModal && (
        <div className="modal-overlay" onClick={() => setShowCreateUserModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h2>Create New User</h2>
            <div className="form-group">
              <label>Username</label>
              <input 
                type="text" 
                value={newUser.username}
                onChange={(e) => setNewUser({...newUser, username: e.target.value})}
                placeholder="Enter username (e.g., john)"
                className="domain-input"
              />
            </div>
            <div className="form-group">
              <label>Display Name</label>
              <input 
                type="text" 
                value={newUser.display_name}
                onChange={(e) => setNewUser({...newUser, display_name: e.target.value})}
                placeholder="Enter display name (e.g., John Doe)"
                className="domain-input"
              />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input 
                type="password" 
                value={newUser.password}
                onChange={(e) => setNewUser({...newUser, password: e.target.value})}
                placeholder="Enter password"
                className="domain-input"
              />
            </div>
            <div className="form-actions">
              <button onClick={() => setShowCreateUserModal(false)} className="btn btn-danger">
                Cancel
              </button>
              <button onClick={createUser} className="btn btn-success">
                Create User
              </button>
            </div>
          </div>
        </div>
      )}

      {isMobile && (
        <div className="mobile-footer" style={{
          position: 'fixed',
          bottom: '0 !important',
          left: 0,
          right: 0,
          padding: '1rem 1.5rem',
          borderTop: '1px solid #2a2a3e',
          backgroundColor: '#1a1a2e',
          zIndex: 1001,
          textAlign: 'center',
          order: 9999
        }}>
          <a 
            href="/"
            style={{
              color: '#646cff',
              textDecoration: 'none',
              fontWeight: 600
            }}
            onMouseEnter={(e) => e.target.style.textDecoration = 'underline'}
            onMouseLeave={(e) => e.target.style.textDecoration = 'none'}
          >
            Device Status
          </a>
        </div>
      )}
    </div>
  )
}

export default App

