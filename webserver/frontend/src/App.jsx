import { useState, useEffect, useRef } from 'react'
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
  const [activeTab, setActiveTab] = useState('packets')
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
    fetchDNSRequests()
    fetchBlockedDomains()
    fetchClientInfo()
    fetchUsers()
    fetchUnregisteredDevices()
    fetchSystemSettings()
    fetchDoHProviders()
  }, [])

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

  const unblockDomainForUser = async (userId, domainId) => {
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
          {clientIP && (
            <div className="client-info">
              <span className="client-ip">📍 {clientIP}</span>
              {userName && <span className="client-user">👤 {userName}</span>}
            </div>
          )}
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
            className={`nav-item ${activeTab === 'traffic' ? 'active' : ''}`}
            onClick={() => setActiveTab('traffic')}
          >
            <span className="nav-icon">📈</span>
            <span className="nav-text">Traffic Monitor</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'logs' ? 'active' : ''}`}
            onClick={() => setActiveTab('logs')}
          >
            <span className="nav-icon">📋</span>
            <span className="nav-text">Logs</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'users' ? 'active' : ''}`}
            onClick={() => setActiveTab('users')}
          >
            <span className="nav-icon">👥</span>
            <span className="nav-text">Users</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'system' ? 'active' : ''}`}
            onClick={() => { setActiveTab('system'); fetchSystemHealth(); }}
          >
            <span className="nav-icon">⚙️</span>
            <span className="nav-text">System Health</span>
          </button>
          <button 
            className={`nav-item ${activeTab === 'settings' ? 'active' : ''}`}
            onClick={() => { setActiveTab('settings'); fetchSystemSettings(); }}
          >
            <span className="nav-icon">🔧</span>
            <span className="nav-text">Settings</span>
          </button>
        </nav>
      </aside>

      <main className="main-content">

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
                          <div key={device.id} className="ip-item" style={{display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'nowrap', marginBottom: '0.75rem', padding: '0.5rem'}}>
                            <div style={{display: 'flex', alignItems: 'center', gap: '1rem', flex: 1, minWidth: 0}}>
                              <span className="ip-address" style={{fontFamily: 'Courier New, monospace', color: '#f59e0b', whiteSpace: 'nowrap'}}>{device.mac_address}</span>
                              {device.ip_address && (
                                <span className="ip-address" style={{fontFamily: 'Courier New, monospace', color: '#888', fontSize: '0.9rem', whiteSpace: 'nowrap'}}>({device.ip_address})</span>
                              )}
                              {editingDeviceName === device.id ? (
                                <div style={{display: 'flex', gap: '0.5rem', alignItems: 'center', flex: 1}}>
                                  <input 
                                    type="text"
                                    value={editDeviceNameValue}
                                    onChange={(e) => setEditDeviceNameValue(e.target.value)}
                                    onKeyPress={(e) => e.key === 'Enter' && updateDeviceName(device.id, editDeviceNameValue)}
                                    placeholder="Device name"
                                    className="domain-input"
                                    style={{flex: 1, padding: '0.5rem', fontSize: '0.9rem', minWidth: '150px'}}
                                    autoFocus
                                  />
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
                              ) : (
                                <>
                                  <span style={{color: '#9ca3af', fontSize: '0.9rem', whiteSpace: 'nowrap'}}>
                                    {device.device_name || 'Unnamed device'}
                                  </span>
                                  <button 
                                    onClick={() => { 
                                      setEditingDeviceName(device.id); 
                                      setEditDeviceNameValue(device.device_name || ''); 
                                    }}
                                    className="btn btn-small btn-primary"
                                    style={{padding: '0.25rem 0.5rem', fontSize: '0.75rem', whiteSpace: 'nowrap'}}
                                  >
                                    ✏️ Edit
                                  </button>
                                </>
                              )}
                            </div>
                            <span className="ip-date" style={{whiteSpace: 'nowrap', marginRight: '1rem', color: '#9ca3af'}}>Added: {new Date(device.created_at).toLocaleDateString()}</span>
                            <button 
                              onClick={() => removeUserMAC(selectedUser.id, device.id)} 
                              className="btn btn-small btn-danger"
                              style={{flexShrink: 0}}
                            >
                              🗑️
                            </button>
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
                        <div className="controls" style={{marginBottom: '1rem'}}>
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
                              ➕ Add Domain
                            </button>
                          </div>
                          <button onClick={() => fetchUserBlockedDomains(selectedUser.id)} className="btn btn-primary">
                            🔄 Refresh
                          </button>
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
                                <th style={{width: '80%'}}>Domain</th>
                                <th style={{width: '20%'}}>Action</th>
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
                                      onClick={() => unblockDomainForUser(selectedUser.id, item.id)} 
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
    </div>
  )
}

export default App

