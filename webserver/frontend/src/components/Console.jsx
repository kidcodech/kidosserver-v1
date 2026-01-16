import { useState, useEffect, useRef } from 'react'
import './Console.css'

function Console() {
  const [output, setOutput] = useState([])
  const [input, setInput] = useState('')
  const [history, setHistory] = useState([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const [ws, setWs] = useState(null)
  const [connected, setConnected] = useState(false)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [namespace, setNamespace] = useState('root')
  const [currentDir, setCurrentDir] = useState('~')
  const outputRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    // Connect to WebSocket
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const websocket = new WebSocket(`${protocol}//${window.location.host}/console`)

    websocket.onopen = () => {
      setConnected(true)
      setOutput(prev => [...prev, { type: 'system', text: 'Console connected. Type commands to execute on the router.' }])
    }

    websocket.onmessage = (event) => {
      const data = JSON.parse(event.data)
      console.log('[Console] Received message:', JSON.stringify(data))
      
      if (data.type === 'output') {
        setOutput(prev => [...prev, { type: 'output', text: data.data }])
      } else if (data.type === 'error') {
        setOutput(prev => [...prev, { type: 'error', text: data.data }])
      } else if (data.type === 'exit') {
        setOutput(prev => [...prev, { type: 'system', text: `Process exited with code: ${data.code}` }])
      } else if (data.type === 'autocomplete') {
        handleAutocomplete(data.data)
      } else if (data.type === 'cwd') {
        setCurrentDir(data.data)
      }
    }

    websocket.onerror = (error) => {
      console.error('Console WebSocket error:', error)
      setOutput(prev => [...prev, { type: 'error', text: 'Connection error' }])
    }

    websocket.onclose = () => {
      setConnected(false)
      setOutput(prev => [...prev, { type: 'system', text: 'Console disconnected' }])
    }

    setWs(websocket)

    return () => {
      if (websocket) {
        websocket.close()
      }
    }
  }, [])

  useEffect(() => {
    // Auto scroll to bottom
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output])

  const handleAutocomplete = (data) => {
    console.log('[Console] handleAutocomplete called with:', JSON.stringify(data))
    if (!data || !data.completions || data.completions.length === 0) {
      console.log('[Console] No completions, returning')
      return
    }

    const { completions, prefix } = data
    console.log('[Console] Completions:', JSON.stringify(completions), 'Prefix:', JSON.stringify(prefix), 'Current input:', JSON.stringify(input))

    if (completions.length === 1) {
      // Single match - autocomplete it
      const newInput = prefix + completions[0]
      console.log('[Console] Single match, setting input to:', JSON.stringify(newInput))
      setInput(newInput)
    } else {
      // Multiple matches - show them and find common prefix
      setOutput(prev => [...prev, { type: 'system', text: completions.join('  ') }])
      
      // Find common prefix among completions
      const commonPrefix = completions.reduce((pfx, str) => {
        let i = 0
        while (i < pfx.length && i < str.length && pfx[i] === str[i]) {
          i++
        }
        return pfx.substring(0, i)
      }, completions[0])
      
      // Only update if common prefix is longer than current partial word
      const currentPartial = input.substring(prefix.length)
      if (commonPrefix.length > currentPartial.length) {
        setInput(prefix + commonPrefix)
      }
    }
  }

  const handleSubmit = (e) => {
    e.preventDefault()
    
    if (!input.trim() || !ws || !connected) return

    // Handle clear command locally
    if (input.trim() === 'clear') {
      setOutput([])
      setInput('')
      return
    }

    // Add to history
    if (input.trim()) {
      setHistory(prev => [...prev, input])
      setHistoryIndex(-1)
    }

    // Display command in output with current directory
    const namespacePrefix = namespace !== 'root' ? `[${namespace}] ` : ''
    setOutput(prev => [...prev, { type: 'command', text: `${namespacePrefix}${currentDir} $ ${input}` }])

    // Send command via WebSocket
    const cmdMsg = { command: input, namespace: namespace }
    console.log('[Console] Sending command:', JSON.stringify(cmdMsg))
    ws.send(JSON.stringify(cmdMsg))

    // Clear input
    setInput('')
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Tab') {
      e.preventDefault()
      // Request autocomplete (allow empty input for listing current dir)
      if (ws && connected) {
        const autocompleteMsg = { autocomplete: input, namespace: namespace, cwd: currentDir }
        console.log('[Console] Sending autocomplete:', JSON.stringify(autocompleteMsg))
        ws.send(JSON.stringify(autocompleteMsg))
      } else {
        console.log('[Console] Tab pressed but not sending:', JSON.stringify({ hasWs: !!ws, connected }))
      }
      return
    }
    
    if (e.key === 'c' && e.ctrlKey) {
      e.preventDefault()
      // Send kill signal
      if (ws && connected) {
        const killMsg = { kill: true }
        console.log('[Console] Sending kill signal:', JSON.stringify(killMsg))
        ws.send(JSON.stringify(killMsg))
        setOutput(prev => [...prev, { type: 'system', text: '^C' }])
      }
      return
    }
    
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (history.length === 0) return

      const newIndex = historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1)
      setHistoryIndex(newIndex)
      setInput(history[newIndex])
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (historyIndex === -1) return

      if (historyIndex === history.length - 1) {
        setHistoryIndex(-1)
        setInput('')
      } else {
        const newIndex = historyIndex + 1
        setHistoryIndex(newIndex)
        setInput(history[newIndex])
      }
    } else if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault()
      setOutput([])
    }
  }

  return (
    <div className={`console-container ${isFullscreen ? 'console-fullscreen' : ''}`}>
      <div className="console-header">
        <div className="console-header-left">
          <span className="console-title">Router Console</span>
          <select 
            className="console-namespace-select" 
            value={namespace} 
            onChange={(e) => setNamespace(e.target.value)}
          >
            <option value="root">root</option>
            <option value="ethns">ethns</option>
            <option value="kidosns">kidosns</option>
            <option value="switchns">switchns</option>
            <option value="appsns">appsns</option>
            <option value="wifins">wifins</option>
            <option value="monns">monns</option>
          </select>
        </div>
        <div className="console-header-controls">
          <span className={`console-status ${connected ? 'connected' : 'disconnected'}`}>
            {connected ? '● Connected' : '○ Disconnected'}
          </span>
          <button 
            className="console-fullscreen-btn" 
            onClick={() => setIsFullscreen(!isFullscreen)}
            title={isFullscreen ? 'Exit fullscreen' : 'Fullscreen'}
          >
            {isFullscreen ? '✕' : '⛶'}
          </button>
        </div>
      </div>
      
      <div className="console-output-area" ref={outputRef}>
        {output.map((line, index) => (
          <div key={index} className={`console-line console-${line.type}`}>
            {line.text}
          </div>
        ))}
      </div>

      <form onSubmit={handleSubmit} className="console-input-form">
        <span className="console-prompt">{currentDir} $</span>
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          className="console-input"
          placeholder="Enter command..."
          disabled={!connected}
          autoFocus
        />
      </form>
    </div>
  )
}

export default Console
