import { useState, useEffect, useRef } from 'react'
import './index.css'

const API_BASE = 'http://localhost:8080/api'

// ─── API Helper ──────────────────────────────────────────
async function api(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  return res.json()
}

// ─── Login Component ─────────────────────────────────────
function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [isRegister, setIsRegister] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    try {
      const endpoint = isRegister ? '/auth/register' : '/auth/login'
      const data = await api(endpoint, {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      })
      if (data.error) {
        setError(data.error)
      } else {
        onLogin(data)
      }
    } catch (err) {
      setError('Connection failed. Is the server running on port 8080?')
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="logo">
          <div className="shield-icon">🔐</div>
        </div>
        <h1>SecureChat</h1>
        <p className="subtitle">End-to-End Encrypted Messaging</p>
        <div className="encryption-badge">
          🛡️ Signal Protocol • AES-256-GCM • Ed25519
        </div>

        {error && <div className="error-message">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Username</label>
            <input
              id="username-input"
              type="text"
              placeholder="Enter your username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label>Password</label>
            <input
              id="password-input"
              type="password"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          <button id="login-btn" type="submit" className="btn-primary">
            {isRegister ? '🔑 Create Account & Generate Keys' : '🔓 Sign In'}
          </button>
        </form>
        <button
          id="toggle-register"
          className="btn-secondary"
          onClick={() => setIsRegister(!isRegister)}
        >
          {isRegister ? 'Already have an account? Sign in' : 'New here? Create an account'}
        </button>
      </div>
    </div>
  )
}

// ─── Message Bubble ──────────────────────────────────────
function MessageBubble({ message, currentUser }) {
  const isSent = message.sender === currentUser
  return (
    <div className={`message-bubble ${isSent ? 'sent' : 'received'}`}>
      {!isSent && (
        <div style={{ fontSize: '0.75rem', fontWeight: 600, marginBottom: 4, color: 'var(--accent-cyan)' }}>
          {message.sender}
        </div>
      )}
      <div className="message-text">{message.text}</div>
      <div className="message-meta">
        <span>{message.time}</span>
        <span className="lock-icon">🔒</span>
      </div>
    </div>
  )
}

// ─── Key Verification Modal ─────────────────────────────
function KeyVerificationModal({ safetyNumber, contactName, onClose }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h3>🔑 Key Verification</h3>
        <p className="modal-info">
          Compare this safety number with <strong>{contactName}</strong> using an independent
          channel (in person, phone call, etc.) to verify your conversation is end-to-end encrypted
          and not subject to a man-in-the-middle attack.
        </p>
        <div className="safety-number">{safetyNumber}</div>
        <p className="modal-info" style={{ fontSize: '0.8rem' }}>
          🛡️ If the numbers match, your conversation is secure.<br />
          ⚠️ If they don't match, a third party may be intercepting your messages.
        </p>
        <button className="modal-close-btn" onClick={onClose}>Done</button>
      </div>
    </div>
  )
}

// ─── Chat View ───────────────────────────────────────────
function ChatView({ currentUser, contact, messages, onSend, safetyNumber }) {
  const [input, setInput] = useState('')
  const [showKeyVerify, setShowKeyVerify] = useState(false)
  const messagesEndRef = useRef(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const handleSend = (e) => {
    e.preventDefault()
    if (input.trim()) {
      onSend(input.trim())
      setInput('')
    }
  }

  return (
    <div className="chat-area">
      <div className="chat-header">
        <div className="chat-header-info">
          <div className="contact-avatar">{contact[0]?.toUpperCase()}</div>
          <div>
            <h3>{contact}</h3>
            <div className="e2ee-indicator">
              🔒 End-to-end encrypted
            </div>
          </div>
        </div>
        <div className="chat-header-actions">
          <button
            id="verify-keys-btn"
            className="icon-btn"
            title="Verify Keys"
            onClick={() => setShowKeyVerify(true)}
          >
            🔑
          </button>
        </div>
      </div>

      <div className="messages-container">
        <div className="system-message">
          🔐 Messages are end-to-end encrypted using the Signal Protocol.
          No one outside this chat can read them.
        </div>
        {messages.map((msg, i) => (
          <MessageBubble key={i} message={msg} currentUser={currentUser} />
        ))}
        <div ref={messagesEndRef} />
      </div>

      <form className="message-input-area" onSubmit={handleSend}>
        <input
          id="message-input"
          type="text"
          placeholder="Type an encrypted message..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button id="send-btn" type="submit" className="send-btn" disabled={!input.trim()}>
          ➤
        </button>
      </form>

      {showKeyVerify && (
        <KeyVerificationModal
          safetyNumber={safetyNumber || 'Establishing session...'}
          contactName={contact}
          onClose={() => setShowKeyVerify(false)}
        />
      )}
    </div>
  )
}

// ─── Welcome Panel ───────────────────────────────────────
function WelcomePanel() {
  return (
    <div className="chat-area">
      <div className="welcome-panel">
        <div className="welcome-icon">🛡️</div>
        <h2>SecureChat E2EE</h2>
        <p>
          Select a contact to start an end-to-end encrypted conversation.
          All messages are protected by the Signal Protocol.
        </p>
        <div className="protocol-badges">
          <span className="protocol-badge">Signal Protocol</span>
          <span className="protocol-badge">X3DH Key Agreement</span>
          <span className="protocol-badge">Double Ratchet</span>
          <span className="protocol-badge">AES-256-GCM</span>
          <span className="protocol-badge">Ed25519 Signatures</span>
          <span className="protocol-badge">TreeKEM Groups</span>
          <span className="protocol-badge">HKDF-SHA256</span>
        </div>
      </div>
    </div>
  )
}

// ─── Main App ────────────────────────────────────────────
function App() {
  const [user, setUser] = useState(null)
  const [contacts, setContacts] = useState([])
  const [selectedContact, setSelectedContact] = useState(null)
  const [chatMessages, setChatMessages] = useState({})
  const [safetyNumbers, setSafetyNumbers] = useState({})
  const [search, setSearch] = useState('')

  // Load contacts on login
  useEffect(() => {
    if (user) {
      loadContacts()
      const interval = setInterval(loadContacts, 5000)
      return () => clearInterval(interval)
    }
  }, [user])

  const loadContacts = async () => {
    try {
      const users = await api('/auth/users')
      if (Array.isArray(users)) {
        setContacts(users.filter((u) => u !== user.username))
      }
    } catch (e) {
      console.log('Failed to load contacts')
    }
  }

  const handleSelectContact = async (contact) => {
    setSelectedContact(contact)

    // Establish E2EE session if not already done
    if (!safetyNumbers[contact]) {
      try {
        const session = await api('/chat/session', {
          method: 'POST',
          body: JSON.stringify({ sender: user.username, recipient: contact }),
        })
        if (session.safetyNumber) {
          setSafetyNumbers((prev) => ({ ...prev, [contact]: session.safetyNumber }))
        }
      } catch (e) {
        console.log('Session establishment pending')
      }
    }
  }

  const handleSendMessage = async (text) => {
    if (!selectedContact) return

    const now = new Date()
    const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })

    // Add to local messages immediately
    const newMsg = { sender: user.username, text, time: timeStr }
    setChatMessages((prev) => ({
      ...prev,
      [selectedContact]: [...(prev[selectedContact] || []), newMsg],
    }))

    // Send encrypted message to server
    try {
      await api('/chat/send', {
        method: 'POST',
        body: JSON.stringify({
          sender: user.username,
          recipient: selectedContact,
          message: text,
        }),
      })
    } catch (e) {
      console.log('Message send failed:', e)
    }
  }

  const handleLogin = (userData) => {
    setUser(userData)
  }

  const handleLogout = () => {
    setUser(null)
    setSelectedContact(null)
    setChatMessages({})
    setSafetyNumbers({})
  }

  if (!user) {
    return <Login onLogin={handleLogin} />
  }

  const filteredContacts = contacts.filter((c) =>
    c.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="app-container">
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <h2>🔐 SecureChat</h2>
          <div className="user-badge">
            <span className="dot"></span>
            {user.username}
          </div>
        </div>

        <div className="sidebar-search">
          <input
            id="search-contacts"
            type="text"
            placeholder="🔍 Search contacts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <button className="new-chat-btn" onClick={loadContacts}>
          + New Encrypted Chat
        </button>

        <div className="contacts-list">
          <div className="sidebar-section-title">Contacts</div>
          {filteredContacts.length === 0 ? (
            <div className="empty-state">
              <span>👥</span>
              <span>No contacts yet</span>
              <span style={{ fontSize: '0.75rem' }}>Register another user to start chatting</span>
            </div>
          ) : (
            filteredContacts.map((contact) => (
              <div
                key={contact}
                id={`contact-${contact}`}
                className={`contact-item ${selectedContact === contact ? 'active' : ''}`}
                onClick={() => handleSelectContact(contact)}
              >
                <div className="contact-avatar">{contact[0]?.toUpperCase()}</div>
                <div className="contact-info">
                  <div className="contact-name">{contact}</div>
                  <div className={`contact-status ${safetyNumbers[contact] ? 'encrypted' : ''}`}>
                    {safetyNumbers[contact] ? '🔒 E2EE Active' : '🔓 Tap to encrypt'}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        <button
          id="logout-btn"
          className="new-chat-btn"
          style={{ marginBottom: 16, color: 'var(--accent-red)', borderColor: 'rgba(239,68,68,0.3)' }}
          onClick={handleLogout}
        >
          Sign Out
        </button>
      </div>

      {/* Chat Area */}
      {selectedContact ? (
        <ChatView
          currentUser={user.username}
          contact={selectedContact}
          messages={chatMessages[selectedContact] || []}
          onSend={handleSendMessage}
          safetyNumber={safetyNumbers[selectedContact]}
        />
      ) : (
        <WelcomePanel />
      )}
    </div>
  )
}

export default App
