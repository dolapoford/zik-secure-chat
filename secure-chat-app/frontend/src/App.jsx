import { useState, useEffect, useRef } from 'react'
import './index.css'
import { getOrCreateIdentity, ensurePrekeys } from './crypto/identity.js'
import { ensureOutgoingSession, encryptMessage, decryptMessage } from './crypto/session.js'
import { Ed25519, bytesToBase64, base64ToBytes } from './crypto/primitives.js'

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
      if (isRegister) {
        const { identityKeyPair, signingKeyPair } = await getOrCreateIdentity(username)
        const data = await api('/auth/register', {
          method: 'POST',
          body: JSON.stringify({
            username,
            password,
            identityPublicKey: bytesToBase64(identityKeyPair.publicKey),
            signingPublicKey: bytesToBase64(signingKeyPair.publicKey),
          }),
        })
        if (data.error) {
          setError(data.error)
          return
        }
        await ensurePrekeys(username, API_BASE, signingKeyPair)
        onLogin(data)
      } else {
        const data = await api('/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username, password }),
        })
        if (data.error) {
          setError(data.error)
          return
        }
        const { signingKeyPair, isNew } = await getOrCreateIdentity(username)
        if (isNew) {
          window.alert(
            'This browser has no saved encryption keys for this account. ' +
            'A new encryption identity has been generated and published — ' +
            'conversations from other devices or browsers cannot be read here.'
          )
        }
        await ensurePrekeys(username, API_BASE, signingKeyPair)
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

// ─── New Group Modal ─────────────────────────────────────
function NewGroupModal({ onCreate, onClose }) {
  const [groupName, setGroupName] = useState('')
  const [membersText, setMembersText] = useState('')

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!groupName.trim()) return
    const members = membersText.split(',').map((m) => m.trim()).filter(Boolean)
    onCreate(groupName.trim(), members)
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h3>➕ New Encrypted Group</h3>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Group Name</label>
            <input
              id="group-name-input"
              type="text"
              placeholder="e.g. Project Team"
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              required
            />
          </div>
          <div className="form-group">
            <label>Members (comma-separated usernames)</label>
            <input
              id="group-members-input"
              type="text"
              placeholder="bob_test, carol_test"
              value={membersText}
              onChange={(e) => setMembersText(e.target.value)}
            />
          </div>
          <button id="create-group-btn" type="submit" className="btn-primary">Create Group</button>
        </form>
        <button className="modal-close-btn" onClick={onClose}>Cancel</button>
      </div>
    </div>
  )
}

// ─── Group Members Modal ─────────────────────────────────
function GroupMembersModal({ members, currentUser, onAdd, onRemove, onClose }) {
  const [newMember, setNewMember] = useState('')

  const handleAdd = (e) => {
    e.preventDefault()
    if (newMember.trim()) {
      onAdd(newMember.trim())
      setNewMember('')
    }
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h3>👥 Group Members</h3>
        <div className="member-list">
          {members.map((m) => (
            <div key={m} className="member-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0' }}>
              <span>{m}{m === currentUser ? ' (you)' : ''}</span>
              {m !== currentUser && (
                <button className="icon-btn" title="Remove member" onClick={() => onRemove(m)}>✕</button>
              )}
            </div>
          ))}
        </div>
        <form onSubmit={handleAdd} className="message-input-area" style={{ marginTop: 12 }}>
          <input
            id="add-member-input"
            type="text"
            placeholder="Add member by username..."
            value={newMember}
            onChange={(e) => setNewMember(e.target.value)}
          />
          <button id="add-member-btn" type="submit" className="send-btn" disabled={!newMember.trim()}>+</button>
        </form>
        <button className="modal-close-btn" onClick={onClose}>Done</button>
      </div>
    </div>
  )
}

// ─── Group Chat View ──────────────────────────────────────
function GroupChatView({ currentUser, group, messages, onSend, onShowMembers }) {
  const [input, setInput] = useState('')
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
          <div className="contact-avatar">{group.groupName?.[0]?.toUpperCase() || 'G'}</div>
          <div>
            <h3>{group.groupName}</h3>
            <div className="e2ee-indicator">
              🔒 TreeKEM group · {group.memberCount} member{group.memberCount === 1 ? '' : 's'} · epoch {group.epoch}
            </div>
          </div>
        </div>
        <div className="chat-header-actions">
          <button id="group-members-btn" className="icon-btn" title="Manage Members" onClick={onShowMembers}>
            👥
          </button>
        </div>
      </div>

      <div className="messages-container">
        <div className="system-message">
          🔐 Group messages are encrypted with TreeKEM using the group's current epoch key.
        </div>
        {messages.map((msg, i) => (
          <MessageBubble key={i} message={msg} currentUser={currentUser} />
        ))}
        <div ref={messagesEndRef} />
      </div>

      <form className="message-input-area" onSubmit={handleSend}>
        <input
          id="group-message-input"
          type="text"
          placeholder="Message the group..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button id="group-send-btn" type="submit" className="send-btn" disabled={!input.trim()}>
          ➤
        </button>
      </form>
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
  const [groups, setGroups] = useState([])
  const [selectedGroup, setSelectedGroup] = useState(null)
  const [groupMessages, setGroupMessages] = useState({})
  const [showNewGroupModal, setShowNewGroupModal] = useState(false)
  const [showGroupMembers, setShowGroupMembers] = useState(false)

  // Load contacts and groups on login
  useEffect(() => {
    if (user) {
      loadContacts()
      loadGroups()
      const interval = setInterval(() => {
        loadContacts()
        loadGroups()
      }, 5000)
      return () => clearInterval(interval)
    }
  }, [user])

  // Poll the decrypted chat history for the open conversation, so messages
  // sent by the other party are actually retrieved, decrypted, and displayed
  // rather than only ever appearing in the sender's own optimistic echo.
  useEffect(() => {
    if (user && selectedContact) {
      loadHistory(selectedContact)
      const interval = setInterval(() => loadHistory(selectedContact), 2000)
      return () => clearInterval(interval)
    }
  }, [user, selectedContact])

  // Poll the decrypted history of the open group in the same way.
  useEffect(() => {
    if (user && selectedGroup) {
      loadGroupMessages(selectedGroup)
      const interval = setInterval(() => loadGroupMessages(selectedGroup), 2000)
      return () => clearInterval(interval)
    }
  }, [user, selectedGroup])

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

  const loadGroups = async () => {
    try {
      const list = await api(`/groups/mine?username=${encodeURIComponent(user.username)}`)
      if (Array.isArray(list)) {
        setGroups(list)
      }
    } catch (e) {
      console.log('Failed to load groups')
    }
  }

  const loadGroupMessages = async (groupId) => {
    try {
      const history = await api(`/groups/${groupId}/messages`)
      if (Array.isArray(history)) {
        const mapped = history.map((m) => ({
          sender: m.sender,
          text: m.text,
          time: new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        }))
        setGroupMessages((prev) => ({ ...prev, [groupId]: mapped }))
      }
    } catch (e) {
      console.log('Failed to load group messages')
    }
  }

  const loadHistory = async (contact) => {
    try {
      const history = await api(
        `/chat/history?user1=${encodeURIComponent(user.username)}&user2=${encodeURIComponent(contact)}`
      )
      if (Array.isArray(history)) {
        const identity = await getOrCreateIdentity(user.username)
        const mapped = []
        for (const m of history) {
          const text = await decryptMessage(user.username, identity.identityKeyPair, m)
          mapped.push({
            sender: m.sender,
            text,
            time: new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          })
        }
        setChatMessages((prev) => ({ ...prev, [contact]: mapped }))
      }
    } catch (e) {
      console.log('Failed to load chat history')
    }
  }

  const handleSelectContact = async (contact) => {
    setSelectedContact(contact)
    setSelectedGroup(null)

    if (!safetyNumbers[contact]) {
      try {
        const identity = await getOrCreateIdentity(user.username)
        const { safetyNumber } = await ensureOutgoingSession(
          API_BASE, user.username, identity.identityKeyPair, identity.signingKeyPair, contact
        )
        setSafetyNumbers((prev) => ({ ...prev, [contact]: safetyNumber }))
      } catch (e) {
        console.log('Session establishment pending')
      }
    }
  }

  const handleSendMessage = async (text) => {
    if (!selectedContact) return

    try {
      const { ciphertext, header } = await encryptMessage(user.username, selectedContact, text)
      const identity = await getOrCreateIdentity(user.username)
      const signature = bytesToBase64(
        Ed25519.sign(base64ToBytes(ciphertext), identity.signingKeyPair.privateKey)
      )
      await api('/chat/send', {
        method: 'POST',
        body: JSON.stringify({
          sender: user.username,
          recipient: selectedContact,
          ciphertext,
          header,
          signature,
        }),
      })
      await loadHistory(selectedContact)
    } catch (e) {
      console.log('Message send failed:', e)
    }
  }

  const handleSelectGroup = (groupId) => {
    setSelectedGroup(groupId)
    setSelectedContact(null)
  }

  const handleSendGroupMessage = async (text) => {
    if (!selectedGroup) return
    try {
      await api(`/groups/${selectedGroup}/messages`, {
        method: 'POST',
        body: JSON.stringify({ sender: user.username, message: text }),
      })
      await loadGroupMessages(selectedGroup)
    } catch (e) {
      console.log('Group message send failed:', e)
    }
  }

  const handleCreateGroup = async (groupName, memberUsernames) => {
    try {
      const created = await api('/groups/create', {
        method: 'POST',
        body: JSON.stringify({ groupName, creator: user.username }),
      })
      for (const member of memberUsernames) {
        if (member && member !== user.username) {
          await api(`/groups/${created.groupId}/members`, {
            method: 'POST',
            body: JSON.stringify({ memberId: member }),
          })
        }
      }
      setShowNewGroupModal(false)
      await loadGroups()
      handleSelectGroup(created.groupId)
    } catch (e) {
      console.log('Group creation failed:', e)
    }
  }

  const handleAddMember = async (username) => {
    if (!selectedGroup) return
    try {
      await api(`/groups/${selectedGroup}/members`, {
        method: 'POST',
        body: JSON.stringify({ memberId: username }),
      })
      await loadGroups()
    } catch (e) {
      console.log('Add member failed:', e)
    }
  }

  const handleRemoveMember = async (username) => {
    if (!selectedGroup) return
    try {
      await api(`/groups/${selectedGroup}/members/${encodeURIComponent(username)}`, {
        method: 'DELETE',
      })
      await loadGroups()
    } catch (e) {
      console.log('Remove member failed:', e)
    }
  }

  const handleLogin = (userData) => {
    setUser(userData)
  }

  const handleLogout = () => {
    setUser(null)
    setSelectedContact(null)
    setSelectedGroup(null)
    setChatMessages({})
    setGroupMessages({})
    setSafetyNumbers({})
    setGroups([])
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

        <button id="new-group-btn" className="new-chat-btn" onClick={() => setShowNewGroupModal(true)}>
          + New Group
        </button>

        <div className="contacts-list">
          <div className="sidebar-section-title">Groups</div>
          {groups.length === 0 ? (
            <div className="empty-state">
              <span>🔐</span>
              <span>No groups yet</span>
              <span style={{ fontSize: '0.75rem' }}>Create a group to start a TreeKEM-encrypted conversation</span>
            </div>
          ) : (
            groups.map((group) => (
              <div
                key={group.groupId}
                id={`group-${group.groupId}`}
                className={`contact-item ${selectedGroup === group.groupId ? 'active' : ''}`}
                onClick={() => handleSelectGroup(group.groupId)}
              >
                <div className="contact-avatar">{group.groupName?.[0]?.toUpperCase() || 'G'}</div>
                <div className="contact-info">
                  <div className="contact-name">{group.groupName}</div>
                  <div className="contact-status encrypted">
                    🔒 {group.memberCount} member{group.memberCount === 1 ? '' : 's'}
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
      ) : selectedGroup ? (
        <GroupChatView
          currentUser={user.username}
          group={groups.find((g) => g.groupId === selectedGroup) || { groupName: 'Group', memberCount: 0, epoch: 0 }}
          messages={groupMessages[selectedGroup] || []}
          onSend={handleSendGroupMessage}
          onShowMembers={() => setShowGroupMembers(true)}
        />
      ) : (
        <WelcomePanel />
      )}

      {showNewGroupModal && (
        <NewGroupModal onCreate={handleCreateGroup} onClose={() => setShowNewGroupModal(false)} />
      )}

      {showGroupMembers && selectedGroup && (
        <GroupMembersModal
          members={(groups.find((g) => g.groupId === selectedGroup) || {}).members || []}
          currentUser={user.username}
          onAdd={handleAddMember}
          onRemove={handleRemoveMember}
          onClose={() => setShowGroupMembers(false)}
        />
      )}
    </div>
  )
}

export default App
