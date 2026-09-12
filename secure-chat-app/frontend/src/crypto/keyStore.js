import { get, set, createStore } from 'idb-keyval'

const identityStore = createStore('securechat-identities', 'identities')
const preKeyStore = createStore('securechat-prekeys', 'prekeys')
const outgoingSessionStore = createStore('securechat-sessions-out', 'sessions')
const incomingSessionStore = createStore('securechat-sessions-in', 'sessions')
const plaintextCacheStore = createStore('securechat-plaintext-cache', 'cache')

export async function getIdentity(username) {
  return get(username, identityStore)
}

export async function saveIdentity(username, identityKeyPair, signingKeyPair) {
  await set(username, { identityKeyPair, signingKeyPair }, identityStore)
}

export async function savePreKeys(username, prekeys) {
  await set(username, prekeys, preKeyStore)
}

export async function getPreKeys(username) {
  return get(username, preKeyStore)
}

function sessionKey(username, contact) {
  return `${username}::${contact}`
}

export async function getOutgoingSession(username, contact) {
  return get(sessionKey(username, contact), outgoingSessionStore)
}

export async function saveOutgoingSession(username, contact, ratchetState) {
  await set(sessionKey(username, contact), ratchetState, outgoingSessionStore)
}

export async function getIncomingSession(username, contact) {
  return get(sessionKey(username, contact), incomingSessionStore)
}

export async function saveIncomingSession(username, contact, ratchetState) {
  await set(sessionKey(username, contact), ratchetState, incomingSessionStore)
}

function plaintextKey(username, messageId) {
  return `${username}::${messageId}`
}

export async function getCachedPlaintext(username, messageId) {
  return get(plaintextKey(username, messageId), plaintextCacheStore)
}

export async function cachePlaintext(username, messageId, text) {
  await set(plaintextKey(username, messageId), text, plaintextCacheStore)
}
