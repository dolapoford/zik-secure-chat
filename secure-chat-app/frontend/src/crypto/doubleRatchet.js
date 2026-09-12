// secure-chat-app/frontend/src/crypto/doubleRatchet.js
import { X25519, HKDF, AESGCM } from './primitives.js'

// Header layout (all fixed-width, big-endian for the two integers). Beyond
// the Java reference format, this also carries the sender's X3DH identity
// and ephemeral public keys (so a first-time recipient can bootstrap their
// incoming session) and the sender's Ed25519 signing public key (so the
// recipient can verify the message signature without a separate network
// lookup — see session.js's decryptMessage in Task 11):
// [ dhPublicKey(32) | previousChainLength(4) | messageNumber(4)
//   | senderIdentityPublicKey(32) | senderEphemeralPublicKey(32)
//   | senderSigningPublicKey(32) ] = 136 bytes
const HEADER_LENGTH = 136

function writeUint32BE(value) {
  const b = new Uint8Array(4)
  b[0] = (value >>> 24) & 0xff
  b[1] = (value >>> 16) & 0xff
  b[2] = (value >>> 8) & 0xff
  b[3] = value & 0xff
  return b
}

function readUint32BE(bytes, offset) {
  return (
    (bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]
  ) >>> 0
}

function serializeHeader({ dhPublicKey, previousChainLength, messageNumber, senderIdentityPublicKey, senderEphemeralPublicKey, senderSigningPublicKey }) {
  const out = new Uint8Array(HEADER_LENGTH)
  out.set(dhPublicKey, 0)
  out.set(writeUint32BE(previousChainLength), 32)
  out.set(writeUint32BE(messageNumber), 36)
  out.set(senderIdentityPublicKey, 40)
  out.set(senderEphemeralPublicKey, 72)
  out.set(senderSigningPublicKey, 104)
  return out
}

export function deserializeHeader(bytes) {
  return {
    dhPublicKey: bytes.slice(0, 32),
    previousChainLength: readUint32BE(bytes, 32),
    messageNumber: readUint32BE(bytes, 36),
    senderIdentityPublicKey: bytes.slice(40, 72),
    senderEphemeralPublicKey: bytes.slice(72, 104),
    senderSigningPublicKey: bytes.slice(104, 136),
  }
}

export function initializeAlice(sharedSecret, remoteDHPublic) {
  const dhKeyPair = X25519.generateKeyPair()
  const dhOutput = X25519.computeSharedSecret(dhKeyPair.privateKey, remoteDHPublic)
  const [rootKey, sendingChainKey] = HKDF.deriveRootAndChainKey(sharedSecret, dhOutput)

  return {
    dhPrivateKey: dhKeyPair.privateKey,
    dhPublicKey: dhKeyPair.publicKey,
    remoteDHPublicKey: remoteDHPublic,
    rootKey,
    sendingChainKey,
    receivingChainKey: null,
    sendingMessageNumber: 0,
    receivingMessageNumber: 0,
    previousSendingChainLength: 0,
    skippedMessageKeys: {},
  }
}

export function initializeBob(sharedSecret, dhKeyPair) {
  return {
    dhPrivateKey: dhKeyPair.privateKey,
    dhPublicKey: dhKeyPair.publicKey,
    remoteDHPublicKey: null,
    rootKey: sharedSecret,
    sendingChainKey: null,
    receivingChainKey: null,
    sendingMessageNumber: 0,
    receivingMessageNumber: 0,
    previousSendingChainLength: 0,
    skippedMessageKeys: {},
  }
}

export function encrypt(state, plaintext, bootstrap) {
  const [messageKey, nextChainKey] = HKDF.deriveMessageAndChainKey(state.sendingChainKey)
  state.sendingChainKey = nextChainKey

  const header = {
    dhPublicKey: state.dhPublicKey,
    previousChainLength: state.previousSendingChainLength,
    messageNumber: state.sendingMessageNumber,
    senderIdentityPublicKey: bootstrap.senderIdentityPublicKey,
    senderEphemeralPublicKey: bootstrap.senderEphemeralPublicKey,
    senderSigningPublicKey: bootstrap.senderSigningPublicKey,
  }
  const headerBytes = serializeHeader(header)
  const ciphertext = AESGCM.encrypt(plaintext, messageKey, headerBytes)

  state.sendingMessageNumber += 1
  return { header: headerBytes, ciphertext }
}

function performDHRatchet(state, newRemoteDHPublic) {
  state.previousSendingChainLength = state.sendingMessageNumber
  state.sendingMessageNumber = 0
  state.receivingMessageNumber = 0
  state.remoteDHPublicKey = newRemoteDHPublic

  const dhReceive = X25519.computeSharedSecret(state.dhPrivateKey, state.remoteDHPublicKey)
  const [rootAfterReceive, receivingChainKey] = HKDF.deriveRootAndChainKey(state.rootKey, dhReceive)
  state.rootKey = rootAfterReceive
  state.receivingChainKey = receivingChainKey

  const newDhKeyPair = X25519.generateKeyPair()
  state.dhPrivateKey = newDhKeyPair.privateKey
  state.dhPublicKey = newDhKeyPair.publicKey

  const dhSend = X25519.computeSharedSecret(state.dhPrivateKey, state.remoteDHPublicKey)
  const [rootAfterSend, sendingChainKey] = HKDF.deriveRootAndChainKey(state.rootKey, dhSend)
  state.rootKey = rootAfterSend
  state.sendingChainKey = sendingChainKey
}

function skipMessageKeys(state, untilMessageNumber) {
  if (!state.receivingChainKey) return
  while (state.receivingMessageNumber < untilMessageNumber) {
    const [messageKey, nextChainKey] = HKDF.deriveMessageAndChainKey(state.receivingChainKey)
    const keyId = bytesEqualKey(state.remoteDHPublicKey) + ':' + state.receivingMessageNumber
    state.skippedMessageKeys[keyId] = messageKey
    state.receivingChainKey = nextChainKey
    state.receivingMessageNumber += 1
  }
}

function bytesEqualKey(bytes) {
  return bytes ? Array.from(bytes).join(',') : 'null'
}

function bytesEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

export function decrypt(state, header, ciphertext) {
  const parsed = deserializeHeader(header)

  if (!state.remoteDHPublicKey || !bytesEqual(parsed.dhPublicKey, state.remoteDHPublicKey)) {
    skipMessageKeys(state, parsed.previousChainLength)
    performDHRatchet(state, parsed.dhPublicKey)
  }

  skipMessageKeys(state, parsed.messageNumber)

  const [messageKey, nextChainKey] = HKDF.deriveMessageAndChainKey(state.receivingChainKey)
  state.receivingChainKey = nextChainKey
  state.receivingMessageNumber += 1

  return AESGCM.decrypt(ciphertext, messageKey, header)
}
