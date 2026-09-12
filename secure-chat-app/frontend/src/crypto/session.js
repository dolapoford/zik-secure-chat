// secure-chat-app/frontend/src/crypto/session.js
import { X25519, Ed25519, bytesToBase64, base64ToBytes } from './primitives.js'
import { performX3DH, performX3DHRecipient } from './x3dh.js'
import { initializeAlice, initializeBob, encrypt, decrypt, deserializeHeader } from './doubleRatchet.js'
import {
  getOutgoingSession, saveOutgoingSession,
  getIncomingSession, saveIncomingSession,
  getPreKeys, getCachedPlaintext, cachePlaintext,
} from './keyStore.js'

/**
 * Establishes (or reuses) this user's outgoing session toward `contact`.
 * Fetches the contact's public prekey bundle, verifies the signed-prekey
 * signature, runs X3DH, and initializes the outgoing Double Ratchet state —
 * entirely client-side. Returns a safety number for out-of-band comparison.
 */
export async function ensureOutgoingSession(apiBase, username, identityKeyPair, signingKeyPair, contact) {
  const existing = await getOutgoingSession(username, contact)

  const bundleRes = await fetch(`${apiBase}/prekeys/${encodeURIComponent(contact)}`)
  const bundle = await bundleRes.json()
  if (bundle.error) throw new Error(bundle.error)

  const contactIdentityPub = base64ToBytes(bundle.identityKey)
  const contactSigningPub = base64ToBytes(bundle.signingPublicKey)
  const contactSignedPrePub = base64ToBytes(bundle.signedPreKey)
  const contactOneTimePub = base64ToBytes(bundle.oneTimePreKey)
  const signature = base64ToBytes(bundle.signedPreKeySignature)

  if (!Ed25519.verify(contactSignedPrePub, signature, contactSigningPub)) {
    throw new Error('Signed prekey signature verification failed — possible MitM attack!')
  }

  const safetyNumber = Ed25519.computeSafetyNumber(identityKeyPair.publicKey, contactIdentityPub)

  if (existing) {
    return { safetyNumber }
  }

  const ephemeralKeyPair = X25519.generateKeyPair()
  const sharedSecret = performX3DH(
    identityKeyPair.privateKey, ephemeralKeyPair.privateKey,
    contactIdentityPub, contactSignedPrePub, contactOneTimePub
  )
  const ratchetState = initializeAlice(sharedSecret, contactSignedPrePub)
  ratchetState.bootstrap = {
    senderIdentityPublicKey: identityKeyPair.publicKey,
    senderEphemeralPublicKey: ephemeralKeyPair.publicKey,
    senderSigningPublicKey: signingKeyPair.publicKey,
  }
  await saveOutgoingSession(username, contact, ratchetState)

  return { safetyNumber }
}

export async function encryptMessage(username, contact, plaintextString) {
  const state = await getOutgoingSession(username, contact)
  if (!state) throw new Error(`No outgoing session for ${contact} — call ensureOutgoingSession first`)

  const plaintextBytes = new TextEncoder().encode(plaintextString)
  const { header, ciphertext } = encrypt(state, plaintextBytes, state.bootstrap)
  await saveOutgoingSession(username, contact, state)

  return {
    ciphertext: bytesToBase64(ciphertext),
    header: bytesToBase64(header),
  }
}

/**
 * Decrypts one received message, bootstrapping an incoming session from the
 * message's embedded X3DH parameters if this is the first message ever
 * received from that sender. Caches the plaintext by message id so a
 * single-use ratchet message key is never consumed twice across repeated
 * history polls.
 */
export async function decryptMessage(username, ownIdentityKeyPair, message) {
  const cached = await getCachedPlaintext(username, message.messageId)
  if (cached !== undefined) return cached

  const headerBytes = base64ToBytes(message.header)
  const ciphertextBytes = base64ToBytes(message.ciphertext)
  const signatureBytes = base64ToBytes(message.signature)
  const parsedHeader = deserializeHeader(headerBytes)

  if (!Ed25519.verify(ciphertextBytes, signatureBytes, parsedHeader.senderSigningPublicKey)) {
    return '[Message authentication failed]'
  }

  let state = await getIncomingSession(username, message.sender)

  if (!state) {
    const prekeys = await getPreKeys(username)
    if (!prekeys) {
      return '[Unable to decrypt — no local prekeys on this device]'
    }
    const sharedSecret = performX3DHRecipient(
      ownIdentityKeyPair.privateKey,
      prekeys.signedPreKeyPair.privateKey,
      prekeys.oneTimePreKeyPairs.length > 0 ? prekeys.oneTimePreKeyPairs[0].privateKey : null,
      parsedHeader.senderIdentityPublicKey,
      parsedHeader.senderEphemeralPublicKey
    )
    state = initializeBob(sharedSecret, prekeys.signedPreKeyPair)
  }

  try {
    const plaintextBytes = decrypt(state, headerBytes, ciphertextBytes)
    const plaintext = new TextDecoder().decode(plaintextBytes)
    await saveIncomingSession(username, message.sender, state)
    await cachePlaintext(username, message.messageId, plaintext)
    return plaintext
  } catch {
    return '[Unable to decrypt — message may be from before this device\'s current identity]'
  }
}
