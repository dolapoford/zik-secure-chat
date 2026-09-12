import { x25519, ed25519 } from '@noble/curves/ed25519'
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha256'
import { gcm } from '@noble/ciphers/aes'
import { randomBytes } from '@noble/hashes/utils'

// ─── Base64 helpers ────────────────────────────────────────
export function bytesToBase64(bytes) {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

export function base64ToBytes(str) {
  const binary = atob(str)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

// ─── X25519 (ECDH key exchange) ────────────────────────────
export const X25519 = {
  generateKeyPair() {
    const privateKey = x25519.utils.randomPrivateKey()
    const publicKey = x25519.getPublicKey(privateKey)
    return { privateKey, publicKey }
  },
  computeSharedSecret(ourPrivateKey, theirPublicKey) {
    return x25519.getSharedSecret(ourPrivateKey, theirPublicKey)
  },
}

// ─── Ed25519 (digital signatures) ──────────────────────────
export const Ed25519 = {
  generateKeyPair() {
    const privateKey = ed25519.utils.randomPrivateKey()
    const publicKey = ed25519.getPublicKey(privateKey)
    return { privateKey, publicKey }
  },
  sign(message, privateKey) {
    return ed25519.sign(message, privateKey)
  },
  verify(message, signature, publicKey) {
    try {
      return ed25519.verify(signature, message, publicKey)
    } catch {
      return false
    }
  },
  computeSafetyNumber(ourIdentityPub, theirIdentityPub) {
    const a = ourIdentityPub
    const b = theirIdentityPub
    let first = a
    let second = b
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] !== b[i]) {
        if (a[i] > b[i]) { first = b; second = a }
        break
      }
    }
    const combined = new Uint8Array(first.length + second.length)
    combined.set(first, 0)
    combined.set(second, first.length)

    const hash = HKDF.deriveKey(combined, new TextEncoder().encode('SafetyNumber'), 30)

    let out = ''
    for (let i = 0; i < 30; i++) {
      const val = hash[i] % 100
      out += String(val).padStart(2, '0')
      if ((i + 1) % 5 === 0 && i < 29) out += ' '
    }
    return out
  },
}

// ─── HKDF-SHA256 ────────────────────────────────────────────
// RFC 5869 expand step, used directly (PRK = ikm) to match Bouncy Castle's
// HKDFParameters.skipExtractParameters behaviour used by the Java reference
// implementation for deriveKey(ikm, info, len).
function hkdfExpand(prk, info, length) {
  const hashLen = 32
  const n = Math.ceil(length / hashLen)
  let t = new Uint8Array(0)
  const out = new Uint8Array(n * hashLen)
  for (let i = 1; i <= n; i++) {
    const input = new Uint8Array(t.length + info.length + 1)
    input.set(t, 0)
    input.set(info, t.length)
    input[input.length - 1] = i
    t = hmac(sha256, prk, input)
    out.set(t, (i - 1) * hashLen)
  }
  return out.slice(0, length)
}

export const HKDF = {
  // Skip-extract form: ikm is used directly as the PRK. Matches Java's
  // HKDFUtil.deriveKey(ikm, info, outputLength).
  deriveKey(ikm, info, outputLength) {
    return hkdfExpand(ikm, info, outputLength)
  },
  // Full extract-then-expand form. Matches Java's
  // HKDFUtil.deriveKey(ikm, salt, info, outputLength) when salt is non-null.
  deriveKeyWithSalt(ikm, salt, info, outputLength) {
    const prk = hmac(sha256, salt, ikm)
    return hkdfExpand(prk, info, outputLength)
  },
  deriveRootAndChainKey(rootKey, dhOutput) {
    const enc = new TextEncoder()
    const material = HKDF.deriveKeyWithSalt(dhOutput, rootKey, enc.encode('DoubleRatchetRootChain'), 64)
    return [material.slice(0, 32), material.slice(32, 64)]
  },
  deriveMessageAndChainKey(chainKey) {
    const enc = new TextEncoder()
    const messageKey = HKDF.deriveKey(chainKey, enc.encode('MessageKey'), 32)
    const nextChainKey = HKDF.deriveKey(chainKey, enc.encode('ChainKey'), 32)
    return [messageKey, nextChainKey]
  },
}

// ─── AES-256-GCM ─────────────────────────────────────────────
export const AESGCM = {
  encrypt(plaintext, key, aad) {
    if (key.length !== 32) throw new Error('AES-256 key must be 32 bytes')
    const nonce = randomBytes(12)
    const cipher = gcm(key, nonce, aad)
    const ciphertext = cipher.encrypt(plaintext)
    const result = new Uint8Array(nonce.length + ciphertext.length)
    result.set(nonce, 0)
    result.set(ciphertext, nonce.length)
    return result
  },
  decrypt(encryptedData, key, aad) {
    if (key.length !== 32) throw new Error('AES-256 key must be 32 bytes')
    const nonce = encryptedData.slice(0, 12)
    const ciphertext = encryptedData.slice(12)
    const cipher = gcm(key, nonce, aad)
    return cipher.decrypt(ciphertext)
  },
}
