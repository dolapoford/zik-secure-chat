import { X25519, Ed25519, HKDF, AESGCM } from './primitives.js'

function assert(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg)
  console.log('PASS: ' + msg)
}

// X25519 shared secret agreement
const alice = X25519.generateKeyPair()
const bob = X25519.generateKeyPair()
const secretA = X25519.computeSharedSecret(alice.privateKey, bob.publicKey)
const secretB = X25519.computeSharedSecret(bob.privateKey, alice.publicKey)
assert(Buffer.from(secretA).equals(Buffer.from(secretB)), 'X25519 shared secrets match')

// Ed25519 sign/verify
const signer = Ed25519.generateKeyPair()
const message = new TextEncoder().encode('test message')
const sig = Ed25519.sign(message, signer.privateKey)
assert(Ed25519.verify(message, sig, signer.publicKey) === true, 'Ed25519 verifies a valid signature')
const tampered = new TextEncoder().encode('tampered message')
assert(Ed25519.verify(tampered, sig, signer.publicKey) === false, 'Ed25519 rejects a tampered message')

// Safety number symmetry
const sn1 = Ed25519.computeSafetyNumber(alice.publicKey, bob.publicKey)
const sn2 = Ed25519.computeSafetyNumber(bob.publicKey, alice.publicKey)
assert(sn1 === sn2, 'Safety number is order-independent')

// HKDF determinism
const ikm = new Uint8Array(32).fill(7)
const info = new TextEncoder().encode('info')
const k1 = HKDF.deriveKey(ikm, info, 32)
const k2 = HKDF.deriveKey(ikm, info, 32)
assert(Buffer.from(k1).equals(Buffer.from(k2)), 'HKDF.deriveKey is deterministic')

// AES-256-GCM round trip
const key = new Uint8Array(32).fill(3)
const plaintext = new TextEncoder().encode('secret payload')
const ct = AESGCM.encrypt(plaintext, key)
const pt = AESGCM.decrypt(ct, key)
assert(Buffer.from(pt).equals(Buffer.from(plaintext)), 'AES-GCM round-trips correctly')

let tagFlipped = false
try {
  const corrupted = ct.slice()
  corrupted[corrupted.length - 1] ^= 0xff
  AESGCM.decrypt(corrupted, key)
} catch {
  tagFlipped = true
}
assert(tagFlipped, 'AES-GCM rejects a tampered ciphertext')

console.log('\nAll primitive tests passed.')
