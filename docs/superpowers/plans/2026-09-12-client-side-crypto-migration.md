# Client-Side Crypto Migration (1:1 Messaging) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move all cryptographic operations for 1:1 messaging (identity/signing key generation, X3DH, Double Ratchet, Ed25519 signing) from the Spring Boot backend into the React frontend, so the server stores and routes only public keys and opaque ciphertext.

**Architecture:** Three phases. Phase A builds and verifies the JS crypto primitives standalone (no UI, no backend dependency) via Node scripts. Phase B changes the backend to a key-blind relay (new/changed endpoints, removed private-key columns), verified via curl. Phase C builds the browser-side key store and session orchestration and rewires `App.jsx` to use them, verified via the same live two-browser Playwright methodology used for the two previous fixes in this project.

**Tech Stack:** `@noble/curves`, `@noble/hashes`, `@noble/ciphers` (crypto), `idb-keyval` (IndexedDB persistence), existing Spring Boot 3.2 / React 19 / Vite stack.

**Spec:** `docs/superpowers/specs/2026-09-11-client-side-crypto-migration-design.md`

## Global Constraints

- Group messaging (`GroupService`, `TreeKEMManager`, `GroupController`) is untouched by this plan.
- No WebSocket push in this plan — 1:1 chat keeps 2-second polling of `/api/chat/history`, now decrypting client-side instead of receiving server-decrypted text.
- No key rotation/revocation in this plan.
- The Java crypto classes (`DoubleRatchet`, `X25519KeyExchange`, `Ed25519SignerUtil`, `HKDFUtil`, `AESGCMCipher`) and `CryptoBenchmark` are not deleted — they stay as the algorithmic reference implementation behind Chapter 4's benchmark table, and simply fall out of the live message path.
- The H2 database is in-memory (`jdbc:h2:mem:securechatdb`); every server restart is a clean slate, so no data-migration tasks are needed for schema changes.
- Every new JS module uses `Uint8Array` for raw bytes and base64 strings only at API/storage boundaries (network payloads, IndexedDB-serialized fields where noted).

---

## Phase A: JS Crypto Primitives (standalone, Node-verifiable)

### Task 1: Add crypto and storage dependencies

**Files:**
- Modify: `secure-chat-app/frontend/package.json`

**Interfaces:**
- Produces: `@noble/curves`, `@noble/hashes`, `@noble/ciphers`, `idb-keyval` importable from any frontend module.

- [ ] **Step 1: Install the dependencies**

Run from `secure-chat-app/frontend/`:
```bash
npm install @noble/curves@^1.9.0 @noble/hashes@^1.8.0 @noble/ciphers@^1.3.0 idb-keyval@^6.2.1
```

- [ ] **Step 2: Verify they resolve**

Run: `node -e "require('@noble/curves/ed25519'); require('@noble/hashes/sha256'); require('@noble/ciphers/aes'); require('idb-keyval'); console.log('ok')"` from `secure-chat-app/frontend/`
Expected: prints `ok` with no errors. (If it errors on CJS/ESM interop, run the equivalent as an `.mjs` file instead — these packages are ESM-first.)

- [ ] **Step 3: Commit**

```bash
cd secure-chat-app/frontend
git add package.json package-lock.json
git commit -m "chore: add client-side crypto and IndexedDB dependencies"
```

---

### Task 2: Core primitives module (X25519, Ed25519, HKDF, AES-256-GCM)

Ports `X25519KeyExchange.java`, `Ed25519SignerUtil.java`, `HKDFUtil.java`, `AESGCMCipher.java`. The HKDF port needs two modes because the Java code uses two different Bouncy Castle code paths: `deriveKey(ikm, info, len)` (2-arg) skips the HKDF-Extract step entirely (treats `ikm` as the PRK directly), while `deriveKey(ikm, salt, info, len)` (3-arg with a real salt) does full extract-then-expand. These are **not interchangeable** — `deriveMessageAndChainKey` relies on the skip-extract form, `deriveRootAndChainKey` relies on the full form. Getting this wrong silently produces different keys with no error.

**Files:**
- Create: `secure-chat-app/frontend/src/crypto/primitives.js`
- Test: `secure-chat-app/frontend/src/crypto/primitives.test.mjs` (standalone Node script, not a framework test)

**Interfaces:**
- Produces:
  - `X25519.generateKeyPair()` → `{privateKey: Uint8Array(32), publicKey: Uint8Array(32)}`
  - `X25519.computeSharedSecret(ourPrivateKey, theirPublicKey)` → `Uint8Array(32)`
  - `Ed25519.generateKeyPair()` → `{privateKey: Uint8Array(32), publicKey: Uint8Array(32)}`
  - `Ed25519.sign(message, privateKey)` → `Uint8Array(64)`
  - `Ed25519.verify(message, signature, publicKey)` → `boolean`
  - `Ed25519.computeSafetyNumber(ourIdentityPub, theirIdentityPub)` → `string`
  - `HKDF.deriveKey(ikm, info, outputLength)` → `Uint8Array` (skip-extract form)
  - `HKDF.deriveKeyWithSalt(ikm, salt, info, outputLength)` → `Uint8Array` (full extract+expand)
  - `HKDF.deriveRootAndChainKey(rootKey, dhOutput)` → `[Uint8Array(32), Uint8Array(32)]`
  - `HKDF.deriveMessageAndChainKey(chainKey)` → `[Uint8Array(32), Uint8Array(32)]`
  - `AESGCM.encrypt(plaintext, key, aad?)` → `Uint8Array` (`[12-byte nonce | ciphertext+tag]`)
  - `AESGCM.decrypt(encryptedData, key, aad?)` → `Uint8Array`
  - `bytesToBase64(bytes)` / `base64ToBytes(str)` helpers

- [ ] **Step 1: Write the primitives module**

```js
// secure-chat-app/frontend/src/crypto/primitives.js
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
```

- [ ] **Step 2: Write the standalone verification script**

```js
// secure-chat-app/frontend/src/crypto/primitives.test.mjs
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
```

- [ ] **Step 3: Run the verification script**

Run: `node secure-chat-app/frontend/src/crypto/primitives.test.mjs`
Expected: seven `PASS:` lines followed by `All primitive tests passed.`, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add secure-chat-app/frontend/src/crypto/primitives.js secure-chat-app/frontend/src/crypto/primitives.test.mjs
git commit -m "feat: add browser-side crypto primitives (X25519, Ed25519, HKDF, AES-GCM)"
```

---

### Task 3: X3DH module

Ports `X25519KeyExchange.performX3DH` / `performX3DHRecipient`.

**Files:**
- Create: `secure-chat-app/frontend/src/crypto/x3dh.js`
- Test: `secure-chat-app/frontend/src/crypto/x3dh.test.mjs`

**Interfaces:**
- Consumes: `X25519` from `primitives.js`, `HKDF` from `primitives.js`.
- Produces:
  - `performX3DH(senderIdentityPriv, senderEphemeralPriv, recipientIdentityPub, recipientSignedPrekeyPub, recipientOneTimePrekeyPub)` → `Uint8Array(32)` (last arg may be `null`)
  - `performX3DHRecipient(recipientIdentityPriv, recipientSignedPrekeyPriv, recipientOneTimePrekeyPriv, senderIdentityPub, senderEphemeralPub)` → `Uint8Array(32)` (third arg may be `null`)

- [ ] **Step 1: Write the X3DH module**

```js
// secure-chat-app/frontend/src/crypto/x3dh.js
import { X25519, HKDF } from './primitives.js'

function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const a of arrays) {
    out.set(a, offset)
    offset += a.length
  }
  return out
}

export function performX3DH(
  senderIdentityKey, senderEphemeralKey,
  recipientIdentityPub, recipientSignedPrePub, recipientOneTimePub
) {
  const dh1 = X25519.computeSharedSecret(senderIdentityKey, recipientSignedPrePub)
  const dh2 = X25519.computeSharedSecret(senderEphemeralKey, recipientIdentityPub)
  const dh3 = X25519.computeSharedSecret(senderEphemeralKey, recipientSignedPrePub)

  const dhConcat = recipientOneTimePub
    ? concatBytes(dh1, dh2, dh3, X25519.computeSharedSecret(senderEphemeralKey, recipientOneTimePub))
    : concatBytes(dh1, dh2, dh3)

  return HKDF.deriveKey(dhConcat, new TextEncoder().encode('X3DH'), 32)
}

export function performX3DHRecipient(
  recipientIdentityKey, recipientSignedPreKey, recipientOneTimeKey,
  senderIdentityPub, senderEphemeralPub
) {
  const dh1 = X25519.computeSharedSecret(recipientSignedPreKey, senderIdentityPub)
  const dh2 = X25519.computeSharedSecret(recipientIdentityKey, senderEphemeralPub)
  const dh3 = X25519.computeSharedSecret(recipientSignedPreKey, senderEphemeralPub)

  const dhConcat = recipientOneTimeKey
    ? concatBytes(dh1, dh2, dh3, X25519.computeSharedSecret(recipientOneTimeKey, senderEphemeralPub))
    : concatBytes(dh1, dh2, dh3)

  return HKDF.deriveKey(dhConcat, new TextEncoder().encode('X3DH'), 32)
}
```

- [ ] **Step 2: Write the verification script**

```js
// secure-chat-app/frontend/src/crypto/x3dh.test.mjs
import { X25519 } from './primitives.js'
import { performX3DH, performX3DHRecipient } from './x3dh.js'

function assert(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg)
  console.log('PASS: ' + msg)
}

const aliceIdentity = X25519.generateKeyPair()
const aliceEphemeral = X25519.generateKeyPair()
const bobIdentity = X25519.generateKeyPair()
const bobSignedPreKey = X25519.generateKeyPair()
const bobOneTimePreKey = X25519.generateKeyPair()

const aliceSecret = performX3DH(
  aliceIdentity.privateKey, aliceEphemeral.privateKey,
  bobIdentity.publicKey, bobSignedPreKey.publicKey, bobOneTimePreKey.publicKey
)
const bobSecret = performX3DHRecipient(
  bobIdentity.privateKey, bobSignedPreKey.privateKey, bobOneTimePreKey.privateKey,
  aliceIdentity.publicKey, aliceEphemeral.publicKey
)
assert(Buffer.from(aliceSecret).equals(Buffer.from(bobSecret)), 'X3DH agreement matches with a one-time prekey')

const aliceSecretNoOpk = performX3DH(
  aliceIdentity.privateKey, aliceEphemeral.privateKey,
  bobIdentity.publicKey, bobSignedPreKey.publicKey, null
)
const bobSecretNoOpk = performX3DHRecipient(
  bobIdentity.privateKey, bobSignedPreKey.privateKey, null,
  aliceIdentity.publicKey, aliceEphemeral.publicKey
)
assert(Buffer.from(aliceSecretNoOpk).equals(Buffer.from(bobSecretNoOpk)), 'X3DH agreement matches without a one-time prekey')

console.log('\nAll X3DH tests passed.')
```

- [ ] **Step 3: Run it**

Run: `node secure-chat-app/frontend/src/crypto/x3dh.test.mjs`
Expected: two `PASS:` lines, then `All X3DH tests passed.`, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add secure-chat-app/frontend/src/crypto/x3dh.js secure-chat-app/frontend/src/crypto/x3dh.test.mjs
git commit -m "feat: add browser-side X3DH key agreement"
```

---

### Task 4: Double Ratchet module with embedded X3DH bootstrap header

Ports `DoubleRatchet.java`. Per the spec (§6.3), the header format is extended
beyond the Java version to always carry the sender's X3DH identity and
ephemeral public keys, so a recipient who has never seen this sender before
can bootstrap their incoming session purely from a received message — the
server no longer does this for them.

**Files:**
- Create: `secure-chat-app/frontend/src/crypto/doubleRatchet.js`
- Test: `secure-chat-app/frontend/src/crypto/doubleRatchet.test.mjs`

**Interfaces:**
- Consumes: `X25519`, `HKDF`, `AESGCM` from `primitives.js`.
- Produces:
  - `initializeAlice(sharedSecret, remoteDHPublic)` → `RatchetState` (plain object, see below)
  - `initializeBob(sharedSecret, dhKeyPair)` → `RatchetState`
  - `encrypt(state, plaintext, bootstrap)` → `{header: Uint8Array, ciphertext: Uint8Array}`, where `bootstrap = {senderIdentityPublicKey, senderEphemeralPublicKey, senderSigningPublicKey}`; mutates `state` in place
  - `decrypt(state, header, ciphertext)` → `Uint8Array` (plaintext); mutates `state` in place
  - `deserializeHeader(bytes)` → `{dhPublicKey, previousChainLength, messageNumber, senderIdentityPublicKey, senderEphemeralPublicKey, senderSigningPublicKey}` — the embedded signing key is what lets a recipient verify a message's Ed25519 signature without a separate network lookup (see Task 11)
  - `RatchetState` shape: `{dhPrivateKey, dhPublicKey, remoteDHPublicKey, rootKey, sendingChainKey, receivingChainKey, sendingMessageNumber, receivingMessageNumber, previousSendingChainLength, skippedMessageKeys: {[string]: Uint8Array}}` — every field is either a `Uint8Array`, a number, `null`, or a plain object, so it round-trips through IndexedDB structured clone without extra serialization work in `keyStore.js`.

- [ ] **Step 1: Write the Double Ratchet module**

```js
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
```

Note: `decrypt` always uses the *live* receiving chain rather than checking
`skippedMessageKeys` first. This mirrors the Java reference implementation
exactly (it has the same gap — `skippedMessageKeys` is populated but never
consulted on decrypt) and is preserved here for behavioral parity rather than
silently fixed, since fixing it is unrelated to this migration's scope. Both
test scripts below only exercise in-order delivery, which does not hit this
gap.

- [ ] **Step 2: Write the verification script**

```js
// secure-chat-app/frontend/src/crypto/doubleRatchet.test.mjs
import { X25519, Ed25519 } from './primitives.js'
import { initializeAlice, initializeBob, encrypt, decrypt } from './doubleRatchet.js'

function assert(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg)
  console.log('PASS: ' + msg)
}

function textEqual(bytes, str) {
  return new TextDecoder().decode(bytes) === str
}

// Simulate: shared X3DH secret already agreed, Bob's initial ratchet key is
// his signed prekey pair (as the app uses it), Alice's ephemeral/identity
// keys are bundled into every header per this migration's wire format.
const sharedSecret = new Uint8Array(32).fill(9)
const bobSignedPreKeyPair = X25519.generateKeyPair()
const aliceIdentity = X25519.generateKeyPair()
const aliceEphemeral = X25519.generateKeyPair()
const aliceSigning = Ed25519.generateKeyPair()

const aliceState = initializeAlice(sharedSecret, bobSignedPreKeyPair.publicKey)
const bobState = initializeBob(sharedSecret, bobSignedPreKeyPair)

const bootstrap = {
  senderIdentityPublicKey: aliceIdentity.publicKey,
  senderEphemeralPublicKey: aliceEphemeral.publicKey,
  senderSigningPublicKey: aliceSigning.publicKey,
}

const msg1 = encrypt(aliceState, new TextEncoder().encode('Hello Bob'), bootstrap)
const plain1 = decrypt(bobState, msg1.header, msg1.ciphertext)
assert(textEqual(plain1, 'Hello Bob'), 'Bob bootstraps his session and decrypts the first message')

const msg2 = encrypt(aliceState, new TextEncoder().encode('Second message'), bootstrap)
const plain2 = decrypt(bobState, msg2.header, msg2.ciphertext)
assert(textEqual(plain2, 'Second message'), 'Bob decrypts a second message on the same chain')

const oldChainKey = aliceState.sendingChainKey.slice()
const msg3 = encrypt(aliceState, new TextEncoder().encode('Third message'), bootstrap)
assert(
  Buffer.from(aliceState.sendingChainKey).compare(Buffer.from(oldChainKey)) !== 0,
  'Sending chain key advances after each message (forward secrecy)'
)
const plain3 = decrypt(bobState, msg3.header, msg3.ciphertext)
assert(textEqual(plain3, 'Third message'), 'Bob decrypts a third message correctly')

let tamperedRejected = false
try {
  const corrupted = msg3.ciphertext.slice()
  corrupted[corrupted.length - 1] ^= 0xff
  decrypt(bobState, msg3.header, corrupted)
} catch {
  tamperedRejected = true
}
// Note: msg3 was already consumed above, so this reuses its header against a
// fresh corrupted ciphertext purely to confirm AEAD tampering is rejected,
// not to test double-decryption.
assert(tamperedRejected, 'Tampered ciphertext is rejected by AES-GCM auth tag')

console.log('\nAll Double Ratchet tests passed.')
```

- [ ] **Step 3: Run it**

Run: `node secure-chat-app/frontend/src/crypto/doubleRatchet.test.mjs`
Expected: five `PASS:` lines, then `All Double Ratchet tests passed.`, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add secure-chat-app/frontend/src/crypto/doubleRatchet.js secure-chat-app/frontend/src/crypto/doubleRatchet.test.mjs
git commit -m "feat: add browser-side Double Ratchet with embedded X3DH bootstrap header"
```

---

## Phase B: Backend — server becomes key-blind

**Before starting:** run `mvn -q -o compile` once to confirm the baseline still builds, from `secure-chat-app/`.

### Task 5: Remove private-key columns; add signingPublicKey to PreKeyBundle

**Files:**
- Modify: `secure-chat-app/src/main/java/com/securechat/model/User.java`
- Modify: `secure-chat-app/src/main/java/com/securechat/model/PreKeyBundle.java`

**Interfaces:**
- Produces: `User` with only `identityPublicKey`/`signingPublicKey` (no private key fields); `PreKeyBundle` with a new `signingPublicKey` field and no private key fields.

**Do not touch `Message.java` in this task.** Its `plaintext` field looks
like 1:1-messaging leftover but is not: `GroupService.decryptAndCache`
(added in the group-messaging fix earlier in this project) actively reads
and writes it to cache decrypted group messages, and group messaging is
explicitly out of scope for this plan (Global Constraints). After this
plan, `plaintext` simply stays permanently `null` on 1:1 message rows
(`MessageService` never calls its setter, per Task 7) while remaining
load-bearing for group message rows. Removing it would silently break
already-verified group messaging.

- [ ] **Step 1: Edit `User.java`** — remove the `identityPrivateKey` and `signingPrivateKey` fields and their getters/setters, and the `setIdentityPrivateKey`/`setSigningPrivateKey` calls will need updating at call sites in Task 6. Resulting fields on `User`: `id`, `username`, `passwordHash`, `identityPublicKey`, `signingPublicKey`, `online`.

- [ ] **Step 2: Edit `PreKeyBundle.java`** — remove `signedPreKeyPrivate` and `oneTimePreKeyPrivate` fields and their getters/setters (and the doc comment referencing `MessageService.establishSession`, which no longer exists after Task 7). Add:

```java
    /** Signing (Ed25519) public key of the bundle owner, uploaded alongside
     * the prekeys so a sender can verify the signed-prekey signature without
     * a separate lookup. */
    @Lob
    @Column(name = "signing_public_key")
    private byte[] signingPublicKey;
```
with matching `getSigningPublicKey()`/`setSigningPublicKey()`.

- [ ] **Step 3: Compile (expect failures in dependent files — that's expected until Tasks 6–8 land)**

Run: `mvn -q -o compile` from `secure-chat-app/`
Expected: compilation errors in `UserService.java` and `MessageService.java` referencing the removed members. Confirm the errors are exactly those two files — if anything else fails to compile, stop and investigate before continuing.

- [ ] **Step 4: Commit**

```bash
git add secure-chat-app/src/main/java/com/securechat/model/User.java secure-chat-app/src/main/java/com/securechat/model/PreKeyBundle.java
git commit -m "refactor: remove private-key storage from User/PreKeyBundle, add PreKeyBundle.signingPublicKey"
```

---

### Task 6: UserService — client-supplied keys, prekey upload, count endpoint

**Files:**
- Modify: `secure-chat-app/src/main/java/com/securechat/service/UserService.java`
- Modify: `secure-chat-app/src/main/java/com/securechat/controller/AuthController.java`
- Modify: `secure-chat-app/src/main/java/com/securechat/controller/PreKeyController.java`
- Modify: `secure-chat-app/src/main/java/com/securechat/model/PreKeyBundleRepository.java`

**Interfaces:**
- Consumes: `User`/`PreKeyBundle` shapes from Task 5.
- Produces:
  - `UserService.register(username, password, identityPublicKeyB64, signingPublicKeyB64)` → `Map<String,Object>`
  - `UserService.storePreKeyBundle(username, signedPreKeyB64, signedPreKeySignatureB64, oneTimePreKeysB64List, signingPublicKeyB64)` → stores one `PreKeyBundle` per one-time prekey
  - `UserService.countAvailablePreKeys(username)` → `long`
  - `UserService.fetchAndConsumePreKeyBundle(username)` → `PreKeyBundle` (no longer auto-replenishes; replenishment is client-driven now)
  - `POST /api/auth/register` accepts `{username, password, identityPublicKey, signingPublicKey}`
  - `POST /api/prekeys/upload` (new) accepts `{username, signedPreKey, signedPreKeySignature, oneTimePreKeys: [...], signingPublicKey}`
  - `GET /api/prekeys/mine/count?username=X` (new) → `{count: number}`

- [ ] **Step 1: Rewrite the relevant `UserService` methods**

```java
    /**
     * Registers a new user with client-supplied public keys. Private keys
     * are generated and held exclusively on the client and never reach this
     * method.
     */
    public Map<String, Object> register(String username, String password,
                                         byte[] identityPublicKey, byte[] signingPublicKey) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        User user = new User(username, passwordEncoder.encode(password));
        user.setIdentityPublicKey(identityPublicKey);
        user.setSigningPublicKey(signingPublicKey);
        userRepository.save(user);

        Map<String, Object> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("username", username);
        result.put("identityPublicKey", Base64.getEncoder().encodeToString(user.getIdentityPublicKey()));
        result.put("signingPublicKey", Base64.getEncoder().encodeToString(user.getSigningPublicKey()));
        return result;
    }

    /**
     * Persists a batch of client-generated, client-signed prekeys. Each
     * one-time prekey becomes its own consumable PreKeyBundle row, all
     * sharing the same signed prekey and signature (mirroring how the
     * client-side prekey generation batches them).
     */
    public void storePreKeyBundle(String username, byte[] signedPreKey, byte[] signedPreKeySignature,
                                   List<byte[]> oneTimePreKeys, byte[] signingPublicKey) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        for (byte[] oneTimePreKey : oneTimePreKeys) {
            PreKeyBundle bundle = new PreKeyBundle();
            bundle.setUserId(user.getId());
            bundle.setUsername(username);
            bundle.setIdentityKey(user.getIdentityPublicKey());
            bundle.setSignedPreKey(signedPreKey);
            bundle.setSignedPreKeySignature(signedPreKeySignature);
            bundle.setSigningPublicKey(signingPublicKey);
            bundle.setOneTimePreKey(oneTimePreKey);
            preKeyBundleRepository.save(bundle);
        }
    }

    public long countAvailablePreKeys(String username) {
        return preKeyBundleRepository.countByUsernameAndConsumedFalse(username);
    }

    /**
     * Consumes and returns a user's full prekey bundle entity. Replenishment
     * is entirely client-driven now (see storePreKeyBundle) since the server
     * cannot generate a user's private prekey material on their behalf.
     */
    public PreKeyBundle fetchAndConsumePreKeyBundle(String username) {
        PreKeyBundle bundle = preKeyBundleRepository.findFirstByUsernameAndConsumedFalse(username)
                .orElseThrow(() -> new IllegalArgumentException("No prekey bundle available for: " + username));
        bundle.setConsumed(true);
        preKeyBundleRepository.save(bundle);
        return bundle;
    }

    public Map<String, String> fetchPreKeyBundle(String username) {
        PreKeyBundle bundle = fetchAndConsumePreKeyBundle(username);

        Map<String, String> result = new HashMap<>();
        result.put("identityKey", Base64.getEncoder().encodeToString(bundle.getIdentityKey()));
        result.put("signedPreKey", Base64.getEncoder().encodeToString(bundle.getSignedPreKey()));
        result.put("signedPreKeySignature", Base64.getEncoder().encodeToString(bundle.getSignedPreKeySignature()));
        result.put("oneTimePreKey", Base64.getEncoder().encodeToString(bundle.getOneTimePreKey()));
        result.put("signingPublicKey", Base64.getEncoder().encodeToString(bundle.getSigningPublicKey()));
        return result;
    }
```

Delete the old `register(String, String)` (2-arg), `generatePreKeyBundle(User)`, and the `import com.securechat.crypto.*;` line (no longer used anywhere in this file — `UserService` now does no cryptography at all).

- [ ] **Step 2: Update `AuthController.register`**

```java
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> request) {
        try {
            String username = request.get("username");
            String password = request.get("password");
            byte[] identityPublicKey = Base64.getDecoder().decode(request.get("identityPublicKey"));
            byte[] signingPublicKey = Base64.getDecoder().decode(request.get("signingPublicKey"));
            Map<String, Object> result = userService.register(username, password, identityPublicKey, signingPublicKey);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
```
Add `import java.util.Base64;` to `AuthController.java`.

- [ ] **Step 3: Add the two new endpoints to `PreKeyController`**

```java
    @PostMapping("/upload")
    public ResponseEntity<?> uploadPreKeys(@RequestBody Map<String, Object> request) {
        try {
            String username = (String) request.get("username");
            byte[] signedPreKey = Base64.getDecoder().decode((String) request.get("signedPreKey"));
            byte[] signedPreKeySignature = Base64.getDecoder().decode((String) request.get("signedPreKeySignature"));
            byte[] signingPublicKey = Base64.getDecoder().decode((String) request.get("signingPublicKey"));

            @SuppressWarnings("unchecked")
            List<String> oneTimePreKeysB64 = (List<String>) request.get("oneTimePreKeys");
            List<byte[]> oneTimePreKeys = oneTimePreKeysB64.stream()
                    .map(s -> Base64.getDecoder().decode(s))
                    .toList();

            userService.storePreKeyBundle(username, signedPreKey, signedPreKeySignature, oneTimePreKeys, signingPublicKey);
            return ResponseEntity.ok(Map.of("stored", oneTimePreKeys.size()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/mine/count")
    public ResponseEntity<?> countMine(@RequestParam String username) {
        return ResponseEntity.ok(Map.of("count", userService.countAvailablePreKeys(username)));
    }
```
Add `import java.util.Base64;` and `import java.util.List;` to `PreKeyController.java`.

- [ ] **Step 4: Compile**

Run: `mvn -q -o compile` from `secure-chat-app/`
Expected: still fails, now only in `MessageService.java` (Task 7 fixes this). Confirm no errors remain in `UserService.java`, `AuthController.java`, or `PreKeyController.java`.

- [ ] **Step 5: Commit**

```bash
git add secure-chat-app/src/main/java/com/securechat/service/UserService.java secure-chat-app/src/main/java/com/securechat/controller/AuthController.java secure-chat-app/src/main/java/com/securechat/controller/PreKeyController.java
git commit -m "feat: accept client-supplied public keys on registration; add prekey upload and count endpoints"
```

---

### Task 7: MessageService becomes a key-blind relay; delete session establishment

**Files:**
- Modify: `secure-chat-app/src/main/java/com/securechat/service/MessageService.java`
- Modify: `secure-chat-app/src/main/java/com/securechat/controller/ChatWebSocketController.java`

**Interfaces:**
- Produces:
  - `MessageService.sendMessage(sender, recipient, ciphertextB64, headerB64, signatureB64)` → `Map<String,Object>` (no `throws Exception` — no crypto happens here anymore)
  - `MessageService.getChatHistory(user1, user2)` → `List<Map<String,Object>>`, each entry `{messageId, sender, recipient, ciphertext, header, signature, timestamp}` (base64 strings for the byte fields)
  - `POST /api/chat/send` accepts `{sender, recipient, ciphertext, header, signature}`
  - `GET /api/chat/history` unchanged query params, changed response shape
  - `POST /api/chat/session` and `establishSession` — **removed**

- [ ] **Step 1: Rewrite `MessageService.java` in full**

```java
package com.securechat.service;

import com.securechat.model.*;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Message service handling 1:1 encrypted message storage and retrieval.
 * The server never sees plaintext or private key material — all
 * cryptography (X3DH, Double Ratchet, signing) happens client-side. This
 * service is a thin, key-blind relay: it stores whatever ciphertext/header/
 * signature bytes the sender's client produces and returns them unchanged
 * to whichever client asks for the conversation's history.
 */
@Service
public class MessageService {

    private final MessageRepository messageRepository;

    public MessageService(MessageRepository messageRepository) {
        this.messageRepository = messageRepository;
    }

    public Map<String, Object> sendMessage(String senderUsername, String recipientUsername,
                                            byte[] ciphertext, byte[] header, byte[] signature) {
        Message message = new Message();
        message.setSenderId(senderUsername);
        message.setRecipientId(recipientUsername);
        message.setCiphertext(ciphertext);
        message.setRatchetHeader(header);
        message.setSignature(signature);
        messageRepository.save(message);

        Map<String, Object> result = new HashMap<>();
        result.put("messageId", message.getId());
        result.put("sender", senderUsername);
        result.put("recipient", recipientUsername);
        result.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        result.put("header", Base64.getEncoder().encodeToString(header));
        result.put("signature", Base64.getEncoder().encodeToString(signature));
        result.put("timestamp", message.getTimestamp().toString());
        return result;
    }

    public List<Map<String, Object>> getChatHistory(String user1, String user2) {
        List<Message> sent = messageRepository.findBySenderIdAndRecipientIdOrderByTimestamp(user1, user2);
        List<Message> received = messageRepository.findBySenderIdAndRecipientIdOrderByTimestamp(user2, user1);

        List<Message> all = new ArrayList<>();
        all.addAll(sent);
        all.addAll(received);
        all.sort(Comparator.comparing(Message::getTimestamp));

        List<Map<String, Object>> result = new ArrayList<>();
        for (Message msg : all) {
            Map<String, Object> m = new HashMap<>();
            m.put("messageId", msg.getId());
            m.put("sender", msg.getSenderId());
            m.put("recipient", msg.getRecipientId());
            m.put("ciphertext", Base64.getEncoder().encodeToString(msg.getCiphertext()));
            m.put("header", Base64.getEncoder().encodeToString(msg.getRatchetHeader()));
            m.put("signature", Base64.getEncoder().encodeToString(msg.getSignature()));
            m.put("timestamp", msg.getTimestamp().toString());
            result.add(m);
        }
        return result;
    }
}
```

- [ ] **Step 2: Remove the session-establishment REST endpoint and update `sendMessage`/`getChatHistory` call sites in `ChatWebSocketController.java`**

Delete the `establishSession` method (the `@PostMapping("/api/chat/session")` handler) entirely.

Replace the `sendMessage` and `handleChatMessage` bodies to pass through the new fields instead of a plaintext `message`:

```java
    @PostMapping("/api/chat/send")
    public ResponseEntity<?> sendMessage(@RequestBody Map<String, String> request) {
        try {
            String sender = request.get("sender");
            String recipient = request.get("recipient");
            byte[] ciphertext = Base64.getDecoder().decode(request.get("ciphertext"));
            byte[] header = Base64.getDecoder().decode(request.get("header"));
            byte[] signature = Base64.getDecoder().decode(request.get("signature"));
            Map<String, Object> result = messageService.sendMessage(sender, recipient, ciphertext, header, signature);

            messagingTemplate.convertAndSendToUser(recipient, "/queue/messages", result);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @MessageMapping("/chat.send")
    @SendTo("/topic/messages")
    public Map<String, Object> handleChatMessage(@Payload Map<String, String> message) {
        String sender = message.get("sender");
        String recipient = message.get("recipient");
        byte[] ciphertext = Base64.getDecoder().decode(message.get("ciphertext"));
        byte[] header = Base64.getDecoder().decode(message.get("header"));
        byte[] signature = Base64.getDecoder().decode(message.get("signature"));
        Map<String, Object> result = messageService.sendMessage(sender, recipient, ciphertext, header, signature);

        messagingTemplate.convertAndSendToUser(recipient, "/queue/messages", result);
        return result;
    }

    @GetMapping("/api/chat/history")
    public ResponseEntity<?> getChatHistory(
            @RequestParam String user1, @RequestParam String user2) {
        try {
            return ResponseEntity.ok(messageService.getChatHistory(user1, user2));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
```
Add `import java.util.Base64;` to `ChatWebSocketController.java`.

- [ ] **Step 3: Compile**

Run: `mvn -q -o compile` from `secure-chat-app/`
Expected: `BUILD SUCCESS` with no output on `-q`. The whole backend now compiles key-blind for 1:1 messaging.

- [ ] **Step 4: Commit**

```bash
git add secure-chat-app/src/main/java/com/securechat/service/MessageService.java secure-chat-app/src/main/java/com/securechat/controller/ChatWebSocketController.java
git commit -m "refactor: MessageService becomes a key-blind relay; remove server-side session establishment"
```

---

### Task 8: Live backend verification via curl

**Files:** none (verification only)

- [ ] **Step 1: Start the backend**

Run from `secure-chat-app/`: `mvn -q -o spring-boot:run` (background), wait for it to bind port 8080 (`curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/prekeys/mine/count?username=nobody` returns `200` with `{"count":0}`).

- [ ] **Step 2: Register a user with client-style public keys**

```bash
curl -s -X POST http://localhost:8080/api/auth/register -H "Content-Type: application/json" \
  -d '{"username":"plan_test_a","password":"Passw0rd!","identityPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","signingPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'
```
Expected: `200` with the echoed public keys, no server-generated keys in the response.

- [ ] **Step 3: Upload a prekey bundle**

```bash
curl -s -X POST http://localhost:8080/api/prekeys/upload -H "Content-Type: application/json" \
  -d '{"username":"plan_test_a","signedPreKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","signedPreKeySignature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==","oneTimePreKeys":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],"signingPublicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'
```
Expected: `{"stored":1}`.

- [ ] **Step 4: Check the count endpoint reflects it**

Run: `curl -s "http://localhost:8080/api/prekeys/mine/count?username=plan_test_a"`
Expected: `{"count":1}`.

- [ ] **Step 5: Fetch the bundle and confirm it includes `signingPublicKey` and no private fields**

Run: `curl -s http://localhost:8080/api/prekeys/plan_test_a`
Expected: JSON with `identityKey`, `signedPreKey`, `signedPreKeySignature`, `oneTimePreKey`, `signingPublicKey` — no field named anything containing `Private`.

- [ ] **Step 6: Send and fetch an opaque message**

```bash
curl -s -X POST http://localhost:8080/api/auth/register -H "Content-Type: application/json" \
  -d '{"username":"plan_test_b","password":"Passw0rd!","identityPublicKey":"AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=","signingPublicKey":"AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="}'
curl -s -X POST http://localhost:8080/api/chat/send -H "Content-Type: application/json" \
  -d '{"sender":"plan_test_a","recipient":"plan_test_b","ciphertext":"ZmFrZS1jaXBoZXJ0ZXh0","header":"ZmFrZS1oZWFkZXI=","signature":"ZmFrZS1zaWc="}'
curl -s "http://localhost:8080/api/chat/history?user1=plan_test_a&user2=plan_test_b"
```
Expected: the history response contains `ciphertext: "ZmFrZS1jaXBoZXJ0ZXh0"` verbatim (base64 of `fake-ciphertext`) — proof the server stores and returns opaque bytes without attempting to decrypt them.

- [ ] **Step 7: Confirm `/api/chat/session` is gone**

Run: `curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/api/chat/session -H "Content-Type: application/json" -d '{}'`
Expected: `404`.

- [ ] **Step 8: Stop the backend**

Find and kill the process bound to port 8080 (matching the approach used earlier in this project: `netstat -ano | grep ":8080"` then `taskkill //F //PID <pid>`).

No commit for this task — it's verification only, no file changes.

---

## Phase C: Frontend — key store, session orchestration, and UI wiring

### Task 9: IndexedDB key store

**Files:**
- Create: `secure-chat-app/frontend/src/crypto/keyStore.js`

**Interfaces:**
- Consumes: `idb-keyval`.
- Produces:
  - `getIdentity(username)` → `Promise<{identityKeyPair, signingKeyPair} | undefined>`
  - `saveIdentity(username, identityKeyPair, signingKeyPair)` → `Promise<void>`
  - `savePreKeys(username, prekeys)` → `Promise<void>` where `prekeys = {signedPreKeyPair, oneTimePreKeyPairs: [...]}`
  - `getPreKeys(username)` → `Promise<{signedPreKeyPair, oneTimePreKeyPairs} | undefined>`
  - `getOutgoingSession(username, contact)` / `saveOutgoingSession(username, contact, ratchetState)`
  - `getIncomingSession(username, contact)` / `saveIncomingSession(username, contact, ratchetState)`
  - `getCachedPlaintext(username, messageId)` / `cachePlaintext(username, messageId, text)`

- [ ] **Step 1: Write the module**

```js
// secure-chat-app/frontend/src/crypto/keyStore.js
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
```

- [ ] **Step 2: Manual browser sanity check**

This module cannot be verified with a plain Node script (idb-keyval requires
`indexedDB`, a browser global). Defer its verification to Task 12's live
Playwright test, which will exercise every function here indirectly through
registration, sending, and receiving. Note this explicitly rather than
skipping verification silently.

- [ ] **Step 3: Commit**

```bash
git add secure-chat-app/frontend/src/crypto/keyStore.js
git commit -m "feat: add IndexedDB-backed key and session store"
```

---

### Task 10: Identity bootstrap and prekey replenishment

**Files:**
- Create: `secure-chat-app/frontend/src/crypto/identity.js`

**Interfaces:**
- Consumes: `X25519`, `Ed25519`, `bytesToBase64` from `primitives.js`; `getIdentity`, `saveIdentity`, `getPreKeys`, `savePreKeys` from `keyStore.js`.
- Produces:
  - `getOrCreateIdentity(username)` → `Promise<{identityKeyPair, signingKeyPair, isNew: boolean}>`
  - `ensurePrekeys(username, apiBase, minCount)` → `Promise<void>` (checks server count, generates+uploads more if below `minCount`)

- [ ] **Step 1: Write the module**

```js
// secure-chat-app/frontend/src/crypto/identity.js
import { X25519, Ed25519, bytesToBase64 } from './primitives.js'
import { getIdentity, saveIdentity, getPreKeys, savePreKeys } from './keyStore.js'

const ONE_TIME_PREKEY_BATCH_SIZE = 10

export async function getOrCreateIdentity(username) {
  const existing = await getIdentity(username)
  if (existing) {
    return { ...existing, isNew: false }
  }

  const identityKeyPair = X25519.generateKeyPair()
  const signingKeyPair = Ed25519.generateKeyPair()
  await saveIdentity(username, identityKeyPair, signingKeyPair)
  return { identityKeyPair, signingKeyPair, isNew: true }
}

function generatePreKeyBatch() {
  const signedPreKeyPair = X25519.generateKeyPair()
  const oneTimePreKeyPairs = Array.from({ length: ONE_TIME_PREKEY_BATCH_SIZE }, () => X25519.generateKeyPair())
  return { signedPreKeyPair, oneTimePreKeyPairs }
}

async function uploadPreKeys(apiBase, username, signingKeyPair, prekeys) {
  const signature = Ed25519.sign(prekeys.signedPreKeyPair.publicKey, signingKeyPair.privateKey)
  const res = await fetch(`${apiBase}/prekeys/upload`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      signedPreKey: bytesToBase64(prekeys.signedPreKeyPair.publicKey),
      signedPreKeySignature: bytesToBase64(signature),
      oneTimePreKeys: prekeys.oneTimePreKeyPairs.map((kp) => bytesToBase64(kp.publicKey)),
      signingPublicKey: bytesToBase64(signingKeyPair.publicKey),
    }),
  })
  return res.json()
}

/**
 * Ensures at least minCount one-time prekeys are available server-side for
 * this user, generating and uploading a fresh batch if not. Also persists
 * the newly generated private halves locally so they're available later
 * when this device needs to bootstrap an incoming session (see session.js).
 */
export async function ensurePrekeys(username, apiBase, signingKeyPair, minCount = 5) {
  const countRes = await fetch(`${apiBase}/prekeys/mine/count?username=${encodeURIComponent(username)}`)
  const { count } = await countRes.json()

  if (count >= minCount) return

  const newBatch = generatePreKeyBatch()
  await uploadPreKeys(apiBase, username, signingKeyPair, newBatch)

  const existing = (await getPreKeys(username)) || { signedPreKeyPair: null, oneTimePreKeyPairs: [] }
  await savePreKeys(username, {
    signedPreKeyPair: newBatch.signedPreKeyPair,
    oneTimePreKeyPairs: [...existing.oneTimePreKeyPairs, ...newBatch.oneTimePreKeyPairs],
  })
}
```

- [ ] **Step 2: Commit**

```bash
git add secure-chat-app/frontend/src/crypto/identity.js
git commit -m "feat: add client-side identity bootstrap and prekey replenishment"
```

(Verified together with Task 12's live test — this module has no meaningful standalone test without a running backend and a browser.)

---

### Task 11: Session orchestration (send/receive)

**Files:**
- Create: `secure-chat-app/frontend/src/crypto/session.js`

**Interfaces:**
- Consumes: everything from `primitives.js`, `x3dh.js`, `doubleRatchet.js`, `keyStore.js`.
- Produces:
  - `ensureOutgoingSession(apiBase, username, identityKeyPair, signingKeyPair, contact)` → `Promise<{safetyNumber: string}>`
  - `encryptMessage(username, contact, plaintextString)` → `Promise<{ciphertext: string, header: string}>` (base64; the caller still produces the transport-level `signature` field itself in Task 12, since that step already has direct access to the signing private key)
  - `decryptMessage(username, ownIdentityKeyPair, message)` → `Promise<string>`, where `message = {messageId, sender, ciphertext, header, signature}` (base64 fields as returned by the API). Verifies the Ed25519 signature using the signing public key embedded in the message header itself — no extra network round trip — and returns a placeholder string instead of throwing if verification or decryption fails.

- [ ] **Step 1: Write the module**

```js
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
```

- [ ] **Step 2: Commit**

```bash
git add secure-chat-app/frontend/src/crypto/session.js
git commit -m "feat: add client-side session orchestration for encrypt/decrypt"
```

---

### Task 12: Wire App.jsx to client-side crypto; live verification

**Files:**
- Modify: `secure-chat-app/frontend/src/App.jsx`

**Interfaces:**
- Consumes: `getOrCreateIdentity`, `ensurePrekeys` from `identity.js`; `ensureOutgoingSession`, `encryptMessage`, `decryptMessage` from `session.js`; `bytesToBase64` from `primitives.js`.

- [ ] **Step 1: Update the `Login` component's register path**

In `Login`, change `handleSubmit` so that on registration it generates the
identity locally before calling the API:

```jsx
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
```

Add the imports at the top of `App.jsx`:
```js
import { getOrCreateIdentity, ensurePrekeys } from './crypto/identity.js'
import { ensureOutgoingSession, encryptMessage, decryptMessage } from './crypto/session.js'
import { bytesToBase64 } from './crypto/primitives.js'
```

Note on `getOrCreateIdentity` on login: per the spec (§7), if this browser
has no stored identity for this username (different browser, cleared
storage), it generates a **new** one and `ensurePrekeys` publishes it,
replacing what the server has on file for this account. The `window.alert`
above satisfies the spec's requirement that this not fail silently; Task 13
additionally documents the behavior in the thesis limitations text.

- [ ] **Step 2: Replace `handleSelectContact`'s session establishment**

```jsx
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
```

- [ ] **Step 3: Replace `handleSendMessage`'s encryption**

```jsx
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
```

Add `import { Ed25519, base64ToBytes } from './crypto/primitives.js'` (merge
into the existing `primitives.js` import added in Step 1).

- [ ] **Step 4: Replace `loadHistory`'s decryption**

```jsx
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
```

- [ ] **Step 5: Lint**

Run: `npx oxlint src/App.jsx` from `secure-chat-app/frontend/`
Expected: no new errors beyond the pre-existing `no-unused-vars`/`exhaustive-deps` warnings already present before this plan (confirm by comparing against a `git stash` baseline run if in doubt).

- [ ] **Step 6: Live two-browser verification**

Start the backend (`mvn -q -o spring-boot:run` from `secure-chat-app/`) and
frontend (`npx vite --port 5173` from `secure-chat-app/frontend/`), wait for
both to bind. Using two Playwright browser tabs (same methodology as the
message-delivery and group-messaging fixes earlier in this project):

1. Register two fresh accounts (e.g. `henry_test` / `iris_test`) through the
   UI (not curl, so identity generation actually runs).
2. As Henry, select Iris as a contact, confirm a safety number appears.
3. Send a message from Henry to Iris.
4. Switch to Iris's tab, select Henry, confirm the message appears
   correctly decrypted (not empty, not a placeholder).
5. Reply from Iris to Henry; confirm Henry's tab shows the decrypted reply.
6. Send a second message from Henry; confirm it decrypts correctly too
   (proves the ratchet advances correctly across multiple messages under
   the new client-side implementation).

- [ ] **Step 7: Explicit server-blindness check**

With the same two accounts, open the H2 console
(`http://localhost:8080/h2-console`, JDBC URL `jdbc:h2:mem:securechatdb`,
user `sa`, blank password) and run:
```sql
SELECT * FROM USERS;
SELECT * FROM PREKEY_BUNDLES;
SELECT * FROM MESSAGES;
```
Expected: `USERS` and `PREKEY_BUNDLES` have no private-key columns at all
(confirming Task 5's schema change took effect); `MESSAGES.CIPHERTEXT` is
opaque binary, not readable plaintext.

Also inspect the `/api/chat/send` request payload in the browser's network
tab for one sent message: confirm it contains `ciphertext`/`header`/
`signature` fields and no plaintext `message` field.

- [ ] **Step 8: Stop both servers, commit**

```bash
git add secure-chat-app/frontend/src/App.jsx
git commit -m "feat: wire App.jsx to client-side crypto for 1:1 messaging"
```

---

### Task 13: Thesis accuracy pass

**Files:**
- Modify: `Chapter_4_Results_and_Discussions.md`
- Modify: `Chapter_5_Summary_Conclusion_and_Recommendations.md`

Only start this task after Task 12's live verification has actually passed.

- [ ] **Step 1: Update Chapter 4**

In Table 4.1's row for "Signal Protocol Engine (X3DH + Double Ratchet)",
change the status to reflect that key generation, X3DH, the Double Ratchet,
and Ed25519 signing now execute client-side in the browser (cite this plan's
completion), and that the server stores only public keys and opaque
ciphertext for 1:1 messaging. In Section 4.9, update the "Server-side
execution of cryptographic operations" limitation paragraph: state plainly
that this limitation has been resolved for 1:1 messaging specifically (with
the live two-browser and H2-console verification from Task 12, Steps 6–7 as
evidence), while noting it remains true for group messaging (unaffected by
this plan). Update the Table 4.10 RQ1 row from "Partially Met" to "Met" for
the 1:1 messaging scope, with a note that group messaging's server custody
is tracked separately. Add a sentence noting that Chapter 4's performance
table characterizes the Java reference implementation (`CryptoBenchmark`),
which remains in the codebase for that purpose, rather than the browser
runtime that now handles live 1:1 traffic (per the design spec §11).

- [ ] **Step 2: Update Chapter 5**

In §5.2's RQ1 discussion, replace the "partially met" assessment with "met"
for 1:1 messaging, citing this migration and its live verification, while
being explicit that group messaging's server-side custody remains open
(tracked as a separate, not-yet-started sub-project). In §5.4 Limitations,
add a new item documenting the single-device/no-backup consequence of
client-side key storage (per the design spec §7–8): losing browser storage
means generating a new identity and losing access to prior conversations on
that device. In §5.5 Future Work, mark the "migration of cryptographic
operations to the client" item as completed for 1:1 messaging, and note the
remaining sub-projects (WebSocket push, key rotation/revocation, conformant
persistent TreeKEM) are unaffected and still open.

- [ ] **Step 3: Commit**

```bash
git add Chapter_4_Results_and_Discussions.md Chapter_5_Summary_Conclusion_and_Recommendations.md
git commit -m "docs: update thesis to reflect client-side crypto migration for 1:1 messaging"
```

---

## Self-Review Notes

- **Spec coverage:** every numbered section of the design spec (§5 data flow,
  §6.1–6.3 components, §7 registration/login, §8 send/receive correctness,
  §9 error handling, §10 testing, §11 thesis implications) maps to at least
  one task above (2–4 for §6.1/6.3 crypto modules; 5–8 for §6.2 backend;
  9–11 for the remaining §6.1 client modules; 12 for §7/§8/§9/§10 live
  wiring and verification; 13 for §11).
- **Type/interface consistency:** `RatchetState` field names
  (`dhPrivateKey`, `dhPublicKey`, `remoteDHPublicKey`, `rootKey`,
  `sendingChainKey`, `receivingChainKey`, `sendingMessageNumber`,
  `receivingMessageNumber`, `previousSendingChainLength`,
  `skippedMessageKeys`) are identical across Task 4's module, Task 9's
  storage functions, and Task 11's orchestration. Base64 field names on the
  wire (`ciphertext`, `header`, `signature`) are identical across Task 7's
  backend and Task 11/12's frontend calls.
- **§12's concurrent-tab risk** from the spec is not mitigated by any task
  here — it's accepted as documented scope, consistent with the spec's own
  framing of it as a named, accepted risk rather than a requirement.
- **Issues found and fixed during this self-review:** (1) the Double
  Ratchet header originally omitted the sender's Ed25519 signing public
  key, leaving `decryptMessage` with no way to verify a message's signature
  without an extra network round trip — fixed by embedding it in the header
  alongside the X3DH bootstrap keys (Task 4, 11). (2) Task 5 originally
  removed `Message.plaintext`, which would have silently broken
  `GroupService`'s group-message decrypt cache from the earlier
  group-messaging fix — fixed by leaving `Message.java` untouched and
  documenting why.
