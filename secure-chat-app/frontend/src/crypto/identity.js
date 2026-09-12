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
