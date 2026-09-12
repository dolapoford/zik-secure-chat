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
