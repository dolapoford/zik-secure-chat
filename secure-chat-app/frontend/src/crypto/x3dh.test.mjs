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
