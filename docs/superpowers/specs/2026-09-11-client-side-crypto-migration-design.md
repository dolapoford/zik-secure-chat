# Client-Side Crypto Migration (1:1 Messaging) — Design

Status: approved by user, pending implementation plan
Date: 2026-09-11
Scope owner: secure-chat-app (thesis reference implementation)

## 1. Goal

Move all cryptographic operations for **one-to-one messaging** — identity/signing
key generation, X3DH session establishment, the Double Ratchet, and Ed25519
message signing — from the Spring Boot backend into the React frontend, so the
server becomes a key-blind relay and prekey directory: it stores and routes
ciphertext and public key material, and never has access to any private key or
any plaintext message.

This is the first of four sub-projects identified after verifying the current
implementation against the thesis's aim and objectives (see
`Chapter_4_Results_and_Discussions.md` §4.9 and
`Chapter_5_Summary_Conclusion_and_Recommendations.md` §5.4–5.5). The other
three — real-time WebSocket push, key rotation/revocation, and conformant
persistent TreeKEM for group messaging — are explicitly **out of scope** here
and will each get their own design once this one ships, because rotation,
revocation, and per-member path-secret encapsulation only mean something once
the client actually holds the keys in question.

## 2. Non-goals

- **Group messaging (TreeKEM) is not touched.** `GroupService` and
  `TreeKEMManager` keep working exactly as they do today — server-side,
  already tested. Migrating group crypto to the client is its own later
  sub-project.
- **No real-time push.** 1:1 chat keeps the existing 2-second polling of
  `/api/chat/history`. Replacing polling with WebSocket push is deferred so
  the server can push ciphertext for on-device decryption once this
  migration exists, rather than doing it twice.
- **No key rotation or revocation.** Deferred to its own sub-project.
- **No multi-device support, key backup, or key export/import.** Private
  keys are scoped to one browser profile. Losing that browser's storage
  means generating a new identity (see §8).
- **No re-benchmarking of the JS crypto path.** Chapter 4's performance
  table is produced by the Java benchmark suite (`CryptoBenchmark.java`),
  which is unaffected by this migration and continues to run. This design
  does not add an equivalent JS benchmark; see §11 for how the thesis text
  should describe this going forward.
- **No changes to password-based account authentication.** Login/registration
  still authenticate the user to the server with a password; that is a
  separate concern from E2EE key custody and is unaffected by this design.

## 3. Background: what's true today

Verified live in earlier sessions:
- `MessageService.establishSession` computes X3DH and initializes **both**
  the sender's outgoing Double Ratchet state and a server-side mirror of the
  recipient's incoming state, using private keys the server generated and
  stored for both accounts (identity/signing keys on `User`, prekey private
  halves on `PreKeyBundle`).
- `MessageService.getChatHistory` decrypts stored messages server-side using
  that mirrored state and returns plaintext to the frontend.
- The database is H2 **in-memory** (`jdbc:h2:mem:securechatdb`) — it is wiped
  on every server restart. This matters for rollout: there is no real user
  data to migrate; a restart after this change ships is a clean slate.

This design replaces that server-side custody model for 1:1 messaging only.

## 4. Key design decisions (confirmed with user)

| Decision | Choice | Rationale |
|---|---|---|
| Scope | 1:1 messaging only; group messaging deferred | Keeps this sub-project independently shippable; TreeKEM's redesign is different in kind, not degree |
| Crypto library | `@noble/curves`, `@noble/hashes`, `@noble/ciphers` | Audited, dependency-free, consistent cross-browser behavior for X25519/Ed25519, unlike native WebCrypto's inconsistent curve support |
| Private key storage | IndexedDB, single browser profile, no backup/export | Matches real E2EE apps' baseline; keeps scope bounded; documented as a limitation |

## 5. Architecture & data flow

```
Registration:
  Browser generates identity keypair (X25519) + signing keypair (Ed25519)
  + 1 signed prekey + N one-time prekeys, all locally.
  Private halves -> IndexedDB (keyed by username).
  Public halves + signature -> POST /api/auth/register, POST /api/prekeys/upload

Session establishment (sender side, "Alice"):
  Browser checks IndexedDB for an existing outgoing ratchet session for the
  contact. If absent: GET /api/prekeys/{contact} (public bundle + signature +
  contact's signingPublicKey) -> verify signature locally -> generate
  ephemeral keypair -> X3DH locally -> initialize Double Ratchet locally ->
  persist state to IndexedDB. Safety number computed locally, no server call.

Sending:
  Encrypt locally with the outgoing ratchet. Embed sender's ephemeral +
  identity public keys in the message header (see §6.3). POST
  {ciphertext, header, signature} to /api/chat/send. Server stores and
  routes only; no crypto, no plaintext.

Receiving (recipient side, "Bob"):
  Poll GET /api/chat/history (2s, unchanged cadence). For each message not
  yet in the local plaintext cache: if no local incoming ratchet session
  exists for that sender, bootstrap one from the header's embedded ephemeral
  + identity public keys plus Bob's own prekey private keys (from IndexedDB)
  via the recipient-side X3DH mirror, exactly mirroring what the server used
  to do — except now using Bob's own keys that never left his browser.
  Decrypt, verify signature, cache plaintext by message id, advance and
  persist ratchet state.

Group messaging: unchanged, server-side, out of scope.
```

## 6. Component changes

### 6.1 New frontend crypto modules (`frontend/src/crypto/`)

- `primitives.js` — thin wrappers over noble libraries, mirroring the shape
  of the existing Java classes for traceability: `X25519KeyExchange`,
  `Ed25519SignerUtil`, `HKDFUtil`, `AESGCMCipher`.
- `doubleRatchet.js` — port of `DoubleRatchet.java`: `RatchetState`,
  `initializeAlice`/`initializeBob`, `encrypt`/`decrypt`,
  `performDHRatchet`, `skipMessageKeys`, header serialize/deserialize
  (extended per §6.3).
- `x3dh.js` — port of `performX3DH`/`performX3DHRecipient`.
- `keyStore.js` — IndexedDB persistence via the `idb-keyval` package:
  own identity/signing keypair, own prekeys (public + private), per-contact
  outgoing and incoming ratchet state, and a message-id → plaintext cache
  (see §8 for why the cache is required, not optional).
- `identity.js` — `getOrCreateIdentity(username)`,
  `ensurePrekeys(username, minCount)` (checks
  `GET /api/prekeys/mine/count`, generates and uploads more when low).

### 6.2 Backend changes

**Data model:**
- `User`: remove `identityPrivateKey`, `signingPrivateKey` columns.
- `PreKeyBundle`: remove `signedPreKeyPrivate`, `oneTimePreKeyPrivate`
  columns (added in the previous fix; this migration reverses that —
  intentionally, since the direction of travel is now "server holds
  nothing," not "server holds more"). Add a `signingPublicKey` column,
  populated from the client's upload, so a sender can verify a prekey
  bundle's signature without a second lookup.
- `Message`: remove the `plaintext` cache column — the server never
  decrypts, so it never has plaintext to cache. (The equivalent cache moves
  client-side; see `keyStore.js` above.)

**Endpoints:**
- `POST /api/auth/register` — now accepts `identityPublicKey`,
  `signingPublicKey` from the client instead of generating them.
- `POST /api/prekeys/upload` (new) — client publishes
  `{signedPreKey, signedPreKeySignature, oneTimePreKeys: [...], signingPublicKey}`.
- `GET /api/prekeys/mine/count?username=X` (new) — lets the client decide
  when to replenish; replaces the server's current auto-replenish-on-fetch
  behavior, which cannot work anymore (the server can't generate a user's
  prekeys for them).
- `GET /api/prekeys/{username}` — unchanged shape, now also returns
  `signingPublicKey`.
- `POST /api/chat/send` — now accepts opaque `ciphertext`, `header`,
  `signature`; no longer accepts plaintext `message`.
- `GET /api/chat/history` — now returns opaque `ciphertext`/`header`/
  `signature`/`timestamp` per message; no `text` field.
- `POST /api/chat/session` and `MessageService.establishSession` —
  **deleted**. Session setup is entirely client-side now (see §5).

**`MessageService.java`** shrinks to CRUD/routing only: no imports of
`DoubleRatchet`, `X25519KeyExchange`, or `Ed25519SignerUtil`. The
`sessions`/`recvSessions` in-memory maps are deleted.

**`UserService.java`**: `register()` stores client-submitted public keys
instead of generating keys; `generatePreKeyBundle()` (server-side
generation) is replaced by a `storePreKeyBundle(...)` that persists what the
client uploads; the auto-replenish side effect inside the old
`fetchAndConsumePreKeyBundle` is removed.

The Java crypto classes (`DoubleRatchet`, `X25519KeyExchange`,
`Ed25519SignerUtil`, `HKDFUtil`, `AESGCMCipher`) and `CryptoBenchmark` are
**kept, unchanged** — they fall out of the live message path but remain the
algorithmic reference implementation behind Chapter 4's performance table.

### 6.3 Wire-format fix: embedding X3DH bootstrap parameters in the header

Today, Alice's X3DH ephemeral public key is generated and discarded — this
only "works" because the server computes both sides itself. Once the client
owns the crypto, Bob's browser has no way to complete X3DH unless Alice's
ephemeral and identity public keys actually reach him. Fix: embed both in
every `MessageHeader` (64 bytes of overhead, always present rather than
special-cased to "first message only," for simplicity). This is a
client-side format change only — `ratchetHeader` is stored as an opaque
`byte[]` server-side already, so no schema change is needed for it beyond
what §6.2 already lists.

On first decrypt from a sender with no existing local incoming session, the
recipient uses these embedded values plus its own prekey private keys
(never transmitted, already in its own IndexedDB) to run the X3DH mirror and
lazily initialize its incoming ratchet — the same logic `establishSession`
used to perform server-side, now running correctly on the actual key owner's
device.

## 7. Registration / login flow

**Register:** generate identity + signing + prekeys locally → persist
private halves to IndexedDB keyed by username → upload public halves via
`/api/auth/register` and `/api/prekeys/upload`.

**Login:** password auth unchanged (server-side, unrelated to E2EE). After
login, check IndexedDB for a stored identity for this username:
- **Found** → proceed normally.
- **Not found** (different browser, cleared storage) → generate a **new**
  identity and publish it, replacing whatever the server has on file. Old
  conversations from other devices become permanently undecryptable on this
  device. The UI must say this plainly (a one-time notice), not fail
  silently.

On every login, call `ensurePrekeys()` to top up if the server-side count is
low (mirrors the old threshold of 5).

## 8. Send / receive correctness

**Send:** encrypt locally, POST opaque bytes. No plaintext leaves the
browser at any point.

**Receive:** poll history, and for each message:
1. Check the local plaintext cache (keyed by message id) first.
2. If not cached, locate or bootstrap the incoming ratchet session for that
   sender (§6.3), decrypt, verify the Ed25519 signature over the ciphertext,
   cache the resulting plaintext, and persist the advanced ratchet state.

This ordering is not optional: Double Ratchet message keys are single-use.
If the client ever re-ran decrypt on a message it had already processed
(e.g., after a naive page-refresh re-fetch of full history), it would be
attempting to decrypt with a key the ratchet has already advanced past, and
would fail. The plaintext cache is what makes repeated history fetches safe,
exactly mirroring the pattern already used server-side before this
migration.

**Decrypt failure** (unknown sender with no bootstrap params, epoch/key
mismatch after a lost-identity reset, or a genuine AEAD failure): show a
placeholder (e.g. "[Unable to decrypt — message may be from before this
device's current identity]") rather than crashing, matching the existing
placeholder convention already used for group messages.

## 9. Error handling

- **IndexedDB unavailable** (rare browser/privacy-mode configurations):
  `keyStore.js` detects this and surfaces a clear error rather than failing
  silently — "Your browser doesn't support the storage this app needs for
  end-to-end encryption."
- **Signature verification failure** on a fetched prekey bundle: same
  behavior as today (rejected as a possible MITM), just evaluated
  client-side now instead of server-side.
- **Prekey exhaustion** (recipient has zero one-time prekeys left): X3DH
  already tolerates a null one-time-prekey input; preserve that fallback
  rather than blocking the sender.

## 10. Testing plan

1. **Primitive-level correctness, pre-UI:** a small standalone Node script
   (not a full test-framework addition) exercising the ported JS primitives
   — X3DH agreement between two simulated parties, Double Ratchet
   encrypt/decrypt round-trips, signature verify/reject — before wiring
   anything into the UI.
2. **Live two-browser verification**, same methodology as the previous two
   fixes: register two fresh accounts, confirm client-side key generation
   (inspect IndexedDB via devtools), establish a session, exchange multiple
   messages bidirectionally, confirm correct decryption on both sides.
3. **Explicit server-blindness check:** inspect the `/api/chat/send`
   network payload (must be opaque base64, no `message` field) and query
   the H2 console directly to confirm `User` and `PreKeyBundle` rows contain
   no private-key columns at all after this migration.

## 11. Thesis text implications (for after implementation)

Once implemented and verified, Chapters 4 and 5 need another accuracy pass:
- RQ1's "partially met" status (server-side key custody) should move to
  "met" for 1:1 messaging specifically, with group messaging's server-side
  custody noted separately as still open (tracked under the deferred TreeKEM
  sub-project).
- Add a clarifying note that Chapter 4's performance table characterizes the
  Java reference algorithms (`CryptoBenchmark`), which remain in the
  codebase for that purpose, rather than the browser runtime that now
  handles live 1:1 traffic.
- Add the single-device/no-backup limitation explicitly, alongside the
  existing limitations list.

## 12. Risks / open items carried forward, not blocking this design

- Group messaging's server-side key custody remains after this ships —
  expected, tracked as its own sub-project.
- No automated regression test suite exists for the Java backend either;
  this migration relies on the same live-browser verification methodology
  used throughout this project, not CI-enforced tests.
- **Same user open in two tabs at once is not race-safe.** Ratchet state
  moves from a single centralized server-side map to per-browser IndexedDB;
  two tabs logged in as the same user and sending concurrently could read
  the same chain key before either writes back its advance, corrupting the
  ratchet for that conversation. The previous server-side design didn't
  have this problem (one process, one map). This is accepted as out of
  scope for a thesis reference implementation — real Signal solves this
  with considerably more session-management machinery — but should be
  named explicitly rather than silently assumed away. Testing in this
  design (§10) always uses one tab per account, which does not exercise
  this failure mode.
