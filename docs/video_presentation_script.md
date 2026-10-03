# Thesis Defense Video — Script & Demo Runbook

Target: 3–5 minutes (aim for ~4:00). Audience: defense/viva panel.

---

## Time budget

| Time | Segment | Purpose |
|---|---|---|
| 0:00–0:20 | Hook + problem | Why E2EE messaging matters, what's broken in custom protocols |
| 0:20–0:45 | Approach | Signal Protocol (X3DH + Double Ratchet), AES-256-GCM, Ed25519, TreeKEM — why formally verified components |
| 0:45–2:45 | **Live demo** | The proof — this is the segment the panel actually scrutinizes |
| 2:45–3:15 | Results | Performance numbers + 7/7 security properties |
| 3:15–3:45 | Limitations & future work | Shows critical self-assessment, not just a sales pitch |
| 3:45–4:00 | Close | Which RQs were met, one-line conclusion |

---

## Narration script

**0:00–0:20 — Hook**

> "Widely deployed messaging platforms have repeatedly shipped custom cryptographic protocols with documented weaknesses. This project asks: can a chat application built entirely on formally verified primitives — the Signal Protocol, AES-256-GCM, Ed25519 — deliver real end-to-end encryption without sacrificing usability or performance?"

**0:20–0:45 — Approach**

> "The system uses X3DH for session establishment, the Double Ratchet for per-message forward secrecy, Ed25519 for message signing, and an MLS-aligned TreeKEM design for group messaging. For one-to-one chat, all of this — key generation, session state, the ratchet itself — runs client-side in the browser. The server only ever sees public keys and ciphertext."

**0:45–2:45 — Live demo**

Narrate over the actions in the Demo Runbook section below. Don't read it verbatim — describe what's happening as it happens ("Alice's client is generating her identity keys now...", "notice Bob's window updates with the decrypted plaintext...").

**2:45–3:15 — Results**

> "Across 1,000 iterations, AES-256-GCM encrypted a message in 0.033 milliseconds, the full X3DH handshake completed in 0.775 milliseconds, and Double Ratchet per-message overhead was 0.030 milliseconds — all well within interactive latency requirements. TreeKEM group operations scaled logarithmically, and all seven evaluated security properties — forward secrecy, authentication, MITM detection, replay prevention, and others — passed."

**3:15–3:45 — Limitations**

> "Group messaging's key custody remains server-side — that migration is scoped as future work, alongside key rotation, revocation, and full RFC 9420 conformance for TreeKEM."

**3:45–4:00 — Close**

> "Four of six research questions are fully met, with the remaining two partially met and clearly scoped. The result is a working, quantitatively evaluated reference implementation in an area where complete open implementations remain scarce."

---

## Demo runbook (click-by-click)

### Before recording

1. Start the backend from `secure-chat-app/`:
   ```
   mvnw spring-boot:run
   ```
2. Start the frontend from `secure-chat-app/frontend/`:
   ```
   npm run dev
   ```
3. Open browser windows:
   - Window A (normal profile) — Alice
   - Window B (incognito / second profile) — Bob
   - Window C (incognito / third profile) — Carol, for the group demo
   - A separate tab open to the H2 console, pre-filtered to the `messages` table, ready to refresh
4. Arrange windows side by side (Alice | Bob) so decryption is visible in the same shot without switching tabs.
5. Do one full silent dry run — timing drifts fast once narration is added.

### 1:1 messaging (Alice ↔ Bob)

1. Register Alice in Window A. Pause briefly on the moment of registration — this is where client-side key generation happens.
2. Register Bob in Window B.
3. From Alice, start a conversation with Bob and send a message (e.g. "Hey Bob, this is end-to-end encrypted").
4. Cut to Bob's window — show the message arriving decrypted.
5. Send a reply from Bob to Alice — show the ratchet advancing (a second message, not just the first).
6. Open the safety-number / key verification view for the conversation — point out it's inline in the chat, not buried in settings.
7. Switch to the H2 console tab, refresh the `messages` table — show ciphertext-only rows, no plaintext or private key columns. **Linger here** — this is the strongest visual proof of the client-side migration.

### Group messaging (Alice, Bob, Carol)

1. From Alice, create a group and add Bob and Carol.
2. Send a message to the group from Alice.
3. Cut to Bob's and Carol's windows — both show the decrypted message.
4. Remove Carol from the group (from Alice's members panel).
5. Show the group's epoch advancing and that the group disappears from Carol's own group list — this demonstrates forward secrecy on membership change.

---

## Recording & editing notes

- **Screen capture:** OBS Studio (free). Record demo silently first; record narration separately as voiceover and sync in editing — easier to re-take flubbed lines without re-running the app.
- **Editing:** DaVinci Resolve or Clipchamp (ships with Windows 11). Trim dead time between clicks, add small on-screen labels for protocol names during the demo (X3DH, Double Ratchet, TreeKEM), title card at the start, closing card with the thesis title.
- **Export:** 1080p, stay under 5:00 — panels penalize overruns more than tight pacing.
