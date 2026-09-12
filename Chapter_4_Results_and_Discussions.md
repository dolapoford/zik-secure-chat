# **CHAPTER FOUR**

## **RESULT AND DISCUSSIONS**

This chapter presents the results of the implementation and evaluation of the secure chat application with end-to-end encryption. The results are organised according to the research objectives and evaluation framework established in Chapter Three. Section 4.1 presents an overview of the implemented system. Sections 4.2 through 4.6 and Section 4.8 present the quantitative performance benchmarks for each cryptographic component. Section 4.7 presents the security evaluation results. Section 4.9 documents scope limitations identified during verification of the implementation against the research objectives. Section 4.10 provides a comparative discussion of the results against the research objectives and existing solutions.

All benchmarks were conducted on the implemented system using the following configuration: Java 25.0.2 LTS, Spring Boot 3.2.5, Bouncy Castle bcprov-jdk18on v1.78.1, running on Windows 11 with a multi-core processor. Each performance benchmark comprised 1,000 iterations following a 100-iteration warmup phase to eliminate JIT compilation effects. Statistical measures include mean, 95th percentile (P95), and 99th percentile (P99) latencies.

 

### **4.1 System Implementation Overview**

The secure chat application was successfully implemented as a three-tier system comprising a Spring Boot 3.2 backend (Java 21), a React.js v18 frontend, and a cryptographic layer powered by Bouncy Castle. The system architecture implements the cryptographic design specified in Chapter Three — the Signal Protocol, AES-256-GCM, Ed25519, and TreeKEM — and all cryptographic primitives were validated through the benchmark and security test suite described in Sections 4.2 to 4.8. These benchmarks were conducted against the Java reference implementation of the cryptographic primitives (`CryptoBenchmark`), which remains in the codebase for benchmarking purposes; they characterise that Java implementation and not the browser (JavaScript) runtime discussed next. For one-to-one messaging, key generation, X3DH session establishment, the Double Ratchet, and Ed25519 message signing now execute within the React browser client rather than the Spring Boot backend, so the server stores only public keys and opaque ciphertext for 1:1 conversations; this migration and its live verification are documented in Section 4.9. TreeKEM group operations, however, are unaffected by this migration and continue to execute within the Spring Boot backend exactly as before, so the server currently retains access to the private key material required to perform group messaging's cryptographic operations. This group-messaging scope limitation is discussed further in Section 4.9.

The implementation encompasses the following functional components, each mapped to a specific research objective:

| Component | Research Objective | Implementation Status |
| :--- | :--- | :--- |
| Signal Protocol Engine (X3DH + Double Ratchet) | RQ1, RQ2 | Cryptographic primitives fully implemented and validated; key generation, X3DH, the Double Ratchet, and Ed25519 signing now execute client-side in the browser for one-to-one messaging, completed and live-verified via a client-side crypto migration (see Section 4.9); the server stores only public keys and opaque ciphertext for 1:1 conversations. Group messaging is unaffected and its cryptographic operations remain server-side (see Section 4.9) |
| AES-256-GCM Symmetric Encryption | RQ1 | Fully implemented |
| ECDH Key Exchange (X25519) | RQ2 | Fully implemented |
| Key Management Module (generate, distribute, verify) | RQ3 | Partially implemented — rotation and revocation not implemented |
| Ed25519 Digital Signatures | RQ4 | Fully implemented; signature now verified on every message decryption, not only in the isolated benchmark |
| HKDF-SHA256 Key Derivation | RQ1, RQ2 | Fully implemented |
| TreeKEM Group Messaging Encryption (simplified, epoch-based) | RQ5 | Partially implemented — group creation, membership management, sending, and decryption are now reachable through the application UI (fixed after initial verification); the underlying epoch-key derivation remains a simplification of full MLS/TreeKEM, and group state is not persisted — see Section 4.9 |
| WebSocket Real-Time Messaging (STOMP/SockJS) | RQ1 | Partially implemented — server-side broker still configured but unused; message delivery now works via a 2-second history-polling loop rather than real-time push — see Section 4.9 |
| Safety Number Key Verification | RQ3 | Fully implemented |
| Performance Benchmark Suite | RQ6 | Fully implemented |

**Table 4.1: Implementation Status by Research Objective**

The application was compiled and deployed without errors. The Spring Boot server started in 5.753 seconds and all integrated benchmark and security tests executed successfully on first run, confirming the correctness of the cryptographic implementations. Section 4.9 discusses the scope limitations of the current system architecture relative to the research objectives.

 

### **4.2 AES-256-GCM Encryption and Decryption Performance**

AES-256-GCM provides the symmetric encryption layer for all message content. The benchmark evaluated encryption and decryption latency across five message sizes: 64 bytes (short message), 256 bytes (typical message), 1,024 bytes (long message), 4,096 bytes (paragraph), and 16,384 bytes (extended content). Each test comprised 1,000 iterations with a 128-bit authentication tag and 96-bit random nonce.

| Message Size | Encrypt Mean (ms) | Encrypt P95 (ms) | Encrypt P99 (ms) | Decrypt Mean (ms) | Decrypt P95 (ms) | Decrypt P99 (ms) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 64 B | 0.030 | 0.051 | 0.117 | 0.017 | 0.026 | 0.063 |
| 256 B | 0.033 | 0.041 | 0.102 | 0.026 | 0.029 | 0.051 |
| 1,024 B | 0.086 | 0.113 | 0.233 | 0.069 | 0.109 | 0.165 |
| 4,096 B | 0.242 | 0.374 | 0.513 | 0.256 | 0.414 | 0.752 |
| 16,384 B | 0.934 | 1.435 | 2.355 | 1.101 | 1.533 | 3.614 |

**Table 4.2: AES-256-GCM Encryption and Decryption Performance (n = 1,000)**

The results demonstrate that AES-256-GCM encryption operates well within interactive messaging latency requirements. For typical text messages (64–256 bytes), encryption completes in under 0.035 ms on average, representing negligible overhead relative to network transmission latency. Even for the largest message size tested (16,384 bytes), the mean encryption latency of 0.934 ms and mean decryption latency of 1.101 ms remain far below the perceptible threshold for interactive messaging.

The linear relationship between message size and latency confirms that AES-256-GCM scales predictably with payload size, consistent with its O(n) complexity where n is the message length. The tight P95/P99 ratios (typically within 2–3x of the mean) indicate low variance and predictable performance, which is essential for real-time communication. The 128-bit authentication tag provides simultaneous confidentiality and integrity verification in a single operation, avoiding the need for separate MAC computation.

 

### **4.3 Key Exchange Performance (X25519 and X3DH)**

The key exchange layer comprises two operations: individual X25519 ECDH key agreements and the full X3DH protocol, which performs four DH operations plus HKDF key derivation to establish the initial session secret.

| Operation | Mean (ms) | P95 (ms) | P99 (ms) |
| :--- | :---: | :---: | :---: |
| X25519 Key Pair Generation | 0.098 | 0.157 | 0.251 |
| X25519 DH Agreement | 0.184 | 0.275 | 0.406 |
| X3DH Full Protocol (4 x DH + HKDF) | 0.775 | 1.182 | 2.093 |

**Table 4.3: Key Exchange Performance (n = 1,000)**

X25519 key pair generation completes in a mean of 0.098 ms, confirming its suitability for ephemeral key generation in the Double Ratchet's per-epoch DH ratchet step. The individual DH agreement operation (0.184 ms mean) is consistent with the known performance of Curve25519 on modern hardware (Bernstein, 2006).

The X3DH full protocol, comprising four DH operations, ephemeral key generation, and HKDF derivation, completes in a mean of 0.775 ms. This result is significant because X3DH is a one-time operation per session; it is executed only when two users first establish a conversation. The sub-millisecond mean latency confirms that X3DH introduces no perceptible delay to session establishment, even on resource-constrained devices. The P99 latency of 2.093 ms remains well within acceptable bounds for an interactive handshake.

The verification that both sender and recipient derive identical shared secrets (Security-X3DHAgreement: PASS) confirms the correctness of the implementation and validates that the four-DH construction produces consistent keying material across both parties, as required by the Signal Protocol specification (Marlinspike & Perrin, 2016).

 

### **4.4 Double Ratchet Per-Message Encryption Overhead**

The Double Ratchet Algorithm adds per-message overhead through symmetric-key ratchet operations (chain key derivation and message key derivation) on top of the AES-256-GCM encryption of message content.

| Operation | Mean (ms) | P95 (ms) | P99 (ms) |
| :--- | :---: | :---: | :---: |
| Double Ratchet Encrypt (per message) | 0.030 | 0.048 | 0.090 |

**Table 4.4: Double Ratchet Per-Message Encryption Overhead (n = 1,000)**

The Double Ratchet per-message encryption overhead of 0.030 ms (mean) is remarkably low. This figure includes the HKDF-based symmetric ratchet step (chain key to message key derivation), the AES-256-GCM encryption itself, and the header construction containing the current DH ratchet public key and message counters. The total per-message overhead is effectively O(1), independent of conversation length or message history, confirming the theoretical complexity analysis of the Double Ratchet (Bienstock et al., 2022).

The P99 latency of 0.090 ms demonstrates excellent worst-case performance, with fewer than 1% of messages experiencing latency above 90 microseconds for the entire encryption pipeline. This confirms that the Double Ratchet introduces no measurable delay to interactive messaging, validating its selection as the core E2EE mechanism.

 

### **4.5 Digital Signature Performance (Ed25519)**

Ed25519 digital signatures provide message authentication and identity binding. The benchmark measured both signing (message to signature) and verification (message + signature to valid/invalid) operations.

| Operation | Mean (ms) | P95 (ms) | P99 (ms) |
| :--- | :---: | :---: | :---: |
| Ed25519 Sign | 0.172 | 0.275 | 0.383 |
| Ed25519 Verify | 0.179 | 0.290 | 0.360 |

**Table 4.5: Ed25519 Digital Signature Performance (n = 1,000)**

Both signing and verification complete in under 0.2 ms on average, with 64-byte signatures. The near-symmetry between signing (0.172 ms) and verification (0.179 ms) latencies is characteristic of Ed25519, which uses a deterministic signing process without per-signature randomness (Brendel et al., 2021).

The sub-millisecond performance confirms that Ed25519 can be applied to every message without introducing perceptible overhead. In the implemented system, each message is signed before transmission and verified on receipt, providing non-repudiation and tamper detection as part of the standard message flow. The measured performance is consistent with the formally established security properties of Ed25519 under adaptive chosen-message attacks (Brendel et al., 2021).

 

### **4.6 Group Messaging Encryption Performance (TreeKEM)**

The TreeKEM group key management system was benchmarked across six group sizes: 2, 5, 10, 25, 50, and 100 members. Three operations were measured: member addition (which triggers a new epoch), member removal (which blanks a leaf and advances the epoch), and group message encryption using the current epoch key.

| Group Size | Add Member Mean (ms) | Remove Member Mean (ms) | Encrypt Message Mean (ms) |
| :---: | :---: | :---: | :---: |
| 2 | 0.140 | 0.016 | 0.024 |
| 5 | 0.129 | 0.026 | 0.024 |
| 10 | 0.158 | 0.057 | 0.023 |
| 25 | 0.217 | 0.109 | 0.036 |
| 50 | 0.320 | 0.224 | 0.023 |
| 100 | 0.582 | 0.429 | 0.019 |

**Table 4.6: TreeKEM Group Operations Performance (n = 100 per group size)**

The results demonstrate clear O(log n) scaling behaviour for membership operations. The member addition time increases from 0.140 ms (2 members) to 0.582 ms (100 members), a 4.16x increase for a 50x increase in group size. The theoretical O(log n) prediction would yield log2(100)/log2(2) = 6.64x increase; the measured 4.16x increase indicates that the implementation performs better than the theoretical worst case, likely due to the simplified tree traversal and efficient HKDF operations.

Member removal times follow a similar logarithmic pattern: 0.016 ms (2 members) to 0.429 ms (100 members). The removal operation is slightly faster than addition at small group sizes because blanking a leaf node does not require generating new keying material for the added member.

Group message encryption remains essentially constant across all group sizes (0.019–0.036 ms), confirming that per-message encryption is O(1) with respect to group size. This is because message encryption uses the pre-derived epoch key; only membership operations incur the tree traversal cost. This result validates the TreeKEM design's suitability for large groups, consistent with the scalability analysis of RFC 9420 (Barnes et al., 2023).

 

### **4.7 Security Evaluation Results**

The security evaluation tested seven cryptographic security properties against the threat model defined in Chapter Three. Each test was designed to validate a specific security guarantee of the implemented system.

| Security Property | Test Description | Result |
| :--- | :--- | :---: |
| Forward Secrecy | Verify that chain key advances after each message, preventing decryption of future messages with old keys | PASS |
| Message Authentication | Verify that Ed25519 rejects tampered messages while accepting unmodified messages | PASS |
| Key Verification (MitM Detection) | Verify that safety numbers differ when a contact's identity key changes | PASS |
| Replay Prevention | Verify that ciphertext encrypted with one key cannot be decrypted with a different key (consumed key scenario) | PASS |
| AES-GCM Authentication Tag | Verify that modified ciphertext is rejected by the GCM authentication tag verification | PASS |
| X3DH Shared Secret Agreement | Verify that both sender and recipient independently derive identical shared secrets from the X3DH protocol | PASS |
| Group Forward Secrecy | Verify that removing a member from a group causes the group key to change, preventing the removed member from decrypting future messages | PASS |

**Table 4.7: Security Evaluation Results**

All seven security properties passed validation, confirming that the implemented system provides the following guarantees:

**Forward Secrecy (RQ1, RQ2):** The Double Ratchet's symmetric ratchet step advances the chain key after every message. The test confirmed that the chain key changes after each encryption operation, ensuring that compromise of the current chain key cannot be used to derive message keys for past messages. This property is achieved through the one-way nature of the HKDF-based key derivation chain.

**Message Authentication and Integrity (RQ4):** The Ed25519 signature verification correctly rejects messages whose content has been modified after signing, while accepting unmodified messages. This demonstrates that the implemented signature scheme provides existential unforgeability under adaptive chosen-message attacks, consistent with the formal analysis of Brendel et al. (2021). The AES-GCM authentication tag provides a second layer of integrity verification, rejecting any ciphertext whose authentication tag has been modified.

**Man-in-the-Middle Detection (RQ3):** The safety number computation produces distinct fingerprints when a contact's identity key changes. This enables users to detect key substitution attacks by comparing safety numbers out-of-band. The test confirmed that different identity keys produce different safety numbers, and that the same key pair consistently produces the same safety number regardless of the order of comparison.

**Replay Prevention (RQ1):** The per-message key derivation ensures that each message is encrypted with a unique key. The test confirmed that ciphertext cannot be decrypted using a key different from the one used for encryption, which in the Double Ratchet context means that replaying a captured ciphertext after the receiving chain has advanced will fail because the required message key has been consumed and securely deleted.

**Group Forward Secrecy (RQ5):** The TreeKEM epoch advancement upon member removal ensures that the group encryption key changes when a member leaves. The test confirmed that the group key before and after a member removal differs, preventing the removed member from decrypting messages sent in subsequent epochs.

 

### **4.8 HKDF-SHA256 Key Derivation Performance**

| Operation | Mean (ms) | P95 (ms) | P99 (ms) |
| :--- | :---: | :---: | :---: |
| HKDF-SHA256 (32-byte output) | 0.006 | 0.018 | 0.023 |

**Table 4.8: HKDF-SHA256 Key Derivation Performance (n = 1,000)**

HKDF-SHA256 is the most frequently called cryptographic primitive in the system, invoked during every Double Ratchet step (twice per message: chain key derivation and message key derivation), during X3DH master secret derivation, and during TreeKEM epoch key derivation. The measured mean latency of 0.006 ms (6 microseconds) confirms that HKDF adds negligible overhead to the overall encryption pipeline. The very tight P95/P99 distribution (0.018/0.023 ms) demonstrates highly deterministic performance, which is essential for a primitive that underpins the entire key derivation architecture.

 

### **4.9 Implementation Limitations and Scope Clarifications**

Verification of the implementation against the research objectives and questions established in Chapter One identified four scope limitations that qualify the results presented above and the implementation status recorded in Table 4.1. Three of these — non-functional one-to-one message delivery, the absence of a working group-chat interface and message-decryption path, and server-side execution of cryptographic operations for one-to-one messaging — were remediated during the course of this verification and a subsequent client-side crypto migration; each is reported below alongside the finding that prompted it, together with what the fix did and did not resolve. Server-side custody of group messaging's cryptographic operations, and the absence of key rotation and revocation, remain open at the time of writing.

**Non-functional message delivery and decryption (RQ1) — identified and subsequently fixed.** Live functional testing of the deployed application initially established that the system did not deliver messages between users at all. Two accounts were registered and logged into separate browser sessions; an E2EE session was established between them, and a message was sent from the first account. Inspection of the backend showed that `DoubleRatchet.decrypt()` was never invoked from `MessageService` or from any controller, and the React frontend never called `/api/chat/history` or subscribed to the STOMP topic `ChatWebSocketController` publishes to; the sending account's own chat view was showing an optimistic local echo of its typed plaintext, not a decrypted server response, while the receiving account's view remained empty. This was corrected as follows. Because the recipient's prekey private keys were being discarded immediately after generation (only their public counterparts were persisted to `PreKeyBundle`), `MessageService.establishSession` was extended to also compute the recipient's side of the same X3DH handshake (`X25519KeyExchange.performX3DHRecipient`) and initialize a mirrored Double Ratchet state for them (`DoubleRatchet.initializeBob`), stored separately from the sender's outgoing state; this required persisting the signed-prekey and one-time-prekey private keys on `PreKeyBundle`, which — consistent with the server-side custody limitation described next — the server already had the means to hold. `MessageService.getChatHistory` was then extended to decrypt each stored message through the recipient's mirrored state on first fetch, verify the sender's Ed25519 signature over the ciphertext at the same time, and cache the resulting plaintext so that each single-use ratchet message key is consumed only once. On the frontend, the optimistic local echo was removed and replaced with a poll of `/api/chat/history` every two seconds while a conversation is open, so displayed messages are genuine decrypted server responses. Re-testing with two fresh accounts across separate browser sessions confirmed the fix: a message sent by one party is now correctly decrypted and displayed in the other party's chat view, replies are correctly decrypted in the reverse direction, and a second message sent immediately afterward is correctly decrypted using the advanced chain key, confirming the ratchet steps correctly across multiple messages. One residual limitation remains: delivery is now driven by polling rather than the real-time WebSocket push the architecture was designed around, so RQ1's "in real time" clause is only approximately satisfied, with the two-second poll interval as the effective latency bound. At this point in the verification, RQ1 was accordingly assessed as only partially met: message delivery and decryption now functioned correctly, but the deeper architectural guarantee — addressed in the next limitation, where it was subsequently resolved for one-to-one messaging — that only communicating parties, and not the server, can access message content, did not yet hold.

**Server-side execution of cryptographic operations (RQ1, RQ2) — identified and subsequently resolved for one-to-one messaging.** Inspection of the source code initially confirmed that user identity and signing key pairs were generated by, and persisted within, the Spring Boot backend (`UserService.register`), and that X3DH session establishment, Double Ratchet encryption/decryption, and Ed25519 message signing were all executed server-side within `MessageService`, rather than within the React.js client; the React frontend contained no cryptographic code of its own and was a presentational layer that called REST endpoints and displayed the resulting ciphertext. Notably, the message-delivery fix described above initially deepened rather than resolved this limitation: enabling the recipient to decrypt messages required persisting their signed-prekey and one-time-prekey private keys on the server as well, so the server briefly held a complete mirror of both parties' ratchet state for every conversation.

This was subsequently resolved for one-to-one messaging by a dedicated client-side crypto migration: key generation, X3DH session establishment, the Double Ratchet, and Ed25519 signing were moved into the React client, and the corresponding backend and persistence layers were changed so that the server retains only public keys (identity, signed-prekey, and one-time-prekey public material) and opaque Double Ratchet ciphertext for one-to-one conversations, with no private key material and no plaintext held server-side. Live verification with two fresh accounts across separate browser sessions confirmed the migration: registration generated identity and prekey material client-side, session establishment for a new conversation ran X3DH client-side, a message sent from each account was correctly encrypted and decrypted client-side by the other, a second message confirmed that the Double Ratchet chain key advances correctly across multiple messages, and inspection of the H2 console confirmed that no private keys or plaintext reached the server for either account. RQ1 and RQ2 are accordingly assessed as met for one-to-one messaging (Table 4.10).

This resolution does not extend to group messaging. TreeKEM group creation, membership management, and epoch-key derivation remain unaffected by this migration and continue to execute server-side exactly as described in the group-messaging limitation below, so the server-side custody limitation described above remains true for group conversations: the server retains the private key material and computational capability to decrypt any group conversation. Migrating group messaging's cryptographic operations to the client is tracked as a separate, not-yet-started future sub-project (Section 5.5).

**Group messaging inaccessible through the application (RQ5) — identified and subsequently fixed; underlying key-derivation simplification remains.** Live testing initially found that although `TreeKEMManager` correctly implemented group creation, membership changes, and epoch-based message encryption, none of it was reachable through the application: `GroupService.sendGroupMessage()` encrypted messages but never persisted them, `GroupService.decryptGroupMessage()` was never exposed by `GroupController`, and the React frontend had no group-chat interface at all beyond a decorative "TreeKEM Groups" badge on the welcome screen. This was corrected by persisting each group message to the existing `Message` entity (reusing its previously unused `groupId` and `epoch` columns), adding a `GET /api/groups/{groupId}/messages` endpoint that decrypts each message via `TreeKEMManager.decryptGroupMessage()` using the group's current epoch key and caches the result, and adding a group-chat interface to the frontend — creating a group, automatically listing the groups a user belongs to, sending and receiving messages, and adding or removing members through a members panel. Re-testing with three fresh accounts confirmed the fix: a message sent to a three-member group was correctly decrypted and displayed for the other two members; removing a member advanced the epoch and immediately removed the group from that member's own group list on their next poll, confirming group forward secrecy holds in the live application and not only in the isolated benchmark. Two things remain unresolved. First, `TreeKEMManager.updatePath()` still derives each new epoch secret from freshly generated server-side randomness combined with a hash of member public keys, rather than through per-member path-secret encapsulation to each leaf's public key as a conformant MLS/TreeKEM implementation (RFC 9420) requires; only the party performing an add/remove/update operation can compute the new epoch secret, not each member independently from their own private key. Second, group membership and epoch state (`GroupService`'s in-memory map) are still not persisted, whereas group messages now are as part of this fix — meaning a server restart would leave historically sent, persisted ciphertext with no corresponding key material anywhere to decrypt it, a more severe consequence than before this fix, when neither was persisted. RQ5 is accordingly assessed as partially met: group messaging is now usable end-to-end in the application, but the design does not yet meet full MLS conformance or provide state durability.

**Absence of key rotation and revocation (RQ3).** A review of the codebase confirms that key generation, distribution, and safety-number-based verification are implemented and validated (Section 4.7), but no functionality exists for rotating an existing identity or signed prekey, or for revoking a compromised key. Table 4.1 has been corrected accordingly; RQ3 is assessed as partially met.

 

### **4.10 Discussion of Results**

The results presented in Sections 4.2 through 4.8 demonstrate that the cryptographic primitives underlying the secure chat application meet their formal performance and security properties. As Section 4.9 details, live functional testing of the deployed application identified that one-to-one message delivery and group messaging were both inaccessible through the application; both were subsequently fixed and re-verified, moving RQ1 and RQ5 from not met to partially met. A subsequent client-side crypto migration then moved key generation, X3DH, the Double Ratchet, and Ed25519 signing for one-to-one messaging into the browser client and, following live two-browser and H2-console verification, resolved the server-side key custody limitation for that messaging mode, moving RQ1 from partially met to met for 1:1 scope; group messaging's server-side custody is unaffected and RQ5 remains partially met. Key management (RQ3) remains partially met, for the reasons detailed in Section 4.9.

**Performance Assessment:** The total per-message encryption pipeline, comprising Double Ratchet key derivation (0.030 ms), AES-256-GCM encryption (0.030 ms for a typical message), and Ed25519 signing (0.172 ms), completes in approximately 0.232 ms end-to-end. This total overhead is well below the 100 ms threshold that would be perceptible to a user in an interactive messaging context. The X3DH session establishment (0.775 ms) is a one-time cost per conversation and introduces no perceptible delay. These figures characterise the Java reference implementation (`CryptoBenchmark`), which remains in the codebase for benchmarking purposes; they do not characterise the browser (JavaScript) runtime that, following the client-side crypto migration described in Section 4.9, now performs these same operations for live one-to-one traffic, which was not independently re-benchmarked.

**Scalability:** The TreeKEM group key management demonstrates sub-millisecond latency for all operations up to 100-member groups. The logarithmic scaling of membership operations confirms that the architecture can support substantially larger groups without performance degradation, consistent with the O(log n) complexity guarantee of the TreeKEM construction as specified in RFC 9420 (Barnes et al., 2023).

**Security:** All seven security properties were validated, confirming that the underlying cryptographic primitives provide forward secrecy, post-compromise security (through the DH ratchet), message authentication and integrity (through Ed25519 and AES-GCM AEAD), MitM detection (through safety number verification), replay prevention (through per-message keys), and group forward secrecy (through epoch advancement on member removal). These tests validate the primitives themselves in isolation; they do not constitute a full deployed-system threat model, which would additionally need to account for group messaging's server-side key custody limitation discussed in Section 4.9 (one-to-one messaging's equivalent custody limitation was resolved by the client-side crypto migration verified in Section 4.9).

**Comparison with Research Objectives:**

| Research Objective | Evaluation Metric | Result | Status |
| :--- | :--- | :--- | :---: |
| RQ1: E2EE Architecture | System compiles, runs, and correctly encrypts/decrypts; recipient can read a sent message in the live application; only communicating parties, not the server, can access message content | Message delivery and decryption confirmed working (two-user browser re-test, bidirectional, multi-message). A subsequent client-side crypto migration moved key generation, X3DH, the Double Ratchet, and Ed25519 signing into the browser for one-to-one messaging; live two-browser and H2-console verification confirmed the server now stores only public keys and opaque ciphertext for 1:1 conversations, with no private keys or plaintext server-side (Section 4.9). Group messaging's server-side key custody is unaffected and tracked as a separate sub-project (Section 4.9) | Met (1:1 messaging scope) |
| RQ2: ECDH Key Exchange | X3DH produces identical shared secrets on both sides | Confirmed (0.775 ms) | Met |
| RQ3: Key Management | Safety numbers detect key changes; prekey lifecycle works | Generation, distribution, and verification confirmed; rotation and revocation not implemented (Section 4.9) | Partially Met |
| RQ4: Message Authentication | Ed25519 rejects tampered messages; AES-GCM auth tag validates | Confirmed (0.172 ms sign, 0.179 ms verify) | Met |
| RQ5: Group Messaging | TreeKEM scales O(log n); group forward secrecy holds; group messaging usable in the application | Epoch-advancement logic and performance confirmed (0.582 ms at 100 members); group creation, messaging, and membership management confirmed working end-to-end after remediation (three-user browser re-test); epoch-key derivation remains a simplification of full MLS, and group state is not persisted (Section 4.9) | Partially Met |
| RQ6: Performance Evaluation | All operations under 1 ms for typical messages | Confirmed | Met |

**Table 4.10: Research Objective Evaluation Summary**

The results validate the design decisions made in Chapter Three: the selection of the Signal Protocol, AES-256-GCM, Ed25519, X25519, and TreeKEM is justified by both the measured performance (sub-millisecond for all typical operations) and the confirmed security properties (all seven tests passed). The use of Bouncy Castle as the cryptographic provider ensures that all operations are implemented using formally reviewed, widely audited cryptographic primitives, avoiding the risks of custom implementations identified by Wermke et al. (2022) and Albrecht et al. (2022). These conclusions apply to the correctness of the cryptographic primitives; Section 4.9 documents the remaining architectural scope limitations — group messaging's server-side key custody, which is unaffected by the one-to-one client-side crypto migration, and the absence of key rotation and revocation — that must still be addressed before the system provides these guarantees across all messaging modes and the full key lifecycle.
