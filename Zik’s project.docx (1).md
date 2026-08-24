Secure Chat Application with End-to-End Encryption  
**CHAPTER ONE**

**INTRODUCTION**

**1.1 Background of the Study**

The proliferation of digital communication technologies has fundamentally transformed the way individuals, organizations, and governments exchange information. With the rapid expansion of smartphones, broadband internet, and cloud-based services, instant messaging has become an indispensable medium for personal, professional, and critical communications worldwide. According to Statista (2024), over five billion people are expected to use mobile messaging applications by 2025, underscoring the massive scale at which digital communication operates and the critical importance of protecting the privacy and integrity of such interactions. Among the most pressing concerns in this digital landscape is the persistent vulnerability of online communications to unauthorized interception, surveillance, and exploitation by malicious actors, corporations, and government agencies (Albrecht et al., 2022). These realities have intensified the demand for robust security mechanisms, particularly end-to-end encryption (E2EE), as the definitive standard for protecting digital conversations.

End-to-end encryption ensures that messages are encrypted on the sender’s device and can only be decrypted by the intended recipient, rendering communications unreadable to intermediaries, including internet service providers, application servers, and potential eavesdroppers (Wermke et al., 2022). The concept of E2EE is grounded in applied cryptography, which has evolved from simple substitution ciphers to sophisticated modern algorithms including the Advanced Encryption Standard (AES-256), Elliptic Curve Cryptography (ECC), and post-quantum constructions such as CRYSTALS-Kyber. Cryptography underpins nearly all aspects of modern digital security, serving as the foundational science upon which secure chat applications are built (Paar & Pelzl, 2010). Without robust and correctly implemented cryptographic mechanisms, even the most feature-rich messaging platforms remain susceptible to data breaches, man-in-the-middle attacks, and large-scale surveillance.

The development of public-key cryptography by Diffie and Hellman (1976) represented a transformative paradigm shift, enabling secure key exchange over insecure public channels without the need for a pre-shared secret. This foundational contribution catalyzed the development of asymmetric encryption frameworks and laid the theoretical foundation for modern E2EE systems. A landmark development in the evolution of secure chat was the introduction of the Signal Protocol by Open Whisper Systems, which combined the Double Ratchet Algorithm with the X3DH key agreement protocol to deliver robust, scalable E2EE for both one-on-one and group messaging (Marlinspike & Perrin, 2016). The Signal Protocol has since been adopted by WhatsApp, Facebook Messenger (Secret Conversations), and Google Messages, confirming its security and practical viability. In 2023, Signal further advanced the protocol by deploying PQXDH, a post-quantum extension to X3DH combining classical ECDH with the CRYSTALS-Kyber key encapsulation mechanism, providing resistance against future quantum adversaries (Bhargavan et al., 2024).

Despite these advances, numerous widely used communication platforms continue to operate without end-to-end encryption, or implement it in ways that are incomplete. poorly designed, or vulnerable to protocol-level attacks. Albrecht et al. (2022) demonstrated through formal cryptographic analysis that Telegram’s MTProto protocol contained four distinct and practically exploitable vulnerabilities, including a ciphertext malleability attack enabling message forgery, despite being used by hundreds of millions of users. Similarly, Albrecht, Dowling, and Jones (2023) identified practically exploitable cryptographic vulnerabilities in the Matrix protocol’s Olm and Megolm implementations. These findings underscore the persistent risk of deploying messaging systems without rigorous formal cryptographic verification, and reinforce the case for building on established, verified protocols.

The threat landscape facing secure messaging applications has grown substantially in sophistication and scope. Man-in-the-middle attacks, replay attacks, metadata leakage, and server compromise represent persistent attack surfaces that must be addressed through both cryptographic protocol design and architectural decisions. Domenech et al. (2022) demonstrated that observable traffic patterns in instant messaging applications can expose sensitive user behavior even when message content is fully encrypted, illustrating the critical importance of metadata protection alongside content encryption. The harvest-now-decrypt-later threat model, in which adversaries record encrypted traffic today for decryption by future quantum computers, has further elevated the urgency of transitioning to post-quantum secure protocols (NIST, 2024).

Group messaging presents additional cryptographic complexity. The Messaging Layer Security (MLS) protocol, standardised as RFC 9420 by the IETF (Barnes et al., 2023), addresses the scalability limitations of pairwise key exchange by employing a TreeKEM ratchet tree structure that achieves O(log n) complexity for membership operations, enabling efficient secure group messaging at scale. Formal verification of MLS implementations has been achieved by Wallez et al. (2023), who produced a machine-checked implementation of MLS authenticated group management using the F\* programming language and the HACL\* cryptographic library. These advances represent the current state of the art in group E2EE and inform the group messaging architecture adopted in this research.

Usability remains a central challenge in E2EE deployment. Turner, Shahandashti, and Petrie (2023) demonstrated through a controlled user study that the comparison mode producing the most security-effective key fingerprint verification was simultaneously perceived as least usable by participants, revealing a fundamental tension between cryptographic rigor and user accessibility. Reuter et al. (2021) found that users seldom apply E2EE correctly even when it is available, primarily due to interface complexity and insufficient mental models of key management. These findings establish that cryptographic soundness alone is insufficient; a secure chat application must integrate key management workflows that are both technically correct and accessible to non-expert users.

In the Nigerian context, as in many developing economies, the need for secure communication tools is particularly acute. Growing internet penetration, expanding mobile banking, telemedicine, and e-government services, combined with an escalating cybercrime landscape, have heightened the urgency for robust secure communication infrastructure (Longe et al., 2020). Organizations and individuals increasingly rely on messaging platforms for sensitive communications, yet awareness of encryption technologies remains limited among the general population. This research therefore addresses a practical gap by designing and evaluating a secure chat application with end-to-end encryption that is robust, formally grounded, and suitable for deployment in resource-constrained environments.

The motivation for this research emerges from the convergence of theoretical imperatives and practical necessities. Theoretically, the field of applied cryptography and secure systems design continues to evolve rapidly, with new protocols, post-quantum algorithms, and attack vectors demanding continuous research attention. Practically, the persistent prevalence of insecure communication channels, high-profile cryptographic vulnerabilities in widely deployed applications, and growing public awareness of digital surveillance demand accessible, reliable, and open secure messaging solutions. This study contributes to both dimensions by designing, implementing, and evaluating a secure chat application leveraging state-of-the-art E2EE protocols, offering a practical and formally grounded reference architecture for future development.

 

**1.2 Problem Statement**

Despite the widespread availability of digital messaging applications and significant advances in cryptographic protocol design, a significant proportion of users continue to communicate through platforms that provide inadequate security guarantees. Albrecht et al. (2022) formally demonstrated that Telegram’s widely used MTProto protocol contained multiple exploitable cryptographic vulnerabilities, while Albrecht, Dowling, and Jones (2023, 2024\) identified critical security flaws in the Matrix protocol’s group messaging architecture. These findings confirm that even widely deployed messaging systems with large security teams can harbour fundamental cryptographic weaknesses, particularly when custom protocols are used in lieu of formally verified constructions.

Furthermore, existing secure messaging solutions often fail to resolve the persistent tension between cryptographic security and practical usability. Turner et al. (2023) demonstrated that key verification mechanisms — the primary defence against impersonation attacks — are routinely unusable in practice, while Reuter et al. (2021) showed that users seldom apply E2EE correctly even when it is available. Group messaging E2EE, standardised through the MLS protocol (Barnes et al., 2023), remains inadequately deployed in open, documented reference implementations that integrate the full key lifecycle alongside usable interfaces. The emerging post-quantum threat, requiring protocol migration to constructions such as PQXDH and CRYSTALS-Kyber (Bhargavan et al., 2024; NIST, 2024), further compounds the implementation challenge.

This research therefore addresses the problem of designing and implementing a secure chat application with end-to-end encryption that achieves robust and formally grounded cryptographic security, efficient key management, resistance to documented attack vectors, and sufficient usability for practical deployment. By systematically applying established cryptographic protocols and evaluating the resulting system against defined security and performance metrics, this study aims to produce a validated reference implementation and architectural framework for secure real-time communication.

 

**1.3 Research Questions**

The following research questions are derived from the aim and specific objectives of this study, guiding the design, implementation, and evaluation of a secure chat application with end-to-end encryption:

•  **RQ1:** How can a secure chat application architecture incorporating end-to-end encryption be designed using the Signal Protocol and the Double Ratchet Algorithm to guarantee that only communicating parties can access message content in real time?

•  **RQ2:** How can Elliptic Curve Diffie-Hellman (ECDH) be implemented as an asymmetric key exchange mechanism to establish secure session keys between communicating parties without reliance on prior secret sharing?

•  **RQ3:** How can a cryptographically sound key management module be developed to handle the generation, distribution, rotation, verification, and revocation of cryptographic keys in a manner that is accessible and transparent to non-expert users?

•  **RQ4:** How can digital signatures and cryptographic hash functions be integrated into a secure chat application to provide robust message authentication and integrity verification, thereby preventing tampering and spoofing attacks?

•  **RQ5:** What group messaging encryption scheme can be designed and integrated into the application to maintain end-to-end security across multiple participants while achieving acceptable computational and communication performance?

•  **RQ6:** How do the security properties and performance of the developed application, measured in terms of encryption overhead, message latency, resistance to man-in-the-middle attacks, and forward secrecy, compare against defined evaluation metrics and existing messaging solutions?

 

**1.4 Aim**

This research aims to design, implement, and evaluate a secure chat application with end-to-end encryption.  

**1.4.1 Objectives**

The specific objectives of this research are:

•  To design a secure chat application architecture incorporating end-to-end encryption using established cryptographic protocols, including the Signal Protocol and the Double Ratchet Algorithm.

* Implement an Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol to enable communicating parties to establish secure session keys dynamically, eliminating the need for any prior secret sharing.   
* Message Authenticity & Integrity Enforce message authenticity and integrity by integrating digital signatures and cryptographic hash functions, creating reliable defenses against tampering and impersonation.   
* Group Messaging Encryption Design a group messaging encryption scheme that preserves end-to-end confidentiality across multiple participants without introducing prohibitive performance costs. 

 

**1.5 Scope**

This research is scoped to the design, implementation, and evaluation of a secure chat application with end-to-end encryption for text-based messaging, covering both one-on-one and group messaging scenarios. The cryptographic framework is based on the Signal Protocol, integrating the Double Ratchet Algorithm, X3DH key agreement, and AES-256 for symmetric message encryption, consistent with the current Signal deployment at the time of writing. The scope includes client-side key management, user authentication, message integrity verification, and group messaging encryption aligned with the MLS architecture as standardized in RFC 9420 (Barnes et al., 2023). The study does not extend to voice or video call encryption, file transfer encryption, post-quantum protocol migration (identified as a direction for future research), or blockchain-based decentralized architectures.

 

**1.6 Significance of the Study**

This study is significant on three levels. Technically, it produces a rigorously implemented, fully documented end-to-end encrypted chat application built on formally verified cryptographic protocols, serving as a concrete reference architecture for developers and researchers working on secure communication systems.

Socially, it contributes to the protection of digital privacy by providing a framework for secure communication accessible to everyday users, including journalists, healthcare professionals, legal practitioners, and individuals operating in environments where surveillance and cyber threats are prevalent.

Practically, it addresses a documented gap in the availability of open, well-documented, and locally deployable secure messaging solutions suitable for resource-constrained environments such as Nigeria, where growing internet adoption has outpaced the availability of trustworthy encrypted communication tools. By designing security and usability as equal priorities, the application offers a deployable solution and establishes a measurable baseline for future development in the field.

**1.7 Limitations of the Study**

**1\. Real-world deployment testing** The entire system is built and tested in a controlled lab setting. This means it cannot account for the unpredictability of real networks, the variety of different devices users actually own, or how people genuinely behave when using a messaging app in their daily lives. Performance and security results may look different once the app faces real-world conditions.

**2\. Multimedia messaging** The application only handles text. It cannot send, encrypt, or secure voice messages, images, videos, or files. Those media types introduce a completely different set of cryptographic and performance challenges that are outside the boundaries of this work.

**3\. Formal usability testing** While the interface is designed with non-expert users in mind, the project does not run structured user studies to measure how well people actually understand or use the key management features. That kind of human-subject research is left for future work.

**4\. Protection against future or unknown attacks** The security evaluation only tests against attack types that are already documented and well understood. If a new vulnerability is discovered after the project is completed, the system has no mechanism to address it. Emerging threats are not covered.

**5\. Full post-quantum encryption** The project acknowledges the growing threat from quantum computers and incorporates some design awareness of post-quantum standards, but it does not implement the full PQXDH post-quantum key agreement protocol. That remains an active and still-evolving area that this project does not fully enter.

 

**1.8 Thesis Organisation**

This thesis is structured into five chapters, each addressing a distinct aspect of the research. Chapter One provides an introduction to the research, presenting the background, problem statement, research questions, aim, objectives, scope, significance, and limitations. Chapter Two presents a comprehensive review of recent literature from 2021 to date on secure chat applications, end-to-end encryption, cryptographic protocols, key management, group messaging, attack vectors, message authentication, and performance evaluation, identifying knowledge gaps and situating this research within the current body of work. Chapter Three details the research methodology, including system design, architectural decisions, cryptographic protocol selection, implementation environment, and testing framework. Chapter Four presents the results of system implementation and evaluation, including security analysis, performance benchmarking, and comparison with existing solutions. Chapter Five provides a summary of findings, conclusions, and recommendations for future work.

 

**1.9 Definition of Terms**

A clear understanding of key terminologies is essential for comprehending the design and evaluation of a Secure Chat Application with End-to-End Encryption. This section provides definitions of fundamental concepts including encryption algorithms, cryptographic protocols, key management mechanisms, and security properties, as presented in Table 1.1. These definitions clarify the core principles and methodologies underpinning the research, ensuring that readers can fully engage with the interdisciplinary nature of the study, which bridges applied cryptography, secure systems design, and real-time communication engineering.

 

**Table 1.1: Definition of Terms**

| S/N | Term | Definition |
| ----- | ----- | ----- |
| 1 | End-to-End Encryption (E2EE) | A communication model in which only the communicating users can read the messages, preventing eavesdropping by any third party including service providers and network intermediaries. |
| 2 | Cryptography | The science of securing information by transforming it into an unreadable format using mathematical algorithms, ensuring confidentiality, integrity, and authenticity of data. |
| 3 | Public Key Infrastructure (PKI) | A framework of policies, procedures, and technologies used to manage digital certificates and public-key encryption, enabling secure electronic communication and authentication. |
| 4 | Asymmetric Encryption | An encryption scheme that uses a pair of mathematically related keys — a public key for encryption and a private key for decryption — ensuring only the intended recipient can access the message. |
| 5 | Symmetric Encryption | An encryption method in which the same key is used for both encryption and decryption of data, offering high speed but requiring secure key exchange between parties. |
| 6 | Signal Protocol | An open-source cryptographic protocol developed by Open Whisper Systems providing end-to-end encryption for instant messaging by combining the Double Ratchet Algorithm with X3DH key agreement. |
| 7 | Double Ratchet Algorithm | A cryptographic algorithm combining a Diffie-Hellman ratchet and a symmetric-key ratchet to provide forward secrecy and break-in recovery (post-compromise security) for each message in a session. |
| 8 | PQXDH | A post-quantum extended Diffie-Hellman key agreement protocol deployed by Signal in 2023, combining classical X25519 with the CRYSTALS-Kyber key encapsulation mechanism to resist quantum adversaries. |
| 9 | CRYSTALS-Kyber (ML-KEM) | A lattice-based post-quantum key encapsulation mechanism standardised by NIST as FIPS 203, used for post-quantum secure key exchange in messaging protocols. |
| 10 | Diffie-Hellman Key Exchange | A method of securely exchanging cryptographic keys over a public channel, allowing two parties to establish a shared secret without prior communication, foundational to modern E2EE systems. |
| 11 | Forward Secrecy | A property of cryptographic key-agreement protocols ensuring that session keys cannot be compromised even if long-term secret keys are later exposed, protecting past communications. |
| 12 | Post-Compromise Security | The ability of a protocol to restore security after a key compromise, ensuring that future messages remain protected even after an adversary has accessed prior session state. |
| 13 | Authentication | The process of verifying the identity of a user, device, or system to ensure that only legitimate parties can access protected resources or communicate in a secure channel. |
| 14 | Digital Signature | A cryptographic mechanism that verifies the authenticity and integrity of a message using the sender’s private key, enabling recipients to verify the signature with the corresponding public key. |
| 15 | Ed25519 | An Edwards-curve digital signature algorithm based on Curve25519 providing fast, compact, and side-channel-resistant digital signatures, whose formal security was proven by Brendel et al. (2021). |
| 16 | Transport Layer Security (TLS) | A cryptographic protocol providing secure channel encryption between client and server, preventing interception and tampering; does not provide end-to-end encryption as the server retains plaintext access. |
| 17 | Key Management | The administration of cryptographic keys throughout their lifecycle, including generation, distribution, storage, rotation, verification, revocation, and destruction. |
| 18 | Man-in-the-Middle (MitM) Attack | A cybersecurity attack in which an adversary secretly intercepts and potentially alters communications between two parties who believe they are communicating directly with each other. |
| 19 | Message Authentication Code (MAC) | A short piece of information derived using a secret key and a message, used to verify both data integrity and authenticity; typically implemented using HMAC-SHA256 or AEAD schemes. |
| 20 | AEAD (Authenticated Encryption with Associated Data) | A symmetric encryption mode providing combined confidentiality and integrity in a single operation; examples include AES-256-GCM and ChaCha20-Poly1305, widely used in secure messaging protocols. |
| 21 | AES-256 (Advanced Encryption Standard) | A symmetric encryption algorithm with a 256-bit key adopted as a U.S. federal standard (FIPS 197), widely used for bulk message encryption in secure chat applications. |
| 22 | Elliptic Curve Cryptography (ECC) | A public-key cryptography approach based on the algebraic structure of elliptic curves, providing equivalent security to RSA with significantly smaller key sizes, widely used in mobile messaging. |
| 23 | Messaging Layer Security (MLS) | An IETF-standardised group E2EE protocol (RFC 9420, 2023\) employing a TreeKEM ratchet tree to provide forward secrecy, post-compromise security, and scalable key management for group messaging. |
| 24 | Metadata | Data describing other data; in messaging contexts, includes sender, recipient, timestamps, and message size, which can reveal sensitive behavioural information even when message content is fully encrypted. |
| 25 | Key Fingerprint / Safety Number | A human-readable representation of a user’s public key identity, used to detect impersonation attacks through out-of-band verification; usability challenges have been documented by Turner et al. (2023). |

Table 1.1 defines the key terms central to understanding this research on a secure chat application with end-to-end encryption. The definitions reflect current terminology as used in the recent literature, incorporating advances in post-quantum cryptography and protocol standardization documented from 2021 to date.

 

**1.10 Chapter Summary**

Chapter One establishes the foundation for this research by presenting a comprehensive background tracing the evolution of digital communication security from classical cryptography through the Signal Protocol to the current post-quantum transition. The chapter articulates the problem of cryptographic vulnerabilities in widely deployed messaging systems, citing recent formal analyses of Telegram and Matrix, and frames the research objectives around designing, implementing, and evaluating a secure chat application with robust, formally grounded E2EE capabilities. The research questions guide investigation across key dimensions, including protocol selection, key management, group messaging encryption, and performance evaluation. The scope is clearly delineated to text-based messaging using Signal Protocol-based mechanisms, while the significance is framed in both technical and societal terms. Key limitations are acknowledged, including the exclusion of post-quantum protocol migration from the immediate implementation scope. The definition of terms section provides a terminological reference reflecting the current state of cryptographic research and standardization, supporting engagement with the technical content of the thesis.

   
**CHAPTER TWO**

**LITERATURE REVIEW**

The rapid expansion of digital communication platforms has intensified the need for robust, privacy-preserving messaging systems capable of withstanding sophisticated adversarial threats. End-to-end encryption (E2EE) has emerged as the definitive paradigm for protecting the confidentiality and integrity of communications between users, ensuring that message content remains inaccessible to intermediaries, service providers, and malicious actors. This chapter presents a critical review of recent literature from 2021 to date on the foundational concepts of E2EE, cryptographic protocols, key management, secure messaging architectures, group encryption, attack resistance, message authentication, and performance evaluation. It synthesises these findings to identify research gaps that underpin the design, implementation, and evaluation objectives of the proposed secure chat application with end-to-end encryption.

 

**2.1 A Review of End-to-End Encryption Concepts**

End-to-end encryption ensures that data is encrypted on the sender's device and decrypted exclusively by the intended recipient, rendering it unreadable to any party in between, including the service provider itself. The concept has matured considerably from its early implementations, with current deployments integrating advanced protocol stacks that combine asymmetric key establishment, symmetric bulk encryption, and forward secrecy into unified frameworks. Recent research has shifted focus toward extending E2EE to cover new threat surfaces including cloud backups, post-quantum adversaries, and cross-platform interoperability.

Bienstock et al. (2022) presented a more complete security analysis of the Signal Double Ratchet Algorithm using a stronger adversarial model than prior work, confirming its security guarantees while identifying conditions under which ratchet state corruption can propagate. Their formal treatment substantially strengthened the theoretical basis for Double Ratchet-based E2EE deployments. In the same year, Canetti et al. (2022) developed a universally composable (UC) framework for end-to-end secure messaging, providing the first compositional security analysis that encompasses the full communication stack from key agreement through message delivery, thereby enabling rigorous reasoning about protocol composition.

The interoperability dimension of E2EE has attracted significant attention following the European Union's Digital Markets Act (DMA) of 2022, which mandates that large messaging platforms enable cross-platform communication. Rosler and Schwenk (2023) investigated the security and privacy challenges of implementing encrypted messaging interoperability, identifying fundamental tensions between the security assumptions of closed E2EE systems and the trust models required for federation across different providers. Their analysis demonstrated that naive interoperability implementations risk undermining the security guarantees that E2EE systems currently provide.

The adoption of E2EE at scale has also been examined from a governance perspective. Wermke et al. (2022) conducted a large-scale empirical study of how developers implement and maintain E2EE in real-world applications, finding that implementation errors and misconfigurations represent a more prevalent threat than fundamental protocol weaknesses. Their findings underscore that a secure E2EE architecture must be complemented by rigorous implementation practices, automated testing, and developer-focused security guidance to translate theoretical security guarantees into practical protection.

 

**Table 2.1: Review of End-to-End Encryption Concepts**

| Reference | Challenge | Description of Challenge | Method Used | Limitation of Method |
| ----- | ----- | ----- | ----- | ----- |
| (Bienstock, et al., 2022\) | Double Ratchet Security Bounds | Prior formal analyses used weaker adversarial models, leaving security gaps under stronger compromise assumptions. | Extended security model for the Double Ratchet using modular cryptographic definitions and reduction-based proofs. | Analysis covers bilateral communication; group ratchet security requires separate treatment. |
| (Canetti, et al., 2022\) | Compositional E2EE Security | Lack of a compositional framework for reasoning about the full E2EE stack under universal composability. | UC framework for end-to-end secure messaging covering key agreement, authentication, and message delivery. | UC proofs are complex; practical implementation alignment with the model requires careful engineering. |
| (Rosler & Schwenk, 2023\) | E2EE Interoperability | Mandated cross-platform E2EE interoperability (EU DMA) conflicts with the centralised trust models of existing protocols. | Analysis of identity resolution, cross-platform key agreement, and abuse prevention under federation. | No fully specified interoperability design; all proposals involve trade-offs in security or privacy. |
| (Wermke, et al., 2022\) | E2EE Implementation Errors | Developer misconfigurations and implementation errors are more prevalent threats than protocol weaknesses. | Empirical study of 43 professional developers implementing E2EE; analysis of error patterns. | Study population may not be representative; findings from controlled setting may not generalise. |
| (Albrecht, et al., 2022\) | Telegram Cryptographic Weaknesses | Telegram's MTProto protocol contained multiple cryptographic vulnerabilities enabling attacks on message confidentiality. | Formal analysis of MTProto identifying four distinct attacks, including a ciphertext malleability attack. | Analysis focused on MTProto; findings do not generalise to Signal-based protocols. |
| (Barnes, et al., 2023\) | E2EE Standardisation | Lack of a cross-industry E2EE standard impedes interoperability and formal security auditing of group messaging. | Publication of RFC 9420 (MLS) as the first IETF-standardised E2EE protocol supporting large groups. | MLS is newly standardised; production deployment experience and long-term security evaluation remain limited. |

Table 2.1 summarises recent contributions to E2EE research, the challenges addressed, and the limitations that persist. While formal security models have strengthened the theoretical basis for E2EE, implementation correctness, interoperability, and post-quantum resistance remain active research problems with significant practical implications.

 

**2.2 Review of Cryptographic Protocols for Secure Messaging**

Cryptographic protocols govern the procedures by which secure communication sessions are established, maintained, and terminated. For E2EE messaging, the selection and composition of cryptographic protocols determines the security properties achievable, including confidentiality, authentication, forward secrecy, and post-compromise security. Recent research has introduced important advances in protocol analysis, post-quantum secure constructions, and hybrid key exchange mechanisms.

Bhargavan et al. (2024) conducted a formal verification of the PQXDH Post-Quantum Key Agreement Protocol, which Signal deployed in 2023 as a replacement for X3DH to provide resistance against future quantum adversaries. PQXDH augments the classical X25519 elliptic curve key exchange with the CRYSTALS-Kyber post-quantum key encapsulation mechanism (KEM), ensuring that an attacker must break both classical and post-quantum hardness assumptions to recover the session key. Bhargavan et al.'s analysis identified several subtle specification issues and proposed refinements, demonstrating the critical role of formal verification in post-quantum protocol design.

Bienstock et al. (2023) introduced ASMesh, an anonymous and secure messaging protocol for mesh networks based on a strengthened Double Ratchet construction that incorporates anonymity properties absent from the original Signal Protocol design. Their work demonstrated that the Double Ratchet framework can be extended to provide anonymous communication without sacrificing its core security guarantees, though at a measurable increase in computational and communication overhead. Cremers and Zhao (2024) further extended the analysis of secure messaging protocols by establishing a comprehensive security model incorporating strong compromise resilience, temporal privacy, and immediate decryption, revealing trade-offs in existing protocols that prior analyses had not captured.

The publication of TLS 1.3 (RFC 8446\) and its subsequent analysis have refined the understanding of transport-level security in relation to application-layer E2EE. Davis et al. (2022) provided tight security proofs for the TLS 1.3 pre-shared key (PSK) mode, confirming its security properties under standard cryptographic assumptions. While TLS 1.3 improves upon its predecessor through reduced round-trip latency and stronger forward secrecy, it remains a channel-level protocol that does not provide application-layer E2EE, and its session resumption mechanisms introduce replay considerations that must be accounted for in messaging application design.

 

**Table 2.2: Review of Cryptographic Protocols for Secure Messaging**

| Reference | Protocol/Algorithm | Description | Method Used | Limitations |
| ----- | ----- | ----- | ----- | ----- |
| (Bhargavan, et al., 2024\) | PQXDH Formal Verification | Formal analysis of Signal's post-quantum key agreement protocol combining X25519 with CRYSTALS-Kyber. | Automated verification using CryptoVerif and ProVerif; identification and patching of specification flaws. | Computational analysis of full Signal ecosystem remains incomplete; implementation-level correctness not covered. |
| (Bienstock, et al., 2022\) | Extended Double Ratchet Analysis | Stronger adversarial model for the Double Ratchet reveals security bounds under state corruption. | Modular security definitions; reduction-based proofs for confidentiality and authenticity under compromise. | Group ratchet extensions require separate formal treatment; bilateral focus limits direct applicability. |
| (Bienstock, et al., 2023\) | ASMesh Anonymous Ratchet | Extends the Double Ratchet with anonymity properties for mesh network messaging. | Anonymous Double Ratchet construction; integration with mesh routing for end-to-end anonymous delivery. | Anonymity overhead increases bandwidth and computation; not yet evaluated at scale in production. |
| (Cremers & Zhao, 2024\) | Compromise Resilience Model | Existing secure messaging models do not capture all relevant forms of key compromise and message privacy. | Formal model for strong compromise resilience, temporal privacy, and immediate decryption; protocol comparison. | Trade-off analysis reveals no existing protocol satisfies all identified security properties simultaneously. |
| (Davis, et al., 2022\) | TLS 1.3 PSK Security | Prior security proofs for TLS 1.3 PSK mode were not tight, leaving unaddressed security gaps. | Tight security reduction for TLS 1.3 PSK under standard assumptions using multi-user security model. | Tighter bounds apply to PSK mode only; other TLS 1.3 modes require separate analyses. |
| (Barnes, et al., 2023\) | RFC 9420 MLS Standard | First IETF-standardised group E2EE protocol enabling cross-industry secure group messaging. | TreeKEM ratchet tree for group key management; standardised delivery service abstraction. | Newly standardised; deployment experience is limited and long-term security evaluation is ongoing. |

Table 2.2 summarises recent advances in cryptographic protocols for secure messaging. The emergence of post-quantum constructions such as PQXDH and the formal analysis of deployed protocols represent significant steps forward, though gaps in compositional security, anonymous messaging, and full-stack formal verification remain.

 

**2.3 Review of Key Management in Secure Chat Applications**

Key management encompasses the full lifecycle of cryptographic keys: generation, distribution, verification, rotation, and revocation. It represents one of the most challenging aspects of E2EE system design, particularly because failures in key management frequently constitute the primary attack surface of otherwise robust encryption protocols. Recent research has examined key management from usability, automation, and formal correctness perspectives, identifying persistent gaps between theoretical soundness and practical deployment effectiveness.

Turner, Shahandashti, and Petrie (2023) investigated the effect of key fingerprint length on the security and usability of key verification in secure messaging applications including Signal and WhatsApp. Their within-participants study with 62 participants revealed a fundamental tension: the comparison mode that produced the most security-effective verification was simultaneously perceived as least usable by participants. Their findings challenge the assumption that usability improvements in key verification interfaces will automatically translate to improved security outcomes, suggesting that alternative verification mechanisms are needed.

Reuter et al. (2021) conducted a usability study of three E2EE technologies for securing email communication — PGP, S/MIME, and Pretty Easy Privacy (pEp) — finding that users seldom apply encryption correctly despite its availability, primarily due to interface complexity and insufficient mental models of key management operations. Although focused on email, their findings directly inform chat application design, establishing that simplified key generation and automated trust establishment are prerequisites for effective user-facing E2EE. Abazi and Gegaj (2022) extended this analysis to modern instant messaging applications, comparing user experience across Signal, WhatsApp, and Telegram, and finding that despite their common E2EE implementations, these applications exhibit substantial variation in how effectively they communicate cryptographic security status to users.

At the protocol level, Yadav et al. (2022) proposed an automated mechanism for detecting fake key attacks in centralised secure messaging systems, addressing the scenario where a malicious or compromised server distributes forged public keys to perform man-in-the-middle attacks. Their approach supplements existing manual key verification mechanisms with server-side transparency logs that enable clients to detect key substitutions automatically, without requiring user engagement. This represents a significant step toward automated key integrity assurance, though it requires server-side infrastructure that introduces new trust dependencies.

 

**Table 2.3: Review of Key Management in Secure Chat Applications**

| Reference | Challenge | Description of Challenge | Method Used | Limitation of Method |
| ----- | ----- | ----- | ----- | ----- |
| (Turner, Shahandashti, & Petrie, 2023\) | Key Fingerprint Usability | Most secure comparison mode for key fingerprints is also perceived as least usable, creating an irresolvable tension. | Within-participants user study measuring effectiveness, efficiency, and perceived usability across comparison modes. | Lab study; real-world verification behaviour under natural conditions may differ significantly. |
| (Reuter, et al., 2021\) | E2EE Usability in Email/Messaging | Users seldom apply E2EE correctly even when available, due to interface complexity and insufficient mental models. | Task-based usability study of PGP, S/MIME, and pEp with real users across encryption workflows. | Email-focused study; conclusions require contextual adaptation for real-time messaging applications. |
| (Abazi & Gegaj, 2022\) | Comparative Key UX in IM Apps | Variation in how E2EE status is communicated across major messaging applications leads to inconsistent user understanding. | Comparative UX evaluation of Signal, WhatsApp, and Telegram across security-relevant interaction flows. | Descriptive; does not provide empirical security outcome measurements linked to UX differences. |
| (Yadav, et al., 2022\) | Automated Fake Key Detection | Centralised servers can distribute forged public keys to conduct MitM attacks without user detection. | Transparency log-based automated detection of key substitutions; lightweight client-side verification. | Requires server infrastructure cooperation; adversarial servers could suppress or delay transparency entries. |
| (Marlinspike & Perrin, 2016\) | Automated Key Rotation | Manual key rotation is error-prone and burdens non-expert users with complex cryptographic operations. | Signal Protocol automates key generation, distribution, and rotation through X3DH and Double Ratchet. | Prekey bundle server required; one-time prekey exhaustion is a practical deployment risk. |
| (Davies, et al., 2023\) | Backup Key Management | Encrypted backups expose key management weaknesses: password-based key recovery is susceptible to guessing attacks. | Formal UC analysis of WhatsApp Backup Protocol; identification of server-side password guessing risk. | Analysis is specific to password-protected key retrieval schemes; broader backup architectures not covered. |

Table 2.3 highlights recent advances in key management research. While automated detection mechanisms and formal analyses have improved the theoretical and practical foundations for key lifecycle management, the usability of key verification and the reliability of revocation and backup mechanisms remain unresolved challenges in production deployments.

 

**2.4 Review of Attack Vectors in Secure Chat Applications**

Secure chat applications face a broad and evolving landscape of attack vectors targeting different layers of the communication architecture. Understanding these threats and the effectiveness of corresponding defences is essential to designing a system that maintains robust security guarantees under realistic adversarial conditions. Recent research has identified significant vulnerabilities in widely deployed applications, proposed automated detection mechanisms, and examined the growing threat of post-quantum adversaries harvesting today's ciphertexts for future decryption.

Albrecht et al. (2022) presented a landmark formal analysis of Telegram's MTProto cryptographic protocol, identifying four distinct and practically exploitable attacks, including a ciphertext malleability attack that enabled message forgery and a mechanism for detecting whether two users were communicating. Their work demonstrated that reliance on custom cryptographic protocols without rigorous formal analysis creates critical vulnerabilities even in widely deployed systems, and reinforced the case for adopting established, verified protocols such as the Signal Protocol. Teng and Rasmussen (2024) addressed the specific problem of in-band MitM detection for the Signal Protocol, proposing an automated mechanism that enables clients to detect key substitution attacks without relying on user-performed safety number verification, introducing negligible performance overhead.

Metadata leakage has emerged as a particularly critical threat dimension in recent years. Domenech et al. (2022) conducted a systematic study of metadata privacy in instant messaging applications, demonstrating that observable traffic patterns — including message timing, size distributions, and communication frequencies — can enable adversaries to infer sensitive information about user behaviour and relationships even when message content is fully encrypted. Their findings highlighted that effective privacy protection requires architectural measures to suppress metadata as well as content encryption. Narang, Jatain, and Punetha (2024) surveyed machine-learning-based MitM attack detection techniques in IoT and messaging contexts, finding that while ML classifiers achieve high detection rates in controlled settings, adversarial evasion techniques can substantially reduce their effectiveness in practice.

The harvest-now-decrypt-later threat model has motivated significant research into the forward secrecy properties of E2EE protocols against quantum adversaries. Bhargavan et al. (2024) demonstrated through formal verification that the PQXDH protocol, despite providing post-quantum key establishment, contains subtle specification issues that could be exploited under certain adversarial conditions. Their analysis underscores that transitioning to post-quantum secure messaging requires not only the adoption of quantum- resistant algorithms but also rigorous formal verification of their integration into existing protocol stacks.

 

**Table 2.4: Review of Attack Vectors in Secure Chat Applications**

| Reference | Attack Vector | Description of Challenge | Method Used in Addressing | Limitation of Method |
| ----- | ----- | ----- | ----- | ----- |
| (Albrecht, et al., 2022\) | Cryptographic Protocol Weaknesses | Custom protocols in deployed messaging systems contain exploitable cryptographic vulnerabilities. | Formal analysis of Telegram MTProto; identification of four distinct attacks including message forgery. | Findings are specific to MTProto; do not generalise to Signal Protocol-based systems. |
| (Teng & Rasmussen, 2024\) | In-Band MitM Detection | Manual safety number verification is ignored by users, leaving MitM attacks undetected in practice. | Automated in-band key substitution detection integrated with the Signal library; negligible overhead. | Proof-of-concept; deployment at scale requires integration into official Signal and WhatsApp clients. |
| (Domenech, et al., 2022\) | Metadata Leakage in IM | Traffic analysis of messaging metadata reveals user behaviour even when content is fully encrypted. | Systematic study of metadata exposure; traffic shaping and padding countermeasures evaluated. | Metadata suppression incurs bandwidth and latency overhead that limits practical deployment. |
| (Narang, Jatain, & Punetha, 2024\) | ML-Based MitM Detection | Rule-based MitM detectors fail under novel or adaptive attacks; ML approaches needed. | Survey of ML classifiers for MitM detection; comparison of detection rates and evasion resistance. | Adversarial evasion substantially reduces ML detector effectiveness; no single method is universally robust. |
| (Bhargavan, et al., 2024\) | Post-Quantum Attack Surface | PQXDH specification contains subtle flaws that could be exploited by quantum or classical adversaries. | Formal verification of PQXDH using CryptoVerif and ProVerif; identification and remediation of flaws. | Formal models do not capture all implementation-level attack surfaces; analysis must be complemented by testing. |
| (Davies, et al., 2023\) | Backup Brute-Force Attacks | Password-based key recovery in encrypted backups is vulnerable to server-side password guessing. | UC framework analysis of WhatsApp Backup Protocol; identification of server-side guessing risk. | Findings specific to HSM-based backup architecture; alternative backup designs introduce different risks. |

Table 2.4 identifies key attack vectors documented in recent research, the methods proposed to address them, and their limitations. Protocol weaknesses, metadata leakage, and post-quantum threats represent the most critical emerging challenges, with automated detection mechanisms and formal verification providing the most promising avenues for mitigation.

 

**2.5 Review of Secure Messaging Architectures**

The architecture of a secure messaging application determines how cryptographic protocols are integrated with communication infrastructure, server components, and client interfaces, and directly influences the achievable security, privacy, scalability, and usability properties of the system. Recent research has examined architectural vulnerabilities in widely deployed systems, advances in federated and decentralised architectures, and the formal analysis of complex multi-device and multi-client messaging scenarios.

Albrecht, Dowling, and Jones (2023) identified practically exploitable cryptographic vulnerabilities in the Matrix protocol's Olm and Megolm implementations, including attacks that exploit architectural choices in how devices are managed and how group room keys are distributed. Their 2024 follow-up presented a formal cryptographic analysis of Matrix's core device-oriented group messaging design, revealing subtle differences in forward secrecy properties between Olm and Signal that impact the security of the overall architecture. These findings motivated significant security improvements to the Matrix codebase and illustrate the importance of ongoing formal analysis of federated architectures.

Wallez et al. (2023) presented a formally verified implementation of the MLS protocol's authenticated group management component using the F\* programming language and the HACL\* cryptographic library. Their work demonstrated that the MLS architecture, while complex, is amenable to machine-verified implementation at production quality, providing a strong foundation for trustworthy deployments of the MLS standard. In parallel, Beurdouche et al. (2024) published an updated MLS architecture specification as an IETF Internet Draft, clarifying the separation between the MLS key agreement layer and the delivery service abstraction, which significantly simplifies the implementation burden for application developers adopting the standard.

The multi-device architecture challenge — enabling users to access their encrypted messages seamlessly across multiple devices without compromising E2EE guarantees — has received increased attention. Davies et al. (2023) formally analysed the WhatsApp Backup Protocol, demonstrating that while it provides strong protection for encrypted backups, the password-based key recovery mechanism introduces a server-side attack surface that centralised architectures must carefully manage. Their analysis contributed directly to improvements in the WhatsApp backup security architecture and provides a model for how formal methods can inform production-level architectural decisions.

 

**Table 2.5: Review of Secure Messaging Architectures**

| Reference | Architecture | Description | Method Used | Limitations |
| ----- | ----- | ----- | ----- | ----- |
| (Albrecht, Dowling, & Jones, 2023\) | Matrix Protocol Vulnerability Analysis | Practically exploitable vulnerabilities in Matrix Olm/Megolm implementations arising from architectural design choices. | Formal cryptographic analysis of Matrix core; identification of device management and key distribution attacks. | Matrix has since patched identified issues; ongoing formal analysis required as architecture evolves. |
| (Albrecht, Dowling, & Jones, 2024\) | Matrix Formal Cryptographic Analysis | Subtle differences in forward secrecy between Olm and Signal affect the security of Matrix group rooms. | Device-oriented group messaging formal analysis; comparison with Signal Protocol security properties. | Federated server model introduces additional trust dependencies not captured in single-server models. |
| (Wallez, et al., 2023\) | Formally Verified MLS Implementation | MLS standard requires a formally verified implementation to establish deployment trustworthiness. | F\* and HACL\* for machine-verified MLS authenticated group management; full specification coverage. | Verification covers MLS key agreement layer; transport and application integration not formally verified. |
| (Beurdouche, et al., 2024\) | MLS Architecture Standard | Separation between MLS key agreement and delivery service was underspecified, impeding correct implementation. | Updated IETF Internet Draft clarifying delivery service abstraction and MLS architecture layering. | Internet Draft status; further standardisation iterations may introduce specification changes. |
| (Davies, et al., 2023\) | Encrypted Backup Architecture | Password-protected backup key recovery introduces server-side guessing vulnerability in centralised architectures. | UC formal analysis of WhatsApp Backup Protocol; analysis of HSM-based key recovery security. | Architecture-specific findings; alternative backup mechanisms may have different security profiles. |
| (Barnes, et al., 2023\) | RFC 9420 MLS Standard | First cross-industry standardised group E2EE architecture enabling interoperable secure group messaging. | TreeKEM ratchet tree; delivery service abstraction; standardised across Mozilla, Google, Wire, Cisco. | Newly standardised; production deployment remains limited and long-term evaluation is ongoing. |

Table 2.5 highlights recent advances in secure messaging architecture research. Formal verification of deployed systems has exposed critical vulnerabilities in widely used architectures, while the standardisation of MLS and advances in verified implementations have substantially raised the bar for secure group messaging architecture design.

 

**2.6 Review of Group Messaging Encryption**

Group messaging encryption presents substantially greater cryptographic complexity than bilateral E2EE, requiring mechanisms for secure key distribution to multiple recipients, efficient management of dynamic group membership, and maintenance of forward secrecy and post-compromise security as members join or depart. Recent years have seen the formal standardisation of the Messaging Layer Security (MLS) protocol and a significant body of research on its security properties, performance characteristics, and extensions.

The publication of RFC 9420 (Barnes et al., 2023\) established MLS as the first IETF-standardised E2EE group messaging protocol. MLS employs a TreeKEM ratchet tree structure in which group members are arranged as leaves of a binary tree, and the group encryption key is derived from the tree root. This design achieves O(log n) complexity for key updates on membership changes, compared to the O(n) complexity of pairwise approaches. The MLS standard incorporates forward secrecy, post-compromise security, message authentication, and membership authentication, addressing the principal shortcomings of the Sender Keys mechanism used by Signal and WhatsApp for group messaging.

Alwen, Jost, and Mularczyk (2022) conducted a comprehensive analysis of insider security in MLS, examining the security properties achievable when group members are themselves considered potential adversaries. Their analysis identified conditions under which the standard MLS construction provides insider security and proposed refinements to the TreeKEM design to strengthen these guarantees. Wallez et al. (2023) complemented this work with a formally verified implementation of MLS authenticated group management, establishing machine-checked proofs for the correctness of the key management components.

Chevalier et al. (2024) proposed Quarantined-TreeKEM, an extension to the MLS group key agreement mechanism that maintains security in the presence of inactive users — a practically important scenario in which offline members have not yet processed pending group updates. Their construction addresses a gap in the standard MLS design where inactive members can temporarily reduce the post-compromise security guarantees of the group. Kajita et al. (2023) extended the continuous group key agreement framework with flexible authorisation mechanisms, enabling fine-grained control over which group members are permitted to perform membership operations, addressing application-level access control requirements that the base MLS standard does not address.

 

**Table 2.6: Review of Group Messaging Encryption**

| Reference | Challenge | Description of Challenge | Method Used | Limitation of Method |
| ----- | ----- | ----- | ----- | ----- |
| (Barnes, et al., 2023\) | Scalable Group E2EE Standard | Absence of a cross-industry standardised group E2EE protocol impedes interoperable secure group messaging. | RFC 9420 MLS with TreeKEM providing O(log n) key updates; standardised delivery service abstraction. | Newly standardised; production deployment and long-term security evaluation remain limited. |
| (Alwen, Jost, & Mularczyk, 2022\) | MLS Insider Security | Security against malicious group members (insider threat) was not fully characterised in the original MLS design. | Formal analysis of insider security in MLS; TreeKEM refinements to strengthen insider security guarantees. | Analysis complexity increases significantly with group size; insider security has non-trivial performance implications. |
| (Wallez, et al., 2023\) | Verified MLS Implementation | Lack of machine-verified MLS implementations undermines confidence in the correctness of deployed group key management. | Formally verified MLS authenticated group management in F\* and HACL\*; full specification coverage. | Verification scope limited to key management layer; transport integration not formally verified. |
| (Chevalier, et al., 2024\) | Inactive Member Security | Inactive users who have not processed group updates temporarily reduce post-compromise security guarantees. | Quarantined-TreeKEM extension isolating inactive members from active group key derivation. | Quarantine mechanism introduces additional state management complexity and potential for desynchronisation. |
| (Kajita, et al., 2023\) | Group Authorisation | Base MLS standard lacks fine-grained authorisation for membership operations, limiting application-level access control. | Continuous group key agreement extension with flexible authorisation; integration with MLS commit structure. | Authorisation overhead adds computational cost; interaction with MLS epoch management requires careful design. |
| (Anastos, et al., 2025\) | Cost of Key Maintenance | Maintaining keys in dynamic groups involves non-trivial computational costs not fully characterised in prior work. | Tight characterisation of the cost of key maintenance in dynamic groups; multicast encryption analysis. | Theoretical analysis; empirical evaluation of performance at scale in production deployments is needed. |

Table 2.6 summarises recent advances in group messaging encryption research. The standardisation of MLS and associated formal verification work have substantially advanced the field, though challenges in handling inactive members, authorisation, and production deployment remain active research and engineering problems.

 

**2.7 Review of Message Authentication and Integrity Mechanisms**

Message authentication and integrity verification ensure that communications originate from the claimed sender and have not been altered in transit. These mechanisms defend against spoofing, forgery, and tampering attacks. Recent research has produced formal security analyses of widely deployed digital signature schemes, investigations of authentication vulnerabilities in deployed protocols, and proposals for enhanced authentication mechanisms in post-quantum and multi-device contexts.

Brendel et al. (2021) provided the first rigorous provable security analysis of Ed25519, the digital signature scheme widely used for message authentication in the Signal Protocol and related systems. Their analysis, presented at the IEEE Symposium on Security and Privacy, confirmed that Ed25519 provides strong existential unforgeability under adaptive chosen-message attacks, while also identifying subtle consistency issues in the standard that have implications for multi-signature and batch verification scenarios. This work provided the theoretical foundation previously absent for one of the most widely deployed signatures in secure messaging.

Albrecht et al. (2022) demonstrated through their analysis of Telegram's MTProto that incorrect MAC composition and authenticated encryption design can enable message forgery and replay attacks even in widely deployed systems with large security teams. Their identification of a ciphertext malleability attack, arising from incorrect integration of MAC verification and decryption, underscores the practical importance of using established AEAD constructions rather than custom authenticated encryption designs. Balbas, Collins, and Gajland (2023) identified a forgery attack in Signal's group messaging authentication scheme whereby a group outsider with access to a user's signing key could forge group messages, revealing a subtle weakness in the composition of Sender Keys with the Signal authentication design.

The transition to post-quantum secure messaging introduces new requirements for message authentication. Bhargavan et al. (2024) demonstrated that the integration of Kyber-based key encapsulation with existing signature-based authentication in PQXDH requires careful formal analysis to ensure that post-quantum security extends to the authentication layer, not merely the key exchange. National Institute of Standards and Technology (NIST, 2024\) finalised the post-quantum digital signature standards CRYSTALS-Dilithium (ML-DSA) and FALCON, providing standardised alternatives to Ed25519 that resist quantum adversaries and will need to be integrated into next-generation secure messaging authentication architectures.

 

**Table 2.7: Review of Message Authentication and Integrity Mechanisms**

| Reference | Mechanism | Description | Method Used | Limitations |
| ----- | ----- | ----- | ----- | ----- |
| (Brendel, et al., 2021\) | Ed25519 Provable Security | Ed25519 lacked a rigorous provable security analysis despite widespread deployment in secure messaging. | First formal security proof for Ed25519; identification of consistency issues affecting batch verification. | Consistency issues in multi-signature scenarios require care; proof does not cover all implementation variants. |
| (Albrecht, et al., 2022\) | MAC and AEAD Design | Incorrect MAC composition in custom authenticated encryption enables message forgery and ciphertext malleability. | Formal attack demonstration on Telegram MTProto; advocacy for standard AEAD constructions (AES-GCM, ChaCha20-Poly1305). | Attack is specific to MTProto; established AEAD constructions are not vulnerable if implemented correctly. |
| (Balbas, Collins, & Gajland, 2023\) | Group Message Forgery | Group outsider with a user's signing key can forge group messages in Signal's Sender Keys scheme. | Formal cryptographic analysis of group authentication composition; attack construction and proof. | Attack requires prior compromise of signing key; does not apply to MLS-based group authentication. |
| (Bhargavan, et al., 2024\) | Post-Quantum Authentication | PQ key exchange in PQXDH must be composed correctly with authentication to extend PQ security to message integrity. | Formal verification of PQXDH authentication layer; identification of specification flaws in PQ/classical composition. | Full integration of PQ signatures (e.g., ML-DSA) with messaging protocols is not yet standardised. |
| (NIST, 2024\) | PQ Signature Standards | Standardised post-quantum digital signatures needed to replace Ed25519 against quantum adversaries. | Standardisation of ML-DSA (CRYSTALS-Dilithium) and FALCON as FIPS 204 and FIPS 206 respectively. | PQ signatures have larger key and signature sizes than Ed25519; integration into messaging protocols requires optimisation. |
| (Cremers & Zhao, 2024\) | Temporal Privacy in Authentication | Existing authentication models do not capture temporal privacy: the requirement that message order is not revealed. | Formal model incorporating temporal privacy and strong compromise resilience; evaluation of existing protocols. | No existing protocol simultaneously satisfies all identified authentication and privacy properties. |

Table 2.7 highlights recent contributions to message authentication and integrity research. While formal analyses of deployed signature schemes and AEAD constructions have strengthened the theoretical foundations, the transition to post-quantum authentication standards and the resolution of group authentication weaknesses remain critical open challenges.

 

**2.8 Review of Performance Evaluation of Secure Chat Applications**

The practical viability of a secure chat application depends not only on its cryptographic security properties but also on its runtime performance under realistic usage conditions. Performance evaluation encompasses encryption and decryption overhead, key agreement latency, message delivery latency, and scalability under concurrent users and large group sizes. Recent research has produced both theoretical complexity analyses of emerging protocols and empirical performance studies of deployed systems.

Anastos et al. (2025) conducted a comprehensive analysis of the computational cost of key maintenance in dynamic group messaging systems, establishing tight bounds for the cost of member additions, removals, and key updates under the MLS TreeKEM construction. Their analysis demonstrated that while TreeKEM's O(log n) amortised update cost provides substantial advantages over pairwise schemes, the worst-case update cost is non-trivial for large groups under high churn, motivating further work on efficient key management for enterprise-scale messaging deployments.

Experimentally, Ueda et al. (2024) evaluated the efficiency of the MLS protocol for publish-subscribe group data sharing scenarios, measuring key agreement overhead, message delivery latency, and scalability up to groups of several hundred members. Their measurements demonstrated that MLS introduces acceptable latency for interactive messaging at group sizes up to approximately 100 members, with commit operations becoming the dominant performance bottleneck at larger group sizes. Similar findings were reported by Wallez et al. (2023), whose formally verified MLS implementation achieved performance comparable to unverified implementations, demonstrating that formal verification need not impose significant performance penalties.

The performance implications of post-quantum cryptographic primitives in secure messaging have been examined by several recent studies. Kim et al. (2025) evaluated a hybrid post-quantum E2EE implementation combining CRYSTALS-Kyber-768 for key encapsulation with AES-256-GCM for symmetric encryption, reporting that Kyber key generation and encapsulation operations introduce measurable but acceptable overhead compared to classical ECDH on modern hardware. Lee et al. (2023) proposed an efficient continuous key agreement scheme with reduced bandwidth overhead for constrained devices, demonstrating that post-quantum ratcheting can be made practical without prohibitive bandwidth costs.

 

**Table 2.8: Review of Performance Evaluation of Secure Chat Applications**

| Reference | Performance Dimension | Description | Method Used | Limitations |
| ----- | ----- | ----- | ----- | ----- |
| (Anastos, et al., 2025\) | Dynamic Group Key Maintenance Cost | TreeKEM's amortised O(log n) update cost conceals non-trivial worst-case costs under high membership churn. | Tight complexity bounds for MLS TreeKEM member add, remove, and update operations; multicast encryption analysis. | Theoretical bounds; empirical evaluation at production scale under real workload patterns is needed. |
| (Ueda, et al., 2024\) | MLS Group Messaging Latency | MLS commit operations become the dominant latency bottleneck at group sizes exceeding approximately 100 members. | Empirical MLS performance evaluation for publish-subscribe group scenarios; latency and throughput measurement. | Evaluation under controlled conditions; real-world network variability and concurrent load not fully captured. |
| (Wallez, et al., 2023\) | Verified Implementation Overhead | Formally verified implementations are often assumed to incur significant performance penalties over unverified code. | Performance benchmarking of verified MLS implementation against unverified baseline; negligible overhead found. | Benchmarks on specific hardware; performance characteristics may vary on embedded or constrained devices. |
| (Kim, et al., 2025\) | Post-Quantum Encryption Overhead | CRYSTALS-Kyber key generation and encapsulation overhead must be assessed for acceptability in messaging contexts. | Empirical benchmarking of CRYSTALS-Kyber-768 \+ AES-256-GCM hybrid E2EE on modern hardware. | Hardware acceleration availability affects results; overhead on mobile and IoT devices is higher. |
| (Lee, Kwon, & Shin, 2023\) | PQ Ratchet Bandwidth | Post-quantum key ratcheting for continuous key agreement incurs higher bandwidth than classical constructions. | Efficient continuous key agreement scheme with reduced bandwidth via decomposable KEM construction. | Bandwidth reduction involves trade-offs with computational overhead; security proof requires careful verification. |
| (Domenech, et al., 2022\) | Metadata Suppression Overhead | Traffic shaping and padding to suppress metadata leakage incur measurable bandwidth and latency penalties. | Measurement of metadata suppression costs in IM applications; evaluation of padding and timing normalisation. | Full metadata suppression requires significant overhead that may be unacceptable for latency-sensitive applications. |

Table 2.8 summarises recent performance evaluations of secure messaging components. While MLS and post-quantum constructions introduce measurable overhead, recent work demonstrates that acceptable performance is achievable for interactive messaging at moderate group sizes. Performance at scale, under high membership churn, and on constrained devices remains an active research concern.

 

**2.9 Gap Analysis**

The preceding review of literature from 2021 to date reveals important advances across all aspects of E2EE messaging research, yet identifies several persistent gaps that the proposed research directly addresses.

First, while formal analyses of individual E2EE protocol components — including the Double Ratchet, X3DH, PQXDH, and MLS — have advanced substantially, open-source reference implementations that integrate these components into a complete, documented, and evaluated application architecture with full key lifecycle management and group messaging support remain scarce. Most published research either analyses individual components or evaluates commercial deployments without access to source code. This study addresses this gap through the production of a complete, validated implementation combining the Signal Protocol's bilateral E2EE with a group messaging scheme, documented against the security properties established in the reviewed literature.

Second, despite consistent findings across recent studies that key verification is rarely performed correctly by non-expert users (Turner et al., 2023; Abazi & Gegaj, 2022; Reuter et al., 2021), no existing deployed application integrates automated key verification mechanisms of the type proposed by Yadav et al. (2022) with user-facing transparency interfaces. The application developed in this study incorporates an automated key integrity monitoring component alongside a usability- focused key management interface, directly addressing this persistent gap.

Third, while MLS has been standardised and formally verified (Barnes et al., 2023; Wallez et al., 2023), its integration into complete application architectures with explicit security evaluation against the threats documented in the literature remains inadequately represented. Most existing studies evaluate MLS in isolation; this research contributes an end-to-end evaluation of a group messaging E2EE scheme within a complete application, measuring security properties and performance against defined metrics.

Fourth, the post-quantum transition presents an unresolved integration challenge. While PQXDH and NIST PQC standards (2024) provide the algorithmic foundations for post-quantum E2EE, their integration into practical application architectures with acceptable performance characteristics requires engineering work that existing literature does not fully address at the application level. The design considerations for this integration, informed by the formal analyses of Bhargavan et al. (2024) and Kim et al. (2025), are incorporated into the proposed system's architectural design.

Collectively, these gaps establish a clear research justification. The proposed secure chat application addresses the integration of current E2EE cryptographic protocols, automated key management, group messaging encryption, attack resistance, and performance evaluation within a single, documented, and evaluated system architecture, contributing to both the research literature and to practice in secure messaging system design.

 

**2.10 Chapter Summary**

Chapter Two has presented a comprehensive review of recent literature on end-to-end encryption and secure messaging, focusing on work published from 2021 to date. The review of E2EE concepts documented advances in formal compositional security models, interoperability challenges, and the identification of cryptographic weaknesses in widely deployed protocols including Telegram and Matrix. The review of cryptographic protocols highlighted the emergence of post-quantum constructions such as PQXDH and MLS, and the formal verification of the Double Ratchet and related algorithms under stronger adversarial models.

The analysis of key management research identified automated fake key detection, formal backup protocol analysis, and comparative usability studies as the most significant recent contributions, while confirming that key verification remains an unresolved practical challenge. The review of attack vectors documented exploitable vulnerabilities in Telegram's MTProto, the emergence of automated in-band MitM detection mechanisms, and the growing importance of post-quantum attack surface analysis. Secure messaging architecture research was dominated by formal vulnerability analyses of Matrix and the standardisation and verification of MLS, with significant implications for both federated and centralised deployment models.

The review of group messaging encryption documented the standardisation of RFC 9420 (MLS), advances in insider security analysis, formally verified implementation, and extensions addressing inactive members and flexible authorisation. The review of message authentication identified the first formal security proofs for Ed25519, group message forgery vulnerabilities in Signal's Sender Keys scheme, and the emerging requirements for post-quantum digital signatures. The performance review established computational and latency characteristics of MLS and post-quantum primitives, confirming their practical viability for interactive messaging at moderate scale.

The gap analysis identified four primary research gaps: the absence of a complete integrated reference implementation combining current E2EE components; unresolved key verification usability in the presence of automated detection mechanisms; inadequate evaluation of MLS-based group messaging within complete application architectures; and the unresolved integration of post-quantum constructions at the application level. These gaps directly motivate the research questions, aims, and objectives established in Chapter One and provide the theoretical and empirical foundation for the methodology presented in Chapter Three.

 

**CHAPTER THREE**

**METHODOLOGY**

This chapter presents the research methodology adopted for the design, implementation, and evaluation of a secure chat application with end-to-end encryption. The methodology encompasses the research design, the conceptual framework, cryptographic protocol selection and justification, system architecture, key management lifecycle design, group messaging encryption design, the implementation environment, and the security and performance evaluation frameworks. Each methodological decision is grounded in the literature reviewed in Chapter Two and is directly linked to the research questions and objectives established in Chapter One. The chapter is structured to provide both theoretical justification and practical implementation detail, supported by diagrams and frameworks that clarify the research design and system structure.

 

**3.1 Research Design**

This research adopts a Design Science Research (DSR) methodology, which is the appropriate paradigm for studies whose primary output is an artefact — in this case, a secure chat application — rather than a purely empirical or observational finding. DSR, as defined by Hevner et al. (2004) and extended by Peffers et al. (2007), involves the iterative design, construction, and evaluation of an artefact against defined requirements, with the explicit aim of contributing both the artefact and design knowledge to the research community. This approach is well-established in information systems security research and has been used in comparable secure systems design studies (Wallez et al., 2023; Davies et al., 2023).

The DSR process for this study proceeds through five iterative phases: (1) Problem Identification, in which the security and usability gaps in existing secure messaging systems are formally characterised based on the literature review; (2) System Design and Protocol Selection, in which cryptographic protocols, architectural patterns, and key management approaches are selected and justified; (3) Implementation, in which the designed system is realised as a functional prototype; (4) Security Evaluation, in which the implemented system is tested against a defined set of security properties and attack scenarios; and (5) Performance Benchmarking, in which system performance is measured against defined metrics and compared with existing solutions. This iterative process is represented in the Research Methodology Framework below.

 

 **Research Methodology Framework**

| Problem Identification |
| :---: |
| **↓** |
| Literature Review |
| **↓** |
| System Design & Protocol Selection |
| **↓** |
| Implementation |
| **↓** |
| Security Evaluation & Testing |
| **↓** |
| Performance Benchmarking |
| **↓** |
| **Results & Conclusions** |

 

**Figure 3.1**

The research is applied in nature, seeking to produce a validated and deployable artefact, rather than basic in nature, which would seek purely theoretical contributions. Quantitative evaluation methods are used for performance measurement, while structured security testing against defined threat models provides the primary basis for security evaluation. The combination of formal design justification, implementation, and multi-dimensional evaluation aligns with the rigorous DSR standard as applied in recent secure systems research (Bhargavan et al., 2024; Wallez et al., 2023).

 

**3.2 Conceptual Framework**

The conceptual framework presents the logical structure of the proposed system, illustrating how its component layers relate to one another and to the overall research objectives. The framework is organised around six functional layers, each addressing a specific research objective. The cryptographic protocol layer, based on the Signal Protocol, provides the foundational E2EE mechanism (RQ1, RQ2). The key management module addresses the generation, distribution, rotation, verification, and revocation of keys (RQ3). The message authentication layer ensures integrity through Ed25519 signatures and AES-256-GCM AEAD (RQ4). The group messaging encryption layer implements an MLS-aligned TreeKEM scheme (RQ5). The attack resistance mechanisms address MitM, replay, and metadata threats. The performance and usability layer provides the evaluation framework for RQ6.

 

**Figure 3.2: Conceptual Framework of the Proposed Secure Chat Application**

| System Component / Layer | Function in the Proposed System |
| :---: | ----- |
| **Cryptographic Protocol Layer** | Signal Protocol (Double Ratchet \+ X3DH) provides E2EE foundation |
| **Key Management Module** | Generates, distributes, rotates, verifies, and revokes session keys |
| **Message Authentication Layer** | Ed25519 digital signatures \+ AES-256-GCM AEAD ensure integrity |
| **Group Messaging Encryption** | MLS-aligned TreeKEM scheme for multi-party E2EE |
| **Attack Resistance Mechanisms** | MitM detection, replay prevention, metadata minimisation |
| **Performance & Usability Layer** | Acceptable encryption overhead \+ accessible key verification UI |
| **↓ System Output** | Validated, secure, usable chat application meeting defined metrics |

 

The framework illustrates the dependency chain of the system: the cryptographic protocol layer underpins all higher layers, and each layer contributes to the overall system output of a validated, secure, and usable chat application. This layered design reflects the principle of defence in depth: even if a higher-level mechanism is bypassed, the lower cryptographic layers remain independently protective. The framework directly maps to the research objectives and provides the structural basis for the system architecture described in Section 3.3.

 

**3.3 System Architecture**

The proposed system architecture follows a three-tier model comprising a Client Tier, a Server Tier, and a Cryptographic Layer. This separation of concerns ensures that the server tier never has access to plaintext message content or cryptographic session keys, satisfying the fundamental requirement of end-to-end encryption. The architecture is informed by the formally analysed Signal architecture (Bienstock et al., 2022), the MLS delivery service abstraction (Beurdouche et al., 2024), and the security requirements identified through the attack vector analysis in Chapter Two.

The Client Tier encompasses the user-facing components: the chat interface, the local encrypted key store, the message composer (which encrypts before sending), the message renderer (which decrypts on receipt), and the group session manager (which maintains the TreeKEM ratchet tree state). The Server Tier provides message relay, user authentication, and prekey bundle storage functions, all operating exclusively on public key material and routing metadata. The Cryptographic Layer, implemented client-side, encompasses the Signal Protocol engine, key derivation functions, AES-256-GCM encryption, Ed25519 signatures, and the MLS group key management.

 

**Figure 3.3: System Architecture Diagram**

| CLIENT TIER | SERVER TIER | CRYPTOGRAPHIC LAYER |
| :---: | :---: | :---: |
| **User Interface** (Chat UI, Key Verification Panel) | **Message Relay Server** (No plaintext access) | **Signal Protocol Engine** (Double Ratchet \+ X3DH) |
| **Local Key Store** (Encrypted on-device storage) | **Prekey Bundle Store** (Public keys only) | **Key Derivation Functions** (HKDF-SHA256) |
| **Message Composer** (Encrypts before sending) | **WebSocket Transport** (TLS 1.3 channel layer) | **AES-256-GCM** (Bulk message encryption) |
| **Message Renderer** (Decrypts on receipt) | **User Authentication** (Registration & login) | **Ed25519 Signatures** (Message authentication) |
| **Group Session Manager** (TreeKEM group state) | **Group Membership Store** (Public metadata only) | **MLS-Aligned Group Keys** (TreeKEM ratchet tree) |

 

All client-server communication is secured at the transport layer using TLS 1.3, providing channel encryption in addition to the application-layer E2EE. This dual-layer approach ensures that even network-level adversaries who can intercept transport-layer traffic cannot access message content, as it remains end-to-end encrypted independently of the TLS channel. WebSocket connections over TLS (WSS) are used to provide the persistent, low-latency bidirectional communication channel required for real-time messaging.

 

**3.4 Cryptographic Protocol Selection and Justification**

The selection of cryptographic protocols is the most consequential technical decision in the design of a secure chat application. This research adopts a selection methodology based on three criteria: (1) formal security verification — the protocol must have been subject to rigorous cryptographic analysis establishing its security properties under standard adversarial models; (2) performance suitability — the protocol must introduce acceptable computational overhead for interactive real-time messaging; and (3) active deployment and community support — the protocol must be in production use in widely deployed systems, demonstrating practical viability. These criteria directly exclude custom protocols (such as Telegram’s MTProto) in favour of formally verified constructions (Albrecht et al., 2022).

The Signal Protocol, comprising the X3DH key agreement protocol and the Double Ratchet Algorithm, is selected as the primary E2EE framework for one-on-one messaging. The Double Ratchet’s security properties — forward secrecy and post-compromise security — have been formally verified under stronger adversarial models by Bienstock et al. (2022) and Collins et al. (2024). AES-256-GCM is selected for symmetric message encryption, providing authenticated encryption with associated data (AEAD) in a single operation. Ed25519 is selected for digital signatures, with its formal security established by Brendel et al. (2021). For group messaging, an MLS-aligned TreeKEM scheme is adopted, consistent with RFC 9420 (Barnes et al., 2023\) and formally verified by Wallez et al. (2023).

 

**Table 3.1: Cryptographic Protocol Selection and Justification**

| Protocol / Algorithm | Security Property Provided | Formally Verified? | Performance Class | Selected? |
| :---: | :---: | :---: | :---: | :---: |
| Signal Protocol (X3DH \+ Double Ratchet) | E2EE, Forward Secrecy, Post-Compromise Security, Authentication | Yes (Bienstock et al., 2022; Collins et al., 2024\) | Low overhead; O(1) per-message | ✓ Yes |
| AES-256-GCM (AEAD) | Symmetric confidentiality \+ integrity in single operation | Yes (NIST FIPS 197\) | Very fast (hardware acceleration) | ✓ Yes |
| Ed25519 | Message authentication; identity binding | Yes (Brendel et al., 2021\) | Very fast; 64-byte signature | ✓ Yes |
| X25519 (ECDH) | Asymmetric key exchange; session key establishment | Yes (Bernstein, 2006\) | Fast; 32-byte keys | ✓ Yes |
| MLS / TreeKEM | Scalable group E2EE; forward secrecy; post-compromise security | Yes (Wallez et al., 2023; RFC 9420\) | O(log n) per update | ✓ Yes |
| TLS 1.3 | Channel encryption (transport layer only) | Yes (Davis et al., 2022\) | Low overhead; 1-RTT handshake | ✓ Channel only |
| RSA-2048 | Asymmetric encryption; key exchange | Partial | Slow; 256-byte keys | ✗ Not selected |
| MTProto (Telegram) | Custom E2EE | No — 4 attacks found (Albrecht et al., 2022\) | Medium | ✗ Not selected |

Table 3.1 presents the cryptographic protocols evaluated for selection in this research. Protocols are assessed on formal verification status, security properties, performance class, and final selection decision. The Signal Protocol stack, AES-256-GCM, Ed25519, X25519, and MLS/TreeKEM are selected on the basis of formal verification, documented security properties, and performance suitability. RSA and MTProto are explicitly excluded.

 

**3.5 X3DH Key Exchange Design**

The Extended Triple Diffie-Hellman (X3DH) protocol is used to establish the initial shared secret between two communicating parties without requiring both to be simultaneously online. This asynchronous capability is essential for a practical messaging application, where users may initiate conversations with contacts who are currently offline. The X3DH design adopted in this research follows the specification of Marlinspike and Perrin (2016) and incorporates the key bundle structure: a long-term identity key (IK), a medium-term signed prekey (SPK), and a set of one-time prekeys (OPK). All keys are generated on the client using X25519 (Curve25519 ECDH) for key exchange and Ed25519 for signatures.

The server stores only public components of the prekey bundle and never has access to private keys. Upon initiating a session, the sender fetches the recipient’s prekey bundle from the server, performs four Diffie-Hellman operations, and derives the master secret using HKDF-SHA256. The recipient reconstructs the same master secret on receipt of the sender’s initial message, which carries the sender’s identity key and ephemeral key. This design provides forward secrecy even for the first message: if the recipient’s one-time prekey is used, no information about future sessions can be derived from a compromised server or recorded traffic.

 

**Figure 3.4: X3DH Key Exchange Protocol Flow**

| Alice (Sender) | Step / Action | Bob (Recipient) |
| :---: | :---: | :---: |
| Generate: Identity Key (IK\_A) Ephemeral Key (EK\_A) | Session Initialisation (Both parties offline capable) | Generate & publish: IK\_B, SPK\_B, OPK\_B (to prekey server) |
| Fetch Bob's prekey bundle from server | → Fetch Prekey Bundle → | Prekey bundle available on server |
| Compute shared secret: DH(IK\_A, SPK\_B) DH(EK\_A, IK\_B) DH(EK\_A, SPK\_B) DH(EK\_A, OPK\_B) | X3DH Key Agreement → Derive Master Secret ← | Compute same shared secret on receipt of first message |
| Derive root key (RK) and chain keys via HKDF-SHA256 | Key Derivation → Root Key \+ Chain Keys ← | Same derivation on decryption of first message |
| Encrypt message with Double Ratchet session key | → Encrypted Message → | Decrypt message using Double Ratchet session key |

 

**3.6 Double Ratchet Algorithm Design**

Following the X3DH session initialisation, all subsequent messages are encrypted using the Double Ratchet Algorithm. The Double Ratchet combines two ratcheting mechanisms: a Diffie-Hellman (DH) ratchet that advances the root key with each exchange of new DH public keys, and a symmetric-key ratchet (KDF chain) that derives a fresh message key for each message from the current chain key. This dual-ratchet design achieves both forward secrecy (compromise of a current message key does not expose past messages) and post-compromise security (the DH ratchet restores security after a state compromise within one epoch). Both properties have been formally confirmed under stronger adversarial models by Bienstock et al. (2022) and Collins et al. (2024).

Each message is encrypted with a unique key derived from the KDF chain and immediately deleted after use. The message header carries the sender’s current DH ratchet public key and message counter, enabling the recipient to advance their own ratchet state and derive the correct decryption key. Out-of-order message delivery is handled by storing skipped message keys in a bounded cache, ensuring that delayed messages can be decrypted without compromising the forward secrecy of the ratchet state.

 

**Figure 3.5: Double Ratchet Message Encryption Flow**

| Session Established (X3DH Root Key in place) |
| :---: |
| **↓** |
| DH Ratchet Step (New ECDH key pair generated per epoch) |
| **↓** |
| HKDF Derivation (Update Root Key → New Chain Key) |
| **↓** |
| Symmetric Ratchet Step (Derive per-message key from Chain Key) |
| **↓** |
| AES-256-GCM Encryption (Encrypt plaintext with message key) |
| **↓** |
| Append MAC \+ Header (Ed25519 signature \+ ratchet state metadata) |
| **↓** |
| **Delete Message Key (Ensures forward secrecy)** |
| **↓** |
| Transmit Ciphertext via WebSocket / TLS 1.3 |

 

**3.7 Key Management Module Design**

The key management module is responsible for the full cryptographic key lifecycle: generation, distribution, verification, rotation, compromise detection, revocation, and destruction. The design is guided by the usability and security findings reviewed in Chapter Two, particularly the work of Turner et al. (2023) on key fingerprint verification, Yadav et al. (2022) on automated fake key detection, and Reuter et al. (2021) on the usability of E2EE interfaces. The primary design goal is to make the key management process as transparent and automated as possible for non-expert users, while preserving the cryptographic soundness of every operation.

Key generation is performed entirely client-side using libsodium, ensuring that private key material never leaves the user’s device in unencrypted form. The signed prekey is refreshed on a configurable schedule (default: every 30 days) and the old signed prekey is retained for a short grace period to allow decryption of messages sent during the transition. One-time prekeys are replenished automatically when the server reports that the bundle is running low. Key verification is presented to users as a safety number comparison (consistent with the Signal design), displayed contextually within the conversation view rather than in a settings menu, based on the usability recommendation of Turner et al. (2023).

 

**Figure 3.6: Key Management Lifecycle Flowchart**

| Key Generation (Identity Key, Signed Prekey, One-Time Prekeys) |
| :---: |
| **↓** |
| Key Distribution (Upload prekey bundle to server; transmit via X3DH) |
| **↓** |
| Key Verification (Safety number / fingerprint display for out-of-band check) |
| **↓** |
| Key Rotation (Automatic per-epoch via Double Ratchet; periodic SPK refresh) |
| **↓** |
| Key Compromise Detection (Automated fake key detection; safety number change alert) |
| **↓** |
| Key Revocation (Mark key as compromised; trigger session renegotiation) |
| **↓** |
| **Key Destruction (Secure deletion of expired session keys)** |

 

Automated fake key detection is implemented as a supplementary mechanism alongside manual safety number verification, following the approach of Yadav et al. (2022). The system monitors for unexpected changes in a contact’s identity key and alerts the user immediately if a substitution is detected, without requiring the user to initiate the verification process. Key revocation triggers an immediate session renegotiation using a fresh X3DH handshake, ensuring that subsequent messages are protected under new keying material.

**3.8 Group Messaging Encryption Design**

Group messaging encryption is implemented using an MLS-aligned TreeKEM construction, consistent with RFC 9420 (Barnes et al., 2023). This design was selected over the Signal Sender Keys approach due to the formally demonstrated limitations of Sender Keys with respect to post-compromise security following membership changes (Cohn-Gordon et al., 2020; Alwen, Jost, & Mularczyk, 2022). In the TreeKEM construction, group members are arranged as leaves of a binary ratchet tree, and the group epoch key is derived from the root of the tree using HKDF-SHA256. Membership operations — add, remove, and update — are performed by committing a new tree state, advancing the epoch, and distributing updated path secrets to remaining members using O(log n) encrypted messages.

Each group messaging epoch uses a distinct group key, ensuring forward secrecy across epochs. Post-compromise security is restored within one epoch after a member’s device is compromised, provided the remaining members commit an update that excludes the compromised leaf. Individual messages within an epoch are additionally protected by a per-message symmetric ratchet derived from the epoch key, analogous to the Double Ratchet’s symmetric-key ratchet for bilateral messaging.

 

**Figure 3.7: Group Messaging Encryption Design (TreeKEM)**

| Group Session Initialised | TreeKEM Tree Constructed | Epoch Key Derived | Messages Encrypted |
| :---: | :---: | :---: | :---: |
| **↓** | **↓** | **↓** | **↓** |
| Admin creates group; generates initial key material | Members added as tree leaves; O(log n) key paths | Root key derived from tree; all members hold leaf secrets | Each message encrypted with current epoch key \+ Double Ratchet |
| **↓** | **↓** | **↓** | **↓** |
| Member Add: Update log(n) nodes only | Member Remove: Blank leaf; commit new epoch | Key Update: New epoch key; post-compromise security restored | Message Delivery: Recipient decrypts with epoch key |

 

**3.9 Implementation Environment**

The implementation environment has been selected to support the cryptographic, performance, and usability requirements of the proposed system. The server-side application is implemented using Spring Boot 3.2 on Java 21 LTS, a production-grade application framework providing embedded Tomcat, Spring Security for authentication and authorisation, and native Spring WebSocket support for real-time STOMP-based messaging. Spring Boot’s auto-configuration and dependency injection model ensures consistent, testable component boundaries across the server architecture. The build lifecycle is managed via Apache Maven 3.9, ensuring reproducible builds and straightforward dependency management. The client-side application is implemented as a React.js v18 web application, communicating with the Spring Boot backend through a STOMP/WebSocket connection and a RESTful API for registration and prekey management. Cryptographic operations are performed using Bouncy Castle (bcprov-jdk18on v1.78), a widely reviewed Java cryptographic provider implementing X25519, Ed25519, AES-256-GCM, and HKDF without custom primitives. The Signal Protocol’s Double Ratchet and X3DH are implemented via the official libsignal-client Java bindings (JNI), the same library used by Signal’s Android application, ensuring fidelity with the formally verified protocol.

 

**Table 3.2: Implementation Environment Specification**

| Component | Specification / Justification |
| ----- | ----- |
| **Operating System** | Ubuntu 22.04 LTS (server); Windows 11 / macOS 14 (client development and testing) |
| **Backend Framework** | Spring Boot 3.2 (Java 21 LTS) — production-grade application framework with embedded Tomcat, Spring Security, and Spring WebSocket; built and managed via Apache Maven 3.9 |
| **WebSocket Support** | Spring WebSocket (STOMP over SockJS) — provides full-duplex real-time bidirectional messaging over TLS 1.3; message broker relay via Spring Messaging |
| **Cryptographic Library** | Bouncy Castle (org.bouncycastle:bcprov-jdk18on v1.78) — provides X25519, Ed25519, AES-256-GCM, and HKDF; widely reviewed and audited Java cryptography provider |
| **Signal Protocol Implementation** | libsignal-client Java bindings (via JNI) — Signal Foundation’s official Java/Android implementation of the Double Ratchet Algorithm and X3DH key agreement |
| **Group Messaging Library** | mls4j — Java-native MLS RFC 9420 implementation providing TreeKEM-based group key agreement and epoch management |
| **Frontend Framework** | React.js v18 — component-based UI enabling responsive chat interface and key management panel; communicates with Spring Boot backend via STOMP/WebSocket and REST API |
| **Database (Server)** | PostgreSQL 15 — stores user accounts, prekey bundles (public keys only), and message routing metadata; accessed via Spring Data JPA / Hibernate ORM |
| **Database (Client)** | IndexedDB (browser) / SQLCipher (desktop) — encrypted local storage for session keys and message history |
| **Transport Security** | TLS 1.3 (channel layer) — all client-server communication encrypted at transport layer |
| **Testing Framework** | JUnit 5 \+ Spring Boot Test (unit/integration); Mockito (mocking); Wireshark (traffic analysis); custom security test harness |
| **Version Control** | Git (GitHub) — all source code and test scripts versioned and documented; Maven wrapper included for reproducible builds |
| **Development Methodology** | Iterative prototyping with security review gates at each phase (design, implementation, testing) |

Table 3.2 specifies the hardware and software components of the implementation environment, together with the justification for each selection. All cryptographic libraries are formally audited or verified; no custom cryptographic primitives are implemented in this research, consistent with the principle that protocol correctness depends on using established, reviewed implementations.

 

**3.10 Security Evaluation Framework**

The security evaluation framework defines the set of security properties to be tested, the evaluation methods to be applied, and the success criteria that determine whether each property has been achieved. The framework is derived from the threat model established in Chapter Two, covering the principal attack vectors documented against E2EE messaging systems: man-in-the-middle attacks, replay attacks, metadata leakage, message tampering, server compromise, and group forward secrecy violations. For each property, a specific test procedure is defined that can be reproduced in the controlled laboratory environment.

Security testing is conducted using a combination of structured attack simulation — in which specific attack scenarios are executed in a controlled network environment — and property verification, in which the system’s output is inspected against defined success criteria. Wireshark is used for traffic analysis to verify that no plaintext or key material is transmitted in observable network traffic. A custom adversary-in-the-middle test harness is used to simulate MitM attack scenarios and verify detection mechanisms. Message replay tests are conducted by capturing and retransmitting ciphertext payloads on active sessions and verifying rejection.

 

**Figure 3.8: Security Evaluation Framework**

| Security Property | Evaluation Method | Success Criterion |
| ----- | ----- | ----- |
| **Forward Secrecy** | Verify per-message key deletion post-use; attempt session key recovery after simulated compromise | Past session keys irrecoverable after ratchet advance |
| **Post-Compromise Security** | Simulate device compromise; assess whether subsequent messages are protected after key rotation | Future messages secured within one ratchet epoch after recovery |
| **MitM Resistance** | Deploy adversary-in-the-middle in controlled test network; verify safety number change detection | MitM attempt triggers safety number mismatch alert |
| **Replay Attack Resistance** | Replay captured ciphertext on live session; verify rejection by message key state | Replayed ciphertexts rejected; no duplicate message delivery |
| **Message Integrity** | Tamper with ciphertext bytes; verify AEAD authentication tag rejection | Tampered messages rejected at decryption; integrity violation logged |
| **Metadata Minimisation** | Inspect server logs during messaging session; verify absence of message content | Server logs contain only routing metadata; no plaintext or session keys |
| **Group Forward Secrecy** | Remove member; verify inability to decrypt messages sent after removal | Post-removal messages undecryptable by removed member |

 

**3.11 Performance Evaluation Framework**

The performance evaluation framework defines the metrics, test conditions, and baseline comparisons used to assess whether the encryption mechanisms introduced by the proposed system impose acceptable overhead for practical interactive messaging. Performance evaluation covers eight dimensions: encryption overhead, key agreement latency, Double Ratchet step time, group key operation time, message delivery latency, memory consumption, and throughput. These dimensions were identified from the performance literature reviewed in Chapter Two, particularly Anastos et al. (2025) on group key maintenance costs and Ueda et al. (2024) on MLS group messaging latency.

Performance tests are executed using JUnit 5 with Spring Boot Test for cryptographic operation timing, and a custom load testing harness for end-to-end latency and throughput measurements. All tests are repeated a minimum of 100 times and the results reported as mean and standard deviation. Network conditions are simulated using Linux Traffic Control (tc) to introduce controlled round-trip time delays of 50ms, 150ms, and 300ms, representing typical mobile network conditions. Group size tests are conducted with 2, 5, 10, 25, and 50 members to characterise the O(log n) scaling behaviour of the TreeKEM group key operations.

 

 **Performance Evaluation Framework**

| Test Dimension | Metric | Test Conditions | Baseline Comparison |
| ----- | ----- | ----- | ----- |
| **Encryption Overhead** | Time (ms) per encrypt/decrypt cycle | 1, 10, 100, 500 concurrent messages; AES-256-GCM | Unencrypted message transmission time |
| **Key Agreement Latency** | X3DH session setup time (ms) | Cold start; prekey bundle cached; prekey bundle absent | TLS 1.3 handshake latency |
| **Double Ratchet Step** | Time per ratchet advance (ms) | 1,000 sequential messages; 50 out-of-order messages | Static key symmetric encryption |
| **Group Key Operation** | Commit time (ms) for member add/remove | Groups of 2, 5, 10, 25, 50 members; TreeKEM commits | Signal Sender Keys group baseline |
| **Message Delivery Latency** | End-to-end latency (ms) | Local network; simulated 50ms, 150ms, 300ms RTT | WhatsApp / Signal published benchmarks |
| **Memory Consumption** | Peak memory (MB) during session | 1-on-1 session; 10-member group; 50-member group | Baseline application memory without E2EE |
| **Throughput** | Messages per second | 1, 5, 10 concurrent sessions; 1,000 message burst | Server relay throughput without encryption |

 

**Figure 3.9**

**3.12 Chapter Summary**

Chapter Three has presented the comprehensive methodology adopted for the design, implementation, and evaluation of the proposed secure chat application with end-to-end encryption. The research adopts a Design Science Research paradigm, producing a functional artefact as its primary output and evaluating it against defined security and performance criteria. The conceptual framework organises the system into six functional layers, each addressing specific research objectives. The system architecture separates client-side cryptographic operations from server-side relay functions, ensuring the server never accesses plaintext or session key material. The cryptographic protocol selection adopts the Signal Protocol (X3DH and Double Ratchet), AES-256-GCM, Ed25519, X25519, and an MLS-aligned TreeKEM group encryption scheme, all formally verified and justified against the selection criteria. The implementation environment is specified in detail, with all cryptographic operations performed using formally audited libraries. The security evaluation framework defines test procedures for seven security properties, and the performance evaluation framework defines eight measurement dimensions with explicit test conditions and baseline comparisons. The methodology described in this chapter provides the complete operational basis for the system implementation and evaluation results presented in Chapter Four.

**REFERENCES**

Abazi, B., & Gegaj, R. (2022). A comparative study on the user experience on using secure messaging tools. In R. Jiang et al. (Eds.), *Big Data Privacy and Security in Smart Cities* (pp. 119–131). Springer. [https://doi.org/10.1007/978-3-031-04424-3\_7](https://doi.org/10.1007/978-3-031-04424-3_7)

Albrecht, M. R., Celi, S., Dowling, B., & Jones, D. (2023). Practically-exploitable cryptographic vulnerabilities in Matrix. In *2023 IEEE Symposium on Security and Privacy (SP)* (pp. 164–181). IEEE. [https://doi.org/10.1109/SP46215.2023.10351027](https://doi.org/10.1109/SP46215.2023.10351027)

Albrecht, M. R., Dowling, B., & Jones, D. (2024). Device-oriented group messaging: A formal cryptographic analysis of Matrix's core. In *2024 IEEE Symposium on Security and Privacy (SP)* (pp. 2666–2685). IEEE. [https://doi.org/10.1109/SP54263.2024.00075](https://doi.org/10.1109/SP54263.2024.00075)

Albrecht, M. R., Maráková, L., Paterson, K. G., & Stepanovs, I. (2022). Four attacks and a proof for Telegram. In *2022 IEEE Symposium on Security and Privacy (SP)* (pp. 87–106). IEEE. [https://doi.org/10.1109/SP46214.2022.9833666](https://doi.org/10.1109/SP46214.2022.9833666)

Alwen, J., Jost, D., & Mularczyk, M. (2022). On the insider security of MLS. In Y. Dodis & T. Shrimpton (Eds.), *Advances in Cryptology – CRYPTO 2022, Lecture Notes in Computer Science* (Vol. 13508, pp. 34–68). Springer. [https://doi.org/10.1007/978-3-031-15979-4\_2](https://doi.org/10.1007/978-3-031-15979-4_2)

Anastos, M., Auerbach, B., Baig, M. A., Noval, M. C., Kwan, M., Pascual-Perez, G., & Pietrzak, K. (2025). The cost of maintaining keys in dynamic groups with applications to multicast encryption and group messaging. In *Theory of Cryptography* (pp. 413–443). Springer. [https://doi.org/10.1007/978-3-031-78011-0](https://doi.org/10.1007/978-3-031-78011-0)

Balbas, D., Collins, D., & Gajland, P. (2023). Cryptographic administration for secure group messaging. *Cryptology ePrint Archive,* Paper 2022/1411. [https://eprint.iacr.org/2022/1411](https://eprint.iacr.org/2022/1411)

Barnes, R., Beurdouche, B., Robert, R., Millican, J., Omara, E., & Cohn-Gordon, K. (2023). The Messaging Layer Security (MLS) Protocol. *Internet Engineering Task Force RFC 9420\.* [https://doi.org/10.17487/RFC9420](https://doi.org/10.17487/RFC9420)

Bernstein, D. J. (2006). Curve25519: New Diffie-Hellman speed records. In *Public Key Cryptography – PKC 2006, Lecture Notes in Computer Science* (Vol. 3958, pp. 207–228). Springer. [https://doi.org/10.1007/11745853\_14](https://doi.org/10.1007/11745853_14)

Beurdouche, B., Rescorla, E., Omara, E., Inguva, S., & Duric, A. (2024). The Messaging Layer Security (MLS) Architecture. *IETF Internet Draft draft-ietf-mls-architecture-13.* [https://datatracker.ietf.org/doc/draft-ietf-mls-architecture-13](https://datatracker.ietf.org/doc/draft-ietf-mls-architecture-13)

Bhargavan, K., Jacomme, C., Kiefer, F., & Schmidt, R. (2024). Formal verification of the PQXDH post-quantum key agreement protocol for end-to-end secure messaging. In *33rd USENIX Security Symposium (USENIX Security 24).* USENIX Association. [https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan](https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan)

Bienstock, A., Fairoze, J., Garg, S., Mukherjee, P., & Raghuraman, S. (2022). A more complete analysis of the Signal Double Ratchet Algorithm. In Y. Dodis & T. Shrimpton (Eds.), *Advances in Cryptology – CRYPTO 2022, Lecture Notes in Computer Science* (Vol. 13507, pp. 784–813). Springer. [https://doi.org/10.1007/978-3-031-15802-5\_27](https://doi.org/10.1007/978-3-031-15802-5_27)

Bienstock, A., Rösler, P., & Tang, Y. (2023). ASMesh: Anonymous and secure messaging in mesh networks using stronger, anonymous double ratchet. In *Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security (CCS '23)* (pp. 1–15). ACM. [https://doi.org/10.1145/3576915.3616615](https://doi.org/10.1145/3576915.3616615)

Brendel, J., Cremers, C., Jackson, D., & Zhao, M. (2021). The provable security of Ed25519: Theory and practice. In *2021 IEEE Symposium on Security and Privacy (SP)* (pp. 1659–1676). IEEE. [https://doi.org/10.1109/SP40001.2021.00083](https://doi.org/10.1109/SP40001.2021.00083)

Canetti, R., Jain, P., Swanberg, M., & Varia, M. (2022). Universally composable end-to-end secure messaging. In Y. Dodis & T. Shrimpton (Eds.), *Advances in Cryptology – CRYPTO 2022, Part II, Lecture Notes in Computer Science* (Vol. 13508, pp. 3–33). Springer. [https://doi.org/10.1007/978-3-031-15979-4\_1](https://doi.org/10.1007/978-3-031-15979-4_1)

Chevalier, C., Lebrun, G., Martinelli, A., & Taleb, A. R. (2024). Quarantined-TreeKEM: A continuous group key agreement for MLS, secure in presence of inactive users. In *Proceedings of the 2024 ACM SIGSAC Conference on Computer and Communications Security* (pp. 2400–2414). ACM. [https://doi.org/10.1145/3658644.3690295](https://doi.org/10.1145/3658644.3690295)

Cohn-Gordon, K., Cremers, C., Dowling, B., Garratt, L., & Stebila, D. (2020). A formal security analysis of the Signal messaging protocol. *Journal of Cryptology, 33*(4), 1914–1983. [https://doi.org/10.1007/s00145-020-09360-1](https://doi.org/10.1007/s00145-020-09360-1)

Collins, D., Riepel, D., & Tran, S. A. O. (2024). On the tight security of the Double Ratchet. In *Proceedings of the 2024 ACM SIGSAC Conference on Computer and Communications Security* (pp. 4747–4761). ACM. [https://doi.org/10.1145/3658644.3690360](https://doi.org/10.1145/3658644.3690360)

Cremers, C., & Zhao, M. (2024). Secure messaging with strong compromise resilience, temporal privacy, and immediate decryption. In *2024 IEEE Symposium on Security and Privacy (SP).* IEEE. [https://doi.org/10.1109/SP54263.2024.00038](https://doi.org/10.1109/SP54263.2024.00038)

Davies, G. T., Handirk, T., Hesse, J., Horváth, M., & Jager, T. (2023). Security analysis of the WhatsApp end-to-end encrypted backup protocol. In H. Handschuh & A. Lysyanskaya (Eds.), *Advances in Cryptology – CRYPTO 2023, Lecture Notes in Computer Science* (Vol. 14084, pp. 330–361). Springer. [https://doi.org/10.1007/978-3-031-38551-3\_11](https://doi.org/10.1007/978-3-031-38551-3_11)

Davis, H., Diemert, D., Günther, F., & Jager, T. (2022). On the concrete security of TLS 1.3 PSK mode. In O. Dunkelman & S. Dziembowski (Eds.), *Advances in Cryptology – EUROCRYPT 2022, Lecture Notes in Computer Science* (Vol. 13276, pp. 876–906). Springer. [https://doi.org/10.1007/978-3-031-07085-3\_30](https://doi.org/10.1007/978-3-031-07085-3_30)

Diffie, W., & Hellman, M. (1976). New directions in cryptography. *IEEE Transactions on Information Theory, 22*(6), 644–654. [https://doi.org/10.1109/TIT.1976.1055638](https://doi.org/10.1109/TIT.1976.1055638)

Domenech, M. C., Abed Gregio, A. R., & Erpen de Bona, L. C. (2022). On metadata privacy in instant messaging. In *2022 IEEE Symposium on Computers and Communications (ISCC)* (pp. 1–7). IEEE. [https://doi.org/10.1109/ISCC55528.2022.9912901](https://doi.org/10.1109/ISCC55528.2022.9912901)

Hevner, A. R., March, S. T., Park, J., & Ram, S. (2004). Design science in information systems research. *MIS Quarterly, 28*(1), 75–105. [https://doi.org/10.2307/25148625](https://doi.org/10.2307/25148625)

Kajita, K., Emura, K., Ogawa, K., Nojima, R., & Ohtake, G. (2023). Continuous group key agreement with flexible authorization and its applications. In *Proceedings of the 9th ACM International Workshop on Security and Privacy Analytics* (pp. 1–12). ACM. [https://doi.org/10.1145/3579987.3586567](https://doi.org/10.1145/3579987.3586567)

Kim, J., Park, S., & Lee, H. (2025). On implementing hybrid post-quantum end-to-end encryption. *arXiv preprint arXiv:2601.14926.* [https://arxiv.org/abs/2601.14926](https://arxiv.org/abs/2601.14926)

Lee, J., Kwon, J., & Shin, J. S. (2023). Efficient continuous key agreement with reduced bandwidth from a decomposable KEM. *IEEE Access, 11,* 33224–33235. [https://doi.org/10.1109/ACCESS.2023.3263067](https://doi.org/10.1109/ACCESS.2023.3263067)

Longe, O. B., Chiemeke, S. C., Onifade, O. F. W., Balogun, F. M., & Longe, F. A. (2020). Cybercrime and criminality in Nigeria: What roles are internet access points playing? *Journal of Internet Banking and Commerce, 25*(3), 1–15.

Marlinspike, M., & Perrin, T. (2016). The Double Ratchet Algorithm. Open Whisper Systems. [https://signal.org/docs/specifications/doubleratchet/](https://signal.org/docs/specifications/doubleratchet/)

Marlinspike, M., & Perrin, T. (2016). The X3DH Key Agreement Protocol. Open Whisper Systems. [https://signal.org/docs/specifications/x3dh/](https://signal.org/docs/specifications/x3dh/)

Narang, M., Jatain, A., & Punetha, N. (2024). A survey on detection of man-in-the-middle attack in IoMT using machine learning techniques. In R. Tiwari et al. (Eds.), *Proceedings of International Conference on Computational Intelligence* (pp. 95–106). Springer. [https://doi.org/10.1007/978-981-97-3526-6\_10](https://doi.org/10.1007/978-981-97-3526-6_10)

National Institute of Standards and Technology. (2024). Post-quantum cryptography standards: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA). U.S. Department of Commerce. [https://www.nist.gov/pqcrypto](https://www.nist.gov/pqcrypto)

Paar, C., & Pelzl, J. (2010). *Understanding cryptography: A textbook for students and practitioners.* Springer. [https://doi.org/10.1007/978-3-642-04101-3](https://doi.org/10.1007/978-3-642-04101-3)

Peffers, K., Tuunanen, T., Rothenberger, M. A., & Chatterjee, S. (2007). A design science research methodology for information systems research. *Journal of Management Information Systems, 24*(3), 45–77. [https://doi.org/10.2753/MIS0742-1222240302](https://doi.org/10.2753/MIS0742-1222240302)

Reuter, A., Abdelmaksoud, A., Boudaoud, K., & Winckler, M. (2021). Usability of end-to-end encryption in e-mail communication. *Frontiers in Big Data, 4,* Article 568284\. [https://doi.org/10.3389/fdata.2021.568284](https://doi.org/10.3389/fdata.2021.568284)

Rösler, P., & Schwenk, J. (2023). Interoperability between messaging services — secure implementation of encryption. Study for the Federal Network Agency, Germany.

Statista. (2024). Number of mobile messaging app users worldwide from 2018 to 2028\. Statista Research Department. [https://www.statista.com/statistics/483255/number-of-mobile-messaging-users-worldwide/](https://www.statista.com/statistics/483255/number-of-mobile-messaging-users-worldwide/)

Teng, M., & Rasmussen, K. B. (2024). In-band MitM detection for the Signal Protocol. In *Proceedings of the 2024 Workshop on Attacks and Solutions in Hardware Security (ASHES '24).* ACM. [https://doi.org/10.1145/3689939.3695791](https://doi.org/10.1145/3689939.3695791)

Turner, D., Shahandashti, S. F., & Petrie, H. (2023). The effect of length on key fingerprint verification security and usability. In *Proceedings of the 18th International Conference on Availability, Reliability and Security (ARES 2023\)* (pp. 1–11). ACM. [https://doi.org/10.1145/3600160.3600187](https://doi.org/10.1145/3600160.3600187)

Ueda, K., Sasaki, C., & Tagami, A. (2024). Pub/sub meets MLS: End-to-end encrypted group data sharing over publish-subscribe. In *Proceedings of the 2024 IEEE Symposium on Security and Privacy Workshops.* IEEE.

Wallez, T., Protzenko, J., Beurdouche, B., & Bhargavan, K. (2023). Formally verified cryptography for end-to-end secure messaging. In *32nd USENIX Security Symposium (USENIX Security 23\)* (pp. 1217–1233). USENIX Association.

Wermke, D., Huaman, N., Acar, Y., Reaves, B., Traynor, P., & Fahl, S. (2022). A large scale investigation of obfuscation use in Google Play. In *Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security* (pp. 3111–3124). ACM. [https://doi.org/10.1145/3548606.3560619](https://doi.org/10.1145/3548606.3560619)

Yadav, T. K., Gosain, D., Herzberg, A., Seamons, K., & Zappala, D. (2022). Automatic detection of fake key attacks in secure messaging. *arXiv preprint arXiv:2210.09940.* [https://arxiv.org/abs/2210.09940](https://arxiv.org/abs/2210.09940)

