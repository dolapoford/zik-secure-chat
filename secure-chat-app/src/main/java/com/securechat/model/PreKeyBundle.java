package com.securechat.model;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * PreKey bundle entity storing a user's public prekey material.
 * The server stores only public components — private keys remain on the client.
 */
@Entity
@Table(name = "prekey_bundles")
public class PreKeyBundle {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "username", nullable = false)
    private String username;

    /** Long-term identity public key (IK) */
    @Lob
    @Column(name = "identity_key")
    private byte[] identityKey;

    /** Medium-term signed prekey public (SPK) */
    @Lob
    @Column(name = "signed_prekey")
    private byte[] signedPreKey;

    /** Signature over the signed prekey using identity key */
    @Lob
    @Column(name = "signed_prekey_signature")
    private byte[] signedPreKeySignature;

    /** One-time prekey public (OPK) — consumed on first use */
    @Lob
    @Column(name = "one_time_prekey")
    private byte[] oneTimePreKey;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "consumed")
    private boolean consumed = false;

    public PreKeyBundle() {
        this.createdAt = Instant.now();
    }

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public byte[] getIdentityKey() { return identityKey; }
    public void setIdentityKey(byte[] identityKey) { this.identityKey = identityKey; }

    public byte[] getSignedPreKey() { return signedPreKey; }
    public void setSignedPreKey(byte[] signedPreKey) { this.signedPreKey = signedPreKey; }

    public byte[] getSignedPreKeySignature() { return signedPreKeySignature; }
    public void setSignedPreKeySignature(byte[] signedPreKeySignature) { this.signedPreKeySignature = signedPreKeySignature; }

    public byte[] getOneTimePreKey() { return oneTimePreKey; }
    public void setOneTimePreKey(byte[] oneTimePreKey) { this.oneTimePreKey = oneTimePreKey; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public boolean isConsumed() { return consumed; }
    public void setConsumed(boolean consumed) { this.consumed = consumed; }
}
