package com.securechat.model;

import jakarta.persistence.*;

/**
 * User entity representing a registered chat participant.
 * Stores the user's identity key pair and authentication credentials.
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String passwordHash;

    @Lob
    @Column(name = "identity_public_key")
    private byte[] identityPublicKey;

    @Lob
    @Column(name = "identity_private_key")
    private byte[] identityPrivateKey;

    @Lob
    @Column(name = "signing_public_key")
    private byte[] signingPublicKey;

    @Lob
    @Column(name = "signing_private_key")
    private byte[] signingPrivateKey;

    @Column(name = "online")
    private boolean online = false;

    public User() {}

    public User(String username, String passwordHash) {
        this.username = username;
        this.passwordHash = passwordHash;
    }

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }

    public byte[] getIdentityPublicKey() { return identityPublicKey; }
    public void setIdentityPublicKey(byte[] identityPublicKey) { this.identityPublicKey = identityPublicKey; }

    public byte[] getIdentityPrivateKey() { return identityPrivateKey; }
    public void setIdentityPrivateKey(byte[] identityPrivateKey) { this.identityPrivateKey = identityPrivateKey; }

    public byte[] getSigningPublicKey() { return signingPublicKey; }
    public void setSigningPublicKey(byte[] signingPublicKey) { this.signingPublicKey = signingPublicKey; }

    public byte[] getSigningPrivateKey() { return signingPrivateKey; }
    public void setSigningPrivateKey(byte[] signingPrivateKey) { this.signingPrivateKey = signingPrivateKey; }

    public boolean isOnline() { return online; }
    public void setOnline(boolean online) { this.online = online; }
}
