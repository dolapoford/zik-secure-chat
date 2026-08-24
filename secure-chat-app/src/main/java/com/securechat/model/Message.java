package com.securechat.model;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Encrypted message entity.
 * Stores ciphertext and Double Ratchet header metadata.
 * The server never sees plaintext — only encrypted bytes and routing information.
 */
@Entity
@Table(name = "messages")
public class Message {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "sender_id", nullable = false)
    private String senderId;

    @Column(name = "recipient_id")
    private String recipientId;

    @Column(name = "group_id")
    private String groupId;

    /** Encrypted message ciphertext (AES-256-GCM) */
    @Lob
    @Column(name = "ciphertext")
    private byte[] ciphertext;

    /** Double Ratchet message header (DH public key + counters) */
    @Lob
    @Column(name = "ratchet_header")
    private byte[] ratchetHeader;

    /** Ed25519 signature over the message */
    @Lob
    @Column(name = "signature")
    private byte[] signature;

    @Column(name = "timestamp")
    private Instant timestamp;

    @Column(name = "is_group_message")
    private boolean groupMessage = false;

    @Column(name = "epoch")
    private int epoch = 0;

    public Message() {
        this.timestamp = Instant.now();
    }

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getSenderId() { return senderId; }
    public void setSenderId(String senderId) { this.senderId = senderId; }

    public String getRecipientId() { return recipientId; }
    public void setRecipientId(String recipientId) { this.recipientId = recipientId; }

    public String getGroupId() { return groupId; }
    public void setGroupId(String groupId) { this.groupId = groupId; }

    public byte[] getCiphertext() { return ciphertext; }
    public void setCiphertext(byte[] ciphertext) { this.ciphertext = ciphertext; }

    public byte[] getRatchetHeader() { return ratchetHeader; }
    public void setRatchetHeader(byte[] ratchetHeader) { this.ratchetHeader = ratchetHeader; }

    public byte[] getSignature() { return signature; }
    public void setSignature(byte[] signature) { this.signature = signature; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public boolean isGroupMessage() { return groupMessage; }
    public void setGroupMessage(boolean groupMessage) { this.groupMessage = groupMessage; }

    public int getEpoch() { return epoch; }
    public void setEpoch(int epoch) { this.epoch = epoch; }
}
