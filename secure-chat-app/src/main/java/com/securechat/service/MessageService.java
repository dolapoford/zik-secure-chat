package com.securechat.service;

import com.securechat.crypto.*;
import com.securechat.model.*;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Message service handling encrypted message sending and receiving.
 * Manages Double Ratchet sessions between user pairs.
 */
@Service
public class MessageService {

    private final MessageRepository messageRepository;
    private final UserService userService;

    // Active Double Ratchet sessions (sender:recipient -> RatchetState)
    private final Map<String, DoubleRatchet.RatchetState> sessions = new ConcurrentHashMap<>();

    public MessageService(MessageRepository messageRepository, UserService userService) {
        this.messageRepository = messageRepository;
        this.userService = userService;
    }

    /**
     * Establishes a new E2EE session using X3DH key agreement,
     * then initializes a Double Ratchet for ongoing messaging.
     *
     * @param senderUsername    The sender's username
     * @param recipientUsername The recipient's username
     * @return Session establishment confirmation
     */
    public Map<String, Object> establishSession(String senderUsername, String recipientUsername) {
        User sender = userService.findByUsername(senderUsername)
                .orElseThrow(() -> new IllegalArgumentException("Sender not found"));

        Map<String, String> recipientBundle = userService.fetchPreKeyBundle(recipientUsername);

        // Decode recipient's prekey bundle
        byte[] recipientIdentityPub = Base64.getDecoder().decode(recipientBundle.get("identityKey"));
        byte[] recipientSignedPrePub = Base64.getDecoder().decode(recipientBundle.get("signedPreKey"));
        byte[] recipientOneTimePub = Base64.getDecoder().decode(recipientBundle.get("oneTimePreKey"));

        // Verify the signed prekey signature
        byte[] signature = Base64.getDecoder().decode(recipientBundle.get("signedPreKeySignature"));
        User recipient = userService.findByUsername(recipientUsername)
                .orElseThrow(() -> new IllegalArgumentException("Recipient not found"));
        boolean signatureValid = Ed25519SignerUtil.verify(
                recipientSignedPrePub, signature, recipient.getSigningPublicKey());

        if (!signatureValid) {
            throw new SecurityException("Signed prekey signature verification failed — possible MitM attack!");
        }

        // Generate ephemeral key for X3DH
        X25519KeyExchange.KeyPair ephemeralKey = X25519KeyExchange.generateKeyPair();

        // Perform X3DH key agreement
        byte[] sharedSecret = X25519KeyExchange.performX3DH(
                sender.getIdentityPrivateKey(),
                ephemeralKey.getPrivateKey(),
                recipientIdentityPub,
                recipientSignedPrePub,
                recipientOneTimePub
        );

        // Initialize Double Ratchet as Alice (session initiator)
        String sessionKey = senderUsername + ":" + recipientUsername;
        DoubleRatchet.RatchetState state = DoubleRatchet.initializeAlice(sharedSecret, recipientSignedPrePub);
        sessions.put(sessionKey, state);

        // Compute safety number for key verification
        String safetyNumber = Ed25519SignerUtil.computeSafetyNumber(
                sender.getIdentityPublicKey(), recipientIdentityPub);

        Map<String, Object> result = new HashMap<>();
        result.put("status", "session_established");
        result.put("sender", senderUsername);
        result.put("recipient", recipientUsername);
        result.put("safetyNumber", safetyNumber);
        result.put("signatureVerified", true);
        result.put("ephemeralPublicKey", Base64.getEncoder().encodeToString(ephemeralKey.getPublicKey()));

        return result;
    }

    /**
     * Encrypts and sends a message using the established Double Ratchet session.
     *
     * @param senderUsername    Sender's username
     * @param recipientUsername Recipient's username
     * @param plaintext         Message plaintext
     * @return Encrypted message metadata
     */
    public Map<String, Object> sendMessage(String senderUsername, String recipientUsername, String plaintext) throws Exception {
        String sessionKey = senderUsername + ":" + recipientUsername;
        DoubleRatchet.RatchetState state = sessions.get(sessionKey);

        if (state == null) {
            // Auto-establish session
            establishSession(senderUsername, recipientUsername);
            state = sessions.get(sessionKey);
        }

        // Encrypt with Double Ratchet
        byte[] plaintextBytes = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        DoubleRatchet.EncryptedMessage encrypted = DoubleRatchet.encrypt(state, plaintextBytes);

        // Sign the ciphertext
        User sender = userService.findByUsername(senderUsername).orElseThrow();
        byte[] messageSignature = Ed25519SignerUtil.sign(encrypted.getCiphertext(), sender.getSigningPrivateKey());

        // Store the encrypted message
        Message message = new Message();
        message.setSenderId(senderUsername);
        message.setRecipientId(recipientUsername);
        message.setCiphertext(encrypted.getCiphertext());
        message.setRatchetHeader(encrypted.getHeader().serialize());
        message.setSignature(messageSignature);
        messageRepository.save(message);

        Map<String, Object> result = new HashMap<>();
        result.put("messageId", message.getId());
        result.put("sender", senderUsername);
        result.put("recipient", recipientUsername);
        result.put("ciphertext", Base64.getEncoder().encodeToString(encrypted.getCiphertext()));
        result.put("timestamp", message.getTimestamp().toString());
        result.put("encrypted", true);

        return result;
    }

    /**
     * Retrieves the chat history (encrypted messages) between two users.
     */
    public List<Map<String, Object>> getChatHistory(String user1, String user2) {
        List<Message> sent = messageRepository.findBySenderIdAndRecipientIdOrderByTimestamp(user1, user2);
        List<Message> received = messageRepository.findBySenderIdAndRecipientIdOrderByTimestamp(user2, user1);

        List<Message> all = new ArrayList<>();
        all.addAll(sent);
        all.addAll(received);
        all.sort(Comparator.comparing(Message::getTimestamp));

        return all.stream().map(msg -> {
            Map<String, Object> m = new HashMap<>();
            m.put("messageId", msg.getId());
            m.put("sender", msg.getSenderId());
            m.put("recipient", msg.getRecipientId());
            m.put("ciphertext", Base64.getEncoder().encodeToString(msg.getCiphertext()));
            m.put("timestamp", msg.getTimestamp().toString());
            m.put("encrypted", true);
            return m;
        }).toList();
    }

    /**
     * Returns the active session for a user pair.
     */
    public DoubleRatchet.RatchetState getSession(String sender, String recipient) {
        return sessions.get(sender + ":" + recipient);
    }
}
