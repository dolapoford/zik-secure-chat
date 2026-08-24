package com.securechat.crypto;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Double Ratchet Algorithm implementation.
 * Provides forward secrecy and post-compromise security for 1-on-1 messaging.
 *
 * The algorithm combines:
 * 1. A DH ratchet (new ECDH key pair per epoch) for post-compromise security
 * 2. A symmetric-key ratchet (KDF chain) for per-message forward secrecy
 *
 * Security Properties:
 * - Forward Secrecy: Compromise of current keys cannot decrypt past messages
 * - Post-Compromise Security: Security is restored after a compromise once both
 *   parties perform a DH ratchet step
 * - Formally verified by Bienstock et al. (2022) and Collins et al. (2024)
 */
public class DoubleRatchet {

    /**
     * Represents the state of one side of a Double Ratchet session.
     */
    public static class RatchetState {
        // DH ratchet keys
        private X25519KeyExchange.KeyPair dhKeyPair;          // Our current DH ratchet key pair
        private byte[] remoteDHPublicKey;                      // Their current DH ratchet public key

        // Root key and chain keys
        private byte[] rootKey;                                // Current root key
        private byte[] sendingChainKey;                         // Current sending chain key
        private byte[] receivingChainKey;                       // Current receiving chain key

        // Message counters
        private int sendingMessageNumber = 0;
        private int receivingMessageNumber = 0;
        private int previousSendingChainLength = 0;

        // Skipped message keys (for out-of-order delivery)
        private final Map<String, byte[]> skippedMessageKeys = new HashMap<>();

        public X25519KeyExchange.KeyPair getDhKeyPair() { return dhKeyPair; }
        public byte[] getRemoteDHPublicKey() { return remoteDHPublicKey; }
        public byte[] getRootKey() { return rootKey; }
        public byte[] getSendingChainKey() { return sendingChainKey; }
        public byte[] getReceivingChainKey() { return receivingChainKey; }
        public int getSendingMessageNumber() { return sendingMessageNumber; }
        public int getReceivingMessageNumber() { return receivingMessageNumber; }
    }

    /**
     * Represents a Double Ratchet message header.
     */
    public static class MessageHeader {
        private final byte[] dhPublicKey;       // Sender's current DH ratchet public key
        private final int previousChainLength;   // Number of messages in the previous sending chain
        private final int messageNumber;         // Message number within the current chain

        public MessageHeader(byte[] dhPublicKey, int previousChainLength, int messageNumber) {
            this.dhPublicKey = dhPublicKey;
            this.previousChainLength = previousChainLength;
            this.messageNumber = messageNumber;
        }

        public byte[] getDhPublicKey() { return dhPublicKey; }
        public int getPreviousChainLength() { return previousChainLength; }
        public int getMessageNumber() { return messageNumber; }

        /**
         * Serializes the header for transmission.
         */
        public byte[] serialize() {
            byte[] result = new byte[32 + 4 + 4]; // DH pub key + prev chain length + msg number
            System.arraycopy(dhPublicKey, 0, result, 0, 32);
            result[32] = (byte) (previousChainLength >> 24);
            result[33] = (byte) (previousChainLength >> 16);
            result[34] = (byte) (previousChainLength >> 8);
            result[35] = (byte) previousChainLength;
            result[36] = (byte) (messageNumber >> 24);
            result[37] = (byte) (messageNumber >> 16);
            result[38] = (byte) (messageNumber >> 8);
            result[39] = (byte) messageNumber;
            return result;
        }

        /**
         * Deserializes a header from received data.
         */
        public static MessageHeader deserialize(byte[] data) {
            byte[] dhPub = Arrays.copyOfRange(data, 0, 32);
            int prevChain = ((data[32] & 0xFF) << 24) | ((data[33] & 0xFF) << 16) |
                           ((data[34] & 0xFF) << 8) | (data[35] & 0xFF);
            int msgNum = ((data[36] & 0xFF) << 24) | ((data[37] & 0xFF) << 16) |
                        ((data[38] & 0xFF) << 8) | (data[39] & 0xFF);
            return new MessageHeader(dhPub, prevChain, msgNum);
        }
    }

    /**
     * Encrypted message wrapper containing header and ciphertext.
     */
    public static class EncryptedMessage {
        private final MessageHeader header;
        private final byte[] ciphertext;

        public EncryptedMessage(MessageHeader header, byte[] ciphertext) {
            this.header = header;
            this.ciphertext = ciphertext;
        }

        public MessageHeader getHeader() { return header; }
        public byte[] getCiphertext() { return ciphertext; }
    }

    /**
     * Initializes a ratchet state for the session initiator (Alice).
     * Called after X3DH establishes the shared secret.
     *
     * @param sharedSecret    The shared secret from X3DH (used as initial root key)
     * @param remoteDHPublic  Bob's signed prekey (used as initial remote DH public key)
     * @return Initialized RatchetState for Alice
     */
    public static RatchetState initializeAlice(byte[] sharedSecret, byte[] remoteDHPublic) {
        RatchetState state = new RatchetState();
        state.dhKeyPair = X25519KeyExchange.generateKeyPair();
        state.remoteDHPublicKey = Arrays.copyOf(remoteDHPublic, remoteDHPublic.length);

        // Perform initial DH ratchet step
        byte[] dhOutput = X25519KeyExchange.computeSharedSecret(
                state.dhKeyPair.getPrivateKey(), remoteDHPublic);

        byte[][] keys = HKDFUtil.deriveRootAndChainKey(sharedSecret, dhOutput);
        state.rootKey = keys[0];
        state.sendingChainKey = keys[1];
        state.receivingChainKey = null; // Will be set on first received message

        Arrays.fill(dhOutput, (byte) 0);
        return state;
    }

    /**
     * Initializes a ratchet state for the session responder (Bob).
     * Called after Bob receives Alice's initial message and computes the X3DH shared secret.
     *
     * @param sharedSecret  The shared secret from X3DH
     * @param dhKeyPair     Bob's signed prekey pair (used as initial DH ratchet key pair)
     * @return Initialized RatchetState for Bob
     */
    public static RatchetState initializeBob(byte[] sharedSecret, X25519KeyExchange.KeyPair dhKeyPair) {
        RatchetState state = new RatchetState();
        state.dhKeyPair = dhKeyPair;
        state.rootKey = Arrays.copyOf(sharedSecret, sharedSecret.length);
        state.sendingChainKey = null;
        state.receivingChainKey = null;
        state.remoteDHPublicKey = null;
        return state;
    }

    /**
     * Encrypts a plaintext message using the Double Ratchet.
     *
     * Steps:
     * 1. Derive message key and advance sending chain key (symmetric ratchet)
     * 2. Encrypt plaintext with AES-256-GCM using message key
     * 3. Create header with current DH public key and message number
     * 4. Securely delete message key (forward secrecy)
     *
     * @param state     The current ratchet state (modified in place)
     * @param plaintext The plaintext message to encrypt
     * @return EncryptedMessage containing header and ciphertext
     */
    public static EncryptedMessage encrypt(RatchetState state, byte[] plaintext) throws Exception {
        // Symmetric ratchet step: derive message key and next chain key
        byte[][] keys = HKDFUtil.deriveMessageAndChainKey(state.sendingChainKey);
        byte[] messageKey = keys[0];
        state.sendingChainKey = keys[1];

        // Create header
        MessageHeader header = new MessageHeader(
                state.dhKeyPair.getPublicKey(),
                state.previousSendingChainLength,
                state.sendingMessageNumber
        );

        // Encrypt with AES-256-GCM, using header as AAD for authenticated encryption
        byte[] ciphertext = AESGCMCipher.encrypt(plaintext, messageKey, header.serialize());

        state.sendingMessageNumber++;

        // Securely delete message key (forward secrecy)
        Arrays.fill(messageKey, (byte) 0);

        return new EncryptedMessage(header, ciphertext);
    }

    /**
     * Decrypts a received Double Ratchet message.
     *
     * Steps:
     * 1. If the sender's DH public key has changed, perform a DH ratchet step
     * 2. Derive message key from the receiving chain (symmetric ratchet)
     * 3. Decrypt ciphertext with AES-256-GCM
     * 4. Securely delete message key (forward secrecy)
     *
     * @param state     The current ratchet state (modified in place)
     * @param message   The received encrypted message
     * @return Decrypted plaintext bytes
     */
    public static byte[] decrypt(RatchetState state, EncryptedMessage message) throws Exception {
        MessageHeader header = message.getHeader();

        // Check if we need to perform a DH ratchet step
        if (state.remoteDHPublicKey == null ||
                !Arrays.equals(header.getDhPublicKey(), state.remoteDHPublicKey)) {
            // Skip any missed messages from the previous receiving chain
            skipMessageKeys(state, header.getPreviousChainLength());
            // Perform DH ratchet step
            performDHRatchet(state, header.getDhPublicKey());
        }

        // Skip any missed messages in the current receiving chain
        skipMessageKeys(state, header.getMessageNumber());

        // Symmetric ratchet step: derive message key
        byte[][] keys = HKDFUtil.deriveMessageAndChainKey(state.receivingChainKey);
        byte[] messageKey = keys[0];
        state.receivingChainKey = keys[1];
        state.receivingMessageNumber++;

        // Decrypt with AES-256-GCM
        byte[] plaintext = AESGCMCipher.decrypt(message.getCiphertext(), messageKey, header.serialize());

        // Securely delete message key (forward secrecy)
        Arrays.fill(messageKey, (byte) 0);

        return plaintext;
    }

    /**
     * Performs a DH ratchet step when a new remote public key is received.
     * This advances the root key and establishes new sending and receiving chains.
     */
    private static void performDHRatchet(RatchetState state, byte[] newRemoteDHPublic) {
        state.previousSendingChainLength = state.sendingMessageNumber;
        state.sendingMessageNumber = 0;
        state.receivingMessageNumber = 0;
        state.remoteDHPublicKey = Arrays.copyOf(newRemoteDHPublic, newRemoteDHPublic.length);

        // Derive new receiving chain key
        byte[] dhReceive = X25519KeyExchange.computeSharedSecret(
                state.dhKeyPair.getPrivateKey(), state.remoteDHPublicKey);
        byte[][] receiveKeys = HKDFUtil.deriveRootAndChainKey(state.rootKey, dhReceive);
        state.rootKey = receiveKeys[0];
        state.receivingChainKey = receiveKeys[1];

        // Generate new DH key pair for sending
        state.dhKeyPair = X25519KeyExchange.generateKeyPair();

        // Derive new sending chain key
        byte[] dhSend = X25519KeyExchange.computeSharedSecret(
                state.dhKeyPair.getPrivateKey(), state.remoteDHPublicKey);
        byte[][] sendKeys = HKDFUtil.deriveRootAndChainKey(state.rootKey, dhSend);
        state.rootKey = sendKeys[0];
        state.sendingChainKey = sendKeys[1];

        Arrays.fill(dhReceive, (byte) 0);
        Arrays.fill(dhSend, (byte) 0);
    }

    /**
     * Stores skipped message keys for out-of-order message delivery.
     */
    private static void skipMessageKeys(RatchetState state, int untilMessageNumber) {
        if (state.receivingChainKey == null) return;

        while (state.receivingMessageNumber < untilMessageNumber) {
            byte[][] keys = HKDFUtil.deriveMessageAndChainKey(state.receivingChainKey);
            String keyId = Arrays.hashCode(state.remoteDHPublicKey) + ":" + state.receivingMessageNumber;
            state.skippedMessageKeys.put(keyId, keys[0]);
            state.receivingChainKey = keys[1];
            state.receivingMessageNumber++;
        }
    }
}
