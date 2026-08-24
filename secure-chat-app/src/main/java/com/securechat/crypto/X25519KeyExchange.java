package com.securechat.crypto;

import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.*;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * X25519 Elliptic Curve Diffie-Hellman key exchange implementation.
 * Provides the ECDH operations used in the X3DH key agreement protocol.
 *
 * Security Properties:
 * - Computational Diffie-Hellman (CDH) security on Curve25519
 * - 128-bit security level
 * - Constant-time implementation via Bouncy Castle
 */
public class X25519KeyExchange {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Represents an X25519 key pair (private + public).
     */
    public static class KeyPair {
        private final byte[] privateKey;
        private final byte[] publicKey;

        public KeyPair(byte[] privateKey, byte[] publicKey) {
            this.privateKey = Arrays.copyOf(privateKey, privateKey.length);
            this.publicKey = Arrays.copyOf(publicKey, publicKey.length);
        }

        public byte[] getPrivateKey() { return Arrays.copyOf(privateKey, privateKey.length); }
        public byte[] getPublicKey() { return Arrays.copyOf(publicKey, publicKey.length); }

        public void destroy() {
            Arrays.fill(privateKey, (byte) 0);
        }
    }

    /**
     * Generates a new X25519 key pair using a cryptographically secure random source.
     */
    public static KeyPair generateKeyPair() {
        X25519KeyPairGenerator generator = new X25519KeyPairGenerator();
        generator.init(new X25519KeyGenerationParameters(SECURE_RANDOM));
        var asymKeyPair = generator.generateKeyPair();

        byte[] privateKey = new byte[32];
        byte[] publicKey = new byte[32];
        ((X25519PrivateKeyParameters) asymKeyPair.getPrivate()).encode(privateKey, 0);
        ((X25519PublicKeyParameters) asymKeyPair.getPublic()).encode(publicKey, 0);

        return new KeyPair(privateKey, publicKey);
    }

    /**
     * Performs an X25519 Diffie-Hellman key agreement.
     *
     * @param ourPrivateKey  Our 32-byte private key
     * @param theirPublicKey Their 32-byte public key
     * @return 32-byte shared secret
     */
    public static byte[] computeSharedSecret(byte[] ourPrivateKey, byte[] theirPublicKey) {
        X25519PrivateKeyParameters privParams = new X25519PrivateKeyParameters(ourPrivateKey, 0);
        X25519PublicKeyParameters pubParams = new X25519PublicKeyParameters(theirPublicKey, 0);

        X25519Agreement agreement = new X25519Agreement();
        agreement.init(privParams);

        byte[] sharedSecret = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(pubParams, sharedSecret, 0);

        return sharedSecret;
    }

    /**
     * Implements the X3DH (Extended Triple Diffie-Hellman) key agreement protocol.
     * Computes the master secret from four DH operations as specified in the Signal Protocol.
     *
     * @param senderIdentityKey    Sender's long-term identity private key (IK_A)
     * @param senderEphemeralKey   Sender's one-time ephemeral private key (EK_A)
     * @param recipientIdentityPub Recipient's long-term identity public key (IK_B)
     * @param recipientSignedPrePub Recipient's medium-term signed prekey public (SPK_B)
     * @param recipientOneTimePub  Recipient's one-time prekey public (OPK_B), may be null
     * @return Master secret derived from four DH operations via HKDF
     */
    public static byte[] performX3DH(
            byte[] senderIdentityKey, byte[] senderEphemeralKey,
            byte[] recipientIdentityPub, byte[] recipientSignedPrePub,
            byte[] recipientOneTimePub) {

        // DH1: IK_A <-> SPK_B (mutual authentication)
        byte[] dh1 = computeSharedSecret(senderIdentityKey, recipientSignedPrePub);

        // DH2: EK_A <-> IK_B (forward secrecy contribution)
        byte[] dh2 = computeSharedSecret(senderEphemeralKey, recipientIdentityPub);

        // DH3: EK_A <-> SPK_B (ephemeral key exchange)
        byte[] dh3 = computeSharedSecret(senderEphemeralKey, recipientSignedPrePub);

        // Concatenate DH results
        byte[] dhConcat;
        if (recipientOneTimePub != null) {
            // DH4: EK_A <-> OPK_B (one-time prekey adds randomness)
            byte[] dh4 = computeSharedSecret(senderEphemeralKey, recipientOneTimePub);
            dhConcat = new byte[dh1.length + dh2.length + dh3.length + dh4.length];
            System.arraycopy(dh1, 0, dhConcat, 0, dh1.length);
            System.arraycopy(dh2, 0, dhConcat, dh1.length, dh2.length);
            System.arraycopy(dh3, 0, dhConcat, dh1.length + dh2.length, dh3.length);
            System.arraycopy(dh4, 0, dhConcat, dh1.length + dh2.length + dh3.length, dh4.length);
            Arrays.fill(dh4, (byte) 0);
        } else {
            dhConcat = new byte[dh1.length + dh2.length + dh3.length];
            System.arraycopy(dh1, 0, dhConcat, 0, dh1.length);
            System.arraycopy(dh2, 0, dhConcat, dh1.length, dh2.length);
            System.arraycopy(dh3, 0, dhConcat, dh1.length + dh2.length, dh3.length);
        }

        // Derive master secret using HKDF-SHA256
        byte[] masterSecret = HKDFUtil.deriveKey(dhConcat, "X3DH".getBytes(), 32);

        // Securely wipe intermediate secrets
        Arrays.fill(dh1, (byte) 0);
        Arrays.fill(dh2, (byte) 0);
        Arrays.fill(dh3, (byte) 0);
        Arrays.fill(dhConcat, (byte) 0);

        return masterSecret;
    }

    /**
     * Recipient-side X3DH computation (mirror of sender's).
     */
    public static byte[] performX3DHRecipient(
            byte[] recipientIdentityKey, byte[] recipientSignedPreKey,
            byte[] recipientOneTimeKey,
            byte[] senderIdentityPub, byte[] senderEphemeralPub) {

        // DH1: SPK_B <-> IK_A
        byte[] dh1 = computeSharedSecret(recipientSignedPreKey, senderIdentityPub);

        // DH2: IK_B <-> EK_A
        byte[] dh2 = computeSharedSecret(recipientIdentityKey, senderEphemeralPub);

        // DH3: SPK_B <-> EK_A
        byte[] dh3 = computeSharedSecret(recipientSignedPreKey, senderEphemeralPub);

        byte[] dhConcat;
        if (recipientOneTimeKey != null) {
            byte[] dh4 = computeSharedSecret(recipientOneTimeKey, senderEphemeralPub);
            dhConcat = new byte[dh1.length + dh2.length + dh3.length + dh4.length];
            System.arraycopy(dh1, 0, dhConcat, 0, dh1.length);
            System.arraycopy(dh2, 0, dhConcat, dh1.length, dh2.length);
            System.arraycopy(dh3, 0, dhConcat, dh1.length + dh2.length, dh3.length);
            System.arraycopy(dh4, 0, dhConcat, dh1.length + dh2.length + dh3.length, dh4.length);
            Arrays.fill(dh4, (byte) 0);
        } else {
            dhConcat = new byte[dh1.length + dh2.length + dh3.length];
            System.arraycopy(dh1, 0, dhConcat, 0, dh1.length);
            System.arraycopy(dh2, 0, dhConcat, dh1.length, dh2.length);
            System.arraycopy(dh3, 0, dhConcat, dh1.length + dh2.length, dh3.length);
        }

        byte[] masterSecret = HKDFUtil.deriveKey(dhConcat, "X3DH".getBytes(), 32);

        Arrays.fill(dh1, (byte) 0);
        Arrays.fill(dh2, (byte) 0);
        Arrays.fill(dh3, (byte) 0);
        Arrays.fill(dhConcat, (byte) 0);

        return masterSecret;
    }
}
