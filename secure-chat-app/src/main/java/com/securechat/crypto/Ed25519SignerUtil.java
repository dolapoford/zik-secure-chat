package com.securechat.crypto;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Ed25519 digital signature implementation for message authentication.
 * Provides existential unforgeability under adaptive chosen-message attacks.
 *
 * Security Properties:
 * - 128-bit security level
 * - 64-byte signatures
 * - Deterministic signing (no per-signature randomness needed)
 * - Formally verified security (Brendel et al., 2021)
 */
public class Ed25519SignerUtil {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Represents an Ed25519 signing key pair.
     */
    public static class SigningKeyPair {
        private final byte[] privateKey;
        private final byte[] publicKey;

        public SigningKeyPair(byte[] privateKey, byte[] publicKey) {
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
     * Generates a new Ed25519 signing key pair.
     */
    public static SigningKeyPair generateKeyPair() {
        Ed25519PrivateKeyParameters privateKeyParams = new Ed25519PrivateKeyParameters(SECURE_RANDOM);
        Ed25519PublicKeyParameters publicKeyParams = privateKeyParams.generatePublicKey();

        byte[] privateKey = privateKeyParams.getEncoded();
        byte[] publicKey = publicKeyParams.getEncoded();

        return new SigningKeyPair(privateKey, publicKey);
    }

    /**
     * Signs a message using Ed25519.
     *
     * @param message    The message bytes to sign
     * @param privateKey The 32-byte Ed25519 private key
     * @return 64-byte Ed25519 signature
     */
    public static byte[] sign(byte[] message, byte[] privateKey) {
        Ed25519PrivateKeyParameters privParams = new Ed25519PrivateKeyParameters(privateKey, 0);
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privParams);
        signer.update(message, 0, message.length);
        return signer.generateSignature();
    }

    /**
     * Verifies an Ed25519 signature on a message.
     *
     * @param message   The original message bytes
     * @param signature The 64-byte Ed25519 signature
     * @param publicKey The 32-byte Ed25519 public key
     * @return true if the signature is valid, false otherwise
     */
    public static boolean verify(byte[] message, byte[] signature, byte[] publicKey) {
        try {
            Ed25519PublicKeyParameters pubParams = new Ed25519PublicKeyParameters(publicKey, 0);
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, pubParams);
            verifier.update(message, 0, message.length);
            return verifier.verifySignature(signature);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Computes a safety number (fingerprint) from two identity keys.
     * Used for out-of-band key verification between users.
     *
     * @param ourIdentityPub   Our identity public key
     * @param theirIdentityPub Their identity public key
     * @return Human-readable safety number string (60 digits in groups of 5)
     */
    public static String computeSafetyNumber(byte[] ourIdentityPub, byte[] theirIdentityPub) {
        // Combine both keys in a canonical order (sort lexicographically)
        byte[] combined;
        if (compareBytes(ourIdentityPub, theirIdentityPub) < 0) {
            combined = new byte[ourIdentityPub.length + theirIdentityPub.length];
            System.arraycopy(ourIdentityPub, 0, combined, 0, ourIdentityPub.length);
            System.arraycopy(theirIdentityPub, 0, combined, ourIdentityPub.length, theirIdentityPub.length);
        } else {
            combined = new byte[ourIdentityPub.length + theirIdentityPub.length];
            System.arraycopy(theirIdentityPub, 0, combined, 0, theirIdentityPub.length);
            System.arraycopy(ourIdentityPub, 0, combined, theirIdentityPub.length, ourIdentityPub.length);
        }

        // Hash the combined keys multiple times for fingerprint
        byte[] hash = HKDFUtil.deriveKey(combined, "SafetyNumber".getBytes(), 30);

        // Convert to numeric string
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 30; i++) {
            int val = (hash[i] & 0xFF) % 100;
            sb.append(String.format("%02d", val));
            if ((i + 1) % 5 == 0 && i < 29) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }

    private static int compareBytes(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            int cmp = Integer.compare(a[i] & 0xFF, b[i] & 0xFF);
            if (cmp != 0) return cmp;
        }
        return Integer.compare(a.length, b.length);
    }
}
