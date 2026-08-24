package com.securechat.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * AES-256-GCM authenticated encryption implementation.
 * Provides confidentiality and integrity in a single operation (AEAD).
 *
 * Security Properties:
 * - 256-bit key strength
 * - 128-bit authentication tag
 * - 96-bit random nonce (IV)
 * - Authenticated Encryption with Associated Data (AEAD)
 */
public class AESGCMCipher {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_NONCE_LENGTH_BYTES = 12; // 96 bits
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Encrypts plaintext using AES-256-GCM.
     *
     * @param plaintext The plaintext bytes to encrypt
     * @param key       The 32-byte (256-bit) encryption key
     * @param aad       Optional Associated Authenticated Data (may be null)
     * @return Encrypted data: [12-byte nonce | ciphertext | 16-byte auth tag]
     */
    public static byte[] encrypt(byte[] plaintext, byte[] key, byte[] aad) throws Exception {
        if (key.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be 32 bytes");
        }

        // Generate random 96-bit nonce
        byte[] nonce = new byte[GCM_NONCE_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        if (aad != null) {
            cipher.updateAAD(aad);
        }

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Prepend nonce to ciphertext: [nonce | ciphertext + tag]
        byte[] result = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);

        return result;
    }

    /**
     * Decrypts AES-256-GCM ciphertext and verifies the authentication tag.
     *
     * @param encryptedData The encrypted data: [12-byte nonce | ciphertext | 16-byte auth tag]
     * @param key           The 32-byte (256-bit) decryption key
     * @param aad           Optional Associated Authenticated Data (must match encryption AAD)
     * @return Decrypted plaintext bytes
     * @throws Exception if decryption fails or authentication tag is invalid
     */
    public static byte[] decrypt(byte[] encryptedData, byte[] key, byte[] aad) throws Exception {
        if (key.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be 32 bytes");
        }

        // Extract nonce from the beginning
        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, GCM_NONCE_LENGTH_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, GCM_NONCE_LENGTH_BYTES, encryptedData.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        if (aad != null) {
            cipher.updateAAD(aad);
        }

        return cipher.doFinal(ciphertext);
    }

    /**
     * Convenience method for encryption without AAD.
     */
    public static byte[] encrypt(byte[] plaintext, byte[] key) throws Exception {
        return encrypt(plaintext, key, null);
    }

    /**
     * Convenience method for decryption without AAD.
     */
    public static byte[] decrypt(byte[] encryptedData, byte[] key) throws Exception {
        return decrypt(encryptedData, key, null);
    }
}
