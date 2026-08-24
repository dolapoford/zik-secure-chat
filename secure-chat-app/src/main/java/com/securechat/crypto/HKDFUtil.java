package com.securechat.crypto;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * HKDF-SHA256 key derivation function utility.
 * Used throughout the protocol for deriving cryptographic keys from shared secrets.
 *
 * Implements RFC 5869 HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
 * using SHA-256 as the underlying hash function.
 */
public class HKDFUtil {

    /**
     * Derives a key of specified length from input keying material using HKDF-SHA256.
     *
     * @param inputKeyMaterial The input keying material (IKM)
     * @param info             Context and application-specific information
     * @param outputLength     The desired output key length in bytes
     * @return Derived key of the specified length
     */
    public static byte[] deriveKey(byte[] inputKeyMaterial, byte[] info, int outputLength) {
        return deriveKey(inputKeyMaterial, null, info, outputLength);
    }

    /**
     * Derives a key using HKDF-SHA256 with an optional salt.
     *
     * @param inputKeyMaterial The input keying material (IKM)
     * @param salt             Optional salt value (if null, a zero-filled salt of hash length is used)
     * @param info             Context and application-specific information
     * @param outputLength     The desired output key length in bytes
     * @return Derived key of the specified length
     */
    public static byte[] deriveKey(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());

        HKDFParameters params;
        if (salt != null) {
            params = new HKDFParameters(inputKeyMaterial, salt, info);
        } else {
            params = HKDFParameters.skipExtractParameters(inputKeyMaterial, info);
        }

        hkdf.init(params);
        byte[] output = new byte[outputLength];
        hkdf.generateBytes(output, 0, outputLength);
        return output;
    }

    /**
     * Derives both a root key and a chain key from a root key and DH output.
     * This is the core KDF chain operation in the Double Ratchet Algorithm.
     *
     * @param rootKey  Current root key (32 bytes)
     * @param dhOutput DH shared secret output (32 bytes)
     * @return Array of two 32-byte keys: [new_root_key, chain_key]
     */
    public static byte[][] deriveRootAndChainKey(byte[] rootKey, byte[] dhOutput) {
        byte[] derivedMaterial = deriveKey(dhOutput, rootKey, "DoubleRatchetRootChain".getBytes(), 64);
        byte[] newRootKey = new byte[32];
        byte[] chainKey = new byte[32];
        System.arraycopy(derivedMaterial, 0, newRootKey, 0, 32);
        System.arraycopy(derivedMaterial, 32, chainKey, 0, 32);
        return new byte[][]{newRootKey, chainKey};
    }

    /**
     * Derives a message key and the next chain key from the current chain key.
     * This is the symmetric-key ratchet step in the Double Ratchet Algorithm.
     *
     * @param chainKey Current chain key (32 bytes)
     * @return Array of two 32-byte keys: [message_key, next_chain_key]
     */
    public static byte[][] deriveMessageAndChainKey(byte[] chainKey) {
        byte[] messageKey = deriveKey(chainKey, null, "MessageKey".getBytes(), 32);
        byte[] nextChainKey = deriveKey(chainKey, null, "ChainKey".getBytes(), 32);
        return new byte[][]{messageKey, nextChainKey};
    }
}
