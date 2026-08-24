package com.securechat.service;

import com.securechat.crypto.*;
import com.securechat.model.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * User service handling registration, authentication, and key generation.
 * Key generation is performed server-side for this reference implementation;
 * in production, private keys would be generated and stored exclusively on the client.
 */
@Service
public class UserService {

    private final UserRepository userRepository;
    private final PreKeyBundleRepository preKeyBundleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PreKeyBundleRepository preKeyBundleRepository) {
        this.userRepository = userRepository;
        this.preKeyBundleRepository = preKeyBundleRepository;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    /**
     * Registers a new user with automatically generated cryptographic key pairs.
     */
    public Map<String, Object> register(String username, String password) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        User user = new User(username, passwordEncoder.encode(password));

        // Generate identity key pair (X25519 for key exchange)
        X25519KeyExchange.KeyPair identityKeys = X25519KeyExchange.generateKeyPair();
        user.setIdentityPublicKey(identityKeys.getPublicKey());
        user.setIdentityPrivateKey(identityKeys.getPrivateKey());

        // Generate signing key pair (Ed25519 for digital signatures)
        Ed25519SignerUtil.SigningKeyPair signingKeys = Ed25519SignerUtil.generateKeyPair();
        user.setSigningPublicKey(signingKeys.getPublicKey());
        user.setSigningPrivateKey(signingKeys.getPrivateKey());

        userRepository.save(user);

        // Generate initial prekey bundle
        generatePreKeyBundle(user);

        Map<String, Object> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("username", username);
        result.put("identityPublicKey", Base64.getEncoder().encodeToString(user.getIdentityPublicKey()));
        result.put("signingPublicKey", Base64.getEncoder().encodeToString(user.getSigningPublicKey()));

        return result;
    }

    /**
     * Authenticates a user and returns session information.
     */
    public Map<String, Object> authenticate(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new IllegalArgumentException("Invalid password");
        }

        user.setOnline(true);
        userRepository.save(user);

        Map<String, Object> result = new HashMap<>();
        result.put("userId", user.getId());
        result.put("username", username);
        result.put("identityPublicKey", Base64.getEncoder().encodeToString(user.getIdentityPublicKey()));
        result.put("signingPublicKey", Base64.getEncoder().encodeToString(user.getSigningPublicKey()));

        return result;
    }

    /**
     * Generates a prekey bundle for X3DH key agreement.
     * Includes identity key, signed prekey, and one-time prekeys.
     */
    public void generatePreKeyBundle(User user) {
        // Generate signed prekey (SPK)
        X25519KeyExchange.KeyPair signedPreKey = X25519KeyExchange.generateKeyPair();

        // Sign the prekey with the identity signing key
        byte[] signature = Ed25519SignerUtil.sign(signedPreKey.getPublicKey(), user.getSigningPrivateKey());

        // Generate one-time prekey (OPK)
        X25519KeyExchange.KeyPair oneTimePreKey = X25519KeyExchange.generateKeyPair();

        PreKeyBundle bundle = new PreKeyBundle();
        bundle.setUserId(user.getId());
        bundle.setUsername(user.getUsername());
        bundle.setIdentityKey(user.getIdentityPublicKey());
        bundle.setSignedPreKey(signedPreKey.getPublicKey());
        bundle.setSignedPreKeySignature(signature);
        bundle.setOneTimePreKey(oneTimePreKey.getPublicKey());

        preKeyBundleRepository.save(bundle);
    }

    /**
     * Fetches a user's prekey bundle for X3DH session establishment.
     * Marks one-time prekey as consumed.
     */
    public Map<String, String> fetchPreKeyBundle(String username) {
        PreKeyBundle bundle = preKeyBundleRepository.findFirstByUsernameAndConsumedFalse(username)
                .orElseThrow(() -> new IllegalArgumentException("No prekey bundle available for: " + username));

        // Mark the one-time prekey as consumed
        bundle.setConsumed(true);
        preKeyBundleRepository.save(bundle);

        // Generate a new prekey bundle if running low
        User user = userRepository.findByUsername(username).orElse(null);
        if (user != null && preKeyBundleRepository.countByUsernameAndConsumedFalse(username) < 5) {
            generatePreKeyBundle(user);
        }

        Map<String, String> result = new HashMap<>();
        result.put("identityKey", Base64.getEncoder().encodeToString(bundle.getIdentityKey()));
        result.put("signedPreKey", Base64.getEncoder().encodeToString(bundle.getSignedPreKey()));
        result.put("signedPreKeySignature", Base64.getEncoder().encodeToString(bundle.getSignedPreKeySignature()));
        result.put("oneTimePreKey", Base64.getEncoder().encodeToString(bundle.getOneTimePreKey()));
        return result;
    }

    public List<String> getOnlineUsers() {
        return userRepository.findAll().stream()
                .filter(User::isOnline)
                .map(User::getUsername)
                .toList();
    }

    public List<String> getAllUsers() {
        return userRepository.findAll().stream()
                .map(User::getUsername)
                .toList();
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
