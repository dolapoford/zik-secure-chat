package com.securechat.service;

import com.securechat.model.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * User service handling registration, authentication, and prekey storage.
 * All cryptographic key material is generated client-side; this service only
 * stores and serves public keys.
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
     * Registers a new user with client-supplied public keys. Private keys
     * are generated and held exclusively on the client and never reach this
     * method.
     */
    public Map<String, Object> register(String username, String password,
                                         byte[] identityPublicKey, byte[] signingPublicKey) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }

        User user = new User(username, passwordEncoder.encode(password));
        user.setIdentityPublicKey(identityPublicKey);
        user.setSigningPublicKey(signingPublicKey);
        userRepository.save(user);

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
     * Persists a batch of client-generated, client-signed prekeys. Each
     * one-time prekey becomes its own consumable PreKeyBundle row, all
     * sharing the same signed prekey and signature (mirroring how the
     * client-side prekey generation batches them).
     */
    public void storePreKeyBundle(String username, byte[] signedPreKey, byte[] signedPreKeySignature,
                                   List<byte[]> oneTimePreKeys, byte[] signingPublicKey) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        for (byte[] oneTimePreKey : oneTimePreKeys) {
            PreKeyBundle bundle = new PreKeyBundle();
            bundle.setUserId(user.getId());
            bundle.setUsername(username);
            bundle.setIdentityKey(user.getIdentityPublicKey());
            bundle.setSignedPreKey(signedPreKey);
            bundle.setSignedPreKeySignature(signedPreKeySignature);
            bundle.setSigningPublicKey(signingPublicKey);
            bundle.setOneTimePreKey(oneTimePreKey);
            preKeyBundleRepository.save(bundle);
        }
    }

    public long countAvailablePreKeys(String username) {
        return preKeyBundleRepository.countByUsernameAndConsumedFalse(username);
    }

    /**
     * Consumes and returns a user's full prekey bundle entity. Replenishment
     * is entirely client-driven now (see storePreKeyBundle) since the server
     * cannot generate a user's private prekey material on their behalf.
     */
    public PreKeyBundle fetchAndConsumePreKeyBundle(String username) {
        PreKeyBundle bundle = preKeyBundleRepository.findFirstByUsernameAndConsumedFalse(username)
                .orElseThrow(() -> new IllegalArgumentException("No prekey bundle available for: " + username));
        bundle.setConsumed(true);
        preKeyBundleRepository.save(bundle);
        return bundle;
    }

    public Map<String, String> fetchPreKeyBundle(String username) {
        PreKeyBundle bundle = fetchAndConsumePreKeyBundle(username);

        Map<String, String> result = new HashMap<>();
        result.put("identityKey", Base64.getEncoder().encodeToString(bundle.getIdentityKey()));
        result.put("signedPreKey", Base64.getEncoder().encodeToString(bundle.getSignedPreKey()));
        result.put("signedPreKeySignature", Base64.getEncoder().encodeToString(bundle.getSignedPreKeySignature()));
        result.put("oneTimePreKey", Base64.getEncoder().encodeToString(bundle.getOneTimePreKey()));
        result.put("signingPublicKey", Base64.getEncoder().encodeToString(bundle.getSigningPublicKey()));
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
