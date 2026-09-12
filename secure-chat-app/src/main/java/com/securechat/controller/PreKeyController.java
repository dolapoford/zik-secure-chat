package com.securechat.controller;

import com.securechat.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * REST controller for prekey bundle management.
 * Handles upload and retrieval of X3DH prekey bundles.
 */
@RestController
@RequestMapping("/api/prekeys")
@CrossOrigin(origins = "*")
public class PreKeyController {

    private final UserService userService;

    public PreKeyController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Fetches a user's prekey bundle for X3DH session establishment.
     * The one-time prekey is consumed upon fetch.
     */
    @GetMapping("/{username}")
    public ResponseEntity<?> fetchPreKeyBundle(@PathVariable String username) {
        try {
            Map<String, String> bundle = userService.fetchPreKeyBundle(username);
            return ResponseEntity.ok(bundle);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/upload")
    public ResponseEntity<?> uploadPreKeys(@RequestBody Map<String, Object> request) {
        try {
            String username = (String) request.get("username");
            byte[] signedPreKey = Base64.getDecoder().decode((String) request.get("signedPreKey"));
            byte[] signedPreKeySignature = Base64.getDecoder().decode((String) request.get("signedPreKeySignature"));
            byte[] signingPublicKey = Base64.getDecoder().decode((String) request.get("signingPublicKey"));

            @SuppressWarnings("unchecked")
            List<String> oneTimePreKeysB64 = (List<String>) request.get("oneTimePreKeys");
            List<byte[]> oneTimePreKeys = oneTimePreKeysB64.stream()
                    .map(s -> Base64.getDecoder().decode(s))
                    .toList();

            userService.storePreKeyBundle(username, signedPreKey, signedPreKeySignature, oneTimePreKeys, signingPublicKey);
            return ResponseEntity.ok(Map.of("stored", oneTimePreKeys.size()));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/mine/count")
    public ResponseEntity<?> countMine(@RequestParam String username) {
        return ResponseEntity.ok(Map.of("count", userService.countAvailablePreKeys(username)));
    }
}
