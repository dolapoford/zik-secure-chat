package com.securechat.controller;

import com.securechat.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
}
