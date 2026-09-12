package com.securechat.controller;

import com.securechat.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Map;

/**
 * REST controller for user registration and authentication.
 */
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> request) {
        try {
            String username = request.get("username");
            String password = request.get("password");
            byte[] identityPublicKey = Base64.getDecoder().decode(request.get("identityPublicKey"));
            byte[] signingPublicKey = Base64.getDecoder().decode(request.get("signingPublicKey"));
            Map<String, Object> result = userService.register(username, password, identityPublicKey, signingPublicKey);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> request) {
        try {
            String username = request.get("username");
            String password = request.get("password");
            Map<String, Object> result = userService.authenticate(username, password);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/users")
    public ResponseEntity<?> listUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/users/online")
    public ResponseEntity<?> onlineUsers() {
        return ResponseEntity.ok(userService.getOnlineUsers());
    }
}
