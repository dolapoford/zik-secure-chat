package com.securechat.controller;

import com.securechat.service.MessageService;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.*;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Map;

/**
 * WebSocket STOMP controller for real-time encrypted messaging.
 * Also provides REST endpoints for message send and history.
 */
@RestController
@CrossOrigin(origins = "*")
public class ChatWebSocketController {

    private final MessageService messageService;
    private final SimpMessagingTemplate messagingTemplate;

    public ChatWebSocketController(MessageService messageService, SimpMessagingTemplate messagingTemplate) {
        this.messageService = messageService;
        this.messagingTemplate = messagingTemplate;
    }

    /**
     * REST endpoint to send an encrypted message.
     */
    @PostMapping("/api/chat/send")
    public ResponseEntity<?> sendMessage(@RequestBody Map<String, String> request) {
        try {
            String sender = request.get("sender");
            String recipient = request.get("recipient");
            byte[] ciphertext = Base64.getDecoder().decode(request.get("ciphertext"));
            byte[] header = Base64.getDecoder().decode(request.get("header"));
            byte[] signature = Base64.getDecoder().decode(request.get("signature"));
            Map<String, Object> result = messageService.sendMessage(sender, recipient, ciphertext, header, signature);

            messagingTemplate.convertAndSendToUser(recipient, "/queue/messages", result);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * STOMP message handler for real-time messaging.
     */
    @MessageMapping("/chat.send")
    @SendTo("/topic/messages")
    public Map<String, Object> handleChatMessage(@Payload Map<String, String> message) {
        String sender = message.get("sender");
        String recipient = message.get("recipient");
        byte[] ciphertext = Base64.getDecoder().decode(message.get("ciphertext"));
        byte[] header = Base64.getDecoder().decode(message.get("header"));
        byte[] signature = Base64.getDecoder().decode(message.get("signature"));
        Map<String, Object> result = messageService.sendMessage(sender, recipient, ciphertext, header, signature);

        messagingTemplate.convertAndSendToUser(recipient, "/queue/messages", result);
        return result;
    }

    /**
     * REST endpoint to get chat history.
     */
    @GetMapping("/api/chat/history")
    public ResponseEntity<?> getChatHistory(
            @RequestParam String user1, @RequestParam String user2) {
        try {
            return ResponseEntity.ok(messageService.getChatHistory(user1, user2));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
