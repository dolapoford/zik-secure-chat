package com.securechat.controller;

import com.securechat.service.MessageService;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.handler.annotation.*;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * WebSocket STOMP controller for real-time encrypted messaging.
 * Also provides REST endpoints for session establishment and message history.
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
     * REST endpoint to establish an encrypted session between two users.
     */
    @PostMapping("/api/chat/session")
    public ResponseEntity<?> establishSession(@RequestBody Map<String, String> request) {
        try {
            String sender = request.get("sender");
            String recipient = request.get("recipient");
            Map<String, Object> result = messageService.establishSession(sender, recipient);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * REST endpoint to send an encrypted message.
     */
    @PostMapping("/api/chat/send")
    public ResponseEntity<?> sendMessage(@RequestBody Map<String, String> request) {
        try {
            String sender = request.get("sender");
            String recipient = request.get("recipient");
            String message = request.get("message");
            Map<String, Object> result = messageService.sendMessage(sender, recipient, message);

            // Notify recipient via WebSocket
            messagingTemplate.convertAndSendToUser(
                    recipient, "/queue/messages", result);

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
    public Map<String, Object> handleChatMessage(@Payload Map<String, String> message) throws Exception {
        String sender = message.get("sender");
        String recipient = message.get("recipient");
        String content = message.get("message");

        Map<String, Object> result = messageService.sendMessage(sender, recipient, content);

        // Also send to recipient's personal queue
        messagingTemplate.convertAndSendToUser(
                recipient, "/queue/messages", result);

        return result;
    }

    /**
     * REST endpoint to get chat history.
     */
    @GetMapping("/api/chat/history")
    public ResponseEntity<?> getChatHistory(
            @RequestParam String user1, @RequestParam String user2) {
        return ResponseEntity.ok(messageService.getChatHistory(user1, user2));
    }
}
