package com.securechat.service;

import com.securechat.model.*;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Message service handling 1:1 encrypted message storage and retrieval.
 * The server never sees plaintext or private key material — all
 * cryptography (X3DH, Double Ratchet, signing) happens client-side. This
 * service is a thin, key-blind relay: it stores whatever ciphertext/header/
 * signature bytes the sender's client produces and returns them unchanged
 * to whichever client asks for the conversation's history.
 */
@Service
public class MessageService {

    private final MessageRepository messageRepository;

    public MessageService(MessageRepository messageRepository) {
        this.messageRepository = messageRepository;
    }

    public Map<String, Object> sendMessage(String senderUsername, String recipientUsername,
                                            byte[] ciphertext, byte[] header, byte[] signature) {
        Message message = new Message();
        message.setSenderId(senderUsername);
        message.setRecipientId(recipientUsername);
        message.setCiphertext(ciphertext);
        message.setRatchetHeader(header);
        message.setSignature(signature);
        messageRepository.save(message);

        Map<String, Object> result = new HashMap<>();
        result.put("messageId", message.getId());
        result.put("sender", senderUsername);
        result.put("recipient", recipientUsername);
        result.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        result.put("header", Base64.getEncoder().encodeToString(header));
        result.put("signature", Base64.getEncoder().encodeToString(signature));
        result.put("timestamp", message.getTimestamp().toString());
        return result;
    }

    public List<Map<String, Object>> getChatHistory(String user1, String user2) {
        List<Message> sent = messageRepository.findBySenderIdAndRecipientIdOrderByTimestamp(user1, user2);
        List<Message> received = messageRepository.findBySenderIdAndRecipientIdOrderByTimestamp(user2, user1);

        List<Message> all = new ArrayList<>();
        all.addAll(sent);
        all.addAll(received);
        all.sort(Comparator.comparing(Message::getTimestamp));

        List<Map<String, Object>> result = new ArrayList<>();
        for (Message msg : all) {
            Map<String, Object> m = new HashMap<>();
            m.put("messageId", msg.getId());
            m.put("sender", msg.getSenderId());
            m.put("recipient", msg.getRecipientId());
            m.put("ciphertext", Base64.getEncoder().encodeToString(msg.getCiphertext()));
            m.put("header", Base64.getEncoder().encodeToString(msg.getRatchetHeader()));
            m.put("signature", Base64.getEncoder().encodeToString(msg.getSignature()));
            m.put("timestamp", msg.getTimestamp().toString());
            result.add(m);
        }
        return result;
    }
}
