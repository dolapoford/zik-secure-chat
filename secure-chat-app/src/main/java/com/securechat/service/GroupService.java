package com.securechat.service;

import com.securechat.crypto.TreeKEMManager;
import com.securechat.model.Message;
import com.securechat.model.MessageRepository;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Group messaging service managing TreeKEM-based group encryption.
 * Handles group creation, member management, and group key lifecycle.
 */
@Service
public class GroupService {

    private final Map<String, TreeKEMManager.GroupState> groups = new ConcurrentHashMap<>();
    private final Map<String, String> groupNames = new ConcurrentHashMap<>();
    private final MessageRepository messageRepository;

    public GroupService(MessageRepository messageRepository) {
        this.messageRepository = messageRepository;
    }

    /**
     * Creates a new encrypted group chat.
     */
    public Map<String, Object> createGroup(String groupName, String creatorUsername) {
        String groupId = UUID.randomUUID().toString();
        TreeKEMManager.GroupState state = TreeKEMManager.createGroup(groupId, creatorUsername);
        groups.put(groupId, state);
        groupNames.put(groupId, groupName);

        Map<String, Object> result = new HashMap<>();
        result.put("groupId", groupId);
        result.put("groupName", groupName);
        result.put("creator", creatorUsername);
        result.put("epoch", state.getEpoch());
        result.put("memberCount", state.getMemberCount());
        return result;
    }

    /**
     * Adds a member to the group, triggering a TreeKEM epoch advance.
     */
    public Map<String, Object> addMember(String groupId, String memberId) {
        TreeKEMManager.GroupState state = groups.get(groupId);
        if (state == null) throw new IllegalArgumentException("Group not found: " + groupId);

        TreeKEMManager.addMember(state, memberId);

        Map<String, Object> result = new HashMap<>();
        result.put("groupId", groupId);
        result.put("addedMember", memberId);
        result.put("epoch", state.getEpoch());
        result.put("memberCount", state.getMemberCount());
        return result;
    }

    /**
     * Removes a member from the group, triggering a TreeKEM epoch advance.
     */
    public Map<String, Object> removeMember(String groupId, String memberId) {
        TreeKEMManager.GroupState state = groups.get(groupId);
        if (state == null) throw new IllegalArgumentException("Group not found: " + groupId);

        TreeKEMManager.removeMember(state, memberId);

        Map<String, Object> result = new HashMap<>();
        result.put("groupId", groupId);
        result.put("removedMember", memberId);
        result.put("epoch", state.getEpoch());
        result.put("memberCount", state.getMemberCount());
        return result;
    }

    /**
     * Encrypts a message for the group using the current epoch key and
     * persists it so it can be retrieved and decrypted by group members.
     */
    public Map<String, Object> sendGroupMessage(String groupId, String senderId, String plaintext) throws Exception {
        TreeKEMManager.GroupState state = groups.get(groupId);
        if (state == null) throw new IllegalArgumentException("Group not found: " + groupId);
        if (!state.getMemberLeafIndex().containsKey(senderId)) {
            throw new IllegalArgumentException(senderId + " is not a member of this group");
        }

        byte[] ciphertext = TreeKEMManager.encryptGroupMessage(state, plaintext.getBytes(StandardCharsets.UTF_8));

        Message message = new Message();
        message.setSenderId(senderId);
        message.setGroupId(groupId);
        message.setGroupMessage(true);
        message.setCiphertext(ciphertext);
        message.setEpoch(state.getEpoch());
        messageRepository.save(message);

        Map<String, Object> result = new HashMap<>();
        result.put("messageId", message.getId());
        result.put("groupId", groupId);
        result.put("sender", senderId);
        result.put("epoch", state.getEpoch());
        result.put("encrypted", true);
        return result;
    }

    /**
     * Retrieves and decrypts a group's message history using the group's
     * current epoch key, caching each decrypted plaintext so a single-use
     * epoch key derivation is not repeated unnecessarily. Messages sent in an
     * epoch prior to the group's current epoch cannot be decrypted — by
     * design, TreeKEM's forward secrecy means the group key used to derive
     * their message key is not retained once the epoch advances.
     */
    public List<Map<String, Object>> getGroupMessages(String groupId) {
        TreeKEMManager.GroupState state = groups.get(groupId);
        if (state == null) throw new IllegalArgumentException("Group not found: " + groupId);

        List<Message> messages = messageRepository.findByGroupIdOrderByTimestamp(groupId);
        List<Map<String, Object>> result = new ArrayList<>();
        for (Message msg : messages) {
            Map<String, Object> m = new HashMap<>();
            m.put("messageId", msg.getId());
            m.put("sender", msg.getSenderId());
            m.put("timestamp", msg.getTimestamp().toString());
            m.put("epoch", msg.getEpoch());
            m.put("text", decryptAndCache(state, msg));
            result.add(m);
        }
        return result;
    }

    private String decryptAndCache(TreeKEMManager.GroupState state, Message msg) {
        if (msg.getPlaintext() != null) {
            return msg.getPlaintext();
        }
        if (msg.getEpoch() != state.getEpoch()) {
            return "[Message unavailable — the group key has since rotated (epoch " + msg.getEpoch() + ")]";
        }
        try {
            byte[] plaintextBytes = TreeKEMManager.decryptGroupMessage(state, msg.getCiphertext(), msg.getEpoch());
            String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
            msg.setPlaintext(plaintext);
            messageRepository.save(msg);
            return plaintext;
        } catch (Exception e) {
            return "[Unable to decrypt message]";
        }
    }

    public TreeKEMManager.GroupState getGroupState(String groupId) {
        return groups.get(groupId);
    }

    public List<Map<String, Object>> listGroups() {
        return groups.entrySet().stream().map(entry -> {
            Map<String, Object> m = new HashMap<>();
            m.put("groupId", entry.getKey());
            m.put("groupName", groupNames.getOrDefault(entry.getKey(), "Group"));
            m.put("epoch", entry.getValue().getEpoch());
            m.put("memberCount", entry.getValue().getMemberCount());
            return m;
        }).toList();
    }

    /**
     * Lists only the groups a given user is currently a member of, along
     * with the current member list — used to populate the group sidebar.
     */
    public List<Map<String, Object>> listGroupsForUser(String username) {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Map.Entry<String, TreeKEMManager.GroupState> entry : groups.entrySet()) {
            TreeKEMManager.GroupState state = entry.getValue();
            if (!state.getMemberLeafIndex().containsKey(username)) continue;

            Map<String, Object> m = new HashMap<>();
            m.put("groupId", entry.getKey());
            m.put("groupName", groupNames.getOrDefault(entry.getKey(), "Group"));
            m.put("epoch", state.getEpoch());
            m.put("memberCount", state.getMemberCount());
            m.put("members", new ArrayList<>(state.getMemberLeafIndex().keySet()));
            result.add(m);
        }
        return result;
    }
}
