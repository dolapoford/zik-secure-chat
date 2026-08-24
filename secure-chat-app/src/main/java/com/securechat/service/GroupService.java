package com.securechat.service;

import com.securechat.crypto.TreeKEMManager;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Group messaging service managing TreeKEM-based group encryption.
 * Handles group creation, member management, and group key lifecycle.
 */
@Service
public class GroupService {

    private final Map<String, TreeKEMManager.GroupState> groups = new ConcurrentHashMap<>();

    /**
     * Creates a new encrypted group chat.
     */
    public Map<String, Object> createGroup(String groupName, String creatorUsername) {
        String groupId = UUID.randomUUID().toString();
        TreeKEMManager.GroupState state = TreeKEMManager.createGroup(groupId, creatorUsername);
        groups.put(groupId, state);

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
     * Encrypts a message for the group.
     */
    public Map<String, Object> sendGroupMessage(String groupId, String senderId, String plaintext) throws Exception {
        TreeKEMManager.GroupState state = groups.get(groupId);
        if (state == null) throw new IllegalArgumentException("Group not found: " + groupId);

        byte[] ciphertext = TreeKEMManager.encryptGroupMessage(state, plaintext.getBytes());

        Map<String, Object> result = new HashMap<>();
        result.put("groupId", groupId);
        result.put("sender", senderId);
        result.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        result.put("epoch", state.getEpoch());
        result.put("encrypted", true);
        return result;
    }

    /**
     * Decrypts a group message.
     */
    public String decryptGroupMessage(String groupId, byte[] ciphertext, int epoch) throws Exception {
        TreeKEMManager.GroupState state = groups.get(groupId);
        if (state == null) throw new IllegalArgumentException("Group not found: " + groupId);

        byte[] plaintext = TreeKEMManager.decryptGroupMessage(state, ciphertext, epoch);
        return new String(plaintext);
    }

    public TreeKEMManager.GroupState getGroupState(String groupId) {
        return groups.get(groupId);
    }

    public List<Map<String, Object>> listGroups() {
        return groups.entrySet().stream().map(entry -> {
            Map<String, Object> m = new HashMap<>();
            m.put("groupId", entry.getKey());
            m.put("epoch", entry.getValue().getEpoch());
            m.put("memberCount", entry.getValue().getMemberCount());
            return m;
        }).toList();
    }
}
