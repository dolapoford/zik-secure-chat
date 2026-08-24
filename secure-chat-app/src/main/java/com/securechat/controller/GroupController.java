package com.securechat.controller;

import com.securechat.service.GroupService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST controller for group chat management.
 * Handles group creation, member management, and group messaging.
 */
@RestController
@RequestMapping("/api/groups")
@CrossOrigin(origins = "*")
public class GroupController {

    private final GroupService groupService;

    public GroupController(GroupService groupService) {
        this.groupService = groupService;
    }

    @PostMapping("/create")
    public ResponseEntity<?> createGroup(@RequestBody Map<String, String> request) {
        try {
            String groupName = request.get("groupName");
            String creator = request.get("creator");
            return ResponseEntity.ok(groupService.createGroup(groupName, creator));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/{groupId}/members")
    public ResponseEntity<?> addMember(@PathVariable String groupId, @RequestBody Map<String, String> request) {
        try {
            return ResponseEntity.ok(groupService.addMember(groupId, request.get("memberId")));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @DeleteMapping("/{groupId}/members/{memberId}")
    public ResponseEntity<?> removeMember(@PathVariable String groupId, @PathVariable String memberId) {
        try {
            return ResponseEntity.ok(groupService.removeMember(groupId, memberId));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/{groupId}/messages")
    public ResponseEntity<?> sendGroupMessage(@PathVariable String groupId, @RequestBody Map<String, String> request) {
        try {
            return ResponseEntity.ok(groupService.sendGroupMessage(
                    groupId, request.get("sender"), request.get("message")));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping
    public ResponseEntity<?> listGroups() {
        return ResponseEntity.ok(groupService.listGroups());
    }
}
