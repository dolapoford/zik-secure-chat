package com.securechat.model;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;

public interface MessageRepository extends JpaRepository<Message, Long> {
    List<Message> findBySenderIdAndRecipientIdOrderByTimestamp(String senderId, String recipientId);
    List<Message> findByRecipientIdOrderByTimestamp(String recipientId);
    List<Message> findByGroupIdOrderByTimestamp(String groupId);
}
