package com.securechat.model;

import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;

public interface PreKeyBundleRepository extends JpaRepository<PreKeyBundle, Long> {
    Optional<PreKeyBundle> findFirstByUsernameAndConsumedFalse(String username);
    List<PreKeyBundle> findByUsernameAndConsumedFalse(String username);
    long countByUsernameAndConsumedFalse(String username);
}
