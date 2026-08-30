package com.aegis.alert.infrastructure.repository;

import com.aegis.alert.domain.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AlertRepository extends JpaRepository<Alert, UUID> {

    List<Alert> findByProjectIdOrderByCreatedAtDesc(UUID projectId);

    List<Alert> findByProjectIdAndAcknowledgedFalse(UUID projectId);

    Optional<Alert> findByIdAndProjectId(UUID id, UUID projectId);

    boolean existsByProjectIdAndAlertTypeAndAcknowledgedFalse(UUID projectId, com.aegis.alert.domain.AlertType alertType);

    @org.springframework.data.jpa.repository.Query("""
            SELECT CASE WHEN COUNT(a) > 0 THEN true ELSE false END
            FROM Alert a
            WHERE a.project.id = :projectId
              AND a.alertType = :alertType
              AND a.acknowledged = false
              AND a.metadataJson LIKE :metadataFragment
            """)
    boolean existsUnacknowledgedWithMetadata(
            @org.springframework.data.repository.query.Param("projectId") UUID projectId,
            @org.springframework.data.repository.query.Param("alertType") com.aegis.alert.domain.AlertType alertType,
            @org.springframework.data.repository.query.Param("metadataFragment") String metadataFragment
    );
}
