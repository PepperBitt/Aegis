package com.aegis.audit.infrastructure;

import com.aegis.audit.domain.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    List<AuditLog> findByProjectId(UUID projectId);

    List<AuditLog> findByOrganizationId(UUID organizationId);

    List<AuditLog> findByUserId(UUID userId);

    Page<AuditLog> findByProjectId(UUID projectId, Pageable pageable);

    Page<AuditLog> findByOrganizationId(UUID organizationId, Pageable pageable);

    @Query("""
            SELECT a FROM AuditLog a
            WHERE (:projectId IS NULL OR a.projectId = :projectId)
              AND (:organizationId IS NULL OR a.organizationId = :organizationId)
              AND (:userId IS NULL OR a.userId = :userId)
              AND (:action IS NULL OR a.action = :action)
              AND (:resourceType IS NULL OR a.resourceType = :resourceType)
            ORDER BY a.createdAt DESC
            """)
    Page<AuditLog> search(
            @Param("projectId") UUID projectId,
            @Param("organizationId") UUID organizationId,
            @Param("userId") UUID userId,
            @Param("action") String action,
            @Param("resourceType") String resourceType,
            Pageable pageable
    );
}
