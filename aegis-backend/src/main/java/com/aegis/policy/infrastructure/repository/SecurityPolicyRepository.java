package com.aegis.policy.infrastructure.repository;

import com.aegis.policy.domain.SecurityPolicy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SecurityPolicyRepository extends JpaRepository<SecurityPolicy, UUID> {

    List<SecurityPolicy> findByProjectId(UUID projectId);

    List<SecurityPolicy> findByOrganizationId(UUID organizationId);

    Optional<SecurityPolicy> findByIdAndProjectId(UUID id, UUID projectId);

    @Query("""
            SELECT p FROM SecurityPolicy p
            WHERE p.enabled = true
              AND (
                   (p.project IS NOT NULL AND p.project.id = :projectId)
                   OR (p.organization IS NOT NULL AND p.organization.id = :organizationId AND p.project IS NULL)
              )
            """)
    List<SecurityPolicy> findEnabledForProject(
            @Param("projectId") UUID projectId,
            @Param("organizationId") UUID organizationId
    );
}
