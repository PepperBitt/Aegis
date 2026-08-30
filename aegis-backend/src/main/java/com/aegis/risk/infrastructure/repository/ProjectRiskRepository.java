package com.aegis.risk.infrastructure.repository;

import com.aegis.risk.domain.ProjectRisk;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ProjectRiskRepository extends JpaRepository<ProjectRisk, UUID> {

    Optional<ProjectRisk> findByProjectId(UUID projectId);
}
