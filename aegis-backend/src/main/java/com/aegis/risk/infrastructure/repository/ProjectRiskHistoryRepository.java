package com.aegis.risk.infrastructure.repository;

import com.aegis.risk.domain.ProjectRiskHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ProjectRiskHistoryRepository extends JpaRepository<ProjectRiskHistory, UUID> {

    List<ProjectRiskHistory> findByProjectIdOrderByCalculatedAtDesc(UUID projectId);
}
