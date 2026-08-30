package com.aegis.policy.infrastructure.repository;

import com.aegis.policy.domain.PolicyEvaluationResult;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PolicyEvaluationResultRepository extends JpaRepository<PolicyEvaluationResult, UUID> {

    List<PolicyEvaluationResult> findByProjectIdOrderByEvaluatedAtDesc(UUID projectId);
}
