package com.aegis.gate.infrastructure.repository;

import com.aegis.gate.domain.GateCheck;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface GateCheckRepository extends JpaRepository<GateCheck, UUID> {

    List<GateCheck> findByProjectIdOrderByCreatedAtDesc(UUID projectId);

    Optional<GateCheck> findByIdAndProjectId(UUID id, UUID projectId);
}
