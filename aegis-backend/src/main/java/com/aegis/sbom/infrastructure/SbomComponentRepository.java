package com.aegis.sbom.infrastructure;

import com.aegis.sbom.domain.SbomComponent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SbomComponentRepository extends JpaRepository<SbomComponent, UUID> {

    List<SbomComponent> findBySbomId(UUID sbomId);

    Optional<SbomComponent> findByIdAndSbomId(UUID id, UUID sbomId);

    @Query("SELECT c FROM SbomComponent c JOIN c.sbom s WHERE s.project.id = :projectId")
    List<SbomComponent> findByProjectId(@Param("projectId") UUID projectId);
}
