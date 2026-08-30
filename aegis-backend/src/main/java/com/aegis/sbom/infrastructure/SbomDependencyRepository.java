package com.aegis.sbom.infrastructure;

import com.aegis.sbom.domain.SbomDependency;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface SbomDependencyRepository extends JpaRepository<SbomDependency, UUID> {

    List<SbomDependency> findBySbomId(UUID sbomId);
}
