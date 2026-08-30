package com.aegis.sbom.infrastructure;

import com.aegis.sbom.domain.SbomDocument;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SbomDocumentRepository extends JpaRepository<SbomDocument, UUID> {

    List<SbomDocument> findByProjectId(UUID projectId);

    Optional<SbomDocument> findByIdAndProjectId(UUID id, UUID projectId);
}
