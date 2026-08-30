package com.aegis.project.infrastructure;

import com.aegis.project.domain.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ProjectRepository extends JpaRepository<Project, UUID> {

    List<Project> findByOrganizationId(UUID orgId);

    Optional<Project> findByIdAndOrganizationId(UUID id, UUID orgId);
}
