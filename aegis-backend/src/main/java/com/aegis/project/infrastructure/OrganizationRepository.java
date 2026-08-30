package com.aegis.project.infrastructure;

import com.aegis.project.domain.Organization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OrganizationRepository extends JpaRepository<Organization, UUID> {

    Optional<Organization> findBySlug(String slug);

    boolean existsBySlug(String slug);

    @Query("SELECT o FROM Organization o JOIN OrgMember om ON o.id = om.id.orgId WHERE om.id.userId = :userId")
    List<Organization> findAllByUserId(@Param("userId") UUID userId);
}
