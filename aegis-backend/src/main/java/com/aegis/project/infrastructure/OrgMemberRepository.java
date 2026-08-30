package com.aegis.project.infrastructure;

import com.aegis.project.domain.OrgMember;
import com.aegis.project.domain.OrgMemberId;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OrgMemberRepository extends JpaRepository<OrgMember, OrgMemberId> {

    List<OrgMember> findByIdOrgId(UUID orgId);

    Optional<OrgMember> findByIdOrgIdAndIdUserId(UUID orgId, UUID userId);

    boolean existsByIdOrgIdAndIdUserId(UUID orgId, UUID userId);

    void deleteByIdOrgIdAndIdUserId(UUID orgId, UUID userId);
}
