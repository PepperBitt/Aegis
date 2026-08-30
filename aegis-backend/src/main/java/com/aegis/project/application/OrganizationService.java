package com.aegis.project.application;

import com.aegis.audit.annotation.AuditAction;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.project.api.dto.*;
import com.aegis.project.domain.*;
import com.aegis.project.infrastructure.OrgMemberRepository;
import com.aegis.project.infrastructure.OrganizationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class OrganizationService {

    private final OrganizationRepository organizationRepository;
    private final OrgMemberRepository orgMemberRepository;
    private final UserRepository userRepository;

    @Transactional
    @AuditAction(action = "ORG_CREATE", resourceType = "ORGANIZATION")
    public OrgResponse createOrganization(User creator, CreateOrgRequest request) {
        if (organizationRepository.existsBySlug(request.getSlug())) {
            throw new IllegalArgumentException("Organization slug already exists");
        }

        Organization organization = Organization.builder()
                .name(request.getName())
                .slug(request.getSlug())
                .description(request.getDescription())
                .plan(request.getPlan() != null ? request.getPlan() : Plan.FREE)
                .build();

        Organization savedOrg = organizationRepository.save(organization);

        OrgMemberId memberId = new OrgMemberId(savedOrg.getId(), creator.getId());
        OrgMember member = OrgMember.builder()
                .id(memberId)
                .organization(savedOrg)
                .user(creator)
                .role(OrgRole.OWNER)
                .build();

        orgMemberRepository.save(member);

        return mapToOrgResponse(savedOrg);
    }

    @Transactional(readOnly = true)
    public List<OrgResponse> getUserOrganizations(User user) {
        return organizationRepository.findAllByUserId(user.getId())
                .stream()
                .map(this::mapToOrgResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public OrgResponse getOrganizationById(User user, UUID orgId) {
        verifyMembership(orgId, user.getId());
        Organization org = organizationRepository.findById(orgId)
                .orElseThrow(() -> new IllegalArgumentException("Organization not found"));
        return mapToOrgResponse(org);
    }

    @Transactional
    public OrgResponse updateOrganization(User user, UUID orgId, UpdateOrgRequest request) {
        OrgMember member = getOrgMember(orgId, user.getId());
        if (member.getRole() != OrgRole.OWNER && member.getRole() != OrgRole.ADMIN) {
            throw new AccessDeniedException("Only OWNER or ADMIN can update organization details");
        }

        Organization org = member.getOrganization();
        org.setName(request.getName());
        if (request.getDescription() != null) {
            org.setDescription(request.getDescription());
        }
        if (request.getPlan() != null) {
            org.setPlan(request.getPlan());
        }

        Organization updated = organizationRepository.save(org);
        return mapToOrgResponse(updated);
    }

    @Transactional
    public void deleteOrganization(User user, UUID orgId) {
        OrgMember member = getOrgMember(orgId, user.getId());
        if (member.getRole() != OrgRole.OWNER) {
            throw new AccessDeniedException("Only organization OWNER can delete the organization");
        }

        organizationRepository.deleteById(orgId);
    }

    @Transactional
    public MemberResponse addMember(User actor, UUID orgId, AddMemberRequest request) {
        OrgMember actorMember = getOrgMember(orgId, actor.getId());
        if (actorMember.getRole() != OrgRole.OWNER && actorMember.getRole() != OrgRole.ADMIN) {
            throw new AccessDeniedException("Only OWNER or ADMIN can add members to the organization");
        }

        User targetUser = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + request.getEmail()));

        if (orgMemberRepository.existsByIdOrgIdAndIdUserId(orgId, targetUser.getId())) {
            throw new IllegalArgumentException("User is already a member of this organization");
        }

        OrgMemberId memberId = new OrgMemberId(orgId, targetUser.getId());
        OrgMember newMember = OrgMember.builder()
                .id(memberId)
                .organization(actorMember.getOrganization())
                .user(targetUser)
                .role(request.getRole() != null ? request.getRole() : OrgRole.MEMBER)
                .build();

        OrgMember saved = orgMemberRepository.save(newMember);
        return mapToMemberResponse(saved);
    }

    @Transactional
    public void removeMember(User actor, UUID orgId, UUID targetUserId) {
        OrgMember actorMember = getOrgMember(orgId, actor.getId());

        boolean isSelf = actor.getId().equals(targetUserId);
        if (!isSelf && actorMember.getRole() != OrgRole.OWNER && actorMember.getRole() != OrgRole.ADMIN) {
            throw new AccessDeniedException("Only OWNER or ADMIN can remove members");
        }

        OrgMember targetMember = orgMemberRepository.findByIdOrgIdAndIdUserId(orgId, targetUserId)
                .orElseThrow(() -> new IllegalArgumentException("Target user is not a member of this organization"));

        if (!isSelf && targetMember.getRole() == OrgRole.OWNER && actorMember.getRole() != OrgRole.OWNER) {
            throw new AccessDeniedException("Only OWNER can remove another OWNER");
        }

        orgMemberRepository.deleteByIdOrgIdAndIdUserId(orgId, targetUserId);
    }

    @Transactional(readOnly = true)
    public List<MemberResponse> getMembers(User user, UUID orgId) {
        verifyMembership(orgId, user.getId());
        return orgMemberRepository.findByIdOrgId(orgId)
                .stream()
                .map(this::mapToMemberResponse)
                .collect(Collectors.toList());
    }

    public void verifyMembership(UUID orgId, UUID userId) {
        if (!orgMemberRepository.existsByIdOrgIdAndIdUserId(orgId, userId)) {
            throw new AccessDeniedException("User is not a member of this organization");
        }
    }

    public OrgMember getOrgMember(UUID orgId, UUID userId) {
        return orgMemberRepository.findByIdOrgIdAndIdUserId(orgId, userId)
                .orElseThrow(() -> new AccessDeniedException("User is not a member of this organization"));
    }

    private OrgResponse mapToOrgResponse(Organization org) {
        return OrgResponse.builder()
                .id(org.getId())
                .name(org.getName())
                .slug(org.getSlug())
                .description(org.getDescription())
                .plan(org.getPlan())
                .createdAt(org.getCreatedAt())
                .updatedAt(org.getUpdatedAt())
                .build();
    }

    private MemberResponse mapToMemberResponse(OrgMember member) {
        return MemberResponse.builder()
                .userId(member.getUser().getId())
                .email(member.getUser().getEmail())
                .fullName(member.getUser().getFullName())
                .role(member.getRole())
                .joinedAt(member.getJoinedAt())
                .build();
    }
}
