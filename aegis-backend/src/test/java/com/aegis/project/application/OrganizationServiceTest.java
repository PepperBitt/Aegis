package com.aegis.project.application;

import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.project.api.dto.AddMemberRequest;
import com.aegis.project.api.dto.CreateOrgRequest;
import com.aegis.project.api.dto.OrgResponse;
import com.aegis.project.api.dto.UpdateOrgRequest;
import com.aegis.project.domain.OrgMember;
import com.aegis.project.domain.OrgRole;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Plan;
import com.aegis.project.infrastructure.OrgMemberRepository;
import com.aegis.project.infrastructure.OrganizationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OrganizationServiceTest {

    @Mock
    private OrganizationRepository organizationRepository;

    @Mock
    private OrgMemberRepository orgMemberRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private OrganizationService organizationService;

    private User owner;
    private User memberUser;
    private Organization org;

    @BeforeEach
    void setUp() {
        owner = User.builder()
                .id(UUID.randomUUID())
                .email("owner@aegis.local")
                .fullName("Owner User")
                .role(Role.DEVELOPER)
                .isActive(true)
                .build();

        memberUser = User.builder()
                .id(UUID.randomUUID())
                .email("member@aegis.local")
                .fullName("Member User")
                .role(Role.DEVELOPER)
                .isActive(true)
                .build();

        org = Organization.builder()
                .id(UUID.randomUUID())
                .name("Acme Corp")
                .slug("acme-corp")
                .description("Acme Security Team")
                .plan(Plan.FREE)
                .build();
    }

    @Test
    void createOrganization_ShouldCreateOrg_AndSetCreatorAsOwner() {
        CreateOrgRequest request = CreateOrgRequest.builder()
                .name("Acme Corp")
                .slug("acme-corp")
                .description("Acme Security Team")
                .plan(Plan.FREE)
                .build();

        when(organizationRepository.existsBySlug("acme-corp")).thenReturn(false);
        when(organizationRepository.save(any(Organization.class))).thenReturn(org);

        OrgResponse response = organizationService.createOrganization(owner, request);

        assertNotNull(response);
        assertEquals("Acme Corp", response.getName());
        assertEquals("acme-corp", response.getSlug());
        verify(orgMemberRepository, times(1)).save(argThat(m -> m.getRole() == OrgRole.OWNER));
    }

    @Test
    void createOrganization_ShouldThrowException_WhenSlugAlreadyExists() {
        CreateOrgRequest request = CreateOrgRequest.builder()
                .name("Acme Corp")
                .slug("acme-corp")
                .build();

        when(organizationRepository.existsBySlug("acme-corp")).thenReturn(true);

        assertThrows(IllegalArgumentException.class, () -> organizationService.createOrganization(owner, request));
        verify(organizationRepository, never()).save(any());
    }

    @Test
    void updateOrganization_ShouldSucceed_WhenUserIsOwnerOrAdmin() {
        UpdateOrgRequest request = UpdateOrgRequest.builder()
                .name("Acme Corp Updated")
                .description("Updated description")
                .build();

        OrgMember ownerMember = OrgMember.builder()
                .organization(org)
                .user(owner)
                .role(OrgRole.OWNER)
                .build();

        when(orgMemberRepository.findByIdOrgIdAndIdUserId(org.getId(), owner.getId()))
                .thenReturn(Optional.of(ownerMember));
        when(organizationRepository.save(any(Organization.class))).thenReturn(org);

        OrgResponse response = organizationService.updateOrganization(owner, org.getId(), request);

        assertNotNull(response);
        verify(organizationRepository, times(1)).save(org);
    }

    @Test
    void updateOrganization_ShouldThrowAccessDenied_WhenUserIsMember() {
        UpdateOrgRequest request = UpdateOrgRequest.builder()
                .name("Acme Corp Updated")
                .build();

        OrgMember regularMember = OrgMember.builder()
                .organization(org)
                .user(memberUser)
                .role(OrgRole.MEMBER)
                .build();

        when(orgMemberRepository.findByIdOrgIdAndIdUserId(org.getId(), memberUser.getId()))
                .thenReturn(Optional.of(regularMember));

        assertThrows(AccessDeniedException.class, () ->
                organizationService.updateOrganization(memberUser, org.getId(), request));
    }

    @Test
    void addMember_ShouldAddUser_WhenActorIsOwnerOrAdmin() {
        AddMemberRequest request = AddMemberRequest.builder()
                .email("member@aegis.local")
                .role(OrgRole.MEMBER)
                .build();

        OrgMember ownerMember = OrgMember.builder()
                .organization(org)
                .user(owner)
                .role(OrgRole.OWNER)
                .build();

        when(orgMemberRepository.findByIdOrgIdAndIdUserId(org.getId(), owner.getId()))
                .thenReturn(Optional.of(ownerMember));
        when(userRepository.findByEmail("member@aegis.local")).thenReturn(Optional.of(memberUser));
        when(orgMemberRepository.existsByIdOrgIdAndIdUserId(org.getId(), memberUser.getId())).thenReturn(false);
        when(orgMemberRepository.save(any(OrgMember.class))).thenAnswer(i -> i.getArgument(0));

        var memberResponse = organizationService.addMember(owner, org.getId(), request);

        assertNotNull(memberResponse);
        assertEquals(memberUser.getId(), memberResponse.getUserId());
        assertEquals(OrgRole.MEMBER, memberResponse.getRole());
    }

    @Test
    void deleteOrganization_ShouldThrowAccessDenied_WhenUserIsNotOwner() {
        OrgMember adminMember = OrgMember.builder()
                .organization(org)
                .user(memberUser)
                .role(OrgRole.ADMIN)
                .build();

        when(orgMemberRepository.findByIdOrgIdAndIdUserId(org.getId(), memberUser.getId()))
                .thenReturn(Optional.of(adminMember));

        assertThrows(AccessDeniedException.class, () -> organizationService.deleteOrganization(memberUser, org.getId()));
        verify(organizationRepository, never()).deleteById(any());
    }
}
