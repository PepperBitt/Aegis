package com.aegis.audit.application;

import com.aegis.audit.api.dto.AuditLogResponse;
import com.aegis.audit.api.dto.AuditSearchRequest;
import com.aegis.audit.domain.AuditLog;
import com.aegis.audit.domain.AuditResult;
import com.aegis.audit.infrastructure.AuditLogRepository;
import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @Mock
    private OrganizationService organizationService;

    @Mock
    private ProjectRepository projectRepository;

    @InjectMocks
    private AuditService auditService;

    private User member;
    private User admin;
    private Organization org;
    private Project project;

    @BeforeEach
    void setUp() {
        member = User.builder()
                .id(UUID.randomUUID())
                .email("dev@aegis.local")
                .role(Role.DEVELOPER)
                .build();
        admin = User.builder()
                .id(UUID.randomUUID())
                .email("admin@aegis.local")
                .role(Role.ADMIN)
                .build();
        org = Organization.builder().id(UUID.randomUUID()).name("Org").build();
        project = Project.builder().id(UUID.randomUUID()).organization(org).name("Proj").build();
    }

    @Test
    void log_ShouldPersistAuditEntry() {
        when(auditLogRepository.save(any(AuditLog.class))).thenAnswer(inv -> {
            AuditLog log = inv.getArgument(0);
            log.setId(UUID.randomUUID());
            log.setCreatedAt(Instant.now());
            return log;
        });

        AuditLog saved = auditService.log(
                member.getId(), org.getId(), project.getId(),
                "PROJECT_CREATE", "PROJECT", project.getId().toString(),
                AuditResult.SUCCESS, "127.0.0.1", "{\"ok\":true}"
        );

        assertNotNull(saved.getId());
        assertEquals("PROJECT_CREATE", saved.getAction());
        assertEquals(AuditResult.SUCCESS, saved.getResult());
        verify(auditLogRepository).save(any(AuditLog.class));
    }

    @Test
    void search_ShouldVerifyMembership_WhenProjectIdProvided() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), member.getId());

        AuditLog entry = AuditLog.builder()
                .id(UUID.randomUUID())
                .projectId(project.getId())
                .action("SBOM_UPLOAD")
                .result(AuditResult.SUCCESS)
                .createdAt(Instant.now())
                .build();
        when(auditLogRepository.search(eq(project.getId()), isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(entry)));

        AuditSearchRequest filters = AuditSearchRequest.builder()
                .projectId(project.getId())
                .page(0)
                .size(50)
                .build();

        Page<AuditLogResponse> page = auditService.search(member, filters);

        assertEquals(1, page.getTotalElements());
        assertEquals("SBOM_UPLOAD", page.getContent().get(0).getAction());
        verify(organizationService).verifyMembership(org.getId(), member.getId());
    }

    @Test
    void search_ShouldAllowAdminWithoutScope() {
        when(auditLogRepository.search(isNull(), isNull(), isNull(), isNull(), isNull(), any(Pageable.class)))
                .thenReturn(Page.empty());

        AuditSearchRequest filters = AuditSearchRequest.builder().page(0).size(20).build();
        Page<AuditLogResponse> page = auditService.search(admin, filters);

        assertNotNull(page);
        verify(organizationService, never()).verifyMembership(any(), any());
    }

    @Test
    void search_ShouldDenyNonAdminWithoutScope() {
        AuditSearchRequest filters = AuditSearchRequest.builder().page(0).size(20).build();
        assertThrows(AccessDeniedException.class, () -> auditService.search(member, filters));
    }
}
