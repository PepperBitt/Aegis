package com.aegis.audit.application;

import com.aegis.audit.api.dto.AuditLogResponse;
import com.aegis.audit.api.dto.AuditSearchRequest;
import com.aegis.audit.domain.AuditLog;
import com.aegis.audit.domain.AuditResult;
import com.aegis.audit.infrastructure.AuditLogRepository;
import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;
    private final OrganizationService organizationService;
    private final ProjectRepository projectRepository;

    @Transactional
    public AuditLog log(
            UUID userId,
            UUID organizationId,
            UUID projectId,
            String action,
            String resourceType,
            String resourceId,
            AuditResult result,
            String ipAddress,
            String metadataJson
    ) {
        AuditLog entry = AuditLog.builder()
                .userId(userId)
                .organizationId(organizationId)
                .projectId(projectId)
                .action(action)
                .resourceType(resourceType)
                .resourceId(resourceId)
                .result(result != null ? result : AuditResult.SUCCESS)
                .ipAddress(ipAddress)
                .metadataJson(metadataJson)
                .build();
        return auditLogRepository.save(entry);
    }

    @Transactional(readOnly = true)
    public Page<AuditLogResponse> search(User user, AuditSearchRequest filters) {
        int page = filters.getPage() >= 0 ? filters.getPage() : 0;
        int size = filters.getSize() > 0 ? Math.min(filters.getSize(), 200) : 50;
        Pageable pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt"));

        boolean isPlatformAdmin = user.getRole() == Role.ADMIN;

        if (filters.getProjectId() != null) {
            Project project = projectRepository.findById(filters.getProjectId())
                    .orElseThrow(() -> new IllegalArgumentException("Project not found"));
            if (!isPlatformAdmin) {
                organizationService.verifyMembership(project.getOrganization().getId(), user.getId());
            }
        } else if (filters.getOrganizationId() != null) {
            if (!isPlatformAdmin) {
                organizationService.verifyMembership(filters.getOrganizationId(), user.getId());
            }
        } else if (!isPlatformAdmin) {
            throw new AccessDeniedException("projectId or organizationId is required unless you are a platform ADMIN");
        }

        Page<AuditLog> results = auditLogRepository.search(
                filters.getProjectId(),
                filters.getOrganizationId(),
                filters.getUserId(),
                blankToNull(filters.getAction()),
                blankToNull(filters.getResourceType()),
                pageable
        );

        return results.map(this::toResponse);
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private AuditLogResponse toResponse(AuditLog log) {
        return AuditLogResponse.builder()
                .id(log.getId())
                .userId(log.getUserId())
                .organizationId(log.getOrganizationId())
                .projectId(log.getProjectId())
                .action(log.getAction())
                .resourceType(log.getResourceType())
                .resourceId(log.getResourceId())
                .result(log.getResult())
                .ipAddress(log.getIpAddress())
                .metadataJson(log.getMetadataJson())
                .createdAt(log.getCreatedAt())
                .build();
    }
}
