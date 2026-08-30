package com.aegis.audit.api.dto;

import com.aegis.audit.domain.AuditResult;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogResponse {
    private UUID id;
    private UUID userId;
    private UUID organizationId;
    private UUID projectId;
    private String action;
    private String resourceType;
    private String resourceId;
    private AuditResult result;
    private String ipAddress;
    private String metadataJson;
    private Instant createdAt;
}
