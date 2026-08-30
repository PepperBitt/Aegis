package com.aegis.audit.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditSearchRequest {
    private UUID projectId;
    private UUID organizationId;
    private UUID userId;
    private String action;
    private String resourceType;
    private int page;
    private int size;
}
