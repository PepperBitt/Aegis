package com.aegis.project.api.dto;

import com.aegis.project.domain.ProjectStatus;
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
public class ProjectResponse {

    private UUID id;
    private UUID orgId;
    private String name;
    private String description;
    private String repositoryUrl;
    private String ecosystem;
    private ProjectStatus status;
    private UUID createdById;
    private Instant createdAt;
    private Instant updatedAt;
}
