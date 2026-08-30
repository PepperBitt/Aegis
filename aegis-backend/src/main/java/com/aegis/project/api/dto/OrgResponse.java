package com.aegis.project.api.dto;

import com.aegis.project.domain.Plan;
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
public class OrgResponse {

    private UUID id;
    private String name;
    private String slug;
    private String description;
    private Plan plan;
    private Instant createdAt;
    private Instant updatedAt;
}
