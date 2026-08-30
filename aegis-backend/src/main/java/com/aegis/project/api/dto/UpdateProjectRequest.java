package com.aegis.project.api.dto;

import com.aegis.project.domain.ProjectStatus;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateProjectRequest {

    @NotBlank(message = "Project name is required")
    @Size(max = 255, message = "Project name must not exceed 255 characters")
    private String name;

    private String description;

    @Size(max = 500, message = "Repository URL must not exceed 500 characters")
    private String repositoryUrl;

    @Size(max = 100, message = "Ecosystem must not exceed 100 characters")
    private String ecosystem;

    private ProjectStatus status;
}
