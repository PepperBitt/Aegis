package com.aegis.project.api;

import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.project.api.dto.CreateProjectRequest;
import com.aegis.project.api.dto.ProjectResponse;
import com.aegis.project.api.dto.UpdateProjectRequest;
import com.aegis.project.application.ProjectService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@Tag(name = "Projects", description = "Endpoints for managing projects within organizations")
public class ProjectController {

    private final ProjectService projectService;
    private final UserRepository userRepository;

    @PostMapping("/api/v1/organizations/{orgId}/projects")
    @Operation(summary = "Create project", description = "Creates a new project in the specified organization. Requires org membership.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Project created successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid request"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the organization")
    })
    public ResponseEntity<ProjectResponse> createProject(
            @PathVariable UUID orgId,
            @Valid @RequestBody CreateProjectRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        ProjectResponse response = projectService.createProject(user, orgId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/api/v1/organizations/{orgId}/projects")
    @Operation(summary = "List organization projects", description = "Returns all projects belonging to the organization. Requires org membership.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the organization")
    })
    public ResponseEntity<List<ProjectResponse>> listOrgProjects(
            @PathVariable UUID orgId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(projectService.getOrgProjects(user, orgId));
    }

    @GetMapping("/api/v1/projects/{id}")
    @Operation(summary = "Get project details", description = "Returns project details. Requires membership in the project's organization.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the organization"),
            @ApiResponse(responseCode = "404", description = "Project not found")
    })
    public ResponseEntity<ProjectResponse> getProject(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(projectService.getProjectById(user, id));
    }

    @PutMapping("/api/v1/projects/{id}")
    @Operation(summary = "Update project", description = "Updates project details. Requires membership in the project's organization.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Project updated successfully"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the organization"),
            @ApiResponse(responseCode = "404", description = "Project not found")
    })
    public ResponseEntity<ProjectResponse> updateProject(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateProjectRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(projectService.updateProject(user, id, request));
    }

    @DeleteMapping("/api/v1/projects/{id}")
    @Operation(summary = "Archive project", description = "Archives a project (soft delete). Requires membership in the project's organization.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Project archived successfully"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the organization"),
            @ApiResponse(responseCode = "404", description = "Project not found")
    })
    public ResponseEntity<ProjectResponse> deleteProject(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(projectService.archiveProject(user, id));
    }

    private User getAuthenticatedUser(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User is not authenticated");
        }
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Authenticated user not found"));
    }
}
