package com.aegis.project.application;

import com.aegis.audit.annotation.AuditAction;
import com.aegis.auth.domain.User;
import com.aegis.project.api.dto.CreateProjectRequest;
import com.aegis.project.api.dto.ProjectResponse;
import com.aegis.project.api.dto.UpdateProjectRequest;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.domain.ProjectStatus;
import com.aegis.project.infrastructure.OrganizationRepository;
import com.aegis.project.infrastructure.ProjectRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ProjectService {

    private final ProjectRepository projectRepository;
    private final OrganizationRepository organizationRepository;
    private final OrganizationService organizationService;

    @Transactional
    @AuditAction(action = "PROJECT_CREATE", resourceType = "PROJECT")
    public ProjectResponse createProject(User creator, UUID orgId, CreateProjectRequest request) {
        organizationService.verifyMembership(orgId, creator.getId());

        Organization org = organizationRepository.findById(orgId)
                .orElseThrow(() -> new IllegalArgumentException("Organization not found"));

        Project project = Project.builder()
                .organization(org)
                .name(request.getName())
                .description(request.getDescription())
                .repositoryUrl(request.getRepositoryUrl())
                .ecosystem(request.getEcosystem())
                .status(ProjectStatus.ACTIVE)
                .createdBy(creator)
                .build();

        Project saved = projectRepository.save(project);
        return mapToProjectResponse(saved);
    }

    @Transactional(readOnly = true)
    public List<ProjectResponse> getOrgProjects(User user, UUID orgId) {
        organizationService.verifyMembership(orgId, user.getId());
        return projectRepository.findByOrganizationId(orgId)
                .stream()
                .map(this::mapToProjectResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public ProjectResponse getProjectById(User user, UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());
        return mapToProjectResponse(project);
    }

    @Transactional
    public ProjectResponse updateProject(User user, UUID projectId, UpdateProjectRequest request) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());

        project.setName(request.getName());
        if (request.getDescription() != null) {
            project.setDescription(request.getDescription());
        }
        if (request.getRepositoryUrl() != null) {
            project.setRepositoryUrl(request.getRepositoryUrl());
        }
        if (request.getEcosystem() != null) {
            project.setEcosystem(request.getEcosystem());
        }
        if (request.getStatus() != null) {
            project.setStatus(request.getStatus());
        }

        Project updated = projectRepository.save(project);
        return mapToProjectResponse(updated);
    }

    @Transactional
    @AuditAction(action = "PROJECT_ARCHIVE", resourceType = "PROJECT")
    public ProjectResponse archiveProject(User user, UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());

        project.setStatus(ProjectStatus.ARCHIVED);
        Project saved = projectRepository.save(project);
        return mapToProjectResponse(saved);
    }

    private ProjectResponse mapToProjectResponse(Project project) {
        return ProjectResponse.builder()
                .id(project.getId())
                .orgId(project.getOrganization().getId())
                .name(project.getName())
                .description(project.getDescription())
                .repositoryUrl(project.getRepositoryUrl())
                .ecosystem(project.getEcosystem())
                .status(project.getStatus())
                .createdById(project.getCreatedBy() != null ? project.getCreatedBy().getId() : null)
                .createdAt(project.getCreatedAt())
                .updatedAt(project.getUpdatedAt())
                .build();
    }
}
