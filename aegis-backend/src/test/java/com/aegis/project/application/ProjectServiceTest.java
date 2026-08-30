package com.aegis.project.application;

import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.project.api.dto.CreateProjectRequest;
import com.aegis.project.api.dto.ProjectResponse;
import com.aegis.project.api.dto.UpdateProjectRequest;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.domain.ProjectStatus;
import com.aegis.project.infrastructure.OrganizationRepository;
import com.aegis.project.infrastructure.ProjectRepository;
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
class ProjectServiceTest {

    @Mock
    private ProjectRepository projectRepository;

    @Mock
    private OrganizationRepository organizationRepository;

    @Mock
    private OrganizationService organizationService;

    @InjectMocks
    private ProjectService projectService;

    private User user;
    private Organization org;
    private Project project;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("dev@aegis.local")
                .fullName("Dev User")
                .role(Role.DEVELOPER)
                .isActive(true)
                .build();

        org = Organization.builder()
                .id(UUID.randomUUID())
                .name("Aegis Security")
                .slug("aegis-sec")
                .build();

        project = Project.builder()
                .id(UUID.randomUUID())
                .organization(org)
                .name("AEGIS Core")
                .description("Core Backend")
                .ecosystem("MAVEN")
                .status(ProjectStatus.ACTIVE)
                .createdBy(user)
                .build();
    }

    @Test
    void createProject_ShouldCreateProject_WhenUserIsMember() {
        CreateProjectRequest request = CreateProjectRequest.builder()
                .name("AEGIS Core")
                .description("Core Backend")
                .ecosystem("MAVEN")
                .build();

        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());
        when(organizationRepository.findById(org.getId())).thenReturn(Optional.of(org));
        when(projectRepository.save(any(Project.class))).thenReturn(project);

        ProjectResponse response = projectService.createProject(user, org.getId(), request);

        assertNotNull(response);
        assertEquals("AEGIS Core", response.getName());
        assertEquals(org.getId(), response.getOrgId());
        assertEquals(ProjectStatus.ACTIVE, response.getStatus());
        verify(projectRepository, times(1)).save(any(Project.class));
    }

    @Test
    void createProject_ShouldThrowAccessDenied_WhenUserIsNotMember() {
        CreateProjectRequest request = CreateProjectRequest.builder()
                .name("AEGIS Core")
                .build();

        doThrow(new AccessDeniedException("User is not a member"))
                .when(organizationService).verifyMembership(org.getId(), user.getId());

        assertThrows(AccessDeniedException.class, () -> projectService.createProject(user, org.getId(), request));
        verify(projectRepository, never()).save(any());
    }

    @Test
    void archiveProject_ShouldSetStatusToArchived_WithoutDeletingData() {
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        when(projectRepository.save(any(Project.class))).thenAnswer(i -> i.getArgument(0));

        ProjectResponse response = projectService.archiveProject(user, project.getId());

        assertNotNull(response);
        assertEquals(ProjectStatus.ARCHIVED, response.getStatus());
        verify(projectRepository, times(1)).save(argThat(p -> p.getStatus() == ProjectStatus.ARCHIVED));
    }
}
