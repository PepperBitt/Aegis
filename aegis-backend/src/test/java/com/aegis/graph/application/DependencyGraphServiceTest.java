package com.aegis.graph.application;

import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.graph.api.dto.ComponentNodeResponse;
import com.aegis.sbom.domain.SbomComponent;
import com.aegis.sbom.domain.SbomDependency;
import com.aegis.sbom.domain.SbomDocument;
import com.aegis.sbom.infrastructure.SbomComponentRepository;
import com.aegis.sbom.infrastructure.SbomDependencyRepository;
import com.aegis.sbom.infrastructure.SbomDocumentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.neo4j.core.Neo4jClient;
import org.springframework.security.access.AccessDeniedException;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DependencyGraphServiceTest {

    @Mock
    private SbomDocumentRepository sbomDocumentRepository;

    @Mock
    private SbomComponentRepository sbomComponentRepository;

    @Mock
    private SbomDependencyRepository sbomDependencyRepository;

    @Mock
    private ProjectRepository projectRepository;

    @Mock
    private OrganizationService organizationService;

    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private Neo4jClient neo4jClient;

    @InjectMocks
    private DependencyGraphService dependencyGraphService;

    private User user;
    private Organization org;
    private Project project;
    private SbomDocument sbom;
    private SbomComponent compA;
    private SbomComponent compB;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("analyst@aegis.local")
                .role(Role.ANALYST)
                .build();

        org = Organization.builder()
                .id(UUID.randomUUID())
                .name("Test Org")
                .build();

        project = Project.builder()
                .id(UUID.randomUUID())
                .organization(org)
                .name("Graph Test Project")
                .ecosystem("MAVEN")
                .build();

        sbom = SbomDocument.builder()
                .id(UUID.randomUUID())
                .project(project)
                .build();

        compA = SbomComponent.builder()
                .id(UUID.randomUUID())
                .sbom(sbom)
                .name("spring-core")
                .version("6.1.0")
                .build();

        compB = SbomComponent.builder()
                .id(UUID.randomUUID())
                .sbom(sbom)
                .name("commons-logging")
                .version("1.2")
                .build();
    }

    @Test
    void syncSbomToGraph_ShouldRunNeo4jClientMergeQueries() {
        when(sbomDocumentRepository.findById(sbom.getId())).thenReturn(Optional.of(sbom));
        when(sbomComponentRepository.findBySbomId(sbom.getId())).thenReturn(List.of(compA, compB));
        when(sbomDependencyRepository.findBySbomId(sbom.getId())).thenReturn(List.of(
                SbomDependency.builder().parentComponent(compA).childComponent(compB).build()
        ));

        dependencyGraphService.syncSbomToGraph(sbom.getId());

        verify(neo4jClient, atLeast(2)).query(anyString());
    }

    @Test
    void syncSbomToGraph_ShouldNotThrow_WhenNeo4jFails() {
        when(sbomDocumentRepository.findById(sbom.getId())).thenReturn(Optional.of(sbom));
        when(sbomComponentRepository.findBySbomId(sbom.getId())).thenReturn(List.of(compA));

        when(neo4jClient.query(anyString())).thenThrow(new RuntimeException("Neo4j connection refused"));

        assertDoesNotThrow(() -> dependencyGraphService.syncSbomToGraph(sbom.getId()));
    }

    @Test
    void getDirectDependencies_ShouldReturnEmptyList_WhenNeo4jQueryFails() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());
        when(neo4jClient.query(anyString())).thenThrow(new RuntimeException("mapping failed"));

        List<ComponentNodeResponse> responses = dependencyGraphService.getDirectDependencies(user, project.getId(), compA.getId());

        assertNotNull(responses);
        assertTrue(responses.isEmpty());
    }

    @Test
    void getDirectDependencies_ShouldThrowAccessDenied_WhenUserIsNotMember() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doThrow(new AccessDeniedException("Forbidden")).when(organizationService).verifyMembership(org.getId(), user.getId());

        assertThrows(AccessDeniedException.class, () ->
                dependencyGraphService.getDirectDependencies(user, project.getId(), compA.getId()));
    }
}
