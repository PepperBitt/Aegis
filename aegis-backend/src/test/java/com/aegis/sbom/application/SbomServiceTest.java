package com.aegis.sbom.application;

import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.sbom.api.dto.SbomDocumentResponse;
import com.aegis.sbom.domain.SbomDocument;
import com.aegis.sbom.domain.SbomFormat;
import com.aegis.sbom.domain.SbomStatus;
import com.aegis.sbom.domain.event.SbomUploadedEvent;
import com.aegis.sbom.infrastructure.SbomComponentRepository;
import com.aegis.sbom.infrastructure.SbomDependencyRepository;
import com.aegis.sbom.infrastructure.SbomDocumentRepository;
import com.aegis.sbom.infrastructure.parser.ParsedComponent;
import com.aegis.sbom.infrastructure.parser.ParsedSbom;
import com.aegis.sbom.infrastructure.parser.SbomParsingService;
import com.aegis.shared.infrastructure.storage.StorageService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.access.AccessDeniedException;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SbomServiceTest {

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

    @Mock
    private SbomParsingService sbomParsingService;

    @Mock
    private StorageService storageService;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @InjectMocks
    private SbomService sbomService;

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
                .build();

        project = Project.builder()
                .id(UUID.randomUUID())
                .organization(org)
                .name("AEGIS Backend")
                .build();
    }

    @Test
    void uploadSbom_ShouldParseSaveStoreAndPublishEvent_WhenRequestIsValid() throws Exception {
        byte[] content = "{\"bomFormat\":\"CycloneDX\"}".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "sbom.json", "application/json", content);

        ParsedComponent component = ParsedComponent.builder()
                .refId("ref-1")
                .name("spring-core")
                .version("6.1.0")
                .build();

        ParsedSbom parsedSbom = ParsedSbom.builder()
                .format(SbomFormat.CYCLONEDX)
                .name("sample-app")
                .version("1.0.0")
                .specVersion("1.4")
                .components(List.of(component))
                .build();

        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());
        when(sbomParsingService.parse(any())).thenReturn(parsedSbom);
        when(storageService.storeSbomFile(any(), any())).thenReturn("sboms/test-file.json");

        when(sbomDocumentRepository.save(any(SbomDocument.class))).thenAnswer(invocation -> {
            SbomDocument doc = invocation.getArgument(0);
            doc.setId(UUID.randomUUID());
            return doc;
        });

        when(sbomComponentRepository.saveAll(any())).thenAnswer(invocation -> invocation.getArgument(0));

        SbomDocumentResponse response = sbomService.uploadSbom(user, project.getId(), file);

        assertNotNull(response);
        assertEquals(SbomFormat.CYCLONEDX, response.getFormat());
        assertEquals(SbomStatus.COMPLETED, response.getStatus());
        assertEquals(1, response.getComponentCount());

        verify(storageService, times(1)).storeSbomFile(any(), eq("sbom.json"));
        verify(eventPublisher, times(1)).publishEvent(any(SbomUploadedEvent.class));
    }

    @Test
    void uploadSbom_ShouldThrowAccessDenied_WhenUserIsNotMemberOfProjectOrg() {
        MockMultipartFile file = new MockMultipartFile("file", "sbom.json", "application/json", "{}".getBytes());

        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doThrow(new AccessDeniedException("User is not a member"))
                .when(organizationService).verifyMembership(org.getId(), user.getId());

        assertThrows(AccessDeniedException.class, () -> sbomService.uploadSbom(user, project.getId(), file));
        verify(sbomDocumentRepository, never()).save(any());
    }

    @Test
    void uploadSbom_ShouldThrowException_WhenFileIsEmpty() {
        MockMultipartFile file = new MockMultipartFile("file", "sbom.json", "application/json", new byte[0]);

        assertThrows(IllegalArgumentException.class, () -> sbomService.uploadSbom(user, project.getId(), file));
    }

    @Test
    void uploadSbom_ShouldFailWithoutPersisting_WhenStorageFails() {
        byte[] content = "{\"bomFormat\":\"CycloneDX\"}".getBytes();
        MockMultipartFile file = new MockMultipartFile("file", "sbom.json", "application/json", content);

        ParsedSbom parsedSbom = ParsedSbom.builder()
                .format(SbomFormat.CYCLONEDX)
                .name("sample-app")
                .version("1.0.0")
                .components(List.of())
                .build();

        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());
        when(sbomParsingService.parse(any())).thenReturn(parsedSbom);
        when(storageService.storeSbomFile(any(), any()))
                .thenThrow(new com.aegis.shared.exception.StorageException("MinIO down"));

        assertThrows(com.aegis.shared.exception.StorageException.class,
                () -> sbomService.uploadSbom(user, project.getId(), file));

        verify(sbomDocumentRepository, never()).save(any());
        verify(eventPublisher, never()).publishEvent(any());
    }
}
