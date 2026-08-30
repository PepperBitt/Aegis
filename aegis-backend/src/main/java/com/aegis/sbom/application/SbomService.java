package com.aegis.sbom.application;

import com.aegis.audit.annotation.AuditAction;
import com.aegis.auth.domain.User;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.sbom.api.dto.SbomComponentResponse;
import com.aegis.sbom.api.dto.SbomDependencyResponse;
import com.aegis.sbom.api.dto.SbomDocumentResponse;
import com.aegis.sbom.domain.SbomComponent;
import com.aegis.sbom.domain.SbomDependency;
import com.aegis.sbom.domain.SbomDocument;
import com.aegis.sbom.domain.SbomStatus;
import com.aegis.sbom.domain.event.SbomUploadedEvent;
import com.aegis.sbom.infrastructure.SbomComponentRepository;
import com.aegis.sbom.infrastructure.SbomDependencyRepository;
import com.aegis.sbom.infrastructure.SbomDocumentRepository;
import com.aegis.sbom.infrastructure.parser.ParsedComponent;
import com.aegis.sbom.infrastructure.parser.ParsedDependency;
import com.aegis.sbom.infrastructure.parser.ParsedSbom;
import com.aegis.sbom.infrastructure.parser.SbomParsingService;
import com.aegis.shared.infrastructure.storage.StorageService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@org.springframework.transaction.annotation.Transactional(transactionManager = "transactionManager")
public class SbomService {

    private final SbomDocumentRepository sbomDocumentRepository;
    private final SbomComponentRepository sbomComponentRepository;
    private final SbomDependencyRepository sbomDependencyRepository;
    private final ProjectRepository projectRepository;
    private final OrganizationService organizationService;
    private final SbomParsingService sbomParsingService;
    private final StorageService storageService;
    private final ApplicationEventPublisher eventPublisher;

    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

    @Transactional
    @AuditAction(action = "SBOM_UPLOAD", resourceType = "SBOM")
    public SbomDocumentResponse uploadSbom(User user, UUID projectId, MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Uploaded file is empty");
        }
        if (file.getSize() > MAX_FILE_SIZE) {
            throw new IllegalArgumentException("File size exceeds maximum limit of 10MB");
        }

        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());

        byte[] contentBytes;
        try {
            contentBytes = file.getBytes();
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not read uploaded file content", e);
        }

        ParsedSbom parsedSbom = sbomParsingService.parse(contentBytes);
        String storagePath = storageService.storeSbomFile(contentBytes, file.getOriginalFilename());

        SbomDocument document = SbomDocument.builder()
                .project(project)
                .name(parsedSbom.getName())
                .version(parsedSbom.getVersion())
                .format(parsedSbom.getFormat())
                .specVersion(parsedSbom.getSpecVersion())
                .serialNumber(parsedSbom.getSerialNumber())
                .supplier(parsedSbom.getSupplier())
                .status(SbomStatus.COMPLETED)
                .componentCount(parsedSbom.getComponents().size())
                .filePath(storagePath)
                .fileSizeBytes(file.getSize())
                .createdBy(user)
                .build();

        SbomDocument savedDocument = sbomDocumentRepository.save(document);

        // Save components
        Map<String, SbomComponent> refToComponentMap = new HashMap<>();
        List<SbomComponent> componentEntities = new ArrayList<>();

        for (ParsedComponent pc : parsedSbom.getComponents()) {
            SbomComponent comp = SbomComponent.builder()
                    .sbom(savedDocument)
                    .name(pc.getName())
                    .version(pc.getVersion())
                    .purl(pc.getPurl())
                    .cpe(pc.getCpe())
                    .componentType(pc.getComponentType())
                    .groupName(pc.getGroupName())
                    .supplier(pc.getSupplier())
                    .licenseExpression(pc.getLicenseExpression())
                    .hashSha256(pc.getHashSha256())
                    .hashSha1(pc.getHashSha1())
                    .hashMd5(pc.getHashMd5())
                    .description(pc.getDescription())
                    .build();

            componentEntities.add(comp);
        }

        List<SbomComponent> savedComponents = sbomComponentRepository.saveAll(componentEntities);

        for (int i = 0; i < parsedSbom.getComponents().size(); i++) {
            ParsedComponent pc = parsedSbom.getComponents().get(i);
            SbomComponent savedComp = savedComponents.get(i);
            if (pc.getRefId() != null) {
                refToComponentMap.put(pc.getRefId(), savedComp);
            }
            refToComponentMap.put(savedComp.getName(), savedComp);
        }

        // Save dependencies
        List<SbomDependency> dependencyEntities = new ArrayList<>();
        Set<String> processedPairs = new HashSet<>();

        for (ParsedDependency pd : parsedSbom.getDependencies()) {
            SbomComponent parent = refToComponentMap.get(pd.getParentRef());
            SbomComponent child = refToComponentMap.get(pd.getChildRef());

            if (parent != null && child != null && !parent.getId().equals(child.getId())) {
                String pairKey = parent.getId() + ":" + child.getId();
                if (!processedPairs.contains(pairKey)) {
                    processedPairs.add(pairKey);
                    dependencyEntities.add(SbomDependency.builder()
                            .sbom(savedDocument)
                            .parentComponent(parent)
                            .childComponent(child)
                            .build());
                }
            }
        }

        if (!dependencyEntities.isEmpty()) {
            sbomDependencyRepository.saveAll(dependencyEntities);
        }

        // Publish event
        eventPublisher.publishEvent(new SbomUploadedEvent(
                this,
                savedDocument.getId(),
                project.getId(),
                savedDocument.getFormat(),
                savedDocument.getComponentCount(),
                savedDocument.getCreatedAt(),
                user.getId()
        ));

        return mapToDocumentResponse(savedDocument);
    }

    @Transactional(readOnly = true)
    public List<SbomDocumentResponse> getProjectSboms(User user, UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());

        return sbomDocumentRepository.findByProjectId(projectId)
                .stream()
                .map(this::mapToDocumentResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public SbomDocumentResponse getSbomDetails(User user, UUID projectId, UUID sbomId) {
        SbomDocument document = sbomDocumentRepository.findByIdAndProjectId(sbomId, projectId)
                .orElseThrow(() -> new IllegalArgumentException("SBOM document not found"));
        organizationService.verifyMembership(document.getProject().getOrganization().getId(), user.getId());

        return mapToDocumentResponse(document);
    }

    @Transactional(readOnly = true)
    public List<SbomComponentResponse> getSbomComponents(User user, UUID projectId, UUID sbomId) {
        SbomDocument document = sbomDocumentRepository.findByIdAndProjectId(sbomId, projectId)
                .orElseThrow(() -> new IllegalArgumentException("SBOM document not found"));
        organizationService.verifyMembership(document.getProject().getOrganization().getId(), user.getId());

        return sbomComponentRepository.findBySbomId(sbomId)
                .stream()
                .map(this::mapToComponentResponse)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<SbomDependencyResponse> getSbomDependencies(User user, UUID projectId, UUID sbomId) {
        SbomDocument document = sbomDocumentRepository.findByIdAndProjectId(sbomId, projectId)
                .orElseThrow(() -> new IllegalArgumentException("SBOM document not found"));
        organizationService.verifyMembership(document.getProject().getOrganization().getId(), user.getId());

        return sbomDependencyRepository.findBySbomId(sbomId)
                .stream()
                .map(this::mapToDependencyResponse)
                .collect(Collectors.toList());
    }

    private SbomDocumentResponse mapToDocumentResponse(SbomDocument doc) {
        return SbomDocumentResponse.builder()
                .id(doc.getId())
                .projectId(doc.getProject().getId())
                .name(doc.getName())
                .version(doc.getVersion())
                .format(doc.getFormat())
                .specVersion(doc.getSpecVersion())
                .serialNumber(doc.getSerialNumber())
                .supplier(doc.getSupplier())
                .status(doc.getStatus())
                .componentCount(doc.getComponentCount())
                .filePath(doc.getFilePath())
                .fileSizeBytes(doc.getFileSizeBytes())
                .createdById(doc.getCreatedBy() != null ? doc.getCreatedBy().getId() : null)
                .createdAt(doc.getCreatedAt())
                .updatedAt(doc.getUpdatedAt())
                .build();
    }

    private SbomComponentResponse mapToComponentResponse(SbomComponent c) {
        return SbomComponentResponse.builder()
                .id(c.getId())
                .sbomId(c.getSbom().getId())
                .name(c.getName())
                .version(c.getVersion())
                .purl(c.getPurl())
                .cpe(c.getCpe())
                .componentType(c.getComponentType())
                .groupName(c.getGroupName())
                .supplier(c.getSupplier())
                .licenseExpression(c.getLicenseExpression())
                .hashSha256(c.getHashSha256())
                .hashSha1(c.getHashSha1())
                .hashMd5(c.getHashMd5())
                .description(c.getDescription())
                .createdAt(c.getCreatedAt())
                .build();
    }

    private SbomDependencyResponse mapToDependencyResponse(SbomDependency d) {
        return SbomDependencyResponse.builder()
                .id(d.getId())
                .sbomId(d.getSbom().getId())
                .parentComponentId(d.getParentComponent().getId())
                .parentComponentName(d.getParentComponent().getName())
                .childComponentId(d.getChildComponent().getId())
                .childComponentName(d.getChildComponent().getName())
                .build();
    }
}
