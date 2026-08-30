package com.aegis.sbom.api;

import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.sbom.api.dto.SbomComponentResponse;
import com.aegis.sbom.api.dto.SbomDependencyResponse;
import com.aegis.sbom.api.dto.SbomDocumentResponse;
import com.aegis.sbom.application.SbomService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/projects/{projectId}/sboms")
@RequiredArgsConstructor
@Tag(name = "SBOM Ingestion", description = "Endpoints for uploading, parsing, and retrieving Software Bill of Materials (SBOMs)")
public class SbomController {

    private final SbomService sbomService;
    private final UserRepository userRepository;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload and parse SBOM", description = "Uploads a CycloneDX JSON or SPDX JSON file for a project. Validates project membership.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "SBOM successfully ingested"),
            @ApiResponse(responseCode = "400", description = "Invalid file format or malformed content"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization")
    })
    public ResponseEntity<SbomDocumentResponse> uploadSbom(
            @PathVariable UUID projectId,
            @RequestParam("file") MultipartFile file,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        SbomDocumentResponse response = sbomService.uploadSbom(user, projectId, file);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    @Operation(summary = "List project SBOMs", description = "Returns all uploaded SBOM documents for a project.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization")
    })
    public ResponseEntity<List<SbomDocumentResponse>> listProjectSboms(
            @PathVariable UUID projectId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(sbomService.getProjectSboms(user, projectId));
    }

    @GetMapping("/{sbomId}")
    @Operation(summary = "Get SBOM details", description = "Returns metadata and status for a specific SBOM document.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization"),
            @ApiResponse(responseCode = "404", description = "SBOM document not found")
    })
    public ResponseEntity<SbomDocumentResponse> getSbomDetails(
            @PathVariable UUID projectId,
            @PathVariable UUID sbomId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(sbomService.getSbomDetails(user, projectId, sbomId));
    }

    @GetMapping("/{sbomId}/components")
    @Operation(summary = "Get SBOM components", description = "Returns all components parsed from an SBOM document.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization"),
            @ApiResponse(responseCode = "404", description = "SBOM document not found")
    })
    public ResponseEntity<List<SbomComponentResponse>> getSbomComponents(
            @PathVariable UUID projectId,
            @PathVariable UUID sbomId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(sbomService.getSbomComponents(user, projectId, sbomId));
    }

    @GetMapping("/{sbomId}/dependencies")
    @Operation(summary = "Get SBOM dependency graph", description = "Returns all parent-child component dependency relationships parsed from an SBOM document.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization"),
            @ApiResponse(responseCode = "404", description = "SBOM document not found")
    })
    public ResponseEntity<List<SbomDependencyResponse>> getSbomDependencies(
            @PathVariable UUID projectId,
            @PathVariable UUID sbomId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(sbomService.getSbomDependencies(user, projectId, sbomId));
    }

    private User getAuthenticatedUser(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User is not authenticated");
        }
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Authenticated user not found"));
    }
}
