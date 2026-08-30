package com.aegis.project.api;

import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.project.api.dto.*;
import com.aegis.project.application.OrganizationService;
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
@RequestMapping("/api/v1/organizations")
@RequiredArgsConstructor
@Tag(name = "Organizations", description = "Endpoints for managing organizations and organization memberships")
public class OrganizationController {

    private final OrganizationService organizationService;
    private final UserRepository userRepository;

    @PostMapping
    @Operation(summary = "Create an organization", description = "Creates a new organization. The creator automatically becomes the OWNER.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Organization successfully created"),
            @ApiResponse(responseCode = "400", description = "Invalid request or duplicate slug"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<OrgResponse> createOrganization(
            @Valid @RequestBody CreateOrgRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        OrgResponse response = organizationService.createOrganization(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    @Operation(summary = "List user organizations", description = "Returns all organizations where the authenticated user is a member.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<List<OrgResponse>> listOrganizations(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(organizationService.getUserOrganizations(user));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get organization details", description = "Returns organization details if the user is a member.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member"),
            @ApiResponse(responseCode = "404", description = "Organization not found")
    })
    public ResponseEntity<OrgResponse> getOrganization(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(organizationService.getOrganizationById(user, id));
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update organization", description = "Updates organization details. Requires OWNER or ADMIN role in the org.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Organization updated successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Insufficient permissions")
    })
    public ResponseEntity<OrgResponse> updateOrganization(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateOrgRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(organizationService.updateOrganization(user, id, request));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete organization", description = "Deletes an organization. Requires OWNER role in the org.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Organization deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Requires OWNER role")
    })
    public ResponseEntity<Void> deleteOrganization(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        organizationService.deleteOrganization(user, id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{orgId}/members")
    @Operation(summary = "Add member to organization", description = "Adds a user to the organization. Requires OWNER or ADMIN role.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Member added successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid user or duplicate membership"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Insufficient permissions")
    })
    public ResponseEntity<MemberResponse> addMember(
            @PathVariable UUID orgId,
            @Valid @RequestBody AddMemberRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        MemberResponse response = organizationService.addMember(user, orgId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/{orgId}/members")
    @Operation(summary = "List organization members", description = "Returns all members of an organization.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member")
    })
    public ResponseEntity<List<MemberResponse>> listMembers(
            @PathVariable UUID orgId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(organizationService.getMembers(user, orgId));
    }

    @DeleteMapping("/{orgId}/members/{userId}")
    @Operation(summary = "Remove member from organization", description = "Removes a member from the organization.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Member removed successfully"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Insufficient permissions")
    })
    public ResponseEntity<Void> removeMember(
            @PathVariable UUID orgId,
            @PathVariable UUID userId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        organizationService.removeMember(user, orgId, userId);
        return ResponseEntity.noContent().build();
    }

    private User getAuthenticatedUser(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User is not authenticated");
        }
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Authenticated user not found"));
    }
}
