package com.aegis.policy.api;

import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.policy.api.dto.*;
import com.aegis.policy.application.PolicyService;
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
@Tag(name = "Policy Engine", description = "Endpoints for managing and evaluating security policies")
public class PolicyController {

    private final PolicyService policyService;
    private final UserRepository userRepository;

    @PostMapping("/api/v1/organizations/{orgId}/policies")
    @Operation(summary = "Create organization policy", description = "Creates an organization-scoped security policy.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Policy created"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<PolicyResponse> createOrganizationPolicy(
            @PathVariable UUID orgId,
            @Valid @RequestBody CreatePolicyRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(policyService.createOrganizationPolicy(user, orgId, request));
    }

    @PostMapping("/api/v1/projects/{projectId}/policies")
    @Operation(summary = "Create project policy", description = "Creates a project-scoped security policy.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Policy created"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<PolicyResponse> createProjectPolicy(
            @PathVariable UUID projectId,
            @Valid @RequestBody CreatePolicyRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(policyService.createProjectPolicy(user, projectId, request));
    }

    @GetMapping("/api/v1/projects/{projectId}/policies")
    @Operation(summary = "List project policies", description = "Lists project and organization-scoped policies for a project.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<List<PolicyResponse>> listPolicies(
            @PathVariable UUID projectId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(policyService.listPoliciesForProject(user, projectId));
    }

    @GetMapping("/api/v1/projects/{projectId}/policies/evaluate")
    @Operation(summary = "Evaluate project policies", description = "Evaluates all enabled policies for a project.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Evaluation completed"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<ProjectPolicyEvaluationResponse> evaluatePoliciesGet(
            @PathVariable UUID projectId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(policyService.evaluateProjectPolicies(user, projectId));
    }

    @PostMapping("/api/v1/projects/{projectId}/policies/evaluate")
    @Operation(summary = "Evaluate project policies", description = "Evaluates all enabled policies for a project.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Evaluation completed"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<ProjectPolicyEvaluationResponse> evaluatePoliciesPost(
            @PathVariable UUID projectId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(policyService.evaluateProjectPolicies(user, projectId));
    }

    @PutMapping("/api/v1/policies/{policyId}")
    @Operation(summary = "Update policy", description = "Updates an existing security policy.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Policy updated"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<PolicyResponse> updatePolicy(
            @PathVariable UUID policyId,
            @Valid @RequestBody UpdatePolicyRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(policyService.updatePolicy(user, policyId, request));
    }

    @DeleteMapping("/api/v1/policies/{policyId}")
    @Operation(summary = "Disable policy", description = "Disables (soft-deletes) a security policy.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Policy disabled"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<Void> deletePolicy(
            @PathVariable UUID policyId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        policyService.deletePolicy(user, policyId);
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
