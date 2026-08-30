package com.aegis.graph.api;

import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.graph.api.dto.ComponentNodeResponse;
import com.aegis.graph.api.dto.DependencyPathResponse;
import com.aegis.graph.application.DependencyGraphService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/projects/{projectId}/components/{componentId}")
@RequiredArgsConstructor
@Tag(name = "Dependency Graph", description = "Endpoints for analyzing direct and transitive component dependencies and shortest paths using Neo4j")
public class DependencyGraphController {

    private final DependencyGraphService dependencyGraphService;
    private final UserRepository userRepository;

    @GetMapping("/dependencies")
    @Operation(summary = "Get direct dependencies", description = "Returns components that the target component directly depends on.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization")
    })
    public ResponseEntity<List<ComponentNodeResponse>> getDirectDependencies(
            @PathVariable UUID projectId,
            @PathVariable UUID componentId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(dependencyGraphService.getDirectDependencies(user, projectId, componentId));
    }

    @GetMapping("/dependents")
    @Operation(summary = "Get direct dependents", description = "Returns components that directly depend on the target component.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization")
    })
    public ResponseEntity<List<ComponentNodeResponse>> getDirectDependents(
            @PathVariable UUID projectId,
            @PathVariable UUID componentId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(dependencyGraphService.getDirectDependents(user, projectId, componentId));
    }

    @GetMapping("/dependencies/transitive")
    @Operation(summary = "Get transitive dependencies", description = "Returns all components reachable downstream via DEPENDS_ON relationships.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization")
    })
    public ResponseEntity<List<ComponentNodeResponse>> getTransitiveDependencies(
            @PathVariable UUID projectId,
            @PathVariable UUID componentId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(dependencyGraphService.getTransitiveDependencies(user, projectId, componentId));
    }

    @GetMapping("/dependents/transitive")
    @Operation(summary = "Get transitive dependents", description = "Returns all components that eventually depend on the target component upstream.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization")
    })
    public ResponseEntity<List<ComponentNodeResponse>> getTransitiveDependents(
            @PathVariable UUID projectId,
            @PathVariable UUID componentId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(dependencyGraphService.getTransitiveDependents(user, projectId, componentId));
    }

    @GetMapping("/dependency-path/{targetComponentId}")
    @Operation(summary = "Get shortest dependency path", description = "Finds the shortest dependency path from source component to target component within the project graph.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization")
    })
    public ResponseEntity<DependencyPathResponse> getDependencyPath(
            @PathVariable UUID projectId,
            @PathVariable UUID componentId,
            @PathVariable UUID targetComponentId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(dependencyGraphService.getDependencyPath(user, projectId, componentId, targetComponentId));
    }

    private User getAuthenticatedUser(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User is not authenticated");
        }
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Authenticated user not found"));
    }
}
