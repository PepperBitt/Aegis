package com.aegis.gate.api;

import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.gate.api.dto.GateCheckRequest;
import com.aegis.gate.api.dto.GateCheckResponse;
import com.aegis.gate.application.GateService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@Tag(name = "Gatekeeper", description = "Endpoints for CI/CD gate checks against security policies")
public class GateController {

    private final GateService gateService;
    private final UserRepository userRepository;

    @PostMapping("/api/v1/gates/check")
    @Operation(summary = "Run gate check", description = "Evaluates project policies and records a PASS/FAIL gate check.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Gate check completed"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<GateCheckResponse> checkGate(
            @Valid @RequestBody GateCheckRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(gateService.checkGate(user, request));
    }

    @GetMapping("/api/v1/projects/{projectId}/gates")
    @Operation(summary = "List gate checks", description = "Returns gate check history for a project.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<List<GateCheckResponse>> listGateChecks(
            @PathVariable UUID projectId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(gateService.listGateChecks(user, projectId));
    }

    @GetMapping("/api/v1/projects/{projectId}/gates/{gateId}")
    @Operation(summary = "Get gate check", description = "Returns a specific gate check for a project.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<GateCheckResponse> getGateCheck(
            @PathVariable UUID projectId,
            @PathVariable UUID gateId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(gateService.getGateCheck(user, projectId, gateId));
    }

    private User getAuthenticatedUser(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User is not authenticated");
        }
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Authenticated user not found"));
    }
}
