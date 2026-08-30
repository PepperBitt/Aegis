package com.aegis.risk.api;

import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.risk.api.dto.RiskHistoryResponse;
import com.aegis.risk.api.dto.RiskResponse;
import com.aegis.risk.application.RiskService;
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
@RequestMapping("/api/v1/projects/{projectId}/risk")
@RequiredArgsConstructor
@Tag(name = "Risk Engine", description = "Endpoints for calculating, querying, and tracking project security risk scores and grades")
public class RiskController {

    private final RiskService riskService;
    private final UserRepository userRepository;

    @GetMapping
    @Operation(summary = "Get current project risk", description = "Returns the latest calculated risk score (0-100), A-F grade, and severity breakdown for a project.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization")
    })
    public ResponseEntity<RiskResponse> getProjectRisk(
            @PathVariable UUID projectId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(riskService.getProjectRisk(user, projectId));
    }

    @GetMapping("/history")
    @Operation(summary = "Get project risk history", description = "Returns historical risk calculation snapshots for a project in reverse chronological order.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization")
    })
    public ResponseEntity<List<RiskHistoryResponse>> getRiskHistory(
            @PathVariable UUID projectId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(riskService.getRiskHistory(user, projectId));
    }

    @PostMapping("/recalculate")
    @Operation(summary = "Recalculate project risk", description = "Triggers an on-demand recalculation of the project risk score and creates a new historical snapshot.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Risk recalculated successfully"),
            @ApiResponse(responseCode = "403", description = "Forbidden - Not a member of the project's organization")
    })
    public ResponseEntity<RiskResponse> recalculateProjectRisk(
            @PathVariable UUID projectId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(riskService.recalculateProjectRisk(user, projectId));
    }

    private User getAuthenticatedUser(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User is not authenticated");
        }
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Authenticated user not found"));
    }
}
