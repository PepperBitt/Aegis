package com.aegis.alert.api;

import com.aegis.alert.api.dto.AcknowledgeAlertRequest;
import com.aegis.alert.api.dto.AlertResponse;
import com.aegis.alert.application.AlertService;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
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
@RequestMapping("/api/v1/projects/{projectId}/alerts")
@RequiredArgsConstructor
@Tag(name = "Alerts", description = "Endpoints for viewing and acknowledging project security alerts")
public class AlertController {

    private final AlertService alertService;
    private final UserRepository userRepository;

    @GetMapping
    @Operation(summary = "List alerts", description = "Returns all alerts for a project, newest first.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<List<AlertResponse>> listAlerts(
            @PathVariable UUID projectId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(alertService.listAlerts(user, projectId));
    }

    @GetMapping("/unread")
    @Operation(summary = "List unread alerts", description = "Returns unacknowledged alerts for a project.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Successful operation"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<List<AlertResponse>> listUnread(
            @PathVariable UUID projectId,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(alertService.listUnread(user, projectId));
    }

    @PostMapping("/{alertId}/acknowledge")
    @Operation(summary = "Acknowledge alert", description = "Marks an alert as acknowledged by the current user.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Alert acknowledged"),
            @ApiResponse(responseCode = "403", description = "Forbidden")
    })
    public ResponseEntity<AlertResponse> acknowledge(
            @PathVariable UUID projectId,
            @PathVariable UUID alertId,
            @RequestBody(required = false) AcknowledgeAlertRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(alertService.acknowledge(user, projectId, alertId));
    }

    private User getAuthenticatedUser(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User is not authenticated");
        }
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Authenticated user not found"));
    }
}
