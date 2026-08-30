package com.aegis.audit.api;

import com.aegis.audit.api.dto.AuditLogResponse;
import com.aegis.audit.api.dto.AuditSearchRequest;
import com.aegis.audit.application.AuditService;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
@Tag(name = "Audit", description = "Search and review security audit logs")
public class AuditController {

    private final AuditService auditService;
    private final UserRepository userRepository;

    @GetMapping
    @Operation(summary = "Search audit logs", description = "Filter by project, organization, action. Platform ADMIN can search all.")
    public ResponseEntity<Page<AuditLogResponse>> search(
            @RequestParam(required = false) UUID projectId,
            @RequestParam(required = false) UUID organizationId,
            @RequestParam(required = false) UUID userId,
            @RequestParam(required = false) String action,
            @RequestParam(required = false) String resourceType,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        AuditSearchRequest filters = AuditSearchRequest.builder()
                .projectId(projectId)
                .organizationId(organizationId)
                .userId(userId)
                .action(action)
                .resourceType(resourceType)
                .page(page)
                .size(size)
                .build();
        return ResponseEntity.ok(auditService.search(user, filters));
    }

    private User getAuthenticatedUser(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("User is not authenticated");
        }
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalArgumentException("Authenticated user not found"));
    }
}
