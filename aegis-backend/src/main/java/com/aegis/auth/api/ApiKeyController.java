package com.aegis.auth.api;

import com.aegis.auth.api.dto.ApiKeyResponse;
import com.aegis.auth.api.dto.CreateApiKeyRequest;
import com.aegis.auth.api.dto.CreateApiKeyResponse;
import com.aegis.auth.application.ApiKeyService;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
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
@RequestMapping("/api/v1/api-keys")
@RequiredArgsConstructor
@Tag(name = "API Key Management", description = "Endpoints for generating, listing, and revoking API keys for automated clients")
public class ApiKeyController {

    private final ApiKeyService apiKeyService;
    private final UserRepository userRepository;

    @PostMapping
    @Operation(summary = "Create an API key", description = "Generates a new API key for the authenticated user. Raw key is returned only once.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "API key created successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<CreateApiKeyResponse> createApiKey(
            @Valid @RequestBody CreateApiKeyRequest request,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        CreateApiKeyResponse response = apiKeyService.createApiKey(user, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    @Operation(summary = "List API keys", description = "Returns all API keys associated with the authenticated user.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "API keys retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    public ResponseEntity<List<ApiKeyResponse>> listApiKeys(
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        return ResponseEntity.ok(apiKeyService.getUserApiKeys(user));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Revoke API key", description = "Revokes an existing API key by ID.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "API key revoked successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "API key not found")
    })
    public ResponseEntity<Void> revokeApiKey(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        apiKeyService.revokeApiKey(user, id);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/revoke")
    @Operation(summary = "Revoke API key (POST)", description = "Revokes an existing API key by ID.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "API key revoked successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "404", description = "API key not found")
    })
    public ResponseEntity<Void> revokeApiKeyPost(
            @PathVariable UUID id,
            @AuthenticationPrincipal UserDetails userDetails
    ) {
        User user = getAuthenticatedUser(userDetails);
        apiKeyService.revokeApiKey(user, id);
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
