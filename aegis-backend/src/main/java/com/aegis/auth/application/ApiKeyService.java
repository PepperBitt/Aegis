package com.aegis.auth.application;

import com.aegis.audit.annotation.AuditAction;
import com.aegis.auth.api.dto.ApiKeyResponse;
import com.aegis.auth.api.dto.CreateApiKeyRequest;
import com.aegis.auth.api.dto.CreateApiKeyResponse;
import com.aegis.auth.domain.ApiKey;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.ApiKeyRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ApiKeyService {

    private final ApiKeyRepository apiKeyRepository;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String KEY_PREFIX_CONSTANT = "aegis_key_";

    @Transactional
    @AuditAction(action = "API_KEY_CREATE", resourceType = "API_KEY")
    public CreateApiKeyResponse createApiKey(User user, CreateApiKeyRequest request) {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String randomHex = HexFormat.of().formatHex(randomBytes);
        String rawApiKey = KEY_PREFIX_CONSTANT + randomHex;
        String keyPrefix = rawApiKey.substring(0, Math.min(rawApiKey.length(), 14));
        String keyHash = hashKey(rawApiKey);

        String normalizedScopes = normalizeScopes(request.getScopes());

        ApiKey apiKey = ApiKey.builder()
                .user(user)
                .name(request.getName())
                .keyHash(keyHash)
                .keyPrefix(keyPrefix)
                .scopes(normalizedScopes)
                .expiresAt(request.getExpiresAt())
                .revoked(false)
                .build();

        ApiKey saved = apiKeyRepository.save(apiKey);

        return CreateApiKeyResponse.builder()
                .id(saved.getId())
                .name(saved.getName())
                .rawApiKey(rawApiKey)
                .keyPrefix(saved.getKeyPrefix())
                .scopes(saved.getScopes())
                .expiresAt(saved.getExpiresAt())
                .createdAt(saved.getCreatedAt())
                .build();
    }

    @Transactional(readOnly = true)
    public List<ApiKeyResponse> getUserApiKeys(User user) {
        return apiKeyRepository.findByUserId(user.getId())
                .stream()
                .map(this::mapToApiKeyResponse)
                .collect(Collectors.toList());
    }

    @Transactional
    @AuditAction(action = "API_KEY_REVOKE", resourceType = "API_KEY")
    public void revokeApiKey(User user, UUID apiKeyId) {
        ApiKey apiKey = apiKeyRepository.findByIdAndUserId(apiKeyId, user.getId())
                .orElseThrow(() -> new IllegalArgumentException("API key not found"));
        apiKey.setRevoked(true);
        apiKeyRepository.save(apiKey);
    }

    @Transactional(readOnly = true)
    public Optional<ApiKey> validateApiKey(String rawApiKey) {
        if (rawApiKey == null || rawApiKey.isBlank()) {
            return Optional.empty();
        }
        String keyHash = hashKey(rawApiKey);
        Optional<ApiKey> apiKeyOpt = apiKeyRepository.findByKeyHash(keyHash);
        if (apiKeyOpt.isEmpty()) {
            return Optional.empty();
        }
        ApiKey apiKey = apiKeyOpt.get();
        if (apiKey.isRevoked()) {
            return Optional.empty();
        }
        if (apiKey.getExpiresAt() != null && apiKey.getExpiresAt().isBefore(Instant.now())) {
            return Optional.empty();
        }
        if (apiKey.getUser() == null || !apiKey.getUser().isActive()) {
            return Optional.empty();
        }
        return Optional.of(apiKey);
    }

    @Transactional
    public void touchApiKey(ApiKey apiKey) {
        apiKey.setLastUsedAt(Instant.now());
        apiKeyRepository.save(apiKey);
    }

    public String hashKey(String rawKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawKey.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm unavailable", e);
        }
    }

    /**
     * Allow only known scopes: read, write, gate, admin. Duplicates removed; default read.
     */
    String normalizeScopes(String rawScopes) {
        if (rawScopes == null || rawScopes.isBlank()) {
            return "read";
        }
        java.util.LinkedHashSet<String> allowed = new java.util.LinkedHashSet<>();
        for (String part : rawScopes.split(",")) {
            String scope = part.trim().toLowerCase(java.util.Locale.ROOT);
            if (scope.equals("read") || scope.equals("write") || scope.equals("gate") || scope.equals("admin")) {
                allowed.add(scope);
            }
        }
        if (allowed.isEmpty()) {
            throw new IllegalArgumentException("API key scopes must include at least one of: read, write, gate, admin");
        }
        return String.join(",", allowed);
    }

    private ApiKeyResponse mapToApiKeyResponse(ApiKey apiKey) {
        return ApiKeyResponse.builder()
                .id(apiKey.getId())
                .name(apiKey.getName())
                .keyPrefix(apiKey.getKeyPrefix())
                .scopes(apiKey.getScopes())
                .revoked(apiKey.isRevoked())
                .expiresAt(apiKey.getExpiresAt())
                .lastUsedAt(apiKey.getLastUsedAt())
                .createdAt(apiKey.getCreatedAt())
                .build();
    }
}
