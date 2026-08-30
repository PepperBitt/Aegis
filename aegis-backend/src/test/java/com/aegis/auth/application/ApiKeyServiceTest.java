package com.aegis.auth.application;

import com.aegis.auth.api.dto.ApiKeyResponse;
import com.aegis.auth.api.dto.CreateApiKeyRequest;
import com.aegis.auth.api.dto.CreateApiKeyResponse;
import com.aegis.auth.domain.ApiKey;
import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.ApiKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ApiKeyServiceTest {

    @Mock
    private ApiKeyRepository apiKeyRepository;

    @InjectMocks
    private ApiKeyService apiKeyService;

    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("ci@aegis.local")
                .fullName("CI Client")
                .role(Role.DEVELOPER)
                .isActive(true)
                .build();
    }

    @Test
    void createApiKey_ShouldReturnRawKey_AndStoreHashedKeyInRepository() {
        CreateApiKeyRequest request = CreateApiKeyRequest.builder()
                .name("GitHub CI")
                .scopes("read,write")
                .build();

        when(apiKeyRepository.save(any(ApiKey.class))).thenAnswer(invocation -> {
            ApiKey key = invocation.getArgument(0);
            key.setId(UUID.randomUUID());
            return key;
        });

        CreateApiKeyResponse response = apiKeyService.createApiKey(user, request);

        assertNotNull(response);
        assertNotNull(response.getRawApiKey());
        assertTrue(response.getRawApiKey().startsWith("aegis_key_"));
        assertEquals("GitHub CI", response.getName());

        verify(apiKeyRepository, times(1)).save(argThat(apiKey ->
                apiKey.getKeyHash() != null &&
                !apiKey.getKeyHash().equals(response.getRawApiKey()) &&
                apiKey.getKeyPrefix().equals(response.getRawApiKey().substring(0, 14))
        ));
    }

    @Test
    void validateApiKey_ShouldReturnApiKey_WhenKeyIsValidAndNotExpiredOrRevoked() {
        String rawKey = "aegis_key_1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        String keyHash = apiKeyService.hashKey(rawKey);

        ApiKey apiKey = ApiKey.builder()
                .id(UUID.randomUUID())
                .user(user)
                .name("Valid Key")
                .keyHash(keyHash)
                .keyPrefix("aegis_key_1234")
                .scopes("read")
                .revoked(false)
                .build();

        when(apiKeyRepository.findByKeyHash(keyHash)).thenReturn(Optional.of(apiKey));

        Optional<ApiKey> result = apiKeyService.validateApiKey(rawKey);

        assertTrue(result.isPresent());
        assertEquals("Valid Key", result.get().getName());
    }

    @Test
    void validateApiKey_ShouldReturnEmpty_WhenKeyIsRevoked() {
        String rawKey = "aegis_key_revokedkeyhash";
        String keyHash = apiKeyService.hashKey(rawKey);

        ApiKey apiKey = ApiKey.builder()
                .id(UUID.randomUUID())
                .user(user)
                .keyHash(keyHash)
                .revoked(true)
                .build();

        when(apiKeyRepository.findByKeyHash(keyHash)).thenReturn(Optional.of(apiKey));

        Optional<ApiKey> result = apiKeyService.validateApiKey(rawKey);

        assertFalse(result.isPresent());
    }

    @Test
    void validateApiKey_ShouldReturnEmpty_WhenKeyIsExpired() {
        String rawKey = "aegis_key_expiredkeyhash";
        String keyHash = apiKeyService.hashKey(rawKey);

        ApiKey apiKey = ApiKey.builder()
                .id(UUID.randomUUID())
                .user(user)
                .keyHash(keyHash)
                .expiresAt(Instant.now().minus(1, ChronoUnit.DAYS))
                .revoked(false)
                .build();

        when(apiKeyRepository.findByKeyHash(keyHash)).thenReturn(Optional.of(apiKey));

        Optional<ApiKey> result = apiKeyService.validateApiKey(rawKey);

        assertFalse(result.isPresent());
    }

    @Test
    void revokeApiKey_ShouldSetRevokedFlagToTrue() {
        UUID keyId = UUID.randomUUID();
        ApiKey apiKey = ApiKey.builder()
                .id(keyId)
                .user(user)
                .revoked(false)
                .build();

        when(apiKeyRepository.findByIdAndUserId(keyId, user.getId())).thenReturn(Optional.of(apiKey));

        apiKeyService.revokeApiKey(user, keyId);

        assertTrue(apiKey.isRevoked());
        verify(apiKeyRepository, times(1)).save(apiKey);
    }

    @Test
    void getUserApiKeys_ShouldReturnListOfApiKeyResponses() {
        ApiKey apiKey = ApiKey.builder()
                .id(UUID.randomUUID())
                .user(user)
                .name("CI Key")
                .keyPrefix("aegis_key_1234")
                .scopes("read")
                .revoked(false)
                .build();

        when(apiKeyRepository.findByUserId(user.getId())).thenReturn(List.of(apiKey));

        List<ApiKeyResponse> keys = apiKeyService.getUserApiKeys(user);

        assertEquals(1, keys.size());
        assertEquals("CI Key", keys.get(0).getName());
    }

    @Test
    void normalizeScopes_ShouldWhitelistKnownScopes_AndRejectUnknownOnly() {
        assertEquals("read,write", apiKeyService.normalizeScopes(" read, WRITE ,bogus "));
        assertEquals("read", apiKeyService.normalizeScopes(null));
        assertThrows(IllegalArgumentException.class, () -> apiKeyService.normalizeScopes("superuser,root"));
    }

    @Test
    void createApiKey_ShouldPersistNormalizedScopesOnly() {
        when(apiKeyRepository.save(any(ApiKey.class))).thenAnswer(inv -> {
            ApiKey key = inv.getArgument(0);
            key.setId(UUID.randomUUID());
            key.setCreatedAt(Instant.now());
            return key;
        });

        CreateApiKeyRequest request = CreateApiKeyRequest.builder()
                .name("Scoped")
                .scopes("gate,admin,evil")
                .build();

        CreateApiKeyResponse response = apiKeyService.createApiKey(user, request);

        assertEquals("gate,admin", response.getScopes());
        assertTrue(response.getRawApiKey().startsWith("aegis_key_"));
        verify(apiKeyRepository).save(argThat(k -> "gate,admin".equals(k.getScopes())
                && k.getKeyHash() != null
                && !k.getKeyHash().contains(response.getRawApiKey())));
    }
}
