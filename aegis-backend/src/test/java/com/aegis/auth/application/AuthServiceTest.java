package com.aegis.auth.application;

import com.aegis.auth.api.dto.LoginRequest;
import com.aegis.auth.api.dto.RefreshRequest;
import com.aegis.auth.api.dto.RegisterRequest;
import com.aegis.auth.api.dto.TokenResponse;
import com.aegis.auth.api.dto.UserResponse;
import com.aegis.auth.domain.RefreshToken;
import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.RefreshTokenRepository;
import com.aegis.auth.infrastructure.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private LoginRateLimiter loginRateLimiter;

    @InjectMocks
    private AuthService authService;

    private User user;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("test@aegis.local")
                .passwordHash("hashed_password")
                .fullName("Test User")
                .role(Role.DEVELOPER)
                .isActive(true)
                .build();
    }

    @Test
    void register_ShouldSaveUser_WhenEmailDoesNotExist() {
        RegisterRequest request = RegisterRequest.builder()
                .email("test@aegis.local")
                .password("password123")
                .fullName("Test User")
                .build();

        when(userRepository.existsByEmail(request.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(request.getPassword())).thenReturn("hashed_password");
        when(userRepository.save(any(User.class))).thenReturn(user);

        UserResponse response = authService.register(request);

        assertNotNull(response);
        assertEquals(user.getEmail(), response.getEmail());
        assertEquals(user.getFullName(), response.getFullName());
        assertEquals(Role.DEVELOPER, response.getRole());
        verify(userRepository, times(1)).save(any(User.class));
    }

    @Test
    void register_ShouldThrowException_WhenEmailExists() {
        RegisterRequest request = RegisterRequest.builder()
                .email("test@aegis.local")
                .password("password123")
                .fullName("Test User")
                .build();

        when(userRepository.existsByEmail(request.getEmail())).thenReturn(true);

        assertThrows(IllegalArgumentException.class, () -> authService.register(request));
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void login_ShouldReturnTokens_WhenCredentialsAreValid() {
        LoginRequest request = LoginRequest.builder()
                .email("test@aegis.local")
                .password("password123")
                .build();

        when(userRepository.findByEmail(request.getEmail())).thenReturn(Optional.of(user));
        when(jwtService.generateToken(user)).thenReturn("jwt_access_token");
        when(jwtService.getExpirationTime()).thenReturn(3600000L);

        TokenResponse response = authService.login(request);

        assertNotNull(response);
        assertEquals("jwt_access_token", response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertEquals("Bearer", response.getTokenType());
        verify(loginRateLimiter, times(1)).checkAndIncrement("127.0.0.1", "test@aegis.local");
        verify(authenticationManager, times(1)).authenticate(any(UsernamePasswordAuthenticationToken.class));
        verify(refreshTokenRepository, times(1)).save(any());
    }

    @Test
    void refreshToken_ShouldRotateTokens_WhenTokenIsValid() {
        String rawToken = "valid-raw-refresh-token";
        String tokenHash = authService.hashToken(rawToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(Instant.now().plus(1, ChronoUnit.DAYS))
                .revoked(false)
                .build();

        RefreshRequest request = RefreshRequest.builder()
                .refreshToken(rawToken)
                .build();

        when(refreshTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(refreshToken));
        when(jwtService.generateToken(user)).thenReturn("new_jwt_access_token");
        when(jwtService.getExpirationTime()).thenReturn(3600000L);

        TokenResponse response = authService.refreshToken(request);

        assertNotNull(response);
        assertEquals("new_jwt_access_token", response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertNotEquals(rawToken, response.getRefreshToken());
        assertTrue(refreshToken.isRevoked());
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
    }

    @Test
    void refreshToken_ShouldRevokeAllUserTokens_WhenRevokedTokenIsReused() {
        String rawToken = "stolen-revoked-token";
        String tokenHash = authService.hashToken(rawToken);

        RefreshToken revokedToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(Instant.now().plus(1, ChronoUnit.DAYS))
                .revoked(true)
                .build();

        RefreshRequest request = RefreshRequest.builder()
                .refreshToken(rawToken)
                .build();

        when(refreshTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(revokedToken));
        when(refreshTokenRepository.findByUserIdAndRevokedFalse(user.getId())).thenReturn(Collections.emptyList());

        assertThrows(IllegalArgumentException.class, () -> authService.refreshToken(request));
        verify(refreshTokenRepository, times(1)).findByUserIdAndRevokedFalse(user.getId());
    }

    @Test
    void refreshToken_ShouldThrowException_WhenTokenIsExpired() {
        String rawToken = "expired-token";
        String tokenHash = authService.hashToken(rawToken);

        RefreshToken expiredToken = RefreshToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(Instant.now().minus(1, ChronoUnit.DAYS))
                .revoked(false)
                .build();

        RefreshRequest request = RefreshRequest.builder()
                .refreshToken(rawToken)
                .build();

        when(refreshTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(expiredToken));

        assertThrows(IllegalArgumentException.class, () -> authService.refreshToken(request));
    }
}
