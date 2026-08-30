package com.aegis.auth.application;

import com.aegis.shared.exception.RateLimitExceededException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginRateLimiter {

    private final StringRedisTemplate redisTemplate;

    @Value("${aegis.rate-limit.login.max-attempts:5}")
    private int maxAttempts;

    @Value("${aegis.rate-limit.login.window-seconds:60}")
    private long windowSeconds;

    @Value("${aegis.rate-limit.login.enabled:true}")
    private boolean enabled;

    public void checkAndIncrement(String clientIp, String email) {
        if (!enabled) {
            return;
        }

        try {
            String normalizedEmail = (email != null) ? email.trim().toLowerCase() : "";
            String rawIdentity = (clientIp != null ? clientIp : "unknown") + ":" + normalizedEmail;
            String identityHash = hashIdentity(rawIdentity);
            String key = "rate_limit:login:" + identityHash;

            Long attempts = redisTemplate.opsForValue().increment(key);
            if (attempts != null && attempts == 1) {
                redisTemplate.expire(key, Duration.ofSeconds(windowSeconds));
            }

            if (attempts != null && attempts > maxAttempts) {
                log.warn("Rate limit exceeded for login attempts from hashed identity: {}", identityHash);
                throw new RateLimitExceededException("Too many login attempts. Please try again later.");
            }
        } catch (RateLimitExceededException e) {
            throw e;
        } catch (Exception e) {
            // In case Redis is down or unavailable in test environments, log error and allow operation
            log.warn("Redis rate limiter unavailable: {}", e.getMessage());
        }
    }

    private String hashIdentity(String rawIdentity) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawIdentity.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm unavailable", e);
        }
    }
}
