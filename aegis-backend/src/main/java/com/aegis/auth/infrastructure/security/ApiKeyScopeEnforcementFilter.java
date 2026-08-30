package com.aegis.auth.infrastructure.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Locale;
import java.util.Set;

/**
 * Enforces API-key scopes for /api/** requests authenticated via {@link ApiKeyAuthenticationToken}.
 * JWT/session users are unaffected.
 *
 * Scopes: read, write, gate, admin
 * - GET/HEAD/OPTIONS  → read | write | gate | admin
 * - POST /api/v1/gates/** → gate | write | admin
 * - other mutating methods → write | admin
 */
@Component
public class ApiKeyScopeEnforcementFilter extends OncePerRequestFilter {

    private static final Set<String> READ_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof ApiKeyAuthenticationToken apiKeyAuth)) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        if (!path.startsWith("/api/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String method = request.getMethod().toUpperCase(Locale.ROOT);
        boolean allowed;
        String required;

        if (path.startsWith("/api/v1/gates") && "POST".equals(method)) {
            required = "gate (or write/admin)";
            allowed = apiKeyAuth.hasAnyScope("gate", "write", "admin");
        } else if (READ_METHODS.contains(method)) {
            required = "read (or write/gate/admin)";
            allowed = apiKeyAuth.hasAnyScope("read", "write", "gate", "admin");
        } else {
            required = "write (or admin)";
            allowed = apiKeyAuth.hasAnyScope("write", "admin");
        }

        if (!allowed) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(
                    "{\"error\":\"Forbidden\",\"message\":\"API key lacks required scope: " + required + "\"}"
            );
            return;
        }

        filterChain.doFilter(request, response);
    }
}
