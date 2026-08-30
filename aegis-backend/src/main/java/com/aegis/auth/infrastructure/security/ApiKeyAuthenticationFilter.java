package com.aegis.auth.infrastructure.security;

import com.aegis.auth.application.ApiKeyService;
import com.aegis.auth.domain.ApiKey;
import com.aegis.auth.domain.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    private final ApiKeyService apiKeyService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        String apiKeyHeader = request.getHeader("X-API-Key");
        if (apiKeyHeader == null || apiKeyHeader.isBlank()) {
            apiKeyHeader = request.getHeader("X-Api-Key");
        }

        if (apiKeyHeader != null && !apiKeyHeader.isBlank()
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            Optional<ApiKey> apiKeyOpt = apiKeyService.validateApiKey(apiKeyHeader);
            if (apiKeyOpt.isPresent()) {
                ApiKey apiKey = apiKeyOpt.get();
                User user = apiKey.getUser();
                Set<String> scopes = ApiKeyAuthenticationToken.parseScopes(apiKey.getScopes());

                List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
                for (String scope : scopes) {
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope.toUpperCase(Locale.ROOT)));
                }

                UserDetails userDetails = new org.springframework.security.core.userdetails.User(
                        user.getEmail(),
                        "",
                        user.isActive(),
                        true,
                        true,
                        true,
                        authorities
                );

                ApiKeyAuthenticationToken authToken = new ApiKeyAuthenticationToken(
                        userDetails,
                        authorities,
                        scopes
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);

                apiKeyService.touchApiKey(apiKey);
            }
        }

        filterChain.doFilter(request, response);
    }
}
