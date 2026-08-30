package com.aegis.auth.infrastructure.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Authentication produced by X-API-Key validation. Carries normalized scopes for enforcement.
 */
public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

    private final UserDetails principal;
    private final Set<String> scopes;

    public ApiKeyAuthenticationToken(UserDetails principal, Collection<? extends GrantedAuthority> authorities, Set<String> scopes) {
        super(authorities);
        this.principal = principal;
        this.scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        setAuthenticated(true);
    }

    public static Set<String> parseScopes(String scopesCsv) {
        if (scopesCsv == null || scopesCsv.isBlank()) {
            return Set.of("read");
        }
        return Stream.of(scopesCsv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }

    public Set<String> getScopes() {
        return Collections.unmodifiableSet(scopes);
    }

    public boolean hasScope(String scope) {
        return scopes.contains(scope.toLowerCase(Locale.ROOT)) || scopes.contains("admin");
    }

    public boolean hasAnyScope(String... candidates) {
        for (String candidate : candidates) {
            if (hasScope(candidate)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
