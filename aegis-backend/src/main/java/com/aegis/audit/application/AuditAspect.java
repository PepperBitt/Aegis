package com.aegis.audit.application;

import com.aegis.audit.annotation.AuditAction;
import com.aegis.audit.domain.AuditResult;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.project.api.dto.CreateProjectRequest;
import com.aegis.project.api.dto.OrgResponse;
import com.aegis.project.api.dto.ProjectResponse;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.sbom.api.dto.SbomDocumentResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.multipart.MultipartFile;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.*;

@Aspect
@Component
@RequiredArgsConstructor
@Slf4j
public class AuditAspect {

    private static final Set<String> SENSITIVE_KEYS = Set.of(
            "password", "passwordhash", "token", "accesstoken", "refreshtoken",
            "apikey", "rawapikey", "secret", "authorization", "credential", "credentials"
    );

    private final AuditService auditService;
    private final UserRepository userRepository;
    private final ProjectRepository projectRepository;
    private final ObjectMapper objectMapper;

    @Around("@annotation(auditAction)")
    public Object audit(ProceedingJoinPoint joinPoint, AuditAction auditAction) throws Throwable {
        User user = resolveUser(joinPoint.getArgs());
        String ip = resolveClientIp();
        UUID projectId = extractProjectId(joinPoint);
        UUID organizationId = extractOrganizationId(joinPoint, projectId);
        String resourceId = null;
        String metadataJson = buildSafeMetadata(joinPoint);

        try {
            Object result = joinPoint.proceed();
            resourceId = extractResourceId(result, joinPoint);
            if (projectId == null) {
                projectId = extractProjectIdFromResult(result);
            }
            if (organizationId == null) {
                organizationId = extractOrganizationIdFromResult(result, projectId);
            }
            auditService.log(
                    user != null ? user.getId() : null,
                    organizationId,
                    projectId,
                    auditAction.action(),
                    blankToNull(auditAction.resourceType()),
                    resourceId,
                    AuditResult.SUCCESS,
                    ip,
                    metadataJson
            );
            return result;
        } catch (Throwable ex) {
            try {
                auditService.log(
                        user != null ? user.getId() : null,
                        organizationId,
                        projectId,
                        auditAction.action(),
                        blankToNull(auditAction.resourceType()),
                        resourceId,
                        AuditResult.FAILURE,
                        ip,
                        appendError(metadataJson, ex)
                );
            } catch (Exception auditEx) {
                log.warn("Failed to write FAILURE audit log for {}: {}", auditAction.action(), auditEx.getMessage());
            }
            throw ex;
        }
    }

    private User resolveUser(Object[] args) {
        if (args != null) {
            for (Object arg : args) {
                if (arg instanceof User user) {
                    return user;
                }
            }
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            return null;
        }
        Object principal = auth.getPrincipal();
        String email = null;
        if (principal instanceof UserDetails details) {
            email = details.getUsername();
        } else if (principal instanceof String s) {
            email = s;
        }
        if (email == null || email.isBlank()) {
            return null;
        }
        return userRepository.findByEmail(email).orElse(null);
    }

    private String resolveClientIp() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return null;
            }
            HttpServletRequest request = attrs.getRequest();
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                return forwarded.split(",")[0].trim();
            }
            return request.getRemoteAddr();
        } catch (Exception e) {
            return null;
        }
    }

    private UUID extractProjectId(ProceedingJoinPoint joinPoint) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Parameter[] parameters = signature.getMethod().getParameters();
        Object[] args = joinPoint.getArgs();
        for (int i = 0; i < parameters.length; i++) {
            String name = parameters[i].getName().toLowerCase(Locale.ROOT);
            Object arg = args[i];
            if (arg instanceof UUID uuid && name.contains("project") && !name.contains("org")) {
                return uuid;
            }
        }
        return null;
    }

    private UUID extractOrganizationId(ProceedingJoinPoint joinPoint, UUID projectId) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Parameter[] parameters = signature.getMethod().getParameters();
        Object[] args = joinPoint.getArgs();
        for (int i = 0; i < parameters.length; i++) {
            String name = parameters[i].getName().toLowerCase(Locale.ROOT);
            Object arg = args[i];
            if (arg instanceof UUID uuid && (name.contains("org"))) {
                return uuid;
            }
        }
        if (projectId != null) {
            return projectRepository.findById(projectId)
                    .map(p -> p.getOrganization().getId())
                    .orElse(null);
        }
        return null;
    }

    private UUID extractProjectIdFromResult(Object result) {
        if (result instanceof ProjectResponse pr) {
            return pr.getId();
        }
        if (result instanceof SbomDocumentResponse sbom) {
            return sbom.getProjectId();
        }
        return null;
    }

    private UUID extractOrganizationIdFromResult(Object result, UUID projectId) {
        if (result instanceof OrgResponse org) {
            return org.getId();
        }
        if (result instanceof ProjectResponse pr) {
            return pr.getOrgId();
        }
        if (projectId != null) {
            return projectRepository.findById(projectId)
                    .map(Project::getOrganization)
                    .map(o -> o.getId())
                    .orElse(null);
        }
        return null;
    }

    private String extractResourceId(Object result, ProceedingJoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        if (result instanceof ProjectResponse pr) {
            return pr.getId() != null ? pr.getId().toString() : null;
        }
        if (result instanceof OrgResponse org) {
            return org.getId() != null ? org.getId().toString() : null;
        }
        if (result instanceof SbomDocumentResponse sbom) {
            return sbom.getId() != null ? sbom.getId().toString() : null;
        }
        if (result != null) {
            try {
                Method getId = result.getClass().getMethod("getId");
                Object id = getId.invoke(result);
                if (id != null) {
                    return id.toString();
                }
            } catch (Exception ignored) {
                // no-op
            }
            try {
                Method getCvId = result.getClass().getMethod("getComponentVulnerabilityId");
                Object id = getCvId.invoke(result);
                if (id != null) {
                    return id.toString();
                }
            } catch (Exception ignored) {
                // no-op
            }
        }
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Parameter[] parameters = signature.getMethod().getParameters();
        for (int i = 0; i < parameters.length; i++) {
            String name = parameters[i].getName().toLowerCase(Locale.ROOT);
            Object arg = args[i];
            if (arg instanceof UUID uuid && (name.contains("key") || name.contains("componentvulnerability")
                    || name.contains("apikey"))) {
                return uuid.toString();
            }
        }
        return null;
    }

    private String buildSafeMetadata(ProceedingJoinPoint joinPoint) {
        try {
            MethodSignature signature = (MethodSignature) joinPoint.getSignature();
            Parameter[] parameters = signature.getMethod().getParameters();
            Object[] args = joinPoint.getArgs();
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("method", signature.getDeclaringType().getSimpleName() + "." + signature.getName());

            for (int i = 0; i < parameters.length; i++) {
                String name = parameters[i].getName();
                if (isSensitiveName(name)) {
                    continue;
                }
                Object arg = args[i];
                if (arg == null || arg instanceof User || arg instanceof MultipartFile) {
                    if (arg instanceof MultipartFile file) {
                        meta.put(name + "Name", file.getOriginalFilename());
                        meta.put(name + "Size", file.getSize());
                    }
                    continue;
                }
                if (arg instanceof CreateProjectRequest req) {
                    Map<String, Object> safe = new LinkedHashMap<>();
                    safe.put("name", req.getName());
                    safe.put("ecosystem", req.getEcosystem());
                    meta.put(name, safe);
                    continue;
                }
                if (isDtoOrPrimitiveSafe(arg)) {
                    Object sanitized = sanitizeValue(arg);
                    if (sanitized != null) {
                        meta.put(name, sanitized);
                    }
                } else if (arg instanceof UUID || arg instanceof String || arg instanceof Number || arg instanceof Boolean) {
                    meta.put(name, arg);
                }
            }
            return objectMapper.writeValueAsString(meta);
        } catch (Exception e) {
            return "{\"note\":\"metadata unavailable\"}";
        }
    }

    private boolean isDtoOrPrimitiveSafe(Object arg) {
        String cn = arg.getClass().getName();
        return cn.startsWith("com.aegis.") && !cn.contains("Password") && !(arg instanceof User);
    }

    private Object sanitizeValue(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String || value instanceof Number || value instanceof Boolean || value instanceof UUID
                || value instanceof Enum<?>) {
            return value;
        }
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> asMap = objectMapper.convertValue(value, Map.class);
            Map<String, Object> cleaned = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : asMap.entrySet()) {
                if (isSensitiveName(e.getKey())) {
                    continue;
                }
                Object v = e.getValue();
                if (v instanceof String || v instanceof Number || v instanceof Boolean || v == null) {
                    cleaned.put(e.getKey(), v);
                } else if (v instanceof Enum<?> || v instanceof UUID) {
                    cleaned.put(e.getKey(), v.toString());
                }
            }
            return cleaned;
        } catch (Exception e) {
            return value.getClass().getSimpleName();
        }
    }

    private boolean isSensitiveName(String name) {
        if (name == null) {
            return true;
        }
        String normalized = name.toLowerCase(Locale.ROOT).replace("_", "");
        return SENSITIVE_KEYS.stream().anyMatch(normalized::contains);
    }

    private String appendError(String metadataJson, Throwable ex) {
        try {
            Map<String, Object> map;
            if (metadataJson != null && !metadataJson.isBlank()) {
                @SuppressWarnings("unchecked")
                Map<String, Object> parsed = objectMapper.readValue(metadataJson, Map.class);
                map = new LinkedHashMap<>(parsed);
            } else {
                map = new LinkedHashMap<>();
            }
            map.put("error", ex.getClass().getSimpleName());
            map.put("errorMessage", ex.getMessage());
            return objectMapper.writeValueAsString(map);
        } catch (Exception e) {
            return metadataJson;
        }
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
