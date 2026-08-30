package com.aegis.audit.application;

import com.aegis.audit.annotation.AuditAction;
import com.aegis.audit.domain.AuditLog;
import com.aegis.audit.domain.AuditResult;
import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import com.aegis.project.api.dto.ProjectResponse;
import com.aegis.project.infrastructure.ProjectRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.lang.reflect.Method;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditAspectTest {

    @Mock
    private AuditService auditService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private ProjectRepository projectRepository;
    @Mock
    private ProceedingJoinPoint joinPoint;
    @Mock
    private MethodSignature methodSignature;

    private AuditAspect auditAspect;
    private User user;

    @BeforeEach
    void setUp() {
        auditAspect = new AuditAspect(auditService, userRepository, projectRepository, new ObjectMapper());
        user = User.builder()
                .id(UUID.randomUUID())
                .email("dev@aegis.local")
                .role(Role.DEVELOPER)
                .build();
        SecurityContextHolder.clearContext();
    }

    @Test
    void audit_ShouldLogSuccess() throws Throwable {
        Method method = SampleAuditedService.class.getMethod("createThing", User.class, String.class);
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(method);
        when(methodSignature.getDeclaringType()).thenReturn(SampleAuditedService.class);
        when(methodSignature.getName()).thenReturn("createThing");
        when(joinPoint.getArgs()).thenReturn(new Object[]{user, "demo"});

        ProjectResponse response = ProjectResponse.builder()
                .id(UUID.randomUUID())
                .orgId(UUID.randomUUID())
                .name("demo")
                .build();
        when(joinPoint.proceed()).thenReturn(response);
        when(auditService.log(any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(AuditLog.builder().id(UUID.randomUUID()).build());

        AuditAction annotation = method.getAnnotation(AuditAction.class);
        Object result = auditAspect.audit(joinPoint, annotation);

        assertSame(response, result);
        ArgumentCaptor<AuditResult> resultCaptor = ArgumentCaptor.forClass(AuditResult.class);
        ArgumentCaptor<String> metadataCaptor = ArgumentCaptor.forClass(String.class);
        verify(auditService).log(
                eq(user.getId()),
                eq(response.getOrgId()),
                eq(response.getId()),
                eq("THING_CREATE"),
                eq("THING"),
                eq(response.getId().toString()),
                resultCaptor.capture(),
                any(),
                metadataCaptor.capture()
        );
        assertEquals(AuditResult.SUCCESS, resultCaptor.getValue());
        assertFalse(metadataCaptor.getValue().toLowerCase().contains("password"));
    }

    @Test
    void audit_ShouldLogFailureAndRethrow() throws Throwable {
        Method method = SampleAuditedService.class.getMethod("createThing", User.class, String.class);
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(method);
        when(methodSignature.getDeclaringType()).thenReturn(SampleAuditedService.class);
        when(methodSignature.getName()).thenReturn("createThing");
        when(joinPoint.getArgs()).thenReturn(new Object[]{user, "demo"});
        when(joinPoint.proceed()).thenThrow(new IllegalArgumentException("boom"));
        when(auditService.log(any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(AuditLog.builder().id(UUID.randomUUID()).build());

        AuditAction annotation = method.getAnnotation(AuditAction.class);
        assertThrows(IllegalArgumentException.class, () -> auditAspect.audit(joinPoint, annotation));

        verify(auditService).log(
                eq(user.getId()),
                isNull(),
                isNull(),
                eq("THING_CREATE"),
                eq("THING"),
                isNull(),
                eq(AuditResult.FAILURE),
                any(),
                any()
        );
    }

    @Test
    void audit_ShouldNotIncludePasswordInMetadata_WhenLoginRequestPresent() throws Throwable {
        Method method = SampleAuditedService.class.getMethod("login", FakeLoginRequest.class);
        when(joinPoint.getSignature()).thenReturn(methodSignature);
        when(methodSignature.getMethod()).thenReturn(method);
        when(methodSignature.getDeclaringType()).thenReturn(SampleAuditedService.class);
        when(methodSignature.getName()).thenReturn("login");

        FakeLoginRequest req = new FakeLoginRequest();
        req.setEmail("dev@aegis.local");
        req.setPassword("super-secret");
        when(joinPoint.getArgs()).thenReturn(new Object[]{req});
        when(joinPoint.proceed()).thenReturn("ok");
        when(auditService.log(any(), any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(AuditLog.builder().id(UUID.randomUUID()).build());

        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(
                        org.springframework.security.core.userdetails.User
                                .withUsername(user.getEmail()).password("x").roles("USER").build(),
                        null,
                        List.of()
                )
        );
        when(userRepository.findByEmail(user.getEmail())).thenReturn(java.util.Optional.of(user));

        AuditAction annotation = method.getAnnotation(AuditAction.class);
        auditAspect.audit(joinPoint, annotation);

        ArgumentCaptor<String> metadataCaptor = ArgumentCaptor.forClass(String.class);
        verify(auditService).log(any(), any(), any(), any(), any(), any(), eq(AuditResult.SUCCESS), any(), metadataCaptor.capture());
        String metadata = metadataCaptor.getValue().toLowerCase();
        assertFalse(metadata.contains("super-secret"));
        assertFalse(metadata.contains("\"password\""));
    }

    static class SampleAuditedService {
        @AuditAction(action = "THING_CREATE", resourceType = "THING")
        public ProjectResponse createThing(User user, String name) {
            return null;
        }

        @AuditAction(action = "USER_LOGIN", resourceType = "USER")
        public String login(FakeLoginRequest request) {
            return "ok";
        }
    }

    static class FakeLoginRequest {
        private String email;
        private String password;

        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}
