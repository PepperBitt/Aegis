package com.aegis.alert.application;

import com.aegis.alert.api.dto.AlertResponse;
import com.aegis.alert.domain.Alert;
import com.aegis.alert.domain.AlertSeverity;
import com.aegis.alert.domain.AlertType;
import com.aegis.alert.infrastructure.repository.AlertRepository;
import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.risk.domain.RiskGrade;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AlertServiceTest {

    @Mock
    private AlertRepository alertRepository;

    @Mock
    private ProjectRepository projectRepository;

    @Mock
    private OrganizationService organizationService;

    @InjectMocks
    private AlertService alertService;

    private User user;
    private Organization org;
    private Project project;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("admin@aegis.local")
                .role(Role.ADMIN)
                .build();

        org = Organization.builder()
                .id(UUID.randomUUID())
                .name("Alert Org")
                .build();

        project = Project.builder()
                .id(UUID.randomUUID())
                .organization(org)
                .name("Alert Project")
                .build();
    }

    @Test
    void createAlert_ShouldPersistAlert() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        when(alertRepository.save(any())).thenAnswer(inv -> {
            Alert alert = inv.getArgument(0);
            alert.setId(UUID.randomUUID());
            alert.setCreatedAt(Instant.now());
            return alert;
        });

        Alert alert = alertService.createAlert(
                project.getId(),
                AlertType.CRITICAL_VULNERABILITY,
                AlertSeverity.CRITICAL,
                "Critical found",
                "message",
                "{}"
        );

        assertNotNull(alert.getId());
        assertEquals(AlertType.CRITICAL_VULNERABILITY, alert.getAlertType());
        assertEquals(org, alert.getOrganization());
    }

    @Test
    void listUnread_ShouldReturnOnlyUnacknowledged() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());

        Alert unread = Alert.builder()
                .id(UUID.randomUUID())
                .project(project)
                .organization(org)
                .alertType(AlertType.GATE_FAILURE)
                .severity(AlertSeverity.HIGH)
                .title("Gate failed")
                .message("fail")
                .acknowledged(false)
                .createdAt(Instant.now())
                .build();

        when(alertRepository.findByProjectIdAndAcknowledgedFalse(project.getId()))
                .thenReturn(List.of(unread));

        List<AlertResponse> results = alertService.listUnread(user, project.getId());

        assertEquals(1, results.size());
        assertFalse(results.get(0).isAcknowledged());
    }

    @Test
    void acknowledge_ShouldMarkAlertAcknowledged() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doNothing().when(organizationService).verifyMembership(org.getId(), user.getId());

        Alert alert = Alert.builder()
                .id(UUID.randomUUID())
                .project(project)
                .organization(org)
                .alertType(AlertType.RISK_THRESHOLD)
                .severity(AlertSeverity.HIGH)
                .title("Risk high")
                .message("score >= 70")
                .acknowledged(false)
                .createdAt(Instant.now())
                .build();

        when(alertRepository.findByIdAndProjectId(alert.getId(), project.getId()))
                .thenReturn(Optional.of(alert));
        when(alertRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        AlertResponse response = alertService.acknowledge(user, project.getId(), alert.getId());

        assertTrue(response.isAcknowledged());
        assertEquals(user.getId(), response.getAcknowledgedBy());
        assertNotNull(response.getAcknowledgedAt());
    }

    @Test
    void createRiskThresholdAlert_ShouldCreateHighSeverityAlert() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        when(alertRepository.existsByProjectIdAndAlertTypeAndAcknowledgedFalse(
                project.getId(), AlertType.RISK_THRESHOLD)).thenReturn(false);
        when(alertRepository.save(any())).thenAnswer(inv -> {
            Alert alert = inv.getArgument(0);
            alert.setId(UUID.randomUUID());
            alert.setCreatedAt(Instant.now());
            return alert;
        });

        alertService.createRiskThresholdAlert(project.getId(), new BigDecimal("75.00"), RiskGrade.D);

        verify(alertRepository).save(argThat(a ->
                a.getAlertType() == AlertType.RISK_THRESHOLD
                        && a.getSeverity() == AlertSeverity.HIGH));
    }

    @Test
    void createCriticalVulnerabilityAlert_ShouldSkipWhenUnacknowledgedExists() {
        when(alertRepository.existsByProjectIdAndAlertTypeAndAcknowledgedFalse(
                project.getId(), AlertType.CRITICAL_VULNERABILITY)).thenReturn(true);

        alertService.createCriticalVulnerabilityAlert(project.getId(), 3);

        verify(alertRepository, never()).save(any());
    }

    @Test
    void createRiskThresholdAlert_ShouldSkipWhenUnacknowledgedExists() {
        when(alertRepository.existsByProjectIdAndAlertTypeAndAcknowledgedFalse(
                project.getId(), AlertType.RISK_THRESHOLD)).thenReturn(true);

        alertService.createRiskThresholdAlert(project.getId(), new BigDecimal("80"), RiskGrade.D);

        verify(alertRepository, never()).save(any());
    }

    @Test
    void listAlerts_ShouldThrowAccessDenied_WhenUserIsNotMember() {
        when(projectRepository.findById(project.getId())).thenReturn(Optional.of(project));
        doThrow(new AccessDeniedException("Forbidden"))
                .when(organizationService).verifyMembership(org.getId(), user.getId());

        assertThrows(AccessDeniedException.class, () -> alertService.listAlerts(user, project.getId()));
    }
}
