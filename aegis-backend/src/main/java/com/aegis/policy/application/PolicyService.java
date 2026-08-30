package com.aegis.policy.application;

import com.aegis.audit.annotation.AuditAction;
import com.aegis.auth.domain.User;
import com.aegis.policy.api.dto.*;
import com.aegis.policy.domain.PolicyEvaluationResult;
import com.aegis.policy.domain.PolicyType;
import com.aegis.policy.domain.SecurityPolicy;
import com.aegis.policy.infrastructure.repository.PolicyEvaluationResultRepository;
import com.aegis.policy.infrastructure.repository.SecurityPolicyRepository;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Organization;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.OrganizationRepository;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.sbom.domain.SbomComponent;
import com.aegis.sbom.infrastructure.SbomComponentRepository;
import com.aegis.vulnerability.domain.ComponentVulnerability;
import com.aegis.vulnerability.domain.Severity;
import com.aegis.vulnerability.infrastructure.repository.ComponentVulnerabilityRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@org.springframework.transaction.annotation.Transactional(transactionManager = "transactionManager")
public class PolicyService {

    private static final String DEFAULT_CVSS_CONFIG = "{\"maxCvss\":9.0}";
    private static final String DEFAULT_LICENSE_CONFIG =
            "{\"allowed\":[\"MIT\",\"Apache-2.0\",\"BSD-2-Clause\",\"BSD-3-Clause\",\"ISC\",\"MPL-2.0\"]}";

    private final SecurityPolicyRepository securityPolicyRepository;
    private final PolicyEvaluationResultRepository evaluationResultRepository;
    private final ComponentVulnerabilityRepository componentVulnerabilityRepository;
    private final SbomComponentRepository sbomComponentRepository;
    private final ProjectRepository projectRepository;
    private final OrganizationRepository organizationRepository;
    private final OrganizationService organizationService;
    private final ObjectMapper objectMapper;

    @Transactional
    @AuditAction(action = "POLICY_CREATE", resourceType = "POLICY")
    public PolicyResponse createOrganizationPolicy(User user, UUID orgId, CreatePolicyRequest request) {
        organizationService.verifyMembership(orgId, user.getId());
        Organization org = organizationRepository.findById(orgId)
                .orElseThrow(() -> new IllegalArgumentException("Organization not found"));

        SecurityPolicy policy = SecurityPolicy.builder()
                .organization(org)
                .project(null)
                .name(request.getName())
                .description(request.getDescription())
                .policyType(request.getPolicyType())
                .enabled(request.getEnabled() == null || request.getEnabled())
                .configJson(normalizeConfig(request.getConfigJson()))
                .build();

        return mapToPolicyResponse(securityPolicyRepository.save(policy));
    }

    @Transactional
    @AuditAction(action = "POLICY_CREATE", resourceType = "POLICY")
    public PolicyResponse createProjectPolicy(User user, UUID projectId, CreatePolicyRequest request) {
        Project project = requireProject(projectId);
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());

        SecurityPolicy policy = SecurityPolicy.builder()
                .organization(project.getOrganization())
                .project(project)
                .name(request.getName())
                .description(request.getDescription())
                .policyType(request.getPolicyType())
                .enabled(request.getEnabled() == null || request.getEnabled())
                .configJson(normalizeConfig(request.getConfigJson()))
                .build();

        return mapToPolicyResponse(securityPolicyRepository.save(policy));
    }

    @Transactional
    @AuditAction(action = "POLICY_UPDATE", resourceType = "POLICY")
    public PolicyResponse updatePolicy(User user, UUID policyId, UpdatePolicyRequest request) {
        SecurityPolicy policy = securityPolicyRepository.findById(policyId)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found"));
        verifyPolicyAccess(user, policy);

        if (request.getName() != null) {
            policy.setName(request.getName());
        }
        if (request.getDescription() != null) {
            policy.setDescription(request.getDescription());
        }
        if (request.getPolicyType() != null) {
            policy.setPolicyType(request.getPolicyType());
        }
        if (request.getConfigJson() != null) {
            policy.setConfigJson(normalizeConfig(request.getConfigJson()));
        }
        if (request.getEnabled() != null) {
            policy.setEnabled(request.getEnabled());
        }

        return mapToPolicyResponse(securityPolicyRepository.save(policy));
    }

    @Transactional(readOnly = true)
    public List<PolicyResponse> listPoliciesForProject(User user, UUID projectId) {
        Project project = requireProject(projectId);
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());

        List<SecurityPolicy> projectPolicies = securityPolicyRepository.findByProjectId(projectId);
        List<SecurityPolicy> orgPolicies = securityPolicyRepository.findByOrganizationId(project.getOrganization().getId())
                .stream()
                .filter(p -> p.getProject() == null)
                .toList();

        Map<UUID, SecurityPolicy> merged = new LinkedHashMap<>();
        for (SecurityPolicy p : orgPolicies) {
            merged.put(p.getId(), p);
        }
        for (SecurityPolicy p : projectPolicies) {
            merged.put(p.getId(), p);
        }

        return merged.values().stream().map(this::mapToPolicyResponse).collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public PolicyResponse getPolicy(User user, UUID policyId) {
        SecurityPolicy policy = securityPolicyRepository.findById(policyId)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found"));
        verifyPolicyAccess(user, policy);
        return mapToPolicyResponse(policy);
    }

    @Transactional
    @AuditAction(action = "POLICY_DISABLE", resourceType = "POLICY")
    public void deletePolicy(User user, UUID policyId) {
        SecurityPolicy policy = securityPolicyRepository.findById(policyId)
                .orElseThrow(() -> new IllegalArgumentException("Policy not found"));
        verifyPolicyAccess(user, policy);
        policy.setEnabled(false);
        securityPolicyRepository.save(policy);
    }

    @Transactional
    public ProjectPolicyEvaluationResponse evaluateProjectPolicies(User user, UUID projectId) {
        verifyProjectAccess(user, projectId);
        return evaluateProjectPolicies(projectId);
    }

    @Transactional
    public ProjectPolicyEvaluationResponse evaluateProjectPolicies(UUID projectId) {
        Project project = requireProject(projectId);
        UUID orgId = project.getOrganization().getId();

        List<SecurityPolicy> policies = securityPolicyRepository.findEnabledForProject(projectId, orgId);
        if (policies.isEmpty()) {
            policies = createDefaultPolicies(project);
        }

        List<ComponentVulnerability> findings = componentVulnerabilityRepository.findByProjectId(projectId);
        List<SbomComponent> components = sbomComponentRepository.findByProjectId(projectId);

        Instant now = Instant.now();
        List<PolicyEvaluationResponse> evaluations = new ArrayList<>();

        for (SecurityPolicy policy : policies) {
            EvaluationOutcome outcome = evaluatePolicy(policy, findings, components);

            PolicyEvaluationResult result = PolicyEvaluationResult.builder()
                    .project(project)
                    .policy(policy)
                    .passed(outcome.passed())
                    .failureReason(outcome.failureReason())
                    .evaluatedAt(now)
                    .build();
            evaluationResultRepository.save(result);

            evaluations.add(PolicyEvaluationResponse.builder()
                    .policyId(policy.getId())
                    .policyName(policy.getName())
                    .policyType(policy.getPolicyType())
                    .passed(outcome.passed())
                    .failureReason(outcome.failureReason())
                    .evaluatedAt(now)
                    .build());
        }

        boolean overallPassed = evaluations.stream().allMatch(PolicyEvaluationResponse::isPassed);

        return ProjectPolicyEvaluationResponse.builder()
                .projectId(projectId)
                .overallPassed(overallPassed)
                .evaluations(evaluations)
                .build();
    }

    private List<SecurityPolicy> createDefaultPolicies(Project project) {
        List<SecurityPolicy> defaults = List.of(
                SecurityPolicy.builder()
                        .project(project)
                        .organization(project.getOrganization())
                        .name("No Critical CVEs")
                        .description("Fail if any non-suppressed critical vulnerability is present")
                        .policyType(PolicyType.NO_CRITICAL_CVE)
                        .enabled(true)
                        .configJson("{}")
                        .build(),
                SecurityPolicy.builder()
                        .project(project)
                        .organization(project.getOrganization())
                        .name("CVSS Threshold")
                        .description("Fail if any non-suppressed finding exceeds max CVSS")
                        .policyType(PolicyType.CVSS_THRESHOLD)
                        .enabled(true)
                        .configJson(DEFAULT_CVSS_CONFIG)
                        .build(),
                SecurityPolicy.builder()
                        .project(project)
                        .organization(project.getOrganization())
                        .name("Allowed Licenses")
                        .description("Fail if a component license is outside the allowed set")
                        .policyType(PolicyType.ALLOWED_LICENSES)
                        .enabled(true)
                        .configJson(DEFAULT_LICENSE_CONFIG)
                        .build()
        );

        return securityPolicyRepository.saveAll(defaults);
    }

    private EvaluationOutcome evaluatePolicy(
            SecurityPolicy policy,
            List<ComponentVulnerability> findings,
            List<SbomComponent> components
    ) {
        return switch (policy.getPolicyType()) {
            case NO_CRITICAL_CVE -> evaluateNoCriticalCve(findings);
            case CVSS_THRESHOLD -> evaluateCvssThreshold(policy.getConfigJson(), findings);
            case ALLOWED_LICENSES -> evaluateAllowedLicenses(policy.getConfigJson(), components);
        };
    }

    private EvaluationOutcome evaluateNoCriticalCve(List<ComponentVulnerability> findings) {
        long criticalCount = findings.stream()
                .filter(cv -> !cv.isSuppressed())
                .filter(cv -> cv.getVulnerability() != null && cv.getVulnerability().getSeverity() == Severity.CRITICAL)
                .count();

        if (criticalCount > 0) {
            return EvaluationOutcome.fail(
                    "Found " + criticalCount + " non-suppressed CRITICAL vulnerability finding(s)");
        }
        return EvaluationOutcome.pass();
    }

    private EvaluationOutcome evaluateCvssThreshold(String configJson, List<ComponentVulnerability> findings) {
        BigDecimal maxCvss = parseMaxCvss(configJson);

        List<ComponentVulnerability> violations = findings.stream()
                .filter(cv -> !cv.isSuppressed())
                .filter(cv -> cv.getVulnerability() != null && cv.getVulnerability().getCvssScore() != null)
                .filter(cv -> cv.getVulnerability().getCvssScore().compareTo(maxCvss) > 0)
                .toList();

        if (!violations.isEmpty()) {
            return EvaluationOutcome.fail(
                    "Found " + violations.size() + " finding(s) with CVSS score above " + maxCvss);
        }
        return EvaluationOutcome.pass();
    }

    private EvaluationOutcome evaluateAllowedLicenses(String configJson, List<SbomComponent> components) {
        Set<String> allowed = parseAllowedLicenses(configJson);

        List<SbomComponent> violations = components.stream()
                .filter(c -> c.getLicenseExpression() != null && !c.getLicenseExpression().isBlank())
                .filter(c -> !isLicenseAllowed(c.getLicenseExpression(), allowed))
                .toList();

        if (!violations.isEmpty()) {
            String samples = violations.stream()
                    .limit(5)
                    .map(c -> c.getName() + " (" + c.getLicenseExpression() + ")")
                    .collect(Collectors.joining(", "));
            return EvaluationOutcome.fail(
                    "Found " + violations.size() + " component(s) with disallowed license(s): " + samples);
        }
        return EvaluationOutcome.pass();
    }

    private boolean isLicenseAllowed(String licenseExpression, Set<String> allowed) {
        String normalized = licenseExpression.trim().toLowerCase(Locale.ROOT);
        return allowed.contains(normalized);
    }

    private BigDecimal parseMaxCvss(String configJson) {
        try {
            JsonNode root = objectMapper.readTree(configJson == null || configJson.isBlank() ? "{}" : configJson);
            if (root.has("maxCvss") && !root.get("maxCvss").isNull()) {
                return root.get("maxCvss").decimalValue();
            }
        } catch (Exception e) {
            log.warn("Failed to parse CVSS threshold config: {}", e.getMessage());
        }
        return new BigDecimal("9.0");
    }

    private Set<String> parseAllowedLicenses(String configJson) {
        Set<String> allowed = new HashSet<>();
        try {
            JsonNode root = objectMapper.readTree(configJson == null || configJson.isBlank() ? "{}" : configJson);
            JsonNode arr = root.get("allowed");
            if (arr == null || !arr.isArray()) {
                arr = root.get("allowedLicenses");
            }
            if (arr != null && arr.isArray()) {
                for (JsonNode node : arr) {
                    if (node != null && !node.isNull()) {
                        allowed.add(node.asText().trim().toLowerCase(Locale.ROOT));
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse allowed licenses config: {}", e.getMessage());
        }
        return allowed;
    }

    private void verifyPolicyAccess(User user, SecurityPolicy policy) {
        if (policy.getProject() != null) {
            organizationService.verifyMembership(policy.getProject().getOrganization().getId(), user.getId());
            return;
        }
        if (policy.getOrganization() != null) {
            organizationService.verifyMembership(policy.getOrganization().getId(), user.getId());
            return;
        }
        throw new IllegalArgumentException("Policy has no organization or project scope");
    }

    private void verifyProjectAccess(User user, UUID projectId) {
        Project project = requireProject(projectId);
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());
    }

    private Project requireProject(UUID projectId) {
        return projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
    }

    private String normalizeConfig(String configJson) {
        if (configJson == null || configJson.isBlank()) {
            return "{}";
        }
        return configJson;
    }

    private PolicyResponse mapToPolicyResponse(SecurityPolicy policy) {
        return PolicyResponse.builder()
                .id(policy.getId())
                .organizationId(policy.getOrganization() != null ? policy.getOrganization().getId() : null)
                .projectId(policy.getProject() != null ? policy.getProject().getId() : null)
                .name(policy.getName())
                .description(policy.getDescription())
                .policyType(policy.getPolicyType())
                .enabled(policy.isEnabled())
                .configJson(policy.getConfigJson())
                .createdAt(policy.getCreatedAt())
                .updatedAt(policy.getUpdatedAt())
                .build();
    }

    private record EvaluationOutcome(boolean passed, String failureReason) {
        static EvaluationOutcome pass() {
            return new EvaluationOutcome(true, null);
        }

        static EvaluationOutcome fail(String reason) {
            return new EvaluationOutcome(false, reason);
        }
    }
}
