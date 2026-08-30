package com.aegis.dashboard.web;

import com.aegis.alert.api.dto.AlertResponse;
import com.aegis.alert.application.AlertService;
import com.aegis.audit.api.dto.AuditLogResponse;
import com.aegis.audit.api.dto.AuditSearchRequest;
import com.aegis.audit.application.AuditService;
import com.aegis.auth.api.dto.ApiKeyResponse;
import com.aegis.auth.application.ApiKeyService;
import com.aegis.auth.domain.User;
import com.aegis.gate.api.dto.GateCheckResponse;
import com.aegis.gate.application.GateService;
import com.aegis.policy.api.dto.PolicyResponse;
import com.aegis.policy.api.dto.ProjectPolicyEvaluationResponse;
import com.aegis.policy.application.PolicyService;
import com.aegis.project.api.dto.OrgResponse;
import com.aegis.project.api.dto.ProjectResponse;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.application.ProjectService;
import com.aegis.report.application.ReportService;
import com.aegis.risk.api.dto.RiskHistoryResponse;
import com.aegis.risk.api.dto.RiskResponse;
import com.aegis.risk.application.RiskService;
import com.aegis.sbom.api.dto.SbomComponentResponse;
import com.aegis.sbom.api.dto.SbomDocumentResponse;
import com.aegis.sbom.application.SbomService;
import com.aegis.vulnerability.api.dto.ProjectVulnerabilityResponse;
import com.aegis.vulnerability.application.VulnerabilityService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;
import java.util.UUID;

@Controller
@RequestMapping("/web")
@RequiredArgsConstructor
public class DashboardController {

    private final CurrentUserResolver currentUserResolver;
    private final OrganizationService organizationService;
    private final ProjectService projectService;
    private final SbomService sbomService;
    private final VulnerabilityService vulnerabilityService;
    private final RiskService riskService;
    private final AuditService auditService;
    private final ApiKeyService apiKeyService;
    private final ReportService reportService;
    private final PolicyService policyService;
    private final GateService gateService;
    private final AlertService alertService;

    @GetMapping({"", "/"})
    public String webRoot() {
        return "redirect:/web/dashboard";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model) {
        User user = currentUserResolver.requireCurrentUser();
        List<OrgResponse> orgs = organizationService.getUserOrganizations(user);
        model.addAttribute("user", user);
        model.addAttribute("organizations", orgs);
        model.addAttribute("activeNav", "dashboard");
        return "dashboard/index";
    }

    @GetMapping("/organizations")
    public String organizations(Model model) {
        User user = currentUserResolver.requireCurrentUser();
        model.addAttribute("user", user);
        model.addAttribute("organizations", organizationService.getUserOrganizations(user));
        model.addAttribute("activeNav", "organizations");
        return "organizations/list";
    }

    @GetMapping("/organizations/{orgId}/projects")
    public String orgProjects(@PathVariable UUID orgId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        OrgResponse org = organizationService.getOrganizationById(user, orgId);
        List<ProjectResponse> projects = projectService.getOrgProjects(user, orgId);
        model.addAttribute("user", user);
        model.addAttribute("organization", org);
        model.addAttribute("projects", projects);
        model.addAttribute("activeNav", "organizations");
        return "projects/list";
    }

    @GetMapping("/projects/{projectId}")
    public String projectDetail(@PathVariable UUID projectId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        ProjectResponse project = projectService.getProjectById(user, projectId);
        RiskResponse risk = null;
        try {
            risk = riskService.getProjectRisk(user, projectId);
        } catch (Exception ignored) {
            // risk may not be calculated yet
        }
        model.addAttribute("user", user);
        model.addAttribute("project", project);
        model.addAttribute("risk", risk);
        model.addAttribute("activeNav", "projects");
        return "projects/detail";
    }

    @GetMapping("/projects/{projectId}/sboms")
    public String projectSboms(@PathVariable UUID projectId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        ProjectResponse project = projectService.getProjectById(user, projectId);
        List<SbomDocumentResponse> sboms = sbomService.getProjectSboms(user, projectId);
        model.addAttribute("user", user);
        model.addAttribute("project", project);
        model.addAttribute("sboms", sboms);
        model.addAttribute("activeNav", "sboms");
        return "sbom/list";
    }

    @GetMapping("/projects/{projectId}/sboms/{sbomId}")
    public String sbomDetail(@PathVariable UUID projectId, @PathVariable UUID sbomId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        ProjectResponse project = projectService.getProjectById(user, projectId);
        SbomDocumentResponse sbom = sbomService.getSbomDetails(user, projectId, sbomId);
        List<SbomComponentResponse> components = sbomService.getSbomComponents(user, projectId, sbomId);
        model.addAttribute("user", user);
        model.addAttribute("project", project);
        model.addAttribute("sbom", sbom);
        model.addAttribute("components", components);
        model.addAttribute("activeNav", "sboms");
        return "sbom/detail";
    }

    @GetMapping("/projects/{projectId}/vulnerabilities")
    public String vulnerabilities(@PathVariable UUID projectId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        ProjectResponse project = projectService.getProjectById(user, projectId);
        List<ProjectVulnerabilityResponse> vulnerabilities =
                vulnerabilityService.getProjectVulnerabilities(user, projectId, null);
        model.addAttribute("user", user);
        model.addAttribute("project", project);
        model.addAttribute("vulnerabilities", vulnerabilities);
        model.addAttribute("activeNav", "vulnerabilities");
        return "vulnerabilities/list";
    }

    @GetMapping("/projects/{projectId}/risk")
    public String risk(@PathVariable UUID projectId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        ProjectResponse project = projectService.getProjectById(user, projectId);
        RiskResponse risk = riskService.getProjectRisk(user, projectId);
        List<RiskHistoryResponse> history = riskService.getRiskHistory(user, projectId);
        model.addAttribute("user", user);
        model.addAttribute("project", project);
        model.addAttribute("risk", risk);
        model.addAttribute("history", history);
        model.addAttribute("activeNav", "risk");
        return "risk/dashboard";
    }

    @GetMapping("/projects/{projectId}/policies")
    public String policies(@PathVariable UUID projectId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        ProjectResponse project = projectService.getProjectById(user, projectId);
        List<PolicyResponse> policies = policyService.listPoliciesForProject(user, projectId);
        ProjectPolicyEvaluationResponse evaluation = null;
        try {
            evaluation = policyService.evaluateProjectPolicies(user, projectId);
        } catch (Exception ignored) {
            // evaluation optional for page render
        }
        model.addAttribute("user", user);
        model.addAttribute("project", project);
        model.addAttribute("policies", policies);
        model.addAttribute("evaluation", evaluation);
        model.addAttribute("message", policies.isEmpty() ? "No policies yet — defaults are created on first evaluation." : null);
        model.addAttribute("activeNav", "policies");
        return "policies/list";
    }

    @GetMapping("/projects/{projectId}/gates")
    public String gates(@PathVariable UUID projectId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        ProjectResponse project = projectService.getProjectById(user, projectId);
        List<GateCheckResponse> gates = gateService.listGateChecks(user, projectId);
        model.addAttribute("user", user);
        model.addAttribute("project", project);
        model.addAttribute("gates", gates);
        model.addAttribute("message", gates.isEmpty() ? "No gate checks yet. Use POST /api/v1/gates/check from CI/CD." : null);
        model.addAttribute("activeNav", "gates");
        return "gates/list";
    }

    @GetMapping("/projects/{projectId}/alerts")
    public String alerts(@PathVariable UUID projectId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        ProjectResponse project = projectService.getProjectById(user, projectId);
        List<AlertResponse> alerts = alertService.listAlerts(user, projectId);
        model.addAttribute("user", user);
        model.addAttribute("project", project);
        model.addAttribute("alerts", alerts);
        model.addAttribute("message", alerts.isEmpty() ? "No alerts for this project." : null);
        model.addAttribute("activeNav", "alerts");
        return "alerts/list";
    }

    @GetMapping("/projects/{projectId}/audit")
    public String audit(@PathVariable UUID projectId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        ProjectResponse project = projectService.getProjectById(user, projectId);
        AuditSearchRequest filters = AuditSearchRequest.builder()
                .projectId(projectId)
                .page(0)
                .size(50)
                .build();
        Page<AuditLogResponse> page = auditService.search(user, filters);
        model.addAttribute("user", user);
        model.addAttribute("project", project);
        model.addAttribute("auditLogs", page.getContent());
        model.addAttribute("activeNav", "audit");
        return "audit/list";
    }

    @GetMapping("/projects/{projectId}/reports")
    public String reports(@PathVariable UUID projectId, Model model) {
        User user = currentUserResolver.requireCurrentUser();
        ProjectResponse project = projectService.getProjectById(user, projectId);
        model.addAttribute("user", user);
        model.addAttribute("project", project);
        model.addAttribute("activeNav", "reports");
        return "reports/index";
    }

    @GetMapping("/projects/{projectId}/reports/security.pdf")
    public ResponseEntity<byte[]> downloadSecurityPdf(@PathVariable UUID projectId) {
        User user = currentUserResolver.requireCurrentUser();
        byte[] pdf = reportService.generateSecurityPdf(user, projectId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"aegis-security-" + projectId + ".pdf\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }

    @GetMapping("/projects/{projectId}/reports/vulnerabilities.csv")
    public ResponseEntity<byte[]> downloadVulnerabilitiesCsv(@PathVariable UUID projectId) {
        User user = currentUserResolver.requireCurrentUser();
        byte[] csv = reportService.generateVulnerabilityCsv(user, projectId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"aegis-vulnerabilities-" + projectId + ".csv\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csv);
    }

    @GetMapping("/api-keys")
    public String apiKeys(Model model) {
        User user = currentUserResolver.requireCurrentUser();
        List<ApiKeyResponse> keys = apiKeyService.getUserApiKeys(user);
        model.addAttribute("user", user);
        model.addAttribute("apiKeys", keys);
        model.addAttribute("activeNav", "api-keys");
        return "api-keys/list";
    }
}
