package com.aegis.report.application;

import com.aegis.auth.domain.User;
import com.aegis.policy.api.dto.ProjectPolicyEvaluationResponse;
import com.aegis.policy.application.PolicyService;
import com.aegis.project.application.OrganizationService;
import com.aegis.project.domain.Project;
import com.aegis.project.infrastructure.ProjectRepository;
import com.aegis.risk.api.dto.RiskResponse;
import com.aegis.risk.application.RiskService;
import com.aegis.vulnerability.api.dto.ProjectVulnerabilityResponse;
import com.aegis.vulnerability.application.VulnerabilityService;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class ReportService {

    private static final DateTimeFormatter TS_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'").withZone(ZoneOffset.UTC);

    private final ProjectRepository projectRepository;
    private final OrganizationService organizationService;
    private final RiskService riskService;
    private final VulnerabilityService vulnerabilityService;
    private final PolicyService policyService;

    @Transactional(readOnly = true)
    public byte[] generateSecurityPdf(User user, UUID projectId) {
        Project project = requireProjectAccess(user, projectId);
        RiskResponse risk = riskService.getProjectRisk(user, projectId);
        String policySummary = resolvePolicySummary(user, projectId);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            PdfWriter writer = new PdfWriter(baos);
            PdfDocument pdf = new PdfDocument(writer);
            Document document = new Document(pdf);

            DeviceRgb teal = new DeviceRgb(15, 118, 110);
            document.add(new Paragraph("AEGIS")
                    .setFontSize(22)
                    .setBold()
                    .setFontColor(teal));
            document.add(new Paragraph("Security Risk Report")
                    .setFontSize(16)
                    .setMarginBottom(12));

            document.add(new Paragraph("Project: " + project.getName()).setFontSize(12));
            document.add(new Paragraph("Project ID: " + project.getId()).setFontSize(10).setFontColor(ColorConstants.GRAY));
            document.add(new Paragraph("Generated: " + TS_FMT.format(Instant.now()))
                    .setFontSize(10)
                    .setMarginBottom(16));

            document.add(new Paragraph("Risk Summary").setBold().setFontSize(14));
            Table riskTable = new Table(UnitValue.createPercentArray(new float[]{1, 1}))
                    .useAllAvailableWidth()
                    .setMarginBottom(16);
            riskTable.addCell("Risk Score");
            riskTable.addCell(risk.getRiskScore() != null ? risk.getRiskScore().toPlainString() : "N/A");
            riskTable.addCell("Risk Grade");
            riskTable.addCell(risk.getRiskGrade() != null ? risk.getRiskGrade().name() : "N/A");
            riskTable.addCell("Critical");
            riskTable.addCell(String.valueOf(risk.getCriticalCount()));
            riskTable.addCell("High");
            riskTable.addCell(String.valueOf(risk.getHighCount()));
            riskTable.addCell("Medium");
            riskTable.addCell(String.valueOf(risk.getMediumCount()));
            riskTable.addCell("Low");
            riskTable.addCell(String.valueOf(risk.getLowCount()));
            document.add(riskTable);

            document.add(new Paragraph("Policy Evaluation").setBold().setFontSize(14));
            document.add(new Paragraph(policySummary).setMarginBottom(16));

            document.add(new Paragraph("This report was generated on demand by AEGIS and is not persisted.")
                    .setFontSize(9)
                    .setFontColor(ColorConstants.GRAY)
                    .setTextAlignment(TextAlignment.CENTER));

            document.close();
            return baos.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate security PDF report", e);
        }
    }

    @Transactional(readOnly = true)
    public byte[] generateVulnerabilityCsv(User user, UUID projectId) {
        requireProjectAccess(user, projectId);
        List<ProjectVulnerabilityResponse> vulns = vulnerabilityService.getProjectVulnerabilities(user, projectId, null);

        StringBuilder csv = new StringBuilder();
        csv.append("cveId,osvId,title,severity,cvssScore,componentName,componentVersion,suppressed\n");
        for (ProjectVulnerabilityResponse v : vulns) {
            csv.append(csvField(v.getCveId())).append(',')
                    .append(csvField(v.getOsvId())).append(',')
                    .append(csvField(v.getTitle())).append(',')
                    .append(csvField(v.getSeverity() != null ? v.getSeverity().name() : null)).append(',')
                    .append(csvField(v.getCvssScore() != null ? v.getCvssScore().toPlainString() : null)).append(',')
                    .append(csvField(v.getComponentName())).append(',')
                    .append(csvField(v.getComponentVersion())).append(',')
                    .append(v.isSuppressed())
                    .append('\n');
        }
        return csv.toString().getBytes(StandardCharsets.UTF_8);
    }

    private Project requireProjectAccess(User user, UUID projectId) {
        Project project = projectRepository.findById(projectId)
                .orElseThrow(() -> new IllegalArgumentException("Project not found"));
        organizationService.verifyMembership(project.getOrganization().getId(), user.getId());
        return project;
    }

    private String resolvePolicySummary(User user, UUID projectId) {
        try {
            ProjectPolicyEvaluationResponse evaluation = policyService.evaluateProjectPolicies(user, projectId);
            long failed = evaluation.getEvaluations() == null ? 0
                    : evaluation.getEvaluations().stream().filter(e -> !e.isPassed()).count();
            int total = evaluation.getEvaluations() == null ? 0 : evaluation.getEvaluations().size();
            return evaluation.isOverallPassed()
                    ? "PASS (" + total + " policies evaluated)"
                    : "FAIL (" + failed + " of " + total + " policies failed)";
        } catch (Exception e) {
            log.warn("Policy evaluation unavailable for report: {}", e.getMessage());
            return "N/A";
        }
    }

    private String csvField(String value) {
        if (value == null) {
            return "";
        }
        String escaped = value.replace("\"", "\"\"");
        if (escaped.contains(",") || escaped.contains("\"") || escaped.contains("\n") || escaped.contains("\r")) {
            return "\"" + escaped + "\"";
        }
        return escaped;
    }
}
