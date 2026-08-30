$ErrorActionPreference = "Continue"
$base = "http://localhost:8080"
$root = "c:\Users\astro\Desktop\summer vacay projects self\Aegis"
$sbom1 = "$root\aegis-backend\src\test\resources\e2e-vulnerable-cyclonedx.json"
$outDir = "$root\e2e-artifacts"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$up=$false
for ($i=0; $i -lt 80; $i++) {
  try { if ((Invoke-RestMethod "$base/actuator/health" -TimeoutSec 2).status -eq "UP") { $up=$true; break } } catch {}
  Start-Sleep 3
}
if (-not $up) { Write-Output "ABORT app down"; exit 1 }
Write-Output "APP UP"

$login = Invoke-RestMethod -Uri "$base/api/v1/auth/login" -Method POST -ContentType "application/json" -Body '{"email":"admin@aegis.local","password":"Aegis@123"}'
$token=$login.accessToken
$hdr=@{Authorization="Bearer $token"}

$slug = "fix-org-" + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$org = Invoke-RestMethod -Uri "$base/api/v1/organizations" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{ name="Fix Org"; slug=$slug; description="fix" } | ConvertTo-Json)
$proj = Invoke-RestMethod -Uri "$base/api/v1/organizations/$($org.id)/projects" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{ name="Fix Project"; ecosystem="Maven" } | ConvertTo-Json)

# policies with both key styles
Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/policies" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{ name="lic-alias"; policyType="ALLOWED_LICENSES"; enabled=$true; configJson='{"allowedLicenses":["MIT","Apache-2.0"]}' } | ConvertTo-Json) | Out-Null
Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/policies" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{ name="no-crit"; policyType="NO_CRITICAL_CVE"; enabled=$true; configJson='{}' } | ConvertTo-Json) | Out-Null
Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/policies" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{ name="cvss"; policyType="CVSS_THRESHOLD"; enabled=$true; configJson='{"maxCvss":7.0}' } | ConvertTo-Json) | Out-Null

$upload = curl.exe -s -w "`n%{http_code}" -H "Authorization: Bearer $token" -F "file=@$sbom1;type=application/json" "$base/api/v1/projects/$($proj.id)/sboms"
$sbomDoc = (($upload -split "`n")[0..((($upload -split "`n").Length)-2)] -join "`n") | ConvertFrom-Json
Write-Output "SBOM status=$($sbomDoc.status) id=$($sbomDoc.id)"

Start-Sleep 40

$vulns = @(Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/vulnerabilities" -Headers $hdr)
$cvDb = (docker exec aegis-postgres psql -U aegis -d aegis -t -A -c "SELECT count(*) FROM component_vulnerabilities cv JOIN sbom_components c ON cv.component_id=c.id WHERE c.sbom_id='$($sbomDoc.id)';").Trim()
$vDb = (docker exec aegis-postgres psql -U aegis -d aegis -t -A -c "SELECT count(*) FROM vulnerabilities;").Trim()
Write-Output "[vuln] api=$($vulns.Count) cvDb=$cvDb vulnTable=$vDb"

$risk = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/risk" -Headers $hdr
Write-Output "[risk] score=$($risk.riskScore) grade=$($risk.riskGrade) crit=$($risk.criticalCount) high=$($risk.highCount)"

$pol = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/policies/evaluate" -Method POST -Headers $hdr
Write-Output "[policy] overall=$($pol.overallPassed)"
$pol.evaluations | ForEach-Object { Write-Output "  $($_.policyType) passed=$($_.passed) reason=$($_.failureReason)" }

$alerts = @(Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/alerts" -Headers $hdr)
Write-Output "[alerts] count=$($alerts.Count) types=$(($alerts | ForEach-Object { $_.alertType }) -join ',')"

if ($vulns.Count -ge 1) {
  $id = $vulns[0].componentVulnerabilityId
  Write-Output "[suppress] trying id=$id sev=$($vulns[0].severity) cve=$($vulns[0].cveId)"
  try {
    $sup = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/vulnerabilities/component-vulnerabilities/$id/suppress" -Method POST -Headers $hdr -ContentType "application/json" -Body '{"reason":"e2e false positive"}'
    Write-Output "[suppress] ok suppressed=$($sup.suppressed)"
  } catch {
    Write-Output "[suppress] FAIL $($_.Exception.Message)"
  }
}

# form login with CSRF
$html = curl.exe -s -c "$outDir\cj.txt" "$base/login"
if ($html -match 'name="_csrf"\s+value="([^"]+)"') { $csrf=$Matches[1] }
elseif ($html -match 'name="([^"]+)"\s+value="([^"]+)"') { }
# thymeleaf renders as name="_csrf" value="..."
$csrf = [regex]::Match($html, 'name="_csrf" value="([^"]+)"').Groups[1].Value
if (-not $csrf) { $csrf = [regex]::Match($html, 'name="_csrf"\s+value="([^"]+)"').Groups[1].Value }
Write-Output "[csrf] tokenLen=$($csrf.Length)"
$formCode = curl.exe -s -c "$outDir\cj.txt" -b "$outDir\cj.txt" -o "$outDir\after-login.html" -w "%{http_code}" -X POST "$base/login" -d "username=admin%40aegis.local&password=Aegis%40123&_csrf=$csrf"
$dashCode = curl.exe -s -c "$outDir\cj.txt" -b "$outDir\cj.txt" -o "$outDir\dash.html" -w "%{http_code}" "$base/web"
Write-Output "[dashboard] loginHttp=$formCode dashHttp=$dashCode"

# rate limit with file body
$bad="$outDir\bad-login.json"
Set-Content $bad '{"email":"ratelimit@example.com","password":"bad"}' -Encoding ascii
$codes=@()
1..8 | ForEach-Object { $codes += curl.exe -s -o NUL -w "%{http_code}" -H "Content-Type: application/json" --data-binary "@$bad" "$base/api/v1/auth/login" }
Write-Output "[redis] codes=$($codes -join ',')"

# MinIO failure scenario if endpoint exists - skip unless easy
Write-Output "DONE project=$($proj.id)"
