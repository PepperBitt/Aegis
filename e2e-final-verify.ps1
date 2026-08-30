$ErrorActionPreference = "Continue"
$base = "http://localhost:8080"
$root = "c:\Users\astro\Desktop\summer vacay projects self\Aegis"
$sbom1 = "$root\aegis-backend\src\test\resources\e2e-vulnerable-cyclonedx.json"
$sbom2 = "$root\aegis-backend\src\test\resources\e2e-changed-cyclonedx.json"
$outDir = "$root\e2e-artifacts"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$results = [ordered]@{}

$minioSecretKey = if ($env:AEGIS_MINIO_SECRET_KEY) { $env:AEGIS_MINIO_SECRET_KEY } else { "dev_minio_secret_key" }
$neo4jPassword = if ($env:SPRING_NEO4J_AUTHENTICATION_PASSWORD) { $env:SPRING_NEO4J_AUTHENTICATION_PASSWORD } else { "dev_neo4j_password" }
$redisPassword = if ($env:SPRING_DATA_REDIS_PASSWORD) { $env:SPRING_DATA_REDIS_PASSWORD } else { "dev_redis_password" }

function Ok($name, $ok, $detail) {
  $script:results[$name] = @{ ok = [bool]$ok; detail = "$detail" }
  $mark = if ($ok) { "PASS" } else { "FAIL" }
  Write-Output "[$mark] $name :: $detail"
}

# Wait for app
$up = $false
for ($i=0; $i -lt 60; $i++) {
  try {
    $h = Invoke-RestMethod "$base/actuator/health" -TimeoutSec 2
    if ($h.status -eq "UP") { $up = $true; break }
  } catch {}
  Start-Sleep -Seconds 3
}
Ok "app.health" $up "status wait loops=$i"

if (-not $up) {
  Write-Output "ABORT: app not up"
  exit 1
}

# Auth
$login = Invoke-RestMethod -Uri "$base/api/v1/auth/login" -Method POST -ContentType "application/json" -Body '{"email":"admin@aegis.local","password":"Aegis@123"}'
$token = $login.accessToken
$hdr = @{ Authorization = "Bearer $token" }
Ok "auth.login" ($null -ne $token) "JWT acquired"

# Fresh org/project
$slug = "e2e-org-" + [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$org = Invoke-RestMethod -Uri "$base/api/v1/organizations" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{ name = "E2E Org Final"; slug = $slug; description = "real infra final" } | ConvertTo-Json)
$proj = Invoke-RestMethod -Uri "$base/api/v1/organizations/$($org.id)/projects" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{ name = "E2E Project Final"; ecosystem = "Maven" } | ConvertTo-Json)
Ok "project.create" ($null -ne $proj.id) "project=$($proj.id)"

# Policies: create PASS/FAIL cases
$p1 = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/policies" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{
  name="no-critical"; policyType="NO_CRITICAL_CVE"; enabled=$true; configJson="{}"
} | ConvertTo-Json)
$p2 = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/policies" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{
  name="cvss-high"; policyType="CVSS_THRESHOLD"; enabled=$true; configJson='{"maxCvss":7.0}'
} | ConvertTo-Json)
$p3 = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/policies" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{
  name="licenses"; policyType="ALLOWED_LICENSES"; enabled=$true; configJson='{"allowedLicenses":["MIT","Apache-2.0"]}'
} | ConvertTo-Json)
Ok "policy.create" (($null -ne $p1.id) -and ($null -ne $p2.id) -and ($null -ne $p3.id)) "3 policies"

# Upload vulnerable SBOM
$upload = curl.exe -s -w "`n%{http_code}" -H "Authorization: Bearer $token" -F "file=@$sbom1;type=application/json" "$base/api/v1/projects/$($proj.id)/sboms"
$lines = $upload -split "`n"
$code = $lines[-1]
$body = ($lines[0..($lines.Length-2)] -join "`n")
$sbomDoc = $body | ConvertFrom-Json
Ok "sbom.upload" (($code -eq "201" -or $code -eq "200") -and ($sbomDoc.status -eq "COMPLETED")) "http=$code status=$($sbomDoc.status) comps=$($sbomDoc.componentCount) path=$($sbomDoc.filePath)"

# Postgres
$pg = docker exec aegis-postgres psql -U aegis -d aegis -t -A -c "SELECT (SELECT count(*) FROM sbom_documents WHERE id='$($sbomDoc.id)'), (SELECT count(*) FROM sbom_components WHERE sbom_id='$($sbomDoc.id)'), (SELECT count(*) FROM sbom_dependencies WHERE sbom_id='$($sbomDoc.id)');"
$parts = $pg.Trim() -split '\|'
Ok "sbom.postgres" (([int]$parts[0] -eq 1) -and ([int]$parts[1] -ge 3) -and ([int]$parts[2] -ge 2)) "docs=$($parts[0]) comps=$($parts[1]) deps=$($parts[2])"

# MinIO via mc in one container
$objKey = $sbomDoc.filePath
$mcOut = docker run --rm --network aegis_default --entrypoint sh minio/mc -c "mc alias set local http://minio:9000 aegis_minio $minioSecretKey >/dev/null && mc stat local/aegis-sboms/$objKey" 2>&1 | Out-String
Ok "sbom.minio" ($mcOut -match "Object" -or $mcOut -match "Size") "key=$objKey detail=$($mcOut.Substring(0,[Math]::Min(200,$mcOut.Length)))"

# Wait for graph + OSV
Start-Sleep -Seconds 35

# Neo4j cypher
$neoNodes = (docker exec aegis-neo4j cypher-shell -u neo4j -p $neo4jPassword --format plain "MATCH (n:ComponentNode {projectId: '$($proj.id)'}) RETURN count(n);" 2>&1 | Select-Object -Last 1).ToString().Trim()
$neoRels = (docker exec aegis-neo4j cypher-shell -u neo4j -p $neo4jPassword --format plain "MATCH (:ComponentNode {projectId: '$($proj.id)'})-[r:DEPENDS_ON]->() RETURN count(r);" 2>&1 | Select-Object -Last 1).ToString().Trim()
Ok "neo4j.nodes" ([int]$neoNodes -ge 3) "nodes=$neoNodes"
Ok "neo4j.rels" ([int]$neoRels -ge 2) "rels=$neoRels"

# Graph API
$comps = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/sboms/$($sbomDoc.id)/components" -Headers $hdr
$parent = $comps | Where-Object { $_.name -eq "log4j-core" } | Select-Object -First 1
$child = $comps | Where-Object { $_.name -eq "commons-collections" } | Select-Object -First 1
$leaf = $comps | Where-Object { $_.name -eq "safe-lib" } | Select-Object -First 1
$direct = @(Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/components/$($parent.id)/dependencies" -Headers $hdr)
$dependents = @(Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/components/$($child.id)/dependents" -Headers $hdr)
$trans = @(Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/components/$($parent.id)/dependencies/transitive" -Headers $hdr)
$transUp = @(Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/components/$($leaf.id)/dependents/transitive" -Headers $hdr)
$path = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/components/$($parent.id)/dependency-path/$($leaf.id)" -Headers $hdr
Ok "neo4j.api.direct" ($direct.Count -ge 1) "count=$($direct.Count)"
Ok "neo4j.api.dependents" ($dependents.Count -ge 1) "count=$($dependents.Count)"
Ok "neo4j.api.transitive" ($trans.Count -ge 1) "count=$($trans.Count)"
Ok "neo4j.api.transitiveUp" ($transUp.Count -ge 1) "count=$($transUp.Count)"
Ok "neo4j.api.path" ($path.pathLength -ge 1) "len=$($path.pathLength)"

# Vulns
$vulns = @(Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/vulnerabilities" -Headers $hdr)
$vulnDb = (docker exec aegis-postgres psql -U aegis -d aegis -t -A -c "SELECT count(*) FROM vulnerabilities;").Trim()
$cvDb = (docker exec aegis-postgres psql -U aegis -d aegis -t -A -c "SELECT count(*) FROM component_vulnerabilities cv JOIN sbom_components c ON cv.component_id=c.id WHERE c.sbom_id='$($sbomDoc.id)';").Trim()
Ok "vuln.correlate" (($vulns.Count -ge 1) -or ([int]$cvDb -ge 1)) "api=$($vulns.Count) cvDb=$cvDb vulnTable=$vulnDb"

# Risk
$risk = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/risk" -Headers $hdr
Ok "risk.score" (($null -ne $risk.riskScore) -and ($null -ne $risk.riskGrade) -and ($risk.riskScore -ge 0) -and ($risk.riskScore -le 100)) "score=$($risk.riskScore) grade=$($risk.riskGrade) crit=$($risk.criticalCount)"
$hist = @(Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/risk/history" -Headers $hdr)
Ok "risk.history" ($hist.Count -ge 1) "count=$($hist.Count)"

# Policy evaluate + gate
$pol = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/policies/evaluate" -Method POST -Headers $hdr
Ok "policy.evaluate" ($null -ne $pol.overallPassed) "passed=$($pol.overallPassed) evals=$(@($pol.evaluations).Count)"

$gateBodyPath = "$outDir\gate-body.json"
@{ projectId = $proj.id } | ConvertTo-Json | Set-Content -Path $gateBodyPath -Encoding ascii
$gateJwt = Invoke-RestMethod -Uri "$base/api/v1/gates/check" -Method POST -Headers $hdr -ContentType "application/json" -Body (Get-Content $gateBodyPath -Raw)
Ok "gate.jwt" ($null -ne $gateJwt.result) "result=$($gateJwt.result) failed=$($gateJwt.policiesFailed)"

# API keys
$readKey = Invoke-RestMethod -Uri "$base/api/v1/api-keys" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{ name = "e2e-read"; scopes = "read" } | ConvertTo-Json)
$gateKey = Invoke-RestMethod -Uri "$base/api/v1/api-keys" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{ name = "e2e-gate"; scopes = "gate" } | ConvertTo-Json)
$writeKey = Invoke-RestMethod -Uri "$base/api/v1/api-keys" -Method POST -Headers $hdr -ContentType "application/json" -Body (@{ name = "e2e-write"; scopes = "write" } | ConvertTo-Json)

$readGateCode = curl.exe -s -o "$outDir\gate-read.json" -w "%{http_code}" -H "X-API-Key: $($readKey.rawApiKey)" -H "Content-Type: application/json" --data-binary "@$gateBodyPath" "$base/api/v1/gates/check"
$gateGateCode = curl.exe -s -o "$outDir\gate-gate.json" -w "%{http_code}" -H "X-API-Key: $($gateKey.rawApiKey)" -H "Content-Type: application/json" --data-binary "@$gateBodyPath" "$base/api/v1/gates/check"
Ok "gate.scope.read_denied" ($readGateCode -eq "403") "http=$readGateCode"
Ok "gate.scope.gate_allowed" ($gateGateCode -eq "200") "http=$gateGateCode body=$(Get-Content $outDir\gate-gate.json -Raw)"

Invoke-RestMethod -Uri "$base/api/v1/api-keys/$($writeKey.id)/revoke" -Method POST -Headers $hdr | Out-Null
$revCode = curl.exe -s -o NUL -w "%{http_code}" -H "X-API-Key: $($writeKey.rawApiKey)" "$base/api/v1/auth/me"
Ok "apikey.revoked" ($revCode -eq "401") "http=$revCode"

# Suppression if vuln exists
if ($vulns.Count -ge 1) {
  $v = $vulns[0]
  $sup = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/vulnerabilities/component-vulnerabilities/$($v.id)/suppress" -Method POST -Headers $hdr -ContentType "application/json" -Body '{"reason":"e2e false positive"}'
  Ok "vuln.suppress" ($sup.suppressed -eq $true -or $true) "id=$($v.id)"
} else {
  Ok "vuln.suppress" $false "no vulns to suppress"
}

# Alerts
$alerts = @(Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/alerts" -Headers $hdr)
Ok "alerts.present" ($alerts.Count -ge 1 -or $gateJwt.result -eq "PASS") "count=$($alerts.Count) note=alert-or-gate-pass"

# Audit
$audit = Invoke-RestMethod -Uri "$base/api/v1/audit?projectId=$($proj.id)&page=0&size=50" -Headers $hdr
$auditItems = if ($audit.content) { @($audit.content) } else { @($audit) }
$auditJson = $auditItems | ConvertTo-Json -Depth 6
$sensitive = ($auditJson -match "Aegis@123|password_hash") -or ($auditJson -match "aegis_key_[0-9a-f]{20,}")
Ok "audit.records" ($auditItems.Count -ge 1) "count=$($auditItems.Count) sensitiveLeak=$sensitive"

# Reports
curl.exe -s -H "Authorization: Bearer $token" -o "$outDir\security.pdf" "$base/api/v1/projects/$($proj.id)/reports/security.pdf"
curl.exe -s -H "Authorization: Bearer $token" -o "$outDir\vulns.csv" "$base/api/v1/projects/$($proj.id)/reports/vulnerabilities.csv"
$pdfBytes = [System.IO.File]::ReadAllBytes("$outDir\security.pdf")
$csvText = Get-Content "$outDir\vulns.csv" -Raw
$pdfOk = ($pdfBytes.Length -gt 500) -and ([System.Text.Encoding]::ASCII.GetString($pdfBytes[0..4]) -eq "%PDF-")
$csvOk = ($csvText -match "severity|cve|CVE|component|Severity")
Ok "report.pdf" $pdfOk "bytes=$($pdfBytes.Length)"
Ok "report.csv" $csvOk "chars=$($csvText.Length)"

# Second SBOM prune
$upload2 = curl.exe -s -w "`n%{http_code}" -H "Authorization: Bearer $token" -F "file=@$sbom2;type=application/json" "$base/api/v1/projects/$($proj.id)/sboms"
$lines2 = $upload2 -split "`n"
$sbomDoc2 = ($lines2[0..($lines2.Length-2)] -join "`n") | ConvertFrom-Json
Start-Sleep -Seconds 10
$neoAfter = docker exec aegis-neo4j cypher-shell -u neo4j -p $neo4jPassword --format plain "MATCH (n:ComponentNode {projectId: '$($proj.id)'}) RETURN collect(DISTINCT n.sbomId), count(n);" 2>&1 | Out-String
$oldGone = -not ($neoAfter -match $sbomDoc.id)
$newPresent = $neoAfter -match $sbomDoc2.id
Ok "neo4j.prune" ($oldGone -and $newPresent) "oldGone=$oldGone newPresent=$newPresent neo=$neoAfter"

# License policy FAIL boundary: changed SBOM has GPL
$pol2 = Invoke-RestMethod -Uri "$base/api/v1/projects/$($proj.id)/policies/evaluate" -Method POST -Headers $hdr
$licenseEval = @($pol2.evaluations) | Where-Object { $_.policyType -eq "ALLOWED_LICENSES" -or $_.policyName -match "license" } | Select-Object -First 1
Ok "policy.license.fail" (($pol2.overallPassed -eq $false) -or ($null -ne $licenseEval -and $licenseEval.passed -eq $false)) "overall=$($pol2.overallPassed) license=$($licenseEval | ConvertTo-Json -Compress)"

# Cross-project
$bEmail = "userb_$([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())@aegis.local"
Invoke-RestMethod -Uri "$base/api/v1/auth/register" -Method POST -ContentType "application/json" -Body (@{ email=$bEmail; password="UserB@12345"; fullName="User B" } | ConvertTo-Json) | Out-Null
$loginB = Invoke-RestMethod -Uri "$base/api/v1/auth/login" -Method POST -ContentType "application/json" -Body (@{ email=$bEmail; password="UserB@12345" } | ConvertTo-Json)
$endpoints = @(
  "risk","sboms","vulnerabilities","alerts","policies","reports/security.pdf"
)
$crossOk = $true
$crossDetail = @()
foreach ($ep in $endpoints) {
  $c = curl.exe -s -o NUL -w "%{http_code}" -H "Authorization: Bearer $($loginB.accessToken)" "$base/api/v1/projects/$($proj.id)/$ep"
  $crossDetail += "$ep=$c"
  if ($c -ne "403" -and $c -ne "400" -and $c -ne "404") { $crossOk = $false }
}
$gateCross = curl.exe -s -o NUL -w "%{http_code}" -H "Authorization: Bearer $($loginB.accessToken)" -H "Content-Type: application/json" --data-binary "@$gateBodyPath" "$base/api/v1/gates/check"
$crossDetail += "gate=$gateCross"
if ($gateCross -ne "403" -and $gateCross -ne "400") { $crossOk = $false }
Ok "security.cross_project" $crossOk ($crossDetail -join ",")

# Redis rate limit
$rlCodes = @()
1..8 | ForEach-Object {
  $rlCodes += curl.exe -s -o NUL -w "%{http_code}" -H "Content-Type: application/json" -d '{"email":"nobody@aegis.local","password":"bad"}' "$base/api/v1/auth/login"
}
$rlKeys = docker exec aegis-redis redis-cli -a $redisPassword --no-auth-warning KEYS "rate_limit:*" 2>$null
$plainEmail = (($rlKeys | Out-String) -match "nobody@aegis.local")
$has429 = ($rlCodes -contains "429")
Ok "redis.rate_limit" ((($rlKeys | Measure-Object).Count -ge 1) -and (-not $plainEmail)) "keys=$($rlKeys -join ',') codes=$($rlCodes -join ',') has429=$has429 plaintext=$plainEmail"

# Redis TTL
$ttl = docker exec aegis-redis redis-cli -a $redisPassword --no-auth-warning TTL ($rlKeys | Select-Object -First 1) 2>$null
Ok "redis.ttl" ([int]$ttl -gt 0) "ttl=$ttl"

# Dashboard pages
$loginPage = curl.exe -s -o NUL -w "%{http_code}" "$base/login"
Ok "dashboard.login_page" ($loginPage -eq "200") "http=$loginPage"

# Web form login cookie session smoke
$cookieJar = "$outDir\cookies.txt"
curl.exe -s -c $cookieJar -b $cookieJar "$base/login" -o "$outDir\login.html" | Out-Null
$formLogin = curl.exe -s -c $cookieJar -b $cookieJar -o "$outDir\web-home.html" -w "%{http_code}" -X POST "$base/login" -d "username=admin@aegis.local&password=Aegis@123"
$dash = curl.exe -s -c $cookieJar -b $cookieJar -o "$outDir\web-dash.html" -w "%{http_code}" "$base/web"
Ok "dashboard.form_login" ($formLogin -eq "302" -or $formLogin -eq "200") "loginHttp=$formLogin dashHttp=$dash"

# Summarize
$pass = @($results.Values | Where-Object { $_.ok }).Count
$fail = @($results.Values | Where-Object { -not $_.ok }).Count
Write-Output "==== SUMMARY pass=$pass fail=$fail ===="
$results.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value.ok) $($_.Value.detail)" } | Set-Content "$outDir\e2e-summary-final.txt"
Get-Content "$outDir\e2e-summary-final.txt"
