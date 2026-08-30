# AEGIS

Secure Software Supply Chain Risk Monitor.

Organizations upload SBOMs, AEGIS parses them, builds dependency graphs, correlates CVEs via OSV, calculates risk, evaluates policies, gates CI/CD, raises alerts, audits actions, and serves a web dashboard.

## Stack

| Layer | Technology |
|-------|------------|
| Backend | Java 21, Spring Boot 3.3.5, Spring Security, Spring Data JPA |
| Graph | Neo4j 5.x, Spring Data Neo4j |
| Object storage | MinIO (required for successful SBOM ingestion) |
| Cache / rate limit | Redis |
| Mail (dev) | MailHog |
| DB migrations | Flyway + PostgreSQL |
| Auth | JWT + `X-API-Key` with scopes |
| Reports | iText PDF + CSV |
| UI | Thymeleaf on the backend (`/login`, `/web/**`) |

## Quick start

### Infrastructure + backend (Docker)

```bash
docker compose up -d --build
```

| Service | URL |
|---------|-----|
| Web UI / API | http://localhost:8080 |
| Login | http://localhost:8080/login |
| Swagger | http://localhost:8080/swagger-ui.html |
| MinIO console | http://localhost:9001 |
| MailHog | http://localhost:8025 |
| Neo4j Browser | http://localhost:7474 |


### Local development

```bash
docker compose up -d postgres neo4j redis minio mailhog
cd aegis-backend
mvn spring-boot:run
```

### Tests

```bash
cd aegis-backend
mvn clean test
```

- Unit + MockMvc tests use H2; MinIO/Redis/Neo4j are stubbed or excluded under the `test` profile.
- `Neo4jDependencyGraphIT` / `MinioStorageIT` use Testcontainers and skip when Docker is unavailable.

## API key scopes

Create keys via `POST /api/v1/api-keys` with a comma-separated `scopes` field.

| Scope | Allows |
|-------|--------|
| `read` | GET/HEAD on APIs |
| `write` | Mutating methods + gate |
| `gate` | `POST /api/v1/gates/check` (+ read) |
| `admin` | All API-key operations |

JWT users are not subject to API-key scope checks (org membership still applies).

Example CI gate:

```bash
curl -X POST http://localhost:8080/api/v1/gates/check \
  -H "X-API-Key: aegis_key_..." \
  -H "Content-Type: application/json" \
  -d '{"projectId":"<uuid>"}'
```

## Risk formula

For each unique non-suppressed vulnerability:

```
weight(severity) * (0.6 * normalizedCvss + 0.2 * epss + 0.2 * blastRadius)
```

- Severity weights: CRITICAL 25, HIGH 15, MEDIUM 5, LOW 1.5, else 0.5
- `normalizedCvss` = CVSS/10, or severity fallback when CVSS missing
- `epss` = stored EPSS only; if absent uses documented unknown default `0.10` (not invented per-CVE data)
- `blastRadius` = 1.0 .. 1.5 from shared finding count
- Score clamped to `[0, 100]`; grade A–F from score bands in `RiskGrade`

## Event flow

```
SBOM upload → MinIO (required) → PostgreSQL
           → SbomUploadedEvent (AFTER_COMMIT)
                ├─ Neo4j sync (project-scoped prune + MERGE)
                └─ OSV correlation → VulnerabilityCorrelatedEvent
                     → Risk → RiskCalculatedEvent → alerts (deduped)
Gate/Policy mutations → audit_logs via @AuditAction
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `SPRING_DATASOURCE_*` | PostgreSQL |
| `SPRING_NEO4J_*` | Neo4j bolt |
| `SPRING_DATA_REDIS_*` | Redis |
| `SPRING_MAIL_*` | SMTP (MailHog in compose) |
| `AEGIS_MINIO_*` | MinIO endpoint/credentials/bucket |
| `AEGIS_JWT_SECRET` / `AEGIS_JWT_EXPIRATION` | JWT signing |

## Notes

- Flyway: `aegis-backend/src/main/resources/db/migration` (`V1`–`V7`).
- Org roles: `OWNER` / `ADMIN` / `MEMBER`.
- MinIO failure aborts SBOM ingestion (no COMPLETED row without raw object).
- Compose no longer references a separate frontend; Thymeleaf is served by the backend.
- OSV CVSS: numeric scores preserved; CVSS v3.0/v3.1 **vectors** are converted with the official FIRST base-score equations when no numeric score is present. Malformed/unsupported vectors leave CVSS null and risk uses the documented severity fallback.
- Event pipeline: `SbomUploadedEvent` is published only after PostgreSQL commit of the SBOM (`AFTER_COMMIT`). Graph sync (`@Order(1)`) then OSV correlation (`@Order(2)`). Downstream failures are logged and do not roll back the committed SBOM.
- Testcontainers on Windows Docker Desktop: the JVM docker-java client may fail Docker Engine `Info` over the `docker_cli` named pipe (empty `ServerVersion`) even when `docker info` works. `Neo4jGraphRealIntegrationTest` / `MinioStorageIT` then **skip** (not fail). Real Neo4j/MinIO paths are verified via compose services. See `src/test/resources/testcontainers.properties`.

## Known limitations

- CVSS v2 / v4 vectors are not scored (left null → severity fallback).
- EPSS is used when stored; otherwise a fixed documented default `0.10` (not per-CVE enrichment).
- Testcontainers ITs skip when Docker is unavailable to the JVM (distinct from `docker` CLI working).
