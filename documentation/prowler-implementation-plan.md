# Prowler CSPM Integration Plan

## Current-state evidence

- The existing Flask application is in `app.py`, uses SQLite, and already enforces fixed mock-only metadata routes, method/path validation, destination allowlisting, token checks, and persisted security events.
- The React dashboard is a single-page app in `src/App.jsx` with existing Overview, Live Monitoring, Security Events, SSRF Detection, Token Management, Security Rules, Test Center, and Configuration sections.
- AWS Security Hub findings were added as a separate optional feature before this Prowler request. Its demo/live state and endpoints remain separate from scanner-run results.
- The selected Python runtime is 3.12.10. Docker Desktop and Ubuntu WSL are available. Prowler is not installed in the project virtual environment.
- Prowler's official README documents `prowler <provider>` and lists IaC as a supported provider. Its official installation guide supports Python 3.10–3.13 and `pip install prowler`; the official GitHub Action documents provider `iac`.

## Implementation phases

1. **Verify scanner capability:** Install the official Prowler PyPI package in an isolated project scanner environment. Record the installed version and verify version/help output and the exact supported IaC command/output options before wiring subprocess execution. Do not start cloud scans; no cloud account is available.
2. **Backend scanner services:** Add Prowler availability/version detection, fixed provider allowlist (`iac`, `aws`, `azure`, `gcp`), IaC path confinement, safe argument-array subprocess execution, timeout, single-active-scan guard, async worker, cancellation, and explicit unavailable/auth/failure states.
3. **Results and persistence:** Parse only actual Prowler JSON/JSON-OCSF report files; preserve each original record; normalize available source fields without fabricated values; persist scan jobs/findings/history in SQLite; implement filters, pagination, summaries, compliance aggregation, and detail lookup.
4. **API and audit:** Add the requested `/api/cloud-security/*` endpoints. Reject malformed or unauthorized scan requests and record scan lifecycle outcomes without logging credentials or subprocess environment values.
5. **Dashboard:** Add Prowler Scanner navigation and management/findings/compliance/history/recommendations views while preserving existing pages. Visibly separate actual Prowler scans, supported local IaC assessments, and sample-only results; show loading, empty, unavailable, running, failed, and complete states.
6. **Verification and docs:** Add mocked subprocess/parser/database/API tests, run existing SSRF tests unchanged, run the focused and full pytest suites, build the frontend, verify scanner health/version and a no-cloud IaC scan if supported by the installed command, and document Windows/WSL/Docker setup and least-privilege cloud configuration.

## Security constraints

- Do not use `shell=True`; do not accept executable paths, shell fragments, output paths, or arbitrary CLI flags from HTTP input.
- Restrict the scanner executable to a configured local Prowler installation; use a fixed provider allowlist and fixed argument templates.
- For local IaC mode, scan only the repository root and its descendants. Do not permit arbitrary filesystem paths.
- Do not load AWS metadata credentials, access cloud metadata endpoints, fetch user-controlled URLs, or include secrets in API responses/logs.
- Cloud scans are opt-in and require credentials supplied in the backend environment or by an explicit managed identity. No credentials are required for sample mode or local IaC scanning.
- Demo/sample records must never be merged into persisted results from an actual scan.
- Scan execution is asynchronous, one at a time, bounded by a configurable timeout, and its actual status remains visible on failures.

## Acceptance checks

- Prowler health distinguishes missing binary, version, and healthy state.
- Local IaC mode is available without cloud credentials only if the installed official Prowler CLI confirms the command.
- Mocked tests cover scanner detection/version, success/failure/timeout, parsing/normalization, filters/pagination, persistence, no-auth local mode, demo/live separation, and rejected input.
- Existing SSRF and proxy-policy tests remain passing.
- Frontend production build succeeds.
- Actual scanner verification states whether a real Prowler binary and local scan were executed; cloud live scan remains unverified without an authorized account.
