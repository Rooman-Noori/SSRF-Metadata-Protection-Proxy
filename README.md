# MetaGuard — SSRF Metadata Protection Proxy

**Project 40 · Cloud Security · Rooman Noori**

MetaGuard is a teaching dashboard for metadata-proxy defenses and cloud security findings. Its metadata service and cloud findings use synthetic demo data by default. An explicitly enabled live mode can read findings from AWS Security Hub through its fixed regional API.

> **Safety boundary:** Live mode contacts only the configured AWS Security Hub API using its supported SDK and read-only `GetFindings` operation. It never accesses instance metadata or credential endpoints, and it never fetches a user-supplied URL. The metadata-protection proxy remains mock-only. Keep credentials on the backend and do not expose this educational application to untrusted networks.

## Problem and objectives

Server-Side Request Forgery (SSRF) can make a server request destinations chosen by an attacker. In cloud environments, that can expose instance metadata and role credentials. This project demonstrates defense-in-depth: short-lived session tokens, method and path validation, a strict mock destination boundary, SSRF indicator detection, an SQLite audit trail, and reproducible security tests.

## Features

- Fake instance ID, hostname, region, availability zone, instance type, role, and dummy temporary credentials.
- AWS Security Hub findings in a normalized dashboard schema, with clearly labeled demo mode by default and opt-in live mode.
- Prowler IaC Security Assessment of supported local infrastructure files, using Prowler's JSON-OCSF report and persisting only actual scan output.
- Read-only AWS authentication from backend environment credentials or web identity; instance-metadata credentials and custom AWS endpoints are disabled.
- Cached findings (60 seconds), bounded provider pagination, rate-limit handling, and explicit live API errors without demo fallback.
- IMDSv2-style `PUT` token acquisition with caller-selected TTL (1–21,600 seconds); token state is held in memory and expires.
- Protected `GET`/`HEAD` metadata routes and exact resource allowlisting.
- SSRF indicator detection and destination validation; the application contains no outbound URL-fetch operation.
- SQLite persistence for allowed/blocked events, editable policy toggles, and saved test executions.
- React dashboard with working navigation, live refresh, event filtering/details, CSV export, token management, configurable rules, test runner, and runtime configuration.
- Pytest backend tests and an 8-scenario in-app test suite that exercises the Flask application.
- Local Docker Compose profile and Windows PowerShell instructions.

## Technology

Python 3.12+, Flask, Flask-CORS, SQLite, React 18, Vite 5, JavaScript, Pytest, Docker Compose.

## Architecture

```text
Browser (React/Vite :5173)
        │ REST / JSON (local CORS origins only)
        ▼
Flask API (:5050 native loopback default; :5000 inside Compose)
  ├─ Cloud findings API (demo default / fixed AWS Security Hub GetFindings)
  ├─ Token issuer and validator (in-memory, expiring)
  ├─ Proxy policy (method → destination → path → token)
  ├─ In-process mock metadata provider (dummy values only)
  └─ SQLite: security_events, security_rules, test_runs
```

The metadata proxy does not make an HTTP request to an arbitrary host. It checks the destination hint against the lab policy and obtains data from the in-process mock provider. Separately, the opt-in findings adapter uses the AWS SDK to call only Security Hub `GetFindings`; its endpoint cannot be overridden by request parameters or AWS endpoint override settings. The separately visible `/api/metadata` route is also token-protected.

## Project layout

```text
ssrf-metadata-protection-proxy/
├── app.py                     # Flask API, policies, mock service, persistence
├── tests/test_app.py          # Automated API/security tests
├── src/                       # React dashboard
├── documentation/             # Technical report, manual, architecture, demo
├── presentation/              # Generated PowerPoint and optional PDF
├── screenshots/               # Local demonstration screenshots
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── requirements.txt
├── package.json
└── README.md
```

## Requirements

- Python 3.10 or later (3.12 recommended)
- Node.js 20 or later and npm
- Optional: Docker Desktop with Compose
- Optional for IaC assessment: Prowler CLI

## Install and run on Windows

Open PowerShell in this project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm install
```

In **PowerShell window 1**, start the API:

```powershell
$env:HOST = "127.0.0.1"
$env:PORT = "5050"
python app.py
```

In **PowerShell window 2**, start the dashboard:

```powershell
npm run dev
```

Open `http://localhost:5173`. Backend health check: `http://127.0.0.1:5050/api/health`.

The API database defaults to `security.db` in the project directory. Set `METAGUARD_DB_PATH` to choose another location and `METAGUARD_ALLOWED_ORIGINS` to set a comma-separated list of dashboard origins. The defaults are local development origins. The server binds to `127.0.0.1` unless `HOST` is explicitly changed.

## Prowler IaC Security Assessment

The **IaC Security Assessment** runs Prowler's official `iac` provider locally against the project directory. It requires no AWS account or cloud credentials. It inspects supported infrastructure-as-code and container configuration files present in the project (for example Terraform, Kubernetes YAML, Dockerfiles, and supported templates). A result is a static assessment of local files; it is **not** a live finding from a deployed cloud account.

The app invokes Prowler with `iac --scan-path <project> --output-formats json-ocsf --output-directory <report-directory>`. The backend checks the installed CLI's version and `iac --help` for the required options before enabling scans. It parses Prowler's JSON-OCSF report and saves those findings, timestamps, status, and report data in the existing SQLite database. It does not create sample findings or substitute demo data when a scan is unavailable or fails.

On Windows, the supported setup below runs Prowler's official open-source
container image through Docker Desktop. This avoids installing its deeply nested
Python dependencies on the Windows filesystem:

```powershell
docker pull prowlercloud/prowler:5.49.0
docker run --pull=never --rm --entrypoint prowler prowlercloud/prowler:5.49.0 -v
docker run --pull=never --rm --entrypoint prowler prowlercloud/prowler:5.49.0 iac --help
```

Set Docker mode in the PowerShell window used to start the backend:

```powershell
$env:PROWLER_EXECUTION_MODE = "docker"
$env:PROWLER_DOCKER_IMAGE = "prowlercloud/prowler:5.49.0"
python app.py
```

The backend detects Docker and verifies the image's Prowler version before
enabling scans. It mounts the project read-only, writes reports to its local
Prowler data directory, and passes no cloud credentials for IaC assessments.
Restart the backend after installation, open **IaC Security Assessment**, and
choose **Run local assessment**. If Docker or the image is unavailable, the
health status remains unavailable and the scan button stays disabled.

The repository includes an intentionally insecure, local-only Terraform sample
at [`samples/prowler-terraform/main.tf`](samples/prowler-terraform/main.tf) to
demonstrate actual IaC findings. It contains no credentials and must not be
applied to an AWS account. To scan only that sample and save a real JSON-OCSF
report for inspection:

```powershell
New-Item -ItemType Directory -Force .metaguard\prowler-sample | Out-Null
$samplePath = (Resolve-Path .\samples\prowler-terraform).Path.Replace('\', '/')
$reportPath = (Resolve-Path .\.metaguard\prowler-sample).Path.Replace('\', '/')
docker run --pull=never --rm `
  --mount "type=bind,source=$samplePath,target=/workspace,readonly" `
  --mount "type=bind,source=$reportPath,target=/home/prowler/output" `
  --entrypoint prowler prowlercloud/prowler:5.49.0 `
  iac --scan-path /workspace --output-formats json-ocsf `
  --output-directory /home/prowler/output
```

AWS, Azure, and Google Cloud provider scans are separate from IaC assessment. Their UI options remain disabled unless the corresponding backend credentials are configured, and the backend still requires explicit authorization. IaC results must not be presented as live cloud-account findings.

## AWS Security Hub findings

Demo mode is the default and does not require AWS credentials. To enable live reads, configure the backend environment:

```powershell
$env:METAGUARD_CLOUD_FINDINGS_MODE = "live"
$env:METAGUARD_CLOUD_FINDINGS_PROVIDER = "aws_security_hub"
$env:AWS_REGION = "us-east-1"
```

Provide either:

- **Local development:** `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`, plus `AWS_SESSION_TOKEN` when using temporary credentials. Keep these in the backend process environment or a secret manager; do not put them in React/Vite variables or commit them.
- **Managed web identity (for example, EKS IRSA):** `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE`, with the token file mounted into the backend runtime.

The role should have only `securityhub:GetFindings` for the intended account/region. Enable Security Hub in that region and ensure the identity is authorized to read findings. This integration intentionally does not use EC2 instance-profile metadata credentials, shared AWS profiles, custom service endpoints, or arbitrary URLs. The SDK's EC2 metadata credential provider is disabled.

For Docker Compose, copy `.env.example` to `.env` and set the mode, region, and backend credentials there; `.env` is ignored by Git. Do not use a committed or frontend `VITE_*` secret. Web-identity token files must be mounted into the backend container by the deployment platform.

When live mode is selected, missing credentials, access denial, provider failures, and rate limits return explicit errors; the API does not fall back to demo findings. `/api/security/health` reports `liveVerified: true` only after a successful live provider read. No valid AWS credentials were included with this project, so live connectivity must be verified in the target AWS account.

## Docker Compose

Docker publishes both services on loopback only. From the project root:

```powershell
docker compose up --build
```

Dashboard: `http://localhost:5173`; API: `http://127.0.0.1:5050`. Stop with `Ctrl+C`, then optionally run `docker compose down`. SQLite data is kept in the named `metaguard-data` volume. Do not edit the compose port bindings to `0.0.0.0` for an Internet-facing deployment.

## Using the application

1. In **Token Management**, acquire a short-lived token.
2. Select an allowlisted metadata resource and send it through the proxy.
3. Use **Overview** or **Live Monitoring** to review AWS Security Hub findings; the header identifies **DEMO DATA** or **LIVE DATA · VERIFIED**. Provider errors are shown explicitly.
4. Use **Test Center → Run all 8 tests** to execute and save actual backend results.
5. Open a saved execution to inspect each expected/actual result and security explanation.
6. Use **Security Events** to search and filter the SQLite audit log; select an event for details or export visible results to CSV.
7. **Security Rules** toggles supported lab rules. All rules start enabled; disabling controls is for demonstrating policy behavior only.
8. **Clear Lab** deletes event and saved test-run records after confirmation. It does not erase the token store until the backend process is restarted.
9. **IaC Security Assessment** runs Prowler against local project configuration files. Its results are not live cloud-account findings.

## API quick reference

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Local service status |
| PUT | `/api/metadata/token` | Issue expiring token; optional `X-aws-ec2-metadata-token-ttl-seconds` |
| GET | `/api/proxy/<resource>` | Protected read from mock provider; pass `X-IMDS-Token` |
| GET | `/api/metadata/<resource>` | Token-protected mock service |
| GET | `/api/security/overview` | Persisted dashboard metrics |
| GET | `/api/security/events` | Filtered event list (`status`, `severity`, `search`) |
| GET | `/api/security/findings?limit=25&cursor=0` | Paginated normalized cloud findings |
| GET | `/api/security/summary` | Finding totals by severity and workflow status |
| GET | `/api/security/alerts?limit=25&cursor=0` | Open high/critical findings |
| GET | `/api/security/health` | Findings mode, provider, fetch time, and live verification status |
| GET/PATCH | `/api/security/rules` and `/api/security/rules/<id>` | Read/update supported rule switches |
| POST | `/api/security/test-center/run` | Execute and save eight backend scenarios |
| GET | `/api/security/test-center/runs[/<id>]` | Read saved test results |
| GET | `/api/config` | Safe lab runtime configuration |
| POST | `/api/security/clear` | Clear local events and saved test runs |
| GET | `/api/cloud-security/health` | Prowler CLI status, IaC readiness, and cloud-credential readiness |
| POST | `/api/cloud-security/scan` | Start an IaC assessment or an explicitly authorized credential-backed cloud scan |
| GET | `/api/cloud-security/findings` | Paginated actual findings from persisted Prowler reports |

## Testing and actual results

```powershell
python -m pytest -q
npm run build
```

Pytest covers token issuance/expiry, valid and denied requests, HTTP methods, allowlisting, SSRF detection/logging, database-backed metrics, test-run persistence, rule management, configuration, data clearing, mocked AWS Security Hub pagination/normalization, and mocked Prowler JSON-OCSF scans. Mocked Prowler tests do not claim that a real scan ran. Run `python -m pytest -q` and `npm run build`. Live cloud scans require authorized credentials; IaC scans require Prowler but no cloud account. See [`documentation/technical-report.md`](documentation/technical-report.md) for details.

## Troubleshooting

- **Dashboard says API unavailable:** start `python app.py`; confirm `/api/health` returns `status: ok`.
- **Port already in use:** set `PORT` and `VITE_API_PROXY_TARGET` consistently; the dashboard calls the API through Vite's same-origin `/api` proxy to avoid browser CORS and connection-reset errors.
- **CORS error:** use the listed `localhost` URLs or add the exact origin to `METAGUARD_ALLOWED_ORIGINS`.
- **Tests cannot import `app`:** run pytest from the project root; `pytest.ini` adds the project root to the import path.
- **Token rejected:** tokens are process-local and expire; acquire another. Restarting Flask invalidates every token.
- **Docker data appears stale:** inspect the named `metaguard-data` volume; do not remove it unless you intend to delete local lab data.
- **Live findings show an error:** verify `METAGUARD_CLOUD_FINDINGS_MODE=live`, `AWS_REGION`, the selected credential method, Security Hub enablement, and the `securityhub:GetFindings` permission. The API intentionally does not substitute demo findings.

## Limitations

This is a teaching demonstration, not a production proxy or cloud hardening product. It has no user/admin authentication, TLS termination, distributed token store, or production-grade rate limiting. SQLite and in-memory tokens suit one local instance only. Live findings are read-only and use a bounded snapshot; they do not harden cloud resources. Security rules that are disabled intentionally demonstrate weaker policy behavior. The metadata proxy still never performs outbound requests.
