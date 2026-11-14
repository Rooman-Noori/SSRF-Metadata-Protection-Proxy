# User Manual

## 1. Prerequisites

Install Python 3 (3.12 recommended), Node.js 20+ and npm. Docker Desktop is optional. This guide assumes Windows and PowerShell.

## 2. Install

From `ssrf-metadata-protection-proxy`:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm install
```

## 3. Start and stop

Use two PowerShell windows.

Window 1:

```powershell
$env:HOST = "127.0.0.1"
$env:PORT = "5050"
python app.py
```

Window 2:

```powershell
npm run dev
```

Open `http://localhost:5173`. The API status is shown in the sidebar. Stop each process with `Ctrl+C`. For the container workflow, use `docker compose up --build`; stop with `Ctrl+C`.

## 4. Dashboard

- **Overview:** live persisted counters, allowed/blocked distribution, blocked categories, hourly counts, and recent events.
- **Live Monitoring:** latest events, refreshed every five seconds.
- **Security Events:** search by source/path/reason, filter by result and severity, select a row for details, or download matching rows with Export CSV.
- **SSRF Detection:** inspect related critical/path/destination events and run the safe backend scenarios.
- **Token Management:** select a TTL from 1 to 21,600 seconds; acquire a token with PUT; select a mock resource and send it through the proxy. The page shows the returned dummy metadata and expiry.
- **Security Rules:** read descriptions/effects and toggle supported controls. Rules are enabled by default. Changing them is only for local policy demonstrations.
- **Test Center:** execute eight real local Flask API scenarios. Each result includes expected outcome, actual HTTP code/outcome, pass/fail, and explanation. The run is saved in SQLite and can be reopened.
- **Configuration:** inspect active local mode, disabled outbound requests, TTL bounds, API port, and approved resources.

## 5. Safe manual API checks

Acquire a token:

```powershell
$tokenResponse = Invoke-RestMethod -Method Put -Uri http://127.0.0.1:5050/api/metadata/token
$token = $tokenResponse.token
```

Read a field through the proxy:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5050/api/proxy/region -Headers @{"X-IMDS-Token" = $token}
```

Show a missing-token denial:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5050/api/proxy/region
```

The final command should return HTTP 401. It targets only the local application.

## 6. Data and privacy

SQLite is `security.db` in the project root unless `METAGUARD_DB_PATH` is set. Compose stores it in the named volume `metaguard-data`. Clear Lab removes saved event records and test-run history after confirmation. The token table is in-memory and tokens disappear when Flask restarts. CSV exports are saved by the browser to the user's normal download location.

## 7. Troubleshooting

- API unavailable: confirm the Flask process is running and open `/api/health`.
- CORS: use `localhost` consistently or configure `METAGUARD_ALLOWED_ORIGINS`.
- Port conflict: stop the conflicting local service or change the backend port and frontend API base together.
- Token failure: reacquire it; it may have expired or the backend may have restarted.
- Compose frontend install fails: ensure Docker has network access for npm package installation; the application itself does not need outbound requests.

Never expose the service on a public interface. Do not insert real cloud credentials or connect a real metadata endpoint.
