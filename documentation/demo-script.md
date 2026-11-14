# Live Demonstration Script

**Duration:** 7–10 minutes · **Environment:** local-only lab · **Safety:** use only the mock data and loopback URLs listed below.

## Preparation

1. In PowerShell, install requirements if needed: `python -m pip install -r requirements.txt` and `npm install`.
2. Start Flask with `$env:HOST = "127.0.0.1"; python app.py`.
3. Start Vite in another terminal with `npm run dev`.
4. Browse to `http://localhost:5173` and confirm the API status is Connected.

## Talk track and actions

1. **Introduce the lab (30 sec).** State that this simulates metadata security and never calls cloud endpoints.
2. **Dashboard (45 sec).** Show Overview metrics and point out that the counts come from SQLite event rows.
3. **Mock service (45 sec).** Open Token Management. Explain that only synthetic instance/region/role data exists.
4. **Acquire a valid token (45 sec).** Keep the default TTL and select Acquire token. Explain that tokens expire and reset when Flask restarts.
5. **Allow a request (30 sec).** Select `instance-id`, choose Send authorized request, and show the dummy response.
6. **Missing token (30 sec).** Use PowerShell: `Invoke-RestMethod -Uri http://127.0.0.1:5050/api/proxy/region`. Explain the expected 401 and logged reason.
7. **Invalid token (30 sec).** In PowerShell: `Invoke-RestMethod -Uri http://127.0.0.1:5050/api/proxy/region -Headers @{"X-IMDS-Token"="not-issued"}`. This is a local request and should be rejected.
8. **Unauthorized destination / SSRF simulation (60 sec).** Open SSRF Detection and run the safe scenarios. Highlight that the lab sends a destination *string* to its policy checker but never contacts that destination.
9. **Event logs (45 sec).** Open Security Events, filter for blocked or critical events, select one for details, and optionally export CSV.
10. **Rules (30 sec).** Show the default-enabled security rules and descriptions. Explain that toggles demonstrate policy behavior and are not an admin-security boundary.
11. **Automated tests (60 sec).** From PowerShell run `python -m pytest -q`; report the observed output rather than a prewritten claim.
12. **Saved test report (30 sec).** Open Test Center, run all eight cases, then reopen the saved run and explain its expected/actual fields.

## Cleanup

Use Clear Lab only if you intend to delete local event and test-run records. Stop Vite and Flask with `Ctrl+C`. Do not use real cloud accounts, metadata services, or credentials during the demonstration.
