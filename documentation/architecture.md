# Architecture and security boundaries

## Context

MetaGuard is a one-machine educational lab. The browser UI is a React/Vite SPA, and Flask is the sole API/security decision point. Persistent event, rule, and test-run data is in SQLite. Metadata values and expiring test tokens are local to the application.

## Component view

```text
┌──────────────────────┐   REST/JSON (localhost origin)   ┌────────────────────────┐
│ React SOC dashboard  │ ─────────────────────────────────▶│ Flask API              │
│ Overview / Events /  │                                    │ :5050 loopback default│
│ Tokens / Rules / Test│                                    ├────────────────────────┤
└──────────────────────┘                                    │ Request policy engine  │
                                                            │ - method validation   │
                                                            │ - destination policy  │
                                                            │ - path allowlist      │
                                                            │ - token validation    │
                                                            └───────────┬────────────┘
                                                                        │
                         ┌──────────────────────────────────────────────┼─────────────────┐
                         │                                              │                 │
              in-process demo provider                 boto3 GetFindings only     SQLite
              mock metadata / demo findings              (live opt-in)       events/rules/runs
                                                                │
                                                    AWS Security Hub regional API
```

## Request decision order

1. The route captures the method and requested resource.
2. Enabled method policy accepts only `GET` and `HEAD`.
3. Destination hints are checked. SSRF indicators are classified; the default rule permits only the mock destination.
4. Enabled path validation rejects traversal and resources outside the exact allowlist.
5. Enabled token validation requires an issued, unexpired `X-IMDS-Token`.
6. The metadata proxy performs only a fixed mock-data lookup and never makes an outbound request. Separately, when live findings mode is explicitly enabled, the findings adapter uses the AWS SDK for the fixed regional Security Hub `GetFindings` operation.
7. An allowed or blocked event, including source, timestamp, path, method, reason, severity, result, and HTTP status, is persisted.

The visible `/api/metadata` route exposes the mock service but also requires a valid token. All credential-like values are explicitly fake and non-functional. Live findings mode is not used to retrieve metadata and does not use EC2 instance metadata credentials.

## Cloud findings integration

The backend defaults to demo mode. Live mode is opt-in and accepts backend environment credentials or web identity variables. It disables the EC2 metadata credential provider, rejects AWS endpoint URL overrides, and uses a 60-second in-memory findings cache. Provider pagination is bounded to 5,000 findings; responses indicate when a snapshot was truncated. The normalized findings API returns explicit errors for missing credentials, authorization failures, provider errors, and rate limits—never demo data as a live fallback.

The read-only IAM action required is `securityhub:GetFindings`. The SDK uses bounded connect/read timeouts and standard retries. No credentials are sent to the browser or written into SQLite/log output.

## Data model

- `security_events`: append-only request decisions used by metrics, event search, and CSV export.
- `security_rules`: five supported switches with secure default values inserted on first startup.
- `test_runs`: timestamped test batch summary and JSON result details; the test center uses the Flask test client to exercise actual API routes.

Tokens are held in process memory with expiry timestamps. They are intentionally not stored in SQLite.

## Deployment boundary

The native server binds to `127.0.0.1`. Compose runs the service on container interfaces but publishes host ports only on `127.0.0.1`. CORS defaults to the two local Vite origins. The Compose database uses a named volume. Changing these settings or adding authentication, an external metadata provider, or outbound proxy behavior requires a separate security review.

## Trust and limitations

This lab is not multi-user or production-ready. It has no admin authentication, TLS, distributed state, or production rate limiting. Optional live findings are read-only and do not harden cloud resources. The rule editor is intentionally unauthenticated because the app is constrained to local use; do not expose its API to untrusted clients.
