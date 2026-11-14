from __future__ import annotations

import ipaddress
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import unquote, urlsplit

from flask import Flask, jsonify, request
from flask_cors import CORS

from backend.routes.cloud_security_routes import register_cloud_security_routes
from backend.services.cloud_security_service import CloudSecurityService
from cloud_findings import CloudFindingsService, FindingsError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("METAGUARD_DB_PATH", os.path.join(BASE_DIR, "security.db"))
TOKEN_TTL_SECONDS = 300
MAX_TOKEN_TTL_SECONDS = 21600
TOKENS: dict[str, float] = {}
PROXY_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

RULE_DEFAULTS = (
    (
        "require_token",
        "Require session token",
        "Reject metadata requests without a valid, unexpired IMDSv2-style token.",
        "Missing or invalid credentials cannot access metadata.",
    ),
    (
        "restrict_methods",
        "Restrict HTTP methods",
        "Allow only GET and HEAD for metadata reads.",
        "Write methods are rejected before metadata is returned.",
    ),
    (
        "destination_allowlist",
        "Destination allowlist",
        "Only the in-process mock metadata service is a valid destination.",
        "No user-controlled or external destination is ever contacted.",
    ),
    (
        "validate_resource_path",
        "Validate resource paths",
        "Reject traversal, malformed paths, and resources outside the exact allowlist.",
        "Path confusion cannot select a different local or remote service.",
    ),
    (
        "detect_ssrf_patterns",
        "Detect SSRF indicators",
        "Classify metadata IPs, loopback URLs, cloud-hosted metadata names, and suspicious URL forms.",
        "Potential SSRF attempts are blocked and logged with critical severity.",
    ),
)

ALLOWED_RESOURCES = {
    "instance-id",
    "hostname",
    "instance-type",
    "placement/availability-zone",
    "region",
    "iam/security-credentials",
    "iam/security-credentials/demo-web-role",
    "meta-data/instance-id",
    "meta-data/hostname",
    "meta-data/instance-type",
    "meta-data/placement/availability-zone",
    "meta-data/region",
    "meta-data/iam/security-credentials",
    "meta-data/iam/security-credentials/demo-web-role",
}

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
cloud_findings_service = CloudFindingsService()
cloud_security_service = CloudSecurityService(
    project_root=Path(BASE_DIR),
    database_path=lambda: DB_PATH,
)
allowed_origins = [
    origin.strip()
    for origin in os.environ.get(
        "METAGUARD_ALLOWED_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]
CORS(app, resources={r"/api/*": {"origins": allowed_origins}})
register_cloud_security_routes(app, cloud_security_service)


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def initialize_database() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                requested_path TEXT NOT NULL,
                method TEXT NOT NULL,
                detection_reason TEXT NOT NULL,
                severity TEXT NOT NULL,
                result TEXT NOT NULL,
                status_code INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                effect TEXT NOT NULL,
                enabled INTEGER NOT NULL CHECK (enabled IN (0, 1))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS test_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                passed INTEGER NOT NULL,
                total INTEGER NOT NULL,
                results_json TEXT NOT NULL
            )
            """
        )
        conn.executemany(
            """
            INSERT OR IGNORE INTO security_rules
            (rule_id, name, description, effect, enabled)
            VALUES (?, ?, ?, ?, 1)
            """,
            RULE_DEFAULTS,
        )
    cloud_security_service.initialize_database()


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def record_event(
    *,
    source: str,
    requested_path: str,
    method: str,
    detection_reason: str,
    severity: str,
    result: str,
    status_code: int,
) -> None:
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO security_events
            (timestamp, source, requested_path, method, detection_reason, severity, result, status_code)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utc_timestamp(),
                source,
                requested_path,
                method,
                detection_reason,
                severity,
                result,
                status_code,
            ),
        )


def get_rules() -> dict[str, bool]:
    with get_db() as conn:
        rows = conn.execute("SELECT rule_id, enabled FROM security_rules").fetchall()
    return {row["rule_id"]: bool(row["enabled"]) for row in rows}


def get_rule_list() -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT rule_id, name, description, effect, enabled FROM security_rules ORDER BY rowid"
        ).fetchall()
    return [
        {**dict(row), "enabled": bool(row["enabled"])}
        for row in rows
    ]


def generate_token(ttl_seconds: int = TOKEN_TTL_SECONDS) -> str:
    token = secrets.token_urlsafe(32)
    TOKENS[token] = time.time() + ttl_seconds
    return token


def token_state(token: str | None) -> str:
    if not token:
        return "missing"
    expiry = TOKENS.get(token)
    if expiry is None:
        return "invalid"
    if time.time() >= expiry:
        return "expired"
    return "valid"


def extract_token() -> str | None:
    token = request.headers.get("X-IMDS-Token") or request.headers.get("X-Metadata-Token")
    if token:
        return token.strip()
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    return None


def normalize_resource(resource: str) -> str:
    return unquote(resource).strip("/").replace("\\", "/").lower()


def get_metadata(resource: str) -> Any:
    role_name = "demo-web-role"
    credential_data = {
        "AccessKeyId": "ASIAFAKEDUMMY0001",
        "SecretAccessKey": "dummy-secret-value-for-local-lab-only",
        "Token": "dummy-session-token-not-valid-in-any-cloud",
        "Expiration": (
            datetime.now(timezone.utc) + timedelta(hours=6)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    data = {
        "instance-id": "i-0d3b4e7a2c19ff123",
        "hostname": "metaguard-demo-01",
        "instance-type": "m5.large",
        "placement/availability-zone": "us-east-1a",
        "region": "us-east-1",
        "iam/security-credentials": [role_name],
        f"iam/security-credentials/{role_name}": credential_data,
        "meta-data/instance-id": "i-0d3b4e7a2c19ff123",
        "meta-data/hostname": "metaguard-demo-01",
        "meta-data/instance-type": "m5.large",
        "meta-data/placement/availability-zone": "us-east-1a",
        "meta-data/region": "us-east-1",
        "meta-data/iam/security-credentials": [role_name],
        f"meta-data/iam/security-credentials/{role_name}": credential_data,
    }
    return data.get(resource)


def destination_is_lab_only(destination: str) -> bool:
    if destination in {"", "mock://metadata"}:
        return True
    try:
        parsed = urlsplit(destination)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
            return False
        if parsed.port not in {None, 5000, 5050}:
            return False
        return parsed.path in {"", "/api/metadata"}
    except ValueError:
        return False


def destination_looks_suspicious(destination: str) -> bool:
    value = unquote(destination).lower()
    indicators = (
        "169.254.",
        "127.0.0.1",
        "localhost",
        "0.0.0.0",
        "metadata.google",
        "metadata.azure",
        "metadata.aws",
        "file://",
        "gopher://",
    )
    if any(indicator in value for indicator in indicators):
        return True
    try:
        parsed = urlsplit(destination)
        if parsed.hostname:
            try:
                address = ipaddress.ip_address(parsed.hostname)
                return address.is_link_local or address.is_loopback or address.is_unspecified
            except ValueError:
                return False
    except ValueError:
        return True
    return False


def block_request(
    *,
    reason: str,
    status_code: int,
    severity: str,
    path: str,
    method: str,
    source: str,
) -> Any:
    record_event(
        source=source,
        requested_path=path,
        method=method,
        detection_reason=reason,
        severity=severity,
        result="blocked",
        status_code=status_code,
    )
    return jsonify(
        {
            "status": "blocked",
            "result": "blocked",
            "severity": severity,
            "reason": reason,
            "source": source,
            "requested_path": path,
            "method": method,
        }
    ), status_code


def source_address() -> str:
    # Forwarding headers are not trusted because this lab has no trusted ingress proxy.
    return request.remote_addr or "unknown"


@app.get("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "metadata-protection-proxy",
            "mode": "isolated-local-lab",
            "time": utc_timestamp(),
        }
    )


@app.route("/api/metadata/token", methods=["PUT", "POST"])
def acquire_token():
    raw_ttl = request.headers.get("X-aws-ec2-metadata-token-ttl-seconds", str(TOKEN_TTL_SECONDS))
    try:
        ttl_seconds = int(raw_ttl)
    except ValueError:
        return jsonify({"status": "error", "error": "Token TTL must be an integer."}), 400
    if not 1 <= ttl_seconds <= MAX_TOKEN_TTL_SECONDS:
        return jsonify(
            {
                "status": "error",
                "error": f"Token TTL must be between 1 and {MAX_TOKEN_TTL_SECONDS} seconds.",
            }
        ), 400
    token = generate_token(ttl_seconds)
    return jsonify({"token": token, "expires_in": ttl_seconds, "status": "ok"})


@app.route(
    "/api/metadata",
    defaults={"resource": ""},
    methods=["GET", "HEAD"],
)
@app.route("/api/metadata/<path:resource>", methods=["GET", "HEAD"])
def mock_metadata_service(resource: str):
    source = source_address()
    requested_path = request.path
    token_status = token_state(extract_token())
    if token_status != "valid":
        return block_request(
            reason=f"Mock metadata service rejected {token_status} token",
            status_code=401,
            severity="high",
            path=requested_path,
            method=request.method,
            source=source,
        )
    normalized = normalize_resource(resource)
    if normalized in {"", "meta-data"}:
        return jsonify(
            {
                "status": "ok",
                "resources": sorted(ALLOWED_RESOURCES),
                "note": "Mock metadata only; all credential values are non-functional.",
            }
        )
    if normalized not in ALLOWED_RESOURCES:
        return jsonify({"status": "not_found", "error": "Unsupported metadata resource."}), 404
    return jsonify({"status": "ok", "resource": normalized, "data": get_metadata(normalized)})


@app.route(
    "/api/proxy",
    defaults={"resource": ""},
    methods=PROXY_METHODS,
    provide_automatic_options=False,
)
@app.route(
    "/api/proxy/<path:resource>",
    methods=PROXY_METHODS,
    provide_automatic_options=False,
)
def proxy_metadata(resource: str):
    source = source_address()
    method = request.method.upper()
    requested_path = request.path
    normalized = normalize_resource(resource)
    rules = get_rules()

    if rules["restrict_methods"] and method not in {"GET", "HEAD"}:
        return block_request(
            reason="Invalid request method for metadata access.",
            status_code=405,
            severity="high",
            path=requested_path,
            method=method,
            source=source,
        )

    destination = request.args.get("destination", request.headers.get("X-Metadata-Destination", ""))
    if destination_looks_suspicious(destination):
        return block_request(
            reason="SSRF indicator detected in requested destination.",
            status_code=403,
            severity="critical",
            path=requested_path,
            method=method,
            source=source,
        )
    if rules["destination_allowlist"] and not destination_is_lab_only(destination):
        return block_request(
            reason="Unauthorized destination rejected; only the local mock metadata service is allowed.",
            status_code=403,
            severity="critical",
            path=requested_path,
            method=method,
            source=source,
        )

    decoded_path = unquote(unquote(resource))
    if rules["detect_ssrf_patterns"] and destination_looks_suspicious(decoded_path):
        return block_request(
            reason="SSRF indicator detected in requested path.",
            status_code=403,
            severity="critical",
            path=requested_path,
            method=method,
            source=source,
        )
    if rules["validate_resource_path"] and (
        ".." in decoded_path
        or "\\" in decoded_path
        or "\x00" in decoded_path
        or normalized not in ALLOWED_RESOURCES
        and normalized not in {"", "meta-data"}
    ):
        return block_request(
            reason="Malformed or unauthorized metadata resource path.",
            status_code=403,
            severity="high",
            path=requested_path,
            method=method,
            source=source,
        )

    if rules["require_token"]:
        status = token_state(extract_token())
        if status != "valid":
            return block_request(
                reason=f"Metadata authentication token is {status}.",
                status_code=401,
                severity="high",
                path=requested_path,
                method=method,
                source=source,
            )
    elif token_state(extract_token()) not in {"valid", "missing"}:
        return block_request(
            reason="Invalid or expired token is not accepted.",
            status_code=401,
            severity="high",
            path=requested_path,
            method=method,
            source=source,
        )

    # The proxy calls only the local mock data provider; it never fetches a supplied URL.
    if normalized in {"", "meta-data"}:
        payload: Any = {"resources": sorted(ALLOWED_RESOURCES)}
    else:
        payload = get_metadata(normalized)
    if payload is None:
        return block_request(
            reason="Requested metadata resource is unsupported.",
            status_code=404,
            severity="medium",
            path=requested_path,
            method=method,
            source=source,
        )

    record_event(
        source=source,
        requested_path=requested_path,
        method=method,
        detection_reason="Authorized metadata request.",
        severity="low",
        result="allowed",
        status_code=200,
    )
    return jsonify({"status": "allowed", "resource": normalized, "data": payload})


@app.get("/api/security/overview")
def security_overview():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
        allowed = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE result = 'allowed'"
        ).fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE result = 'blocked'"
        ).fetchone()[0]
        ssrf_attempts = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE severity = 'critical'"
        ).fetchone()[0]
        invalid_tokens = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE detection_reason LIKE '%token%'"
        ).fetchone()[0]
        alerts = conn.execute(
            "SELECT COUNT(*) FROM security_events WHERE severity IN ('high', 'critical')"
        ).fetchone()[0]
        result_rows = conn.execute(
            "SELECT result, COUNT(*) AS count FROM security_events GROUP BY result"
        ).fetchall()
        severity_rows = conn.execute(
            """
            SELECT severity AS label, COUNT(*) AS count
            FROM security_events
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'low' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'high' THEN 3
                WHEN 'critical' THEN 4
                ELSE 5
            END, severity
            """
        ).fetchall()
        method_rows = conn.execute(
            "SELECT method AS label, COUNT(*) AS count FROM security_events GROUP BY method"
        ).fetchall()
        status_code_rows = conn.execute(
            """
            SELECT CAST(status_code AS TEXT) AS label, COUNT(*) AS count
            FROM security_events GROUP BY status_code ORDER BY count DESC, status_code LIMIT 6
            """
        ).fetchall()
        path_rows = conn.execute(
            """
            SELECT requested_path AS label, COUNT(*) AS count
            FROM security_events GROUP BY requested_path ORDER BY count DESC, requested_path LIMIT 6
            """
        ).fetchall()
        source_rows = conn.execute(
            """
            SELECT source AS label, COUNT(*) AS count
            FROM security_events GROUP BY source ORDER BY count DESC, source LIMIT 6
            """
        ).fetchall()
        category_rows = conn.execute(
            """
            SELECT detection_reason AS category, COUNT(*) AS count
            FROM security_events WHERE result = 'blocked'
            GROUP BY detection_reason ORDER BY count DESC LIMIT 6
            """
        ).fetchall()
        hourly_rows = conn.execute(
            """
            SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS count
            FROM security_events GROUP BY hour ORDER BY hour DESC LIMIT 12
            """
        ).fetchall()
        hourly_result_rows = conn.execute(
            """
            SELECT
                substr(timestamp, 1, 13) AS hour,
                SUM(CASE WHEN result = 'allowed' THEN 1 ELSE 0 END) AS allowed,
                SUM(CASE WHEN result = 'blocked' THEN 1 ELSE 0 END) AS blocked
            FROM security_events
            GROUP BY hour ORDER BY hour DESC LIMIT 12
            """
        ).fetchall()
    return jsonify(
        {
            "totalRequests": total,
            "allowedRequests": allowed,
            "blockedRequests": blocked,
            "ssrfAttempts": ssrf_attempts,
            "invalidTokenAttempts": invalid_tokens,
            "securityAlerts": alerts,
            "resultBreakdown": [dict(row) for row in result_rows],
            "severityBreakdown": [dict(row) for row in severity_rows],
            "methodBreakdown": [dict(row) for row in method_rows],
            "statusCodeBreakdown": [dict(row) for row in status_code_rows],
            "topPaths": [dict(row) for row in path_rows],
            "sourceBreakdown": [dict(row) for row in source_rows],
            "attackCategories": [dict(row) for row in category_rows],
            "activity": [dict(row) for row in reversed(hourly_rows)],
            "hourlyResults": [dict(row) for row in reversed(hourly_result_rows)],
        }
    )


@app.get("/api/security/events")
def list_security_events():
    status_filter = request.args.get("status", "all").lower()
    severity_filter = request.args.get("severity", "all").lower()
    search_term = request.args.get("search", "").strip().lower()[:200]
    allowed_statuses = {"all", "allowed", "blocked"}
    allowed_severities = {"all", "low", "medium", "high", "critical"}
    if status_filter not in allowed_statuses or severity_filter not in allowed_severities:
        return jsonify({"error": "Invalid event filter."}), 400

    query = "SELECT * FROM security_events WHERE 1 = 1"
    params: list[Any] = []
    if status_filter != "all":
        query += " AND result = ?"
        params.append(status_filter)
    if severity_filter != "all":
        query += " AND severity = ?"
        params.append(severity_filter)
    if search_term:
        query += """
            AND (LOWER(requested_path) LIKE ? OR
                 LOWER(detection_reason) LIKE ? OR LOWER(source) LIKE ?)
        """
        params.extend([f"%{search_term}%"] * 3)
    query += " ORDER BY id DESC LIMIT 500"
    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
    return jsonify([dict(row) for row in rows])


def findings_page_request(*, alerts_only: bool = False):
    try:
        limit = int(request.args.get("limit", "25"))
        cursor = int(request.args.get("cursor", "0"))
    except ValueError:
        return jsonify({"status": "error", "error": "limit and cursor must be integers."}), 400
    if not 1 <= limit <= 100 or not 0 <= cursor <= 5000:
        return jsonify(
            {
                "status": "error",
                "error": "limit must be 1–100 and cursor must be 0–5000.",
            }
        ), 400
    try:
        return jsonify(
            cloud_findings_service.page(
                limit=limit,
                cursor=cursor,
                alerts_only=alerts_only,
            )
        )
    except FindingsError as error:
        return findings_error_response(error)


def findings_error_response(error: FindingsError):
    status_code = error.status_code
    response = jsonify(
        {
            "status": "error",
            "source": "live",
            "error": error.public_message,
        }
    )
    if status_code == 429:
        response.headers["Retry-After"] = "30"
    return response, status_code


@app.get("/api/security/findings")
def list_cloud_findings():
    return findings_page_request()


@app.get("/api/security/summary")
def cloud_findings_summary():
    try:
        return jsonify(cloud_findings_service.summary())
    except FindingsError as error:
        return findings_error_response(error)


@app.get("/api/security/alerts")
def list_cloud_alerts():
    return findings_page_request(alerts_only=True)


@app.get("/api/security/health")
def cloud_findings_health():
    try:
        snapshot = cloud_findings_service.get_snapshot()
    except FindingsError as error:
        return findings_error_response(error)
    return jsonify(
        {
            "status": "ok",
            "mode": snapshot.mode,
            "provider": snapshot.provider,
            "liveVerified": snapshot.mode == "live",
            "fetched_at": snapshot.fetched_at,
            "finding_count": len(snapshot.items),
            "truncated": snapshot.truncated,
        }
    )


def run_security_test_suite() -> list[dict[str, Any]]:
    client = app.test_client()
    valid_token = generate_token()
    expired_token = "test-expired-token"
    TOKENS[expired_token] = time.time() - 1
    cases = [
        {
            "name": "Valid token request",
            "description": "Use a token acquired from the local token endpoint.",
            "expectedResult": "ALLOWED",
            "method": "GET",
            "path": "/api/proxy/instance-id",
            "headers": {"X-IMDS-Token": valid_token},
            "explanation": "A live token and allowlisted metadata resource satisfy the proxy policy.",
        },
        {
            "name": "Missing token",
            "description": "Request metadata without an authentication token.",
            "expectedResult": "BLOCKED",
            "method": "GET",
            "path": "/api/proxy/instance-id",
            "headers": {},
            "explanation": "The token requirement blocks unauthenticated metadata access.",
        },
        {
            "name": "Invalid token",
            "description": "Send an unissued token to an otherwise valid resource.",
            "expectedResult": "BLOCKED",
            "method": "GET",
            "path": "/api/proxy/instance-id",
            "headers": {"X-IMDS-Token": "forged-token"},
            "explanation": "Only random tokens issued by this running lab instance are accepted.",
        },
        {
            "name": "Expired token",
            "description": "Use a token whose local expiration time has passed.",
            "expectedResult": "BLOCKED",
            "method": "GET",
            "path": "/api/proxy/instance-id",
            "headers": {"X-IMDS-Token": expired_token},
            "explanation": "The proxy checks expiry on every request and rejects expired tokens.",
        },
        {
            "name": "Invalid HTTP method",
            "description": "Attempt to write to the read-only metadata proxy.",
            "expectedResult": "BLOCKED",
            "method": "POST",
            "path": "/api/proxy/instance-id",
            "headers": {"X-IMDS-Token": valid_token},
            "explanation": "Only GET and HEAD are accepted for metadata reads.",
        },
        {
            "name": "Unauthorized destination",
            "description": "Supply a destination outside the local mock service.",
            "expectedResult": "BLOCKED",
            "method": "GET",
            "path": "/api/proxy/instance-id",
            "headers": {
                "X-IMDS-Token": valid_token,
                "X-Metadata-Destination": "https://example.invalid/metadata",
            },
            "explanation": "The proxy does not make outbound requests and rejects non-lab destinations.",
        },
        {
            "name": "Valid metadata request",
            "description": "Read the mock region resource using a valid token.",
            "expectedResult": "ALLOWED",
            "method": "GET",
            "path": "/api/proxy/region",
            "headers": {"X-IMDS-Token": valid_token},
            "explanation": "The region field is explicitly allowlisted and served from dummy lab data.",
        },
        {
            "name": "Simulated SSRF attempt",
            "description": "Try a link-local metadata destination indicator.",
            "expectedResult": "BLOCKED",
            "method": "GET",
            "path": "/api/proxy/instance-id",
            "headers": {
                "X-IMDS-Token": valid_token,
                "X-Metadata-Destination": "http://169.254.169.254/latest/meta-data/",
            },
            "explanation": "The simulated link-local destination is classified as a critical SSRF indicator and is never contacted.",
        },
    ]

    results: list[dict[str, Any]] = []
    for case in cases:
        response = client.open(
            case["path"],
            method=case["method"],
            headers=case["headers"],
        )
        actual_result = "ALLOWED" if response.status_code < 400 else "BLOCKED"
        results.append(
            {
                "name": case["name"],
                "description": case["description"],
                "expectedResult": case["expectedResult"],
                "actualStatus": response.status_code,
                "actualResult": actual_result,
                "pass": actual_result == case["expectedResult"],
                "explanation": case["explanation"],
            }
        )
    return results


@app.post("/api/security/test-center/run")
def run_test_center():
    results = run_security_test_suite()
    passed = sum(1 for result in results if result["pass"])
    timestamp = utc_timestamp()
    with get_db() as conn:
        cursor = conn.execute(
            """
            INSERT INTO test_runs (timestamp, passed, total, results_json)
            VALUES (?, ?, ?, ?)
            """,
            (timestamp, passed, len(results), json.dumps(results)),
        )
        run_id = cursor.lastrowid
    return jsonify(
        {
            "id": run_id,
            "timestamp": timestamp,
            "passed": passed,
            "total": len(results),
            "results": results,
        }
    ), 201


@app.get("/api/security/test-center/runs")
def list_test_runs():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, timestamp, passed, total FROM test_runs ORDER BY id DESC LIMIT 50"
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/api/security/test-center/runs/<int:run_id>")
def get_test_run(run_id: int):
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, timestamp, passed, total, results_json FROM test_runs WHERE id = ?",
            (run_id,),
        ).fetchone()
    if row is None:
        return jsonify({"error": "Test run not found."}), 404
    return jsonify(
        {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "passed": row["passed"],
            "total": row["total"],
            "results": json.loads(row["results_json"]),
        }
    )


@app.get("/api/security/rules")
def list_security_rules():
    return jsonify(get_rule_list())


@app.patch("/api/security/rules/<rule_id>")
def update_security_rule(rule_id: str):
    if rule_id not in {rule[0] for rule in RULE_DEFAULTS}:
        return jsonify({"error": "Unsupported security rule."}), 404
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("enabled"), bool):
        return jsonify({"error": "Request body must include a boolean 'enabled' value."}), 400
    with get_db() as conn:
        conn.execute(
            "UPDATE security_rules SET enabled = ? WHERE rule_id = ?",
            (int(payload["enabled"]), rule_id),
        )
    updated = next(rule for rule in get_rule_list() if rule["rule_id"] == rule_id)
    return jsonify(updated)


@app.get("/api/config")
def get_configuration():
    return jsonify(
        {
            "mode": "isolated-local-lab",
            "mockService": "in-process mock metadata provider",
            "externalRequestsEnabled": False,
            "cloudFindingsMode": cloud_findings_service.mode(),
            "cloudFindingsProvider": cloud_findings_service.provider(),
            "tokenTtlSeconds": TOKEN_TTL_SECONDS,
            "maximumTokenTtlSeconds": MAX_TOKEN_TTL_SECONDS,
            "allowedResources": sorted(ALLOWED_RESOURCES),
            "apiPort": int(os.environ.get("PORT", "5050")),
        }
    )


@app.route("/api/security/clear", methods=["POST", "DELETE"])
def clear_security_data():
    with get_db() as conn:
        conn.execute("DELETE FROM security_events")
        conn.execute("DELETE FROM test_runs")
        conn.execute("DELETE FROM sqlite_sequence WHERE name IN ('security_events', 'test_runs')")
    return jsonify({"status": "ok", "message": "Lab security events and saved test runs were cleared."})


initialize_database()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5050")),
        debug=False,
    )
