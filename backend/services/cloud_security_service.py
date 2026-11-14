from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from backend.services.prowler_parser import ProwlerReportError, parse_output_directory
from backend.services.prowler_service import (
    SUPPORTED_PROVIDERS,
    ProwlerScanner,
)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class CloudSecurityService:
    def __init__(
        self,
        project_root: Path,
        database_path: Callable[[], str],
        scanner: ProwlerScanner | None = None,
    ) -> None:
        self.project_root = project_root.resolve()
        self._database_path = database_path
        self.scanner = scanner or ProwlerScanner(self.project_root)
        configured_data_dir = os.environ.get("METAGUARD_PROWLER_DATA_DIR", "").strip()
        if configured_data_dir:
            data_dir = Path(configured_data_dir)
        elif os.environ.get("LOCALAPPDATA"):
            data_dir = Path(os.environ["LOCALAPPDATA"]) / "MetaGuard" / "prowler"
        else:
            data_dir = Path.home() / ".local" / "share" / "metaguard" / "prowler"
        self.data_dir = data_dir.resolve()
        self._scan_lock = threading.Lock()
        self._active_scan_id: str | None = None
        self._cancel_events: dict[str, threading.Event] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._initialize_lock = threading.Lock()
        self._initialized_db_path = ""

    def _connect(self) -> sqlite3.Connection:
        database_path = self._database_path()
        parent = os.path.dirname(database_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        connection = sqlite3.connect(database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def initialize_database(self) -> None:
        with self._initialize_lock:
            database_path = self._database_path()
            if self._initialized_db_path == database_path:
                return
            with self._connection() as connection:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS prowler_scans (
                        scan_id TEXT PRIMARY KEY,
                        provider TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        status TEXT NOT NULL,
                        submitted_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT,
                        exit_code INTEGER,
                        findings_count INTEGER NOT NULL DEFAULT 0,
                        passed_count INTEGER NOT NULL DEFAULT 0,
                        failed_count INTEGER NOT NULL DEFAULT 0,
                        error_message TEXT NOT NULL DEFAULT '',
                        compliance_json TEXT NOT NULL DEFAULT '[]'
                    )
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS prowler_findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL REFERENCES prowler_scans(scan_id)
                            ON DELETE CASCADE,
                        finding_id TEXT NOT NULL,
                        check_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL,
                        provider TEXT NOT NULL,
                        service TEXT NOT NULL,
                        resource_id TEXT NOT NULL,
                        resource_name TEXT NOT NULL,
                        affected_file TEXT NOT NULL DEFAULT '',
                        region TEXT NOT NULL,
                        risk_details TEXT NOT NULL,
                        remediation TEXT NOT NULL,
                        compliance_json TEXT NOT NULL,
                        source TEXT NOT NULL,
                        detected_at TEXT NOT NULL,
                        last_updated TEXT NOT NULL,
                        raw_json TEXT NOT NULL
                    )
                    """
                )
                finding_columns = {
                    row["name"]
                    for row in connection.execute("PRAGMA table_info(prowler_findings)")
                }
                if "affected_file" not in finding_columns:
                    connection.execute(
                        "ALTER TABLE prowler_findings ADD COLUMN affected_file TEXT NOT NULL DEFAULT ''"
                    )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_prowler_findings_scan ON prowler_findings(scan_id, id)"
                )
                connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_prowler_findings_filters ON prowler_findings(provider, severity, status, service)"
                )
                connection.execute(
                    """
                    UPDATE prowler_scans
                    SET status = 'failed',
                        completed_at = ?,
                        error_message = 'Scanner backend restarted before this scan completed.'
                    WHERE status IN ('queued', 'running')
                    """,
                    (utc_timestamp(),),
                )
            self._initialized_db_path = database_path

    @staticmethod
    def _cloud_auth_configured(provider: str) -> bool:
        if provider == "aws":
            access_key = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
            secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
            role_arn = os.environ.get("AWS_ROLE_ARN", "").strip()
            token_file = os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE", "").strip()
            web_identity_configured = bool(
                role_arn and token_file and Path(token_file).is_file()
            )
            return bool(access_key and secret_key or web_identity_configured)
        if provider == "azure":
            return all(
                os.environ.get(key, "").strip()
                for key in (
                    "AZURE_CLIENT_ID",
                    "AZURE_CLIENT_SECRET",
                    "AZURE_TENANT_ID",
                    "AZURE_SUBSCRIPTION_ID",
                )
            )
        if provider == "gcp":
            credential_file = os.environ.get(
                "GOOGLE_APPLICATION_CREDENTIALS", ""
            ).strip()
            return bool(credential_file and Path(credential_file).is_file())
        return True

    def health(self, *, refresh: bool = False) -> dict[str, Any]:
        scanner_info = self.scanner.detect(refresh=refresh)
        status = self.status()
        return {
            "status": "ok" if scanner_info.installed else "unavailable",
            "scanner": "prowler",
            "installed": scanner_info.installed,
            "version": scanner_info.version,
            "error": scanner_info.error,
            "cloud_providers_ready": {
                provider: self._cloud_auth_configured(provider)
                for provider in ("aws", "azure", "gcp")
            },
            "active_scan": status.get("active_scan"),
        }

    def start_scan(self, payload: Any) -> dict[str, Any]:
        self.initialize_database()
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
        provider = payload.get("provider")
        if not isinstance(provider, str) or provider not in SUPPORTED_PROVIDERS:
            raise ValueError("provider must be one of iac, aws, azure, or gcp.")

        if "scan_path" in payload or "args" in payload or "executable" in payload:
            raise ValueError("Custom scan paths, commands, and executables are not accepted.")
        if provider == "iac":
            if payload.get("mode") not in {None, "local"}:
                raise ValueError("The iac provider supports local mode only.")
            mode = "local_assessment"
        else:
            if payload.get("mode") not in {None, "live"}:
                raise ValueError("Cloud providers require live mode.")
            if payload.get("authorized") is not True:
                raise PermissionError("Confirm that you are authorized to scan this cloud account.")
            if not self._cloud_auth_configured(provider):
                raise PermissionError(
                    f"Cloud authentication failed for {provider}. No live scan was started."
                )
            mode = "live_scan"

        scanner_info = self.scanner.detect(refresh=True)
        if not scanner_info.installed:
            raise FileNotFoundError("Scanner not installed or configured.")

        with self._scan_lock:
            if self._active_scan_id is not None:
                raise BlockingIOError("A Prowler scan is already running.")
            scan_id = uuid.uuid4().hex
            submitted_at = utc_timestamp()
            with self._connection() as connection:
                active = connection.execute(
                    "SELECT scan_id FROM prowler_scans WHERE status IN ('queued', 'running') LIMIT 1"
                ).fetchone()
                if active:
                    raise BlockingIOError("A Prowler scan is already running.")
                connection.execute(
                    """
                    INSERT INTO prowler_scans
                    (scan_id, provider, mode, status, submitted_at)
                    VALUES (?, ?, ?, 'queued', ?)
                    """,
                    (scan_id, provider, mode, submitted_at),
                )
            cancel_event = threading.Event()
            thread = threading.Thread(
                target=self._run_scan,
                args=(scan_id, provider, mode, cancel_event),
                name=f"prowler-{scan_id[:8]}",
                daemon=True,
            )
            self._active_scan_id = scan_id
            self._cancel_events[scan_id] = cancel_event
            self._threads[scan_id] = thread
            thread.start()
        return self.get_scan(scan_id)

    def _run_scan(
        self,
        scan_id: str,
        provider: str,
        mode: str,
        cancel_event: threading.Event,
    ) -> None:
        self.initialize_database()
        output_directory = (self.data_dir / scan_id).resolve()
        if not output_directory.is_relative_to(self.data_dir):
            self._finish_scan(
                scan_id,
                status="failed",
                error="Unsafe scanner output directory.",
            )
            return
        try:
            output_directory.mkdir(parents=True, exist_ok=False)
            started_at = utc_timestamp()
            with self._connection() as connection:
                connection.execute(
                    "UPDATE prowler_scans SET status = 'running', started_at = ? WHERE scan_id = ?",
                    (started_at, scan_id),
                )
            execution = self.scanner.execute(
                scan_id=scan_id,
                provider=provider,
                output_directory=output_directory,
                cancel_event=cancel_event,
                on_process=lambda process: None,
            )
            if execution.cancelled or cancel_event.is_set():
                self._finish_scan(
                    scan_id,
                    status="cancelled",
                    exit_code=execution.return_code,
                    error="Scan cancelled by operator.",
                )
                return
            if execution.timed_out:
                self._finish_scan(
                    scan_id,
                    status="timed_out",
                    exit_code=execution.return_code,
                    error="Prowler scan exceeded its configured timeout.",
                )
                return

            try:
                findings = parse_output_directory(
                    output_directory,
                    scan_id=scan_id,
                    scan_provider=provider,
                )
            except ProwlerReportError as error:
                self._finish_scan(
                    scan_id,
                    status="failed",
                    exit_code=execution.return_code,
                    error=str(error),
                )
                return

            passed_count = sum(
                1 for finding in findings if finding["status"] in {"pass", "passed"}
            )
            failed_count = sum(
                1 for finding in findings if finding["status"] in {"fail", "failed"}
            )
            error_message = ""
            if execution.return_code not in {0, 3}:
                status = "partial" if findings else "failed"
                error_message = self._classify_error(execution.stderr)
            else:
                status = "completed"
            self._persist_findings(
                scan_id,
                findings,
                status=status,
                exit_code=execution.return_code,
                passed_count=passed_count,
                failed_count=failed_count,
                error=error_message,
            )
        except (OSError, RuntimeError, ValueError) as error:
            self._finish_scan(scan_id, status="failed", error=str(error))
        finally:
            with self._scan_lock:
                self._cancel_events.pop(scan_id, None)
                self._threads.pop(scan_id, None)
                if self._active_scan_id == scan_id:
                    self._active_scan_id = None

    @staticmethod
    def _classify_error(stderr: str) -> str:
        message = stderr.lower()
        if any(
            indicator in message
            for indicator in (
                "authentication",
                "credential",
                "accessdenied",
                "unauthorized",
                "invalid token",
                "expiredtoken",
            )
        ):
            return "Cloud authentication failed. No live findings retrieved."
        return "Prowler scan failed. Check the scanner installation and provider configuration."

    def _persist_findings(
        self,
        scan_id: str,
        findings: list[dict[str, Any]],
        *,
        status: str,
        exit_code: int,
        passed_count: int,
        failed_count: int,
        error: str,
    ) -> None:
        compliance = sorted(
            {
                framework
                for finding in findings
                for framework in finding["compliance_frameworks"]
            }
        )
        with self._connection() as connection:
            for finding in findings:
                connection.execute(
                    """
                    INSERT INTO prowler_findings (
                        scan_id, finding_id, check_id, title, description, severity,
                        status, provider, service, resource_id, resource_name, affected_file,
                        region, risk_details, remediation, compliance_json, source,
                        detected_at, last_updated, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        finding["finding_id"],
                        finding["check_id"],
                        finding["title"],
                        finding["description"],
                        finding["severity"],
                        finding["status"],
                        finding["provider"],
                        finding["service"],
                        finding["resource_id"],
                        finding["resource_name"],
                        finding["affected_file"],
                        finding["region"],
                        finding["risk_details"],
                        finding["remediation"],
                        json.dumps(finding["compliance_frameworks"]),
                        finding["source"],
                        finding["detected_at"],
                        finding["last_updated"],
                        json.dumps(finding["raw"], ensure_ascii=False),
                    ),
                )
            connection.execute(
                """
                UPDATE prowler_scans
                SET status = ?, completed_at = ?, exit_code = ?, findings_count = ?,
                    passed_count = ?, failed_count = ?, error_message = ?, compliance_json = ?
                WHERE scan_id = ?
                """,
                (
                    status,
                    utc_timestamp(),
                    exit_code,
                    len(findings),
                    passed_count,
                    failed_count,
                    error,
                    json.dumps(compliance),
                    scan_id,
                ),
            )

    def _finish_scan(
        self,
        scan_id: str,
        *,
        status: str,
        exit_code: int | None = None,
        error: str,
    ) -> None:
        with self._connection() as connection:
            connection.execute(
                """
                UPDATE prowler_scans
                SET status = ?, completed_at = ?, exit_code = ?, error_message = ?
                WHERE scan_id = ?
                """,
                (status, utc_timestamp(), exit_code, error[:500], scan_id),
            )

    def cancel_scan(self, scan_id: str) -> dict[str, Any]:
        self.initialize_database()
        with self._scan_lock:
            cancel_event = self._cancel_events.get(scan_id)
            if cancel_event is None:
                scan = self.get_scan(scan_id)
                if scan is None:
                    raise LookupError("Scan not found.")
                raise ValueError("Scan is not active.")
            cancel_event.set()
            self.scanner.cancel(scan_id)
        return self.get_scan(scan_id)

    def status(self) -> dict[str, Any]:
        self.initialize_database()
        with self._connection() as connection:
            active = connection.execute(
                """
                SELECT scan_id, provider, mode, status, submitted_at, started_at,
                       completed_at, findings_count, error_message
                FROM prowler_scans
                WHERE status IN ('queued', 'running')
                ORDER BY submitted_at DESC LIMIT 1
                """
            ).fetchone()
            latest = connection.execute(
                """
                SELECT scan_id, provider, mode, status, submitted_at, started_at,
                       completed_at, exit_code, findings_count, passed_count,
                       failed_count, error_message
                FROM prowler_scans ORDER BY submitted_at DESC LIMIT 1
                """
            ).fetchone()
        return {
            "active_scan": self._scan_row(active) if active else None,
            "latest_scan": self._scan_row(latest) if latest else None,
        }

    @staticmethod
    def _scan_row(row: sqlite3.Row) -> dict[str, Any]:
        scan = {key: row[key] for key in row.keys()}
        compliance_json = scan.pop("compliance_json", "[]")
        scan["compliance_frameworks"] = json.loads(compliance_json)
        return scan

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        self.initialize_database()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM prowler_scans WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
        return self._scan_row(row) if row else None

    def scan_history(self, *, limit: int, cursor: int) -> dict[str, Any]:
        self.initialize_database()
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT scan_id, provider, mode, status, submitted_at, started_at,
                       completed_at, exit_code, findings_count, passed_count,
                       failed_count, error_message
                FROM prowler_scans ORDER BY submitted_at DESC LIMIT ? OFFSET ?
                """,
                (limit + 1, cursor),
            ).fetchall()
        has_more = len(rows) > limit
        return {
            "items": [self._scan_row(row) for row in rows[:limit]],
            "next_cursor": str(cursor + limit) if has_more else None,
            "has_more": has_more,
        }

    def findings(
        self,
        *,
        limit: int,
        cursor: int,
        filters: dict[str, str],
        source: str = "actual",
    ) -> dict[str, Any]:
        self.initialize_database()
        if source != "actual":
            raise ValueError("Only persisted Prowler scan findings are available.")

        clauses: list[str] = []
        parameters: list[Any] = []
        for field in ("severity", "provider", "status", "service"):
            if filters.get(field):
                clauses.append(f"{field} = ?")
                parameters.append(filters[field].lower())
        if filters.get("resource"):
            clauses.append(
                "(resource_name LIKE ? OR resource_id LIKE ? OR affected_file LIKE ?)"
            )
            needle = f"%{filters['resource']}%"
            parameters.extend([needle, needle, needle])
        if filters.get("search"):
            clauses.append(
                "(title LIKE ? OR description LIKE ? OR check_id LIKE ? "
                "OR resource_name LIKE ? OR affected_file LIKE ?)"
            )
            needle = f"%{filters['search']}%"
            parameters.extend([needle] * 5)
        if filters.get("scan_id"):
            clauses.append("scan_id = ?")
            parameters.append(filters["scan_id"])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connection() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM prowler_findings {where}
                ORDER BY detected_at DESC, id DESC LIMIT ? OFFSET ?
                """,
                [*parameters, limit + 1, cursor],
            ).fetchall()
        has_more = len(rows) > limit
        items = [self._finding_row(row) for row in rows[:limit]]
        return {
            "items": items,
            "next_cursor": str(cursor + limit) if has_more else None,
            "has_more": has_more,
            "source": "actual",
        }

    @staticmethod
    def _finding_row(row: sqlite3.Row) -> dict[str, Any]:
        finding = {key: row[key] for key in row.keys() if key != "raw_json"}
        finding["compliance_frameworks"] = json.loads(finding.pop("compliance_json"))
        finding["raw"] = json.loads(row["raw_json"])
        return finding

    def finding_detail(self, finding_id: str) -> dict[str, Any] | None:
        self.initialize_database()
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT * FROM prowler_findings
                WHERE finding_id = ? ORDER BY id DESC LIMIT 1
                """,
                (finding_id,),
            ).fetchone()
        return self._finding_row(row) if row else None

    def summary(self, *, scan_id: str = "") -> dict[str, Any]:
        self.initialize_database()
        where = "WHERE scan_id = ?" if scan_id else ""
        params = (scan_id,) if scan_id else ()
        with self._connection() as connection:
            count_rows = connection.execute(
                f"SELECT severity, status, COUNT(*) AS count FROM prowler_findings {where} GROUP BY severity, status",
                params,
            ).fetchall()
            scan = connection.execute(
                """
                SELECT scan_id, provider, mode, status, completed_at, passed_count,
                       failed_count, findings_count
                FROM prowler_scans WHERE scan_id = ?
                """,
                (scan_id,),
            ).fetchone() if scan_id else connection.execute(
                """
                SELECT scan_id, provider, mode, status, completed_at, passed_count,
                       failed_count, findings_count
                FROM prowler_scans ORDER BY submitted_at DESC LIMIT 1
                """
            ).fetchone()

        by_severity: dict[str, int] = {}
        by_status: dict[str, int] = {}
        total = 0
        for row in count_rows:
            severity = row["severity"] or "unknown"
            status = row["status"] or "unknown"
            by_severity[severity] = by_severity.get(severity, 0) + row["count"]
            by_status[status] = by_status.get(status, 0) + row["count"]
            total += row["count"]
        return {
            "total_findings": total,
            "by_severity": by_severity,
            "by_status": by_status,
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
            "passed_checks": by_status.get("pass", 0) + by_status.get("passed", 0),
            "failed_checks": by_status.get("fail", 0) + by_status.get("failed", 0),
            "scan": self._scan_row(scan) if scan else None,
            "source": "actual",
        }

    def compliance(self, *, scan_id: str = "") -> dict[str, Any]:
        self.initialize_database()
        with self._connection() as connection:
            if scan_id:
                row = connection.execute(
                    "SELECT compliance_json, mode FROM prowler_scans WHERE scan_id = ?",
                    (scan_id,),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT scan_id, compliance_json, mode FROM prowler_scans
                    ORDER BY submitted_at DESC LIMIT 1
                    """
                ).fetchone()
        return {
            "scan_id": scan_id or (row["scan_id"] if row else None),
            "source": "actual",
            "mode": row["mode"] if row else None,
            "frameworks": json.loads(row["compliance_json"]) if row else [],
        }

