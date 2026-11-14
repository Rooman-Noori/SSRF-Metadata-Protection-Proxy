import json
import subprocess
import threading
import time

import pytest

import app as proxy_app
from backend.services.prowler_parser import (
    ProwlerReportError,
    normalize_finding,
    parse_report_file,
)
from backend.services.prowler_service import (
    ProwlerScanner,
    ScanExecution,
    ScannerInfo,
)


def ocsf_finding(
    *,
    finding_id="prowler-finding-001",
    status="FAIL",
    severity="High",
    provider="iac",
):
    return {
        "message": "Public access is enabled.",
        "severity": severity,
        "status": "New",
        "status_code": status,
        "risk_details": "The resource may expose sensitive data.",
        "time": 1740787200,
        "finding_info": {
            "uid": finding_id,
            "title": "Public access enabled",
            "desc": "The resource allows public access.",
            "created_time": 1740700800,
        },
        "metadata": {"event_code": "example_check"},
        "remediation": {"desc": "Disable public access."},
        "resources": [
            {
                "uid": "resource-001",
                "name": "example-bucket",
                "region": "local",
                "type": "storage",
                "group": {"name": "storage"},
            }
        ],
        "unmapped": {
            "provider": provider,
            "file_path": "docker-compose.yml",
            "compliance": [{"Framework": "CIS Benchmark"}],
        },
    }


class FakeScanner:
    def __init__(self, *, result=None, report=None, gate=None):
        self.result = result or ScanExecution(0, False, False, "", "")
        self.report = report
        self.gate = gate
        self.cancel_calls = []

    def detect(self, refresh=False):
        return ScannerInfo(True, "prowler", "Prowler 5.49.0", "")

    def execute(
        self,
        *,
        scan_id,
        provider,
        output_directory,
        cancel_event,
        on_process,
    ):
        if self.gate is not None:
            while not self.gate.wait(timeout=0.05):
                if cancel_event.is_set():
                    return ScanExecution(-1, False, True, "", "")
        if self.report is not None:
            (output_directory / "scan.ocsf.json").write_text(
                json.dumps([self.report]),
                encoding="utf-8",
            )
        return self.result

    def cancel(self, scan_id):
        self.cancel_calls.append(scan_id)
        return True


@pytest.fixture
def scanner_client(tmp_path, monkeypatch):
    service = proxy_app.cloud_security_service
    scanner = FakeScanner(report=ocsf_finding())
    monkeypatch.setattr(proxy_app, "DB_PATH", str(tmp_path / "security.db"))
    monkeypatch.setattr(service, "data_dir", tmp_path / "prowler-reports")
    monkeypatch.setattr(service, "scanner", scanner)
    service._initialized_db_path = ""
    service._active_scan_id = None
    service._cancel_events.clear()
    service._threads.clear()
    service.initialize_database()
    with proxy_app.app.test_client() as test_client:
        yield test_client, service, scanner
    for thread in list(service._threads.values()):
        thread.join(timeout=3)
    service._active_scan_id = None
    service._cancel_events.clear()
    service._threads.clear()


def wait_for_status(service, scan_id, status):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        scan = service.get_scan(scan_id)
        if scan and scan["status"] == status:
            return scan
        time.sleep(0.02)
    raise AssertionError(f"Scan {scan_id} did not reach status {status}.")


def test_normalize_finding_uses_report_values_without_inventing_missing_fields():
    finding = normalize_finding(
        ocsf_finding(),
        scan_id="scan-123",
        scan_provider="iac",
    )

    assert finding["finding_id"] == "prowler-finding-001"
    assert finding["check_id"] == "example_check"
    assert finding["provider"] == "iac"
    assert finding["severity"] == "high"
    assert finding["status"] == "fail"
    assert finding["affected_file"] == "docker-compose.yml"
    assert finding["service"] == "storage"
    assert finding["resource_id"] == "resource-001"
    assert finding["detected_at"] == "2025-02-28T00:00:00Z"
    assert finding["compliance_frameworks"] == ["CIS Benchmark"]
    assert finding["raw"] == ocsf_finding()

    missing = normalize_finding(
        {"resources": [], "finding_info": {}},
        scan_id="scan-123",
        scan_provider="iac",
    )
    assert missing["finding_id"] == ""
    assert missing["title"] == ""
    assert missing["region"] == ""
    assert missing["compliance_frameworks"] == []


def test_parse_report_file_accepts_actual_json_array_and_rejects_malformed(tmp_path):
    report = tmp_path / "report.ocsf.json"
    report.write_text(json.dumps([ocsf_finding()]), encoding="utf-8")

    parsed = parse_report_file(report, scan_id="scan-123", scan_provider="iac")
    assert len(parsed) == 1
    assert parsed[0]["finding_id"] == "prowler-finding-001"

    report.write_text("{broken", encoding="utf-8")
    with pytest.raises(ProwlerReportError):
        parse_report_file(report, scan_id="scan-123", scan_provider="iac")


def test_scanner_detection_and_version_are_explicit(tmp_path, monkeypatch):
    scanner = ProwlerScanner(tmp_path)
    executable = tmp_path / "prowler.exe"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setenv("PROWLER_EXECUTABLE", str(executable))
    def fake_run(args, **kwargs):
        if args[1:] == ["-v"]:
            return subprocess.CompletedProcess(
                args, 0, stdout="Prowler 5.49.0\n", stderr=""
            )
        return subprocess.CompletedProcess(
            args,
            0,
            stdout="--scan-path --output-formats json-ocsf --output-directory",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    info = scanner.detect(refresh=True)

    assert info.installed is True
    assert info.version == "Prowler 5.49.0"
    assert info.error == ""
    assert scanner.build_command(
        provider="iac",
        output_directory=tmp_path / "output",
    ) == [
        str(executable),
        "iac",
        "--output-formats",
        "json-ocsf",
        "--output-directory",
        str(tmp_path / "output"),
        "--scan-path",
        str(tmp_path.resolve()),
    ]


def test_scanner_health_reports_missing_installation(scanner_client, monkeypatch):
    client, service, _ = scanner_client
    monkeypatch.setattr(
        service.scanner,
        "detect",
        lambda refresh=False: ScannerInfo(False, "", "", "Scanner not installed or configured."),
    )

    response = client.get("/api/cloud-security/health")

    assert response.status_code == 200
    assert response.get_json()["installed"] is False
    assert response.get_json()["error"] == "Scanner not installed or configured."


def test_local_iac_scan_needs_no_cloud_auth_and_persists_findings(scanner_client, monkeypatch):
    client, service, _ = scanner_client
    for variable in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
    ):
        monkeypatch.delenv(variable, raising=False)

    response = client.post("/api/cloud-security/scan", json={"provider": "iac"})
    assert response.status_code == 202
    scan_id = response.get_json()["scan_id"]
    scan = wait_for_status(service, scan_id, "completed")

    findings = client.get("/api/cloud-security/findings").get_json()
    summary = client.get(f"/api/cloud-security/summary?scan_id={scan_id}").get_json()
    compliance = client.get(
        f"/api/cloud-security/compliance?scan_id={scan_id}"
    ).get_json()
    history = client.get("/api/cloud-security/scan-history").get_json()
    detail = client.get(
        "/api/cloud-security/findings/prowler-finding-001"
    ).get_json()

    assert scan["mode"] == "local_assessment"
    assert scan["findings_count"] == 1
    assert findings["source"] == "actual"
    assert findings["items"][0]["raw"]["metadata"]["event_code"] == "example_check"
    assert summary["high"] == 1
    assert summary["failed_checks"] == 1
    assert compliance["frameworks"] == ["CIS Benchmark"]
    assert history["items"][0]["scan_id"] == scan_id
    assert detail["finding_id"] == "prowler-finding-001"


def test_findings_endpoint_never_returns_demo_data(scanner_client):
    client, _, _ = scanner_client
    actual = client.get("/api/cloud-security/findings").get_json()
    assert actual["items"] == []
    assert actual["source"] == "actual"
    assert client.get("/api/cloud-security/findings?source=demo").status_code == 400
    assert client.get("/api/cloud-security/summary?source=demo").status_code == 400


def test_cloud_scan_requires_authorization_and_backend_credentials(scanner_client, monkeypatch):
    client, _, _ = scanner_client
    for variable in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
    ):
        monkeypatch.delenv(variable, raising=False)

    unauthorized = client.post(
        "/api/cloud-security/scan",
        json={"provider": "aws", "authorized": False},
    )
    unauthenticated = client.post(
        "/api/cloud-security/scan",
        json={"provider": "aws", "authorized": True},
    )

    assert unauthorized.status_code == 403
    assert unauthenticated.status_code == 403
    assert "authentication failed" in unauthenticated.get_json()["error"].lower()


@pytest.mark.parametrize(
    "payload",
    [
        {"provider": "invalid"},
        {"provider": "iac", "scan_path": "C:\\Windows"},
        {"provider": "iac", "args": ["--no-check"]},
        {"provider": "iac", "executable": "python"},
        {"provider": "iac", "mode": "live"},
    ],
)
def test_scan_request_rejects_unsupported_provider_or_arbitrary_input(
    scanner_client, payload
):
    client, _, _ = scanner_client
    response = client.post("/api/cloud-security/scan", json=payload)

    assert response.status_code == 400
    assert response.get_json()["status"] == "error"


def test_failed_and_timed_out_scans_keep_real_status(scanner_client, monkeypatch):
    client, service, scanner = scanner_client
    scanner.report = None
    scanner.result = ScanExecution(1, False, False, "", "scanner error")

    failed_response = client.post(
        "/api/cloud-security/scan",
        json={"provider": "iac"},
    )
    failed = wait_for_status(service, failed_response.get_json()["scan_id"], "failed")
    assert failed["exit_code"] == 1

    scanner.result = ScanExecution(-1, True, False, "", "")
    timed_out_response = client.post(
        "/api/cloud-security/scan",
        json={"provider": "iac"},
    )
    timed_out = wait_for_status(
        service,
        timed_out_response.get_json()["scan_id"],
        "timed_out",
    )
    assert "timeout" in timed_out["error_message"].lower()


def test_cancel_endpoint_cancels_active_scan(scanner_client):
    client, service, scanner = scanner_client
    scanner.gate = threading.Event()
    response = client.post("/api/cloud-security/scan", json={"provider": "iac"})
    scan_id = response.get_json()["scan_id"]

    cancelled_response = client.post(
        f"/api/cloud-security/scan/{scan_id}/cancel"
    )

    assert cancelled_response.status_code == 200
    scan = wait_for_status(service, scan_id, "cancelled")
    assert scan["status"] == "cancelled"
    assert scanner.cancel_calls == [scan_id]


def test_pagination_and_filters_are_validated(scanner_client):
    client, service, scanner = scanner_client
    scanner.report = ocsf_finding()
    response = client.post("/api/cloud-security/scan", json={"provider": "iac"})
    scan_id = response.get_json()["scan_id"]
    wait_for_status(service, scan_id, "completed")

    filtered = client.get(
        "/api/cloud-security/findings?severity=high&provider=iac&service=storage"
    )
    invalid = client.get("/api/cloud-security/findings?severity=urgent")
    bad_page = client.get("/api/cloud-security/findings?limit=101")

    assert len(filtered.get_json()["items"]) == 1
    assert invalid.status_code == 400
    assert bad_page.status_code == 400
