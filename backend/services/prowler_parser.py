from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ProwlerReportError(ValueError):
    pass


_FILE_PATH_KEYS = {
    "file_path",
    "filepath",
    "filename",
    "source_file",
    "source_path",
}
_IAC_FILE_SUFFIXES = {
    ".arm",
    ".bicep",
    ".cf",
    ".json",
    ".tf",
    ".tf.json",
    ".yaml",
    ".yml",
}


def _iso_timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    if isinstance(value, str):
        return value
    return ""


def _first_resource(record: dict[str, Any]) -> dict[str, Any]:
    resources = record.get("resources")
    if isinstance(resources, list) and resources and isinstance(resources[0], dict):
        return resources[0]
    return {}


def _find_file_path(value: Any) -> str:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in _FILE_PATH_KEYS and isinstance(child, str) and child:
                return child
        for child in value.values():
            path = _find_file_path(child)
            if path:
                return path
    elif isinstance(value, list):
        for child in value:
            path = _find_file_path(child)
            if path:
                return path
    return ""


def _resource_file_path(resource: dict[str, Any]) -> str:
    for candidate in (resource.get("uid"), resource.get("name")):
        if not isinstance(candidate, str) or not candidate:
            continue
        path = candidate.removeprefix("file://")
        filename = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        if filename == "dockerfile" or filename.startswith("dockerfile.") or any(
            filename.endswith(suffix) for suffix in _IAC_FILE_SUFFIXES
        ):
            return candidate
    return ""


def _compliance_frameworks(record: dict[str, Any]) -> list[str]:
    unmapped = record.get("unmapped")
    compliance = unmapped.get("compliance") if isinstance(unmapped, dict) else None
    if not isinstance(compliance, (list, dict)):
        return []

    values = compliance.values() if isinstance(compliance, dict) else compliance
    frameworks: list[str] = []
    for item in values:
        if isinstance(item, str):
            frameworks.append(item)
        elif isinstance(item, dict):
            framework = (
                item.get("Framework")
                or item.get("framework")
                or item.get("FrameworkName")
                or item.get("framework_name")
            )
            if isinstance(framework, str) and framework:
                frameworks.append(framework)
    return list(dict.fromkeys(frameworks))


def normalize_finding(
    record: dict[str, Any],
    *,
    scan_id: str,
    scan_provider: str,
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ProwlerReportError("A finding record must be a JSON object.")

    finding_info = record.get("finding_info")
    finding_info = finding_info if isinstance(finding_info, dict) else {}
    resource = _first_resource(record)
    resource_group = resource.get("group")
    resource_group = resource_group if isinstance(resource_group, dict) else {}
    metadata = record.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    unmapped = record.get("unmapped")
    unmapped = unmapped if isinstance(unmapped, dict) else {}
    cloud = record.get("cloud")
    cloud = cloud if isinstance(cloud, dict) else {}

    finding_provider = unmapped.get("provider") or cloud.get("provider") or scan_provider
    affected_file = _find_file_path(record) if scan_provider == "iac" else ""
    if not affected_file and scan_provider == "iac":
        affected_file = _resource_file_path(resource)
    check_id = metadata.get("event_code") or ""
    finding_uid = finding_info.get("uid") or ""
    identifier = finding_uid or record.get("uid") or ""
    status = record.get("status_code") or record.get("status") or ""
    title = finding_info.get("title") or ""
    description = finding_info.get("desc") or record.get("message") or ""
    remediation = record.get("remediation")
    remediation = remediation if isinstance(remediation, dict) else {}

    return {
        "finding_id": str(identifier),
        "check_id": str(check_id),
        "title": str(title),
        "description": str(description),
        "severity": str(record.get("severity") or "").lower(),
        "status": str(status).lower(),
        "provider": str(finding_provider).lower(),
        "service": str(resource_group.get("name") or ""),
        "resource_id": str(resource.get("uid") or ""),
        "resource_name": str(resource.get("name") or ""),
        "affected_file": affected_file,
        "region": str(resource.get("region") or ""),
        "risk_details": str(record.get("risk_details") or ""),
        "remediation": str(remediation.get("desc") or ""),
        "compliance_frameworks": _compliance_frameworks(record),
        "scan_id": scan_id,
        "source": "prowler",
        "detected_at": _iso_timestamp(
            finding_info.get("created_time_dt")
            or finding_info.get("created_time")
            or finding_info.get("time")
        ),
        "last_updated": _iso_timestamp(
            record.get("time_dt") or record.get("time") or record.get("timestamp")
        ),
        "raw": record,
    }


def parse_report_file(
    path: Path,
    *,
    scan_id: str,
    scan_provider: str,
) -> list[dict[str, Any]]:
    try:
        content = path.read_text(encoding="utf-8-sig")
        document = json.loads(content)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProwlerReportError(
            f"Prowler report could not be read as JSON ({path.name})."
        ) from error

    if isinstance(document, list):
        records = document
    elif isinstance(document, dict):
        records = document.get("findings")
        if not isinstance(records, list):
            raise ProwlerReportError(
                f"Prowler report has an unsupported JSON shape ({path.name})."
            )
    else:
        raise ProwlerReportError(
            f"Prowler report has an unsupported JSON shape ({path.name})."
        )

    findings: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            raise ProwlerReportError(
                f"Prowler report contains a non-object finding ({path.name})."
            )
        findings.append(
            normalize_finding(record, scan_id=scan_id, scan_provider=scan_provider)
        )
    return findings


def parse_output_directory(
    output_directory: Path,
    *,
    scan_id: str,
    scan_provider: str,
) -> list[dict[str, Any]]:
    report_files = sorted(
        path
        for path in output_directory.glob("*.json")
        if path.is_file() and not path.is_symlink()
    )
    if not report_files:
        raise ProwlerReportError("Prowler did not produce a JSON report.")

    findings: list[dict[str, Any]] = []
    for path in report_files:
        findings.extend(
            parse_report_file(path, scan_id=scan_id, scan_provider=scan_provider)
        )
    return findings
