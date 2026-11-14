from __future__ import annotations

from typing import Any

from flask import Blueprint, current_app, jsonify, request

from backend.services.cloud_security_service import CloudSecurityService


cloud_security_routes = Blueprint("cloud_security", __name__)


def _service() -> CloudSecurityService:
    return current_app.extensions["cloud_security_service"]


def _page_arguments() -> tuple[int, int] | tuple[None, None]:
    try:
        limit = int(request.args.get("limit", "25"))
        cursor = int(request.args.get("cursor", "0"))
    except ValueError:
        return None, None
    if not 1 <= limit <= 100 or not 0 <= cursor <= 1000000:
        return None, None
    return limit, cursor


@cloud_security_routes.get("/api/cloud-security/health")
def cloud_security_health():
    return jsonify(_service().health(refresh=request.args.get("refresh") == "true"))


@cloud_security_routes.get("/api/cloud-security/status")
def cloud_security_status():
    return jsonify(_service().status())


@cloud_security_routes.post("/api/cloud-security/scan")
def start_cloud_security_scan():
    payload = request.get_json(silent=True)
    try:
        result = _service().start_scan(payload)
    except ValueError as error:
        return jsonify({"status": "error", "error": str(error)}), 400
    except PermissionError as error:
        return jsonify({"status": "error", "error": str(error)}), 403
    except FileNotFoundError as error:
        return jsonify({"status": "unavailable", "error": str(error)}), 503
    except BlockingIOError as error:
        return jsonify({"status": "conflict", "error": str(error)}), 409
    return jsonify(result), 202


@cloud_security_routes.get("/api/cloud-security/findings")
def list_cloud_security_findings():
    limit, cursor = _page_arguments()
    if limit is None:
        return jsonify(
            {"status": "error", "error": "limit must be 1–100 and cursor must be 0–1000000."}
        ), 400
    filters = {}
    for name in (
        "severity",
        "provider",
        "status",
        "service",
        "resource",
        "search",
        "scan_id",
    ):
        value = request.args.get(name, "").strip()
        if len(value) > 200:
            return jsonify({"status": "error", "error": f"{name} filter is too long."}), 400
        if value:
            filters[name] = value
    if filters.get("severity") and filters["severity"].lower() not in {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "unknown",
    }:
        return jsonify({"status": "error", "error": "Invalid severity filter."}), 400
    if filters.get("provider") and filters["provider"].lower() not in {
        "aws",
        "azure",
        "gcp",
        "iac",
    }:
        return jsonify({"status": "error", "error": "Invalid provider filter."}), 400

    source = request.args.get("source", "actual").lower()
    if source != "actual":
        return jsonify(
            {"status": "error", "error": "Only persisted Prowler scan findings are available."}
        ), 400
    try:
        return jsonify(
            _service().findings(
                limit=limit,
                cursor=cursor,
                filters=filters,
                source=source,
            )
        )
    except ValueError as error:
        return jsonify({"status": "error", "error": str(error)}), 400


@cloud_security_routes.get("/api/cloud-security/summary")
def cloud_security_summary():
    if request.args.get("source", "actual").lower() != "actual":
        return jsonify(
            {"status": "error", "error": "Only persisted Prowler scan findings are available."}
        ), 400
    scan_id = request.args.get("scan_id", "").strip()
    if len(scan_id) > 64:
        return jsonify({"status": "error", "error": "Invalid scan_id."}), 400
    return jsonify(_service().summary(scan_id=scan_id))


@cloud_security_routes.get("/api/cloud-security/compliance")
def cloud_security_compliance():
    scan_id = request.args.get("scan_id", "").strip()
    if len(scan_id) > 64:
        return jsonify({"status": "error", "error": "Invalid scan_id."}), 400
    return jsonify(_service().compliance(scan_id=scan_id))


@cloud_security_routes.get("/api/cloud-security/scan-history")
def cloud_security_scan_history():
    limit, cursor = _page_arguments()
    if limit is None:
        return jsonify(
            {"status": "error", "error": "limit must be 1–100 and cursor must be 0–1000000."}
        ), 400
    return jsonify(_service().scan_history(limit=limit, cursor=cursor))


@cloud_security_routes.get("/api/cloud-security/findings/<path:finding_id>")
def cloud_security_finding_detail(finding_id: str):
    if len(finding_id) > 256:
        return jsonify({"status": "error", "error": "Invalid finding ID."}), 400
    finding = _service().finding_detail(finding_id)
    if finding is None:
        return jsonify({"status": "not_found", "error": "Finding not found."}), 404
    return jsonify(finding)


@cloud_security_routes.post("/api/cloud-security/scan/<scan_id>/cancel")
def cancel_cloud_security_scan(scan_id: str):
    if len(scan_id) != 32 or any(char not in "0123456789abcdef" for char in scan_id):
        return jsonify({"status": "error", "error": "Invalid scan ID."}), 400
    try:
        return jsonify(_service().cancel_scan(scan_id))
    except LookupError as error:
        return jsonify({"status": "not_found", "error": str(error)}), 404
    except ValueError as error:
        return jsonify({"status": "conflict", "error": str(error)}), 409


def register_cloud_security_routes(
    app: Any,
    service: CloudSecurityService,
) -> None:
    app.extensions["cloud_security_service"] = service
    app.register_blueprint(cloud_security_routes)
