from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


os.environ["AWS_EC2_METADATA_DISABLED"] = "true"

CACHE_TTL_SECONDS = 60
AWS_PAGE_SIZE = 100
MAX_FINDINGS = 5000


class FindingsError(Exception):
    status_code = 502
    public_message = "The cloud findings provider is unavailable."


class FindingsConfigurationError(FindingsError):
    status_code = 503
    public_message = "Live findings are not configured. Check the backend AWS settings."


class FindingsAuthenticationError(FindingsError):
    status_code = 503
    public_message = "AWS Security Hub authentication or authorization failed."


class FindingsRateLimitError(FindingsError):
    status_code = 429
    public_message = "AWS Security Hub rate limit was reached. Retry after a short delay."


class FindingsProviderError(FindingsError):
    status_code = 502
    public_message = "AWS Security Hub could not return findings."


@dataclass(frozen=True)
class FindingsSnapshot:
    items: list[dict[str, Any]]
    fetched_at: str
    truncated: bool
    mode: str
    provider: str


DEMO_FINDINGS = [
    {
        "finding_id": "demo-aws-001",
        "title": "Demo storage resource is publicly accessible",
        "description": "Synthetic example only. No AWS resource was inspected.",
        "severity": "high",
        "status": "new",
        "resource_name": "demo-storage-bucket",
        "resource_type": "AwsS3Bucket",
        "cloud_provider": "aws",
        "created_at": "2025-01-15T10:00:00Z",
        "updated_at": "2025-01-15T10:00:00Z",
        "remediation": "Demo guidance: review the resource's public-access settings.",
    },
    {
        "finding_id": "demo-aws-002",
        "title": "Demo compute resource has a missing security update",
        "description": "Synthetic example only. No AWS resource was inspected.",
        "severity": "medium",
        "status": "new",
        "resource_name": "i-demo0000000000001",
        "resource_type": "AwsEc2Instance",
        "cloud_provider": "aws",
        "created_at": "2025-01-14T08:30:00Z",
        "updated_at": "2025-01-14T08:30:00Z",
        "remediation": "Demo guidance: review and apply the relevant security update.",
    },
    {
        "finding_id": "demo-aws-003",
        "title": "Demo encryption setting needs review",
        "description": "Synthetic example only. No AWS resource was inspected.",
        "severity": "low",
        "status": "resolved",
        "resource_name": "demo-volume",
        "resource_type": "AwsEc2Volume",
        "cloud_provider": "aws",
        "created_at": "2025-01-12T12:00:00Z",
        "updated_at": "2025-01-13T12:00:00Z",
        "remediation": "Demo guidance: verify that encryption is enabled.",
    },
]


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    severity_data = finding.get("Severity") or {}
    workflow_data = finding.get("Workflow") or {}
    resources = finding.get("Resources") or []
    resource = resources[0] if resources else {}
    recommendation = (
        (finding.get("Remediation") or {}).get("Recommendation") or {}
    )
    remediation = recommendation.get("Text") or recommendation.get("Url") or ""

    return {
        "finding_id": finding.get("Id") or "",
        "title": finding.get("Title") or "Untitled finding",
        "description": finding.get("Description") or "",
        "severity": str(severity_data.get("Label") or "unknown").lower(),
        "status": str(workflow_data.get("Status") or "unknown").lower(),
        "resource_name": resource.get("Name") or resource.get("Id") or "",
        "resource_type": resource.get("Type") or "",
        "cloud_provider": "aws",
        "created_at": finding.get("CreatedAt") or "",
        "updated_at": finding.get("UpdatedAt") or "",
        "remediation": remediation,
    }


class CloudFindingsService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot: FindingsSnapshot | None = None
        self._cached_at = 0.0

    @staticmethod
    def mode() -> str:
        mode = os.environ.get("METAGUARD_CLOUD_FINDINGS_MODE", "demo").strip().lower()
        if mode not in {"demo", "live"}:
            raise FindingsConfigurationError(
                "METAGUARD_CLOUD_FINDINGS_MODE must be 'demo' or 'live'."
            )
        return mode

    @staticmethod
    def provider() -> str:
        if CloudFindingsService.mode() == "demo":
            return "demo"
        provider = os.environ.get(
            "METAGUARD_CLOUD_FINDINGS_PROVIDER", "aws_security_hub"
        ).strip().lower()
        if provider != "aws_security_hub":
            raise FindingsConfigurationError(
                "METAGUARD_CLOUD_FINDINGS_PROVIDER must be 'aws_security_hub'."
            )
        return provider

    def clear_cache(self) -> None:
        with self._lock:
            self._snapshot = None
            self._cached_at = 0.0

    def get_snapshot(self) -> FindingsSnapshot:
        mode = self.mode()
        provider = self.provider()
        with self._lock:
            if (
                self._snapshot is not None
                and self._snapshot.mode == mode
                and self._snapshot.provider == provider
                and time.monotonic() - self._cached_at < CACHE_TTL_SECONDS
            ):
                return self._snapshot

            if mode == "demo":
                items = [dict(item) for item in DEMO_FINDINGS]
                truncated = False
            else:
                items, truncated = self._fetch_aws_findings()

            self._snapshot = FindingsSnapshot(
                items=items,
                fetched_at=utc_timestamp(),
                truncated=truncated,
                mode=mode,
                provider=provider,
            )
            self._cached_at = time.monotonic()
            return self._snapshot

    @staticmethod
    def _aws_region() -> str:
        region = (
            os.environ.get("AWS_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or ""
        ).strip()
        if not region:
            raise FindingsConfigurationError(
                "Set AWS_REGION for the Security Hub region."
            )
        return region

    @staticmethod
    def _make_aws_client(region: str) -> Any:
        if any(name.startswith("AWS_ENDPOINT_URL") for name in os.environ):
            raise FindingsConfigurationError(
                "Custom AWS service endpoints are disabled for this integration."
            )

        access_key = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
        session_token = os.environ.get("AWS_SESSION_TOKEN", "").strip()
        role_arn = os.environ.get("AWS_ROLE_ARN", "").strip()
        web_identity_token_file = os.environ.get(
            "AWS_WEB_IDENTITY_TOKEN_FILE", ""
        ).strip()

        if bool(access_key) != bool(secret_key):
            raise FindingsConfigurationError(
                "Set both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."
            )
        if session_token and not (access_key and secret_key):
            raise FindingsConfigurationError(
                "AWS_SESSION_TOKEN requires the AWS access-key pair."
            )
        if bool(role_arn) != bool(web_identity_token_file):
            raise FindingsConfigurationError(
                "Set both AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE for web identity."
            )
        if not (access_key and secret_key) and not (
            role_arn and web_identity_token_file
        ):
            raise FindingsConfigurationError(
                "Configure backend AWS access-key variables or web-identity role variables."
            )

        try:
            import boto3
            from botocore.config import Config
            from botocore.exceptions import BotoCoreError
        except ImportError:
            raise FindingsConfigurationError(
                "Install the backend boto3 dependency to enable AWS Security Hub."
            ) from None

        os.environ["AWS_CONFIG_FILE"] = os.devnull
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
        try:
            if access_key and secret_key:
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token or None,
                    region_name=region,
                )
            else:
                session = boto3.Session(region_name=region)
            return session.client(
                "securityhub",
                region_name=region,
                config=Config(
                    connect_timeout=3,
                    read_timeout=10,
                    retries={"max_attempts": 3, "mode": "standard"},
                ),
            )
        except BotoCoreError:
            raise FindingsAuthenticationError() from None

    def _fetch_aws_findings(self) -> tuple[list[dict[str, Any]], bool]:
        client = self._make_aws_client(self._aws_region())
        from botocore.exceptions import BotoCoreError, ClientError

        findings: list[dict[str, Any]] = []
        next_token: str | None = None
        truncated = False

        try:
            while len(findings) < MAX_FINDINGS:
                request: dict[str, Any] = {
                    "MaxResults": min(AWS_PAGE_SIZE, MAX_FINDINGS - len(findings))
                }
                if next_token:
                    request["NextToken"] = next_token
                response = client.get_findings(**request)
                finding_batch = response.get("Findings") or []
                findings.extend(normalize_finding(item) for item in finding_batch)
                next_token = response.get("NextToken")
                if not next_token:
                    break
                if len(findings) >= MAX_FINDINGS:
                    truncated = True
        except ClientError as error:
            code = str((error.response.get("Error") or {}).get("Code") or "")
            if code in {
                "ThrottlingException",
                "LimitExceededException",
                "TooManyRequestsException",
                "RequestLimitExceeded",
            }:
                raise FindingsRateLimitError() from None
            if code in {
                "AccessDeniedException",
                "InvalidAccessException",
                "UnrecognizedClientException",
                "ExpiredTokenException",
                "InvalidToken",
            }:
                raise FindingsAuthenticationError() from None
            raise FindingsProviderError() from None
        except BotoCoreError:
            raise FindingsProviderError() from None

        return findings, truncated

    def page(
        self,
        *,
        limit: int,
        cursor: int,
        alerts_only: bool = False,
    ) -> dict[str, Any]:
        snapshot = self.get_snapshot()
        items = snapshot.items
        if alerts_only:
            items = [
                item
                for item in items
                if item["severity"] in {"high", "critical"}
                and item["status"] not in {"resolved", "suppressed"}
            ]
        page_items = items[cursor : cursor + limit]
        next_cursor = cursor + len(page_items)
        has_more = next_cursor < len(items)
        return {
            "items": page_items,
            "next_cursor": str(next_cursor) if has_more else None,
            "has_more": has_more,
            "truncated": snapshot.truncated,
            "source": snapshot.mode,
            "provider": snapshot.provider,
            "fetched_at": snapshot.fetched_at,
        }

    def summary(self) -> dict[str, Any]:
        snapshot = self.get_snapshot()
        severity_counts: dict[str, int] = {}
        status_counts: dict[str, int] = {}
        for item in snapshot.items:
            severity_counts[item["severity"]] = severity_counts.get(item["severity"], 0) + 1
            status_counts[item["status"]] = status_counts.get(item["status"], 0) + 1
        return {
            "total": len(snapshot.items),
            "by_severity": severity_counts,
            "by_status": status_counts,
            "high": severity_counts.get("high", 0),
            "critical": severity_counts.get("critical", 0),
            "open": sum(
                count
                for status, count in status_counts.items()
                if status not in {"resolved", "suppressed"}
            ),
            "truncated": snapshot.truncated,
            "source": snapshot.mode,
            "provider": snapshot.provider,
            "fetched_at": snapshot.fetched_at,
        }
