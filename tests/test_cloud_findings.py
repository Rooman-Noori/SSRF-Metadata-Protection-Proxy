import pytest

import app as proxy_app
from cloud_findings import CloudFindingsService, normalize_finding


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("METAGUARD_CLOUD_FINDINGS_MODE", "demo")
    proxy_app.cloud_findings_service.clear_cache()
    with proxy_app.app.test_client() as test_client:
        yield test_client
    proxy_app.cloud_findings_service.clear_cache()


def aws_finding(finding_id, severity="HIGH", status="NEW"):
    return {
        "Id": finding_id,
        "Title": f"Finding {finding_id}",
        "Description": "A mocked Security Hub finding.",
        "Severity": {"Label": severity},
        "Workflow": {"Status": status},
        "Resources": [
            {"Id": "arn:aws:s3:::example-resource", "Name": "example-resource", "Type": "AwsS3Bucket"}
        ],
        "CreatedAt": "2025-02-01T10:00:00Z",
        "UpdatedAt": "2025-02-02T10:00:00Z",
        "Remediation": {
            "Recommendation": {"Text": "Review the resource configuration."}
        },
    }


def test_normalize_finding_maps_security_hub_fields():
    finding = normalize_finding(aws_finding("finding-123"))

    assert finding == {
        "finding_id": "finding-123",
        "title": "Finding finding-123",
        "description": "A mocked Security Hub finding.",
        "severity": "high",
        "status": "new",
        "resource_name": "example-resource",
        "resource_type": "AwsS3Bucket",
        "cloud_provider": "aws",
        "created_at": "2025-02-01T10:00:00Z",
        "updated_at": "2025-02-02T10:00:00Z",
        "remediation": "Review the resource configuration.",
    }


def test_demo_mode_exposes_marked_findings_summary_alerts_and_health(client):
    findings = client.get("/api/security/findings?limit=2").get_json()
    summary = client.get("/api/security/summary").get_json()
    alerts = client.get("/api/security/alerts").get_json()
    health = client.get("/api/security/health").get_json()

    assert findings["source"] == "demo"
    assert findings["provider"] == "demo"
    assert len(findings["items"]) == 2
    assert findings["next_cursor"] == "2"
    assert summary["source"] == "demo"
    assert summary["total"] == 3
    assert summary["high"] == 1
    assert len(alerts["items"]) == 1
    assert health["mode"] == "demo"
    assert health["liveVerified"] is False


def test_live_mode_uses_mocked_aws_pages_and_caches_snapshot(client, monkeypatch):
    monkeypatch.setenv("METAGUARD_CLOUD_FINDINGS_MODE", "live")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "mock-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "mock-secret-key")

    class MockSecurityHub:
        def __init__(self):
            self.calls = []

        def get_findings(self, **kwargs):
            self.calls.append(kwargs)
            if kwargs.get("NextToken") == "page-2":
                return {"Findings": [aws_finding("finding-2", "CRITICAL", "NEW")]}
            return {
                "Findings": [aws_finding("finding-1")],
                "NextToken": "page-2",
            }

    provider = MockSecurityHub()
    monkeypatch.setattr(
        proxy_app.cloud_findings_service,
        "_make_aws_client",
        lambda region: provider,
    )
    proxy_app.cloud_findings_service.clear_cache()

    first_page = client.get("/api/security/findings?limit=1").get_json()
    second_page = client.get(
        f"/api/security/findings?limit=1&cursor={first_page['next_cursor']}"
    ).get_json()
    summary = client.get("/api/security/summary").get_json()
    health = client.get("/api/security/health").get_json()

    assert first_page["source"] == "live"
    assert first_page["provider"] == "aws_security_hub"
    assert first_page["items"][0]["finding_id"] == "finding-1"
    assert second_page["items"][0]["finding_id"] == "finding-2"
    assert summary["total"] == 2
    assert summary["critical"] == 1
    assert health["liveVerified"] is True
    assert len(provider.calls) == 2
    assert provider.calls[0] == {"MaxResults": 100}
    assert provider.calls[1] == {"MaxResults": 100, "NextToken": "page-2"}


def test_live_authentication_configuration_error_never_falls_back_to_demo(client, monkeypatch):
    monkeypatch.setenv("METAGUARD_CLOUD_FINDINGS_MODE", "live")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    for variable in (
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
    ):
        monkeypatch.delenv(variable, raising=False)
    proxy_app.cloud_findings_service.clear_cache()

    response = client.get("/api/security/findings")

    assert response.status_code == 503
    assert response.get_json()["source"] == "live"
    assert "items" not in response.get_json()
    assert "demo-aws" not in response.get_data(as_text=True)


@pytest.mark.parametrize(
    "query",
    ["?limit=0", "?limit=101", "?limit=nope", "?cursor=-1", "?cursor=5001"],
)
def test_findings_pagination_rejects_invalid_values(client, query):
    assert client.get(f"/api/security/findings{query}").status_code == 400
