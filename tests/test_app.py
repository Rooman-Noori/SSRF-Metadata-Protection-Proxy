import time

import pytest

import app as proxy_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(proxy_app, "DB_PATH", str(tmp_path / "test-security.db"))
    proxy_app.TOKENS.clear()
    proxy_app.initialize_database()
    with proxy_app.app.test_client() as test_client:
        yield test_client


def issue_token(client, ttl=300):
    response = client.put(
        "/api/metadata/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": str(ttl)},
    )
    assert response.status_code == 200
    return response.get_json()["token"]


def test_token_creation_and_ttl_validation(client):
    response = client.put(
        "/api/metadata/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "42"},
    )
    assert response.status_code == 200
    token = response.get_json()["token"]
    assert response.get_json()["expires_in"] == 42
    assert proxy_app.token_state(token) == "valid"

    invalid_ttl = client.put(
        "/api/metadata/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "999999"},
    )
    assert invalid_ttl.status_code == 400


def test_token_expiration_and_validation(client):
    token = issue_token(client, ttl=1)
    proxy_app.TOKENS[token] = time.time() - 1
    assert proxy_app.token_state(token) == "expired"
    assert proxy_app.token_state("not-issued") == "invalid"
    assert proxy_app.token_state(None) == "missing"


def test_missing_invalid_and_expired_tokens_are_blocked(client):
    expired = "expired-test-token"
    proxy_app.TOKENS[expired] = time.time() - 10
    responses = [
        client.get("/api/proxy/instance-id"),
        client.get("/api/proxy/instance-id", headers={"X-IMDS-Token": "forged"}),
        client.get("/api/proxy/instance-id", headers={"X-IMDS-Token": expired}),
    ]
    assert [response.status_code for response in responses] == [401, 401, 401]
    assert all(response.get_json()["result"] == "blocked" for response in responses)


def test_valid_metadata_request_is_allowed_and_contains_dummy_data(client):
    token = issue_token(client)
    response = client.get("/api/proxy/instance-id", headers={"X-IMDS-Token": token})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "allowed"
    assert payload["resource"] == "instance-id"
    assert payload["data"] == "i-0d3b4e7a2c19ff123"


def test_mock_metadata_endpoint_requires_valid_token(client):
    assert client.get("/api/metadata/region").status_code == 401
    token = issue_token(client)
    response = client.get("/api/metadata/region", headers={"X-IMDS-Token": token})
    assert response.status_code == 200
    assert response.get_json()["data"] == "us-east-1"


def test_unauthorized_path_is_blocked(client):
    token = issue_token(client)
    response = client.get(
        "/api/proxy/unlisted-secret",
        headers={"X-IMDS-Token": token},
    )
    assert response.status_code == 403
    assert response.get_json()["result"] == "blocked"


def test_unauthorized_destination_is_blocked_and_never_fetched(client):
    token = issue_token(client)
    response = client.get(
        "/api/proxy/instance-id",
        headers={
            "X-IMDS-Token": token,
            "X-Metadata-Destination": "https://example.invalid/metadata",
        },
    )
    assert response.status_code == 403
    assert "Unauthorized destination" in response.get_json()["reason"]


def test_invalid_method_is_blocked(client):
    token = issue_token(client)
    response = client.post(
        "/api/proxy/instance-id",
        headers={"X-IMDS-Token": token},
    )
    assert response.status_code == 405
    assert response.get_json()["result"] == "blocked"


def test_simulated_ssrf_is_blocked_and_logged_as_critical(client):
    token = issue_token(client)
    response = client.get(
        "/api/proxy/instance-id",
        headers={
            "X-IMDS-Token": token,
            "X-Metadata-Destination": "http://169.254.169.254/latest/meta-data/",
        },
    )
    assert response.status_code == 403
    assert response.get_json()["severity"] == "critical"

    events = client.get("/api/security/events?severity=critical").get_json()
    assert len(events) == 1
    assert events[0]["result"] == "blocked"
    assert events[0]["method"] == "GET"
    assert events[0]["source"] == "127.0.0.1"


def test_overview_and_event_filters_are_backed_by_database(client):
    token = issue_token(client)
    client.get("/api/proxy/region", headers={"X-IMDS-Token": token})
    client.get("/api/proxy/instance-id")

    overview = client.get("/api/security/overview").get_json()
    assert overview["totalRequests"] == 2
    assert overview["allowedRequests"] == 1
    assert overview["blockedRequests"] == 1
    assert overview["severityBreakdown"] == [
        {"label": "low", "count": 1},
        {"label": "high", "count": 1},
    ]
    assert overview["methodBreakdown"] == [{"label": "GET", "count": 2}]
    assert overview["statusCodeBreakdown"] == [
        {"label": "200", "count": 1},
        {"label": "401", "count": 1},
    ]
    assert {item["label"]: item["count"] for item in overview["topPaths"]} == {
        "/api/proxy/region": 1,
        "/api/proxy/instance-id": 1,
    }
    assert overview["sourceBreakdown"] == [{"label": "127.0.0.1", "count": 2}]
    assert sum(item["allowed"] + item["blocked"] for item in overview["hourlyResults"]) == 2
    assert len(client.get("/api/security/events?status=blocked").get_json()) == 1
    assert client.get("/api/security/events?status=invalid").status_code == 400


def test_test_center_executes_and_persists_all_results(client):
    response = client.post("/api/security/test-center/run")
    assert response.status_code == 201
    run = response.get_json()
    assert run["total"] == 8
    assert run["passed"] == 8
    assert all(result["pass"] for result in run["results"])
    assert all("explanation" in result for result in run["results"])

    runs = client.get("/api/security/test-center/runs").get_json()
    assert len(runs) == 1
    saved = client.get(f"/api/security/test-center/runs/{run['id']}").get_json()
    assert saved["results"] == run["results"]


def test_security_rules_have_secure_defaults_and_can_be_changed(client):
    rules = client.get("/api/security/rules").get_json()
    assert rules and all(rule["enabled"] for rule in rules)

    changed = client.patch(
        "/api/security/rules/require_token",
        json={"enabled": False},
    )
    assert changed.status_code == 200
    response = client.get("/api/proxy/region")
    assert response.status_code == 200

    assert client.patch(
        "/api/security/rules/unknown-rule",
        json={"enabled": False},
    ).status_code == 404


def test_configuration_confirms_external_requests_are_disabled(client):
    configuration = client.get("/api/config").get_json()
    assert configuration["mode"] == "isolated-local-lab"
    assert configuration["externalRequestsEnabled"] is False
    assert "region" in configuration["allowedResources"]


def test_clear_lab_removes_events_and_saved_test_runs(client):
    client.post("/api/security/test-center/run")
    assert client.get("/api/security/events").get_json()
    response = client.post("/api/security/clear")
    assert response.status_code == 200
    assert client.get("/api/security/events").get_json() == []
    assert client.get("/api/security/test-center/runs").get_json() == []
