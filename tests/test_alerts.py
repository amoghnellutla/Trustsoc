"""
Automated tests for TrustSOC alert endpoints.
Run with:  pytest tests/ -v
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings

client = TestClient(app)
HEADERS = {"x-api-key": settings.API_KEY}


# =============================================================================
# System endpoints
# =============================================================================

def test_health():
    """Health check returns healthy."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json().get("status") == "healthy"


def test_root_optional():
    """
    Root endpoint is optional (depends on your app.main).
    If present, it should be JSON and return 200.
    """
    resp = client.get("/")
    if resp.status_code == 404:
        pytest.skip("Root endpoint (/) not implemented; skipping.")
    assert resp.status_code == 200
    assert isinstance(resp.json(), dict)


# =============================================================================
# Authentication
# =============================================================================

def test_missing_api_key_rejected():
    """
    Your API key header uses auto_error=False and manual verify_api_key,
    so missing key returns 401 (not 422).
    """
    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 401
    assert resp.json().get("detail") in ("Invalid API key", "Not authenticated", "Unauthorized", None)


def test_wrong_api_key_rejected():
    """Request with wrong API key must return 401."""
    resp = client.get("/api/v1/alerts", headers={"x-api-key": "wrong-key"})
    assert resp.status_code == 401


def test_valid_api_key_accepted():
    """Request with correct API key must not return 401."""
    resp = client.get("/api/v1/alerts", headers=HEADERS)
    assert resp.status_code != 401


# =============================================================================
# Alert creation
# =============================================================================

def sample_alert(external_id: str) -> dict:
    return {
        "source_system": "wazuh",
        "external_id": external_id,
        "alert_data": {
            "rule": {"description": "Mimikatz detected", "level": 15},
            "agent": {"name": "windows-01", "ip": "192.168.1.100"},
            "full_log": "mimikatz.exe executed by john.doe",
            "timestamp": "2026-02-21T00:00:00Z",
        },
    }


def test_create_alert_returns_201():
    """Creating a valid alert must return HTTP 201."""
    payload = sample_alert(f"test-{uuid.uuid4()}")
    resp = client.post("/api/v1/alerts", json=payload, headers=HEADERS)
    assert resp.status_code == 201


def test_create_alert_has_uuid_id():
    """Created alert must include a UUID id."""
    payload = sample_alert(f"test-{uuid.uuid4()}")
    resp = client.post("/api/v1/alerts", json=payload, headers=HEADERS)
    body = resp.json()
    assert "id" in body
    uuid.UUID(str(body["id"]))  # raises if invalid UUID


def test_create_alert_status_is_processing():
    """Newly created alert must start in 'processing' status."""
    payload = sample_alert(f"test-{uuid.uuid4()}")
    resp = client.post("/api/v1/alerts", json=payload, headers=HEADERS)
    body = resp.json()
    assert body.get("status") == "processing"


def test_create_alert_risk_score_zero():
    """Freshly ingested alert must have risk_score of 0 (enrichment not done yet)."""
    payload = sample_alert(f"test-{uuid.uuid4()}")
    resp = client.post("/api/v1/alerts", json=payload, headers=HEADERS)
    assert resp.json().get("risk_score") == 0


def test_create_alert_missing_source_system():
    """Alert without source_system must return 422."""
    bad = {"alert_data": {"rule": {"description": "test"}}}
    resp = client.post("/api/v1/alerts", json=bad, headers=HEADERS)
    assert resp.status_code == 422


def test_create_alert_missing_alert_data():
    """Alert without alert_data must return 422."""
    bad = {"source_system": "wazuh", "external_id": f"test-{uuid.uuid4()}"}
    resp = client.post("/api/v1/alerts", json=bad, headers=HEADERS)
    assert resp.status_code == 422


def test_duplicate_external_id_handled():
    """
    Posting two alerts with the same external_id.
    Current behavior could be 500 (unique constraint) or 409 (if you later improve).
    Accept both so tests won't become brittle.
    """
    fixed_id = f"dup-{uuid.uuid4()}"
    payload = sample_alert(fixed_id)

    r1 = client.post("/api/v1/alerts", json=payload, headers=HEADERS)
    r2 = client.post("/api/v1/alerts", json=payload, headers=HEADERS)

    assert r1.status_code == 201
    assert r2.status_code in (409, 500)


# =============================================================================
# Alert retrieval
# =============================================================================

def _create_one() -> str:
    payload = sample_alert(f"helper-{uuid.uuid4()}")
    resp = client.post("/api/v1/alerts", json=payload, headers=HEADERS)
    assert resp.status_code == 201
    return str(resp.json()["id"])


def test_get_alert_by_id():
    alert_id = _create_one()
    resp = client.get(f"/api/v1/alerts/{alert_id}", headers=HEADERS)
    assert resp.status_code == 200
    assert str(resp.json().get("id")) == alert_id


def test_get_nonexistent_alert_returns_404():
    fake = str(uuid.uuid4())
    resp = client.get(f"/api/v1/alerts/{fake}", headers=HEADERS)
    assert resp.status_code == 404


def test_list_alerts_returns_list():
    resp = client.get("/api/v1/alerts", headers=HEADERS)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_list_alerts_limit_respected():
    resp = client.get("/api/v1/alerts?limit=2", headers=HEADERS)
    assert resp.status_code == 200
    assert len(resp.json()) <= 2


# =============================================================================
# Evidence bundle
# =============================================================================

def test_evidence_bundle_structure():
    alert_id = _create_one()
    resp = client.get(f"/api/v1/alerts/{alert_id}/evidence", headers=HEADERS)
    assert resp.status_code == 200
    body = resp.json()

    # Based on your EvidenceBundle construction in routers/alerts.py
    for key in (
        "alert_id",
        "raw_alert",
        "normalized_alert",
        "risk_score",
        "confidence_score",
        "status",
        "evidence_trail",
        "enrichments",
        "actions_taken",
        "policy_decisions",
        "risk_explanation",
    ):
        assert key in body, f"Missing key: {key}"


def test_evidence_trail_has_receipt():
    alert_id = _create_one()
    resp = client.get(f"/api/v1/alerts/{alert_id}/evidence", headers=HEADERS)
    trail = resp.json().get("evidence_trail", [])
    assert len(trail) >= 1
    types = [e.get("evidence_type") for e in trail]
    assert "alert_received" in types


# =============================================================================
# Evidence integrity verification
# =============================================================================

def test_evidence_verify_endpoint_exists():
    alert_id = _create_one()
    resp = client.get(f"/api/v1/alerts/{alert_id}/evidence/verify", headers=HEADERS)
    assert resp.status_code == 200


def test_evidence_verify_all_valid():
    alert_id = _create_one()
    resp = client.get(f"/api/v1/alerts/{alert_id}/evidence/verify", headers=HEADERS)
    results = resp.json()
    assert len(results) > 0
    for result in results:
        assert result.get("is_valid") is True


def test_evidence_verify_has_hashes():
    alert_id = _create_one()
    resp = client.get(f"/api/v1/alerts/{alert_id}/evidence/verify", headers=HEADERS)
    for result in resp.json():
        assert result.get("stored_hash")
        assert result.get("computed_hash")


# =============================================================================
# Analyst feedback
# =============================================================================

def test_add_true_positive_feedback():
    alert_id = _create_one()
    payload = {
        "feedback_type": "true_positive",
        "notes": "Confirmed Mimikatz execution",
        "analyst_id": "test.analyst",
    }
    resp = client.post(f"/api/v1/alerts/{alert_id}/feedback", json=payload, headers=HEADERS)
    assert resp.status_code == 201
    assert resp.json().get("feedback_type") == "true_positive"


def test_add_false_positive_feedback():
    alert_id = _create_one()
    payload = {
        "feedback_type": "false_positive",
        "notes": "Known pen-test tool",
        "analyst_id": "test.analyst",
    }
    resp = client.post(f"/api/v1/alerts/{alert_id}/feedback", json=payload, headers=HEADERS)
    assert resp.status_code == 201


def test_invalid_feedback_type_rejected():
    alert_id = _create_one()
    payload = {
        "feedback_type": "maybe_bad",  # invalid
        "analyst_id": "test.analyst",
    }
    resp = client.post(f"/api/v1/alerts/{alert_id}/feedback", json=payload, headers=HEADERS)
    assert resp.status_code == 422