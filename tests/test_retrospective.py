from datetime import datetime

from fastapi.testclient import TestClient

from ocskg.api import app
from ocskg.retrospective import analyze_historical_events


def test_retrospective_sessionizes_shared_ocsf_entities_and_explains_baseline() -> None:
    events = [
        {
            "event_uid": "auth-1",
            "event_time": "2026-08-10T10:00:00Z",
            "class_uid": 3002,
            "severity_id": 3,
            "actor_user_name": "alice",
            "device_hostname": "web-01",
            "message": "authentication failed",
        },
        {
            "event_uid": "egress-1",
            "event_time": "2026-08-10T10:06:00Z",
            "class_uid": 4001,
            "severity_id": 5,
            "actor_user_name": "alice",
            "device_hostname": "web-01",
            "dst_ip": "198.51.100.9",
            "message": "rare outbound connection",
        },
        {
            "event_uid": "unrelated-1",
            "event_time": "2026-08-10T11:30:00Z",
            "class_uid": 3002,
            "severity_id": 1,
            "actor_user_name": "bob",
            "device_hostname": "laptop-02",
            "message": "ordinary login",
        },
    ]

    result = analyze_historical_events(
        events,
        tenant_id="acme",
        start_time=datetime(2026, 8, 10, 10),
        end_time=datetime(2026, 8, 10, 12),
        session_gap_minutes=30,
        baseline_rows=[{"class_uid": 3002, "event_count": 4000}],
    )

    primary = result["clusters"][0]
    assert result["coverage"]["candidate_clusters"] == 2
    assert primary["event_count"] == 2
    assert "user:alice" in primary["shared_entities"]
    assert primary["baseline_comparison"]["unseen_class_uids"] == [4001]
    assert primary["evidence"][1]["event_uid"] == "egress-1"
    assert "not incident verdicts" not in result["method"]["description"]
    assert any("归因" in note for note in result["analyst_notes"])


def test_retrospective_mock_api_returns_customer_demo_results_without_dependencies() -> None:
    client = TestClient(app)

    response = client.post(
        "/v1/retrospective/analyses",
        json={
            "tenant_id": "offline-demo",
            "mode": "mock",
            "scenario": "ransomware_lateral_movement",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "mock"
    assert body["coverage"]["events_examined"] == 7
    assert body["clusters"][0]["risk_score"] >= 80
    assert body["query_guardrails"]["partition_pruning"] == "simulated in mock mode"
