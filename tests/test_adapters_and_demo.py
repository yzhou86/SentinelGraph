from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from ocskg.adapters import detect_source_format, to_ocsf_event
from ocskg.api import app
from ocskg.demo import make_demo_scenario


def test_ecs_mapping_preserves_source_and_maps_authentication() -> None:
    source = {
        "@timestamp": "2026-08-10T08:00:00Z",
        "event": {"id": "ecs-1", "category": "authentication", "outcome": "failure"},
        "severity": "warning",
        "user": {"id": "u-1", "name": "alice"},
        "source": {"ip": "203.0.113.42"},
        "host": {"id": "h-1", "name": "web-01"},
        "message": "invalid password",
    }

    event = to_ocsf_event(source, "auto")

    assert detect_source_format(source) == "ecs"
    assert event["class_uid"] == 3002
    assert event["status_id"] == 2
    assert event["severity_id"] == 3
    assert event["actor"]["user"]["name"] == "alice"
    assert event["unmapped"] == source


def test_cloudtrail_and_zeek_mappings() -> None:
    cloudtrail = to_ocsf_event(
        {
            "eventID": "aws-1",
            "eventTime": "2026-08-10T08:00:00Z",
            "eventName": "ConsoleLogin",
            "errorCode": "Failed authentication",
            "sourceIPAddress": "203.0.113.42",
            "userIdentity": {"arn": "arn:aws:iam::123:user/alice"},
        },
        "cloudtrail",
    )
    zeek = to_ocsf_event(
        {
            "uid": "zeek-1",
            "ts": 1,
            "id": {"orig_h": "10.0.0.1", "resp_h": "1.1.1.1", "resp_p": 443},
        },
        "zeek",
    )

    assert cloudtrail["class_uid"] == 3002
    assert cloudtrail["status_id"] == 2
    assert zeek["time"] == 1000
    assert zeek["dst_endpoint"]["port"] == 443


def test_demo_scenario_is_current_and_matches_default_detection_thresholds() -> None:
    run_id, events, documents = make_demo_scenario("test-run")
    auth_events = [event for event in events if event["class_uid"] == 3002]
    egress_events = [event for event in events if event["class_uid"] == 4001]

    assert run_id == "test-run"
    assert len(events) == 9
    assert len(auth_events) == 5
    assert len(egress_events) == 3
    assert any("CVE-" in event["message"] for event in events)
    assert len(documents) == 3
    now = datetime.now(UTC)
    assert all(
        now - timedelta(minutes=10) < datetime.fromtimestamp(event["time"] / 1000, UTC) <= now
        for event in events
    )


def test_demo_console_is_served_without_database_access() -> None:
    client = TestClient(app)
    response = client.get("/")

    assert response.status_code == 200
    assert "启动实时攻击演示" in response.text
    active = client.get("/v1/system/connection")
    assert active.status_code == 200
    assert "password" not in active.json()["active"]
