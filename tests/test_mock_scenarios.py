from fastapi.testclient import TestClient

from ocskg import mock
from ocskg.api import app


def test_mock_catalogue_has_consistent_ocsf_evidence_graphs() -> None:
    catalogue = mock.list_scenarios()

    assert catalogue["default_scenario"] == "credential_to_impact"
    assert {item["id"] for item in catalogue["scenarios"]} == {
        "credential_to_impact",
        "cloud_account_takeover",
        "ransomware_lateral_movement",
    }
    for scenario_id in (item["id"] for item in catalogue["scenarios"]):
        scenario = mock._materialize(scenario_id, "test-tenant")
        event_ids = {event["event_uid"] for event in scenario["events"]}
        node_ids = {node["entity_id"] for node in scenario["nodes"]}
        assert all(event["class_uid"] for event in scenario["events"])
        assert all(
            edge["src_id"] in node_ids and edge["dst_id"] in node_ids for edge in scenario["edges"]
        )
        assert all(edge["event_uid"] in event_ids for edge in scenario["edges"])
        alert_refs = {
            event_id for alert in scenario["alerts"] for event_id in alert["evidence"]["event_uids"]
        }
        assert alert_refs <= event_ids


def test_mock_api_can_switch_to_cloud_and_endpoint_scenarios() -> None:
    client = TestClient(app)

    catalogue = client.get("/v1/demo/scenarios")
    cloud = client.post(
        "/v1/demo/load",
        json={"tenant_id": "offline-demo", "mode": "mock", "scenario": "cloud_account_takeover"},
    )
    ransomware = client.post(
        "/v1/agent/investigations",
        json={
            "tenant_id": "offline-demo",
            "entity_id": "asset:finance-lt-23",
            "mode": "mock",
            "scenario": "ransomware_lateral_movement",
        },
    )

    assert catalogue.status_code == 200
    assert cloud.json()["scenario_summary"]["title"].startswith("云账号接管")
    assert cloud.json()["ingested_events"] == 7
    assert ransomware.json()["mock_analyst_answer"]["risk_score"] == 96
    assert "T1486" in ransomware.json()["mock_analyst_answer"]["attack_path"][2]["mitre"]
