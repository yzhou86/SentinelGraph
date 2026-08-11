from fastapi.testclient import TestClient

from ocskg.api import app
from ocskg.text_graph import attach_llm_relations, extract_rule_graph


def test_rule_text_graph_extracts_iocs_and_labels_derived_relations() -> None:
    extraction = extract_rule_graph(
        "Host web-01.prod.demo connected to 198.51.100.9 after CVE-2025-9999. "
        "Contact soc@example.com and review https://intel.example.org/case.",
        "report-1",
    )

    entity_ids = {entity["entity_id"] for entity in extraction["entities"]}
    relations = extraction["relations"]
    assert {"ip:198.51.100.9", "vulnerability:CVE-2025-9999", "email:soc@example.com"} <= entity_ids
    assert all(relation["status"] == "pending_review" for relation in relations)
    assert any(relation["relation"] == "co_mentioned_in_sentence" for relation in relations)
    assert any(relation["src_id"] == "document:report-1" for relation in relations)


def test_llm_proposals_are_bounded_to_known_entities_and_relation_types() -> None:
    extraction = extract_rule_graph("198.51.100.9 connected to 203.0.113.8.", "report-2")
    accepted = attach_llm_relations(
        extraction,
        {
            "relations": [
                {
                    "source_id": "ip:198.51.100.9",
                    "target_id": "ip:203.0.113.8",
                    "relation": "communicates_with",
                    "confidence": 0.8,
                    "evidence": "198.51.100.9 connected to 203.0.113.8.",
                },
                {
                    "source_id": "ip:unknown",
                    "target_id": "ip:203.0.113.8",
                    "relation": "communicates_with",
                    "confidence": 0.9,
                    "evidence": "unsupported",
                },
            ]
        },
    )

    proposals = [item for item in accepted["relations"] if item["relation_kind"] == "llm_proposed"]
    assert len(proposals) == 1
    assert proposals[0]["status"] == "pending_review"
    assert accepted["extractor"]["name"] == "rules+llm"


def test_mock_text_graph_endpoint_needs_no_external_dependency() -> None:
    client = TestClient(app)
    response = client.post(
        "/v1/text-graph/extract",
        json={"mode": "mock", "scenario": "cloud_account_takeover", "tenant_id": "offline"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] == "mock"
    assert payload["persisted"] is False
    assert any(entity["entity_id"] == "ip:198.51.100.77" for entity in payload["entities"])
    assert all(relation["status"] == "pending_review" for relation in payload["relations"])
