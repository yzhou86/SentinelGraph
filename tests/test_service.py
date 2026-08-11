from datetime import datetime
from pathlib import Path
from typing import Any

from ocskg.config import Settings
from ocskg.embedding import HashEmbeddingProvider
from ocskg.service import SecurityGraphService


class FakeRepository:
    def __init__(self) -> None:
        self.documents: list[tuple[Any, ...]] = []

    def add_document(self, *args: Any) -> None:
        self.documents.append(args)

    def graph_context(
        self, entity_id: str, tenant_id: str, depth: int, limit: int
    ) -> dict[str, Any]:
        return {
            "seed": entity_id,
            "nodes": [{"entity_id": "event:evt-1", "entity_type": "event", "name": "event"}],
            "edges": [],
        }

    def event_summary(
        self, entity_ids: list[str], tenant_id: str, limit: int
    ) -> list[dict[str, Any]]:
        return [{"event_uid": "evt-1", "event_time": datetime(2026, 8, 10)}]

    def semantic_search(
        self, tenant_id: str, vector: list[float], limit: int
    ) -> list[dict[str, Any]]:
        return [{"chunk_id": "playbook-1", "score": 0.9}]


def test_investigation_combines_graph_events_and_semantic_context() -> None:
    settings = Settings(rules_path=Path("rules/default.yaml"), vector_search_enabled=True)
    service = SecurityGraphService(FakeRepository(), settings, HashEmbeddingProvider(64))  # type: ignore[arg-type]

    result = service.investigate("user:alice", "is this suspicious?", "demo", depth=3)

    assert result["graph"]["seed"] == "user:alice"
    assert result["events"][0]["event_uid"] == "evt-1"
    assert result["retrieved_context"][0]["chunk_id"] == "playbook-1"
    assert "raw_event" in result["agent_instruction"]
