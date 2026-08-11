from typing import Any

from fastapi.testclient import TestClient

from ocskg.api import app
from ocskg.config import Settings
from ocskg.llm import OpenAICompatibleClient


def test_mock_mode_returns_full_demo_without_starrocks_or_llm() -> None:
    client = TestClient(app)

    health = client.get("/health?mode=mock")
    demo = client.post("/v1/demo/load", json={"tenant_id": "offline-demo", "mode": "mock"})
    alerts = client.get("/v1/alerts?tenant_id=offline-demo&mode=mock")
    graph = client.get("/v1/graph/user:demo-alice?tenant_id=offline-demo&mode=mock")
    investigation = client.post(
        "/v1/agent/investigations",
        json={
            "tenant_id": "offline-demo",
            "entity_id": "user:demo-alice",
            "question": "What happened?",
            "mode": "mock",
        },
    )

    assert health.json() == {"status": "ok", "mode": "mock"}
    assert demo.status_code == 200
    assert demo.json()["ingested_events"] == 10
    assert len(alerts.json()["alerts"]) == 4
    assert graph.json()["nodes"]
    answer = investigation.json()["mock_analyst_answer"]
    assert answer["risk_score"] == 92
    assert {"mock-auth-01", "mock-egress-01", "mock-vulnerability-01"} <= set(
        answer["evidence_refs"]
    )


def test_openai_compatible_client_uses_server_side_chat_completions(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, Any]:
            return {
                "model": "test-model",
                "choices": [{"message": {"content": "CONNECTION_OK"}}],
                "usage": {"total_tokens": 4},
            }

    def fake_post(*args: Any, **kwargs: Any) -> FakeResponse:
        captured["url"] = args[0]
        captured.update(kwargs)
        return FakeResponse()

    monkeypatch.setattr("ocskg.llm.httpx.post", fake_post)
    client = OpenAICompatibleClient(
        Settings(
            llm_enabled=True,
            llm_api_base="https://gateway.example/v1/",
            llm_api_key="server-secret",
            llm_model="chosen-model",
        )
    )

    result = client.test()

    assert captured["url"] == "https://gateway.example/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer server-secret"
    assert captured["json"]["model"] == "chosen-model"
    assert result["answer"] == "CONNECTION_OK"
    assert "server-secret" not in str(client.info())
