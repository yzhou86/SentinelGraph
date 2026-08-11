from fastapi.testclient import TestClient

from ocskg.api import app
from ocskg.config import get_settings


def test_integration_key_is_optional_but_enforced_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("INTEGRATION_API_KEYS", "first-key, second-key")
    get_settings.cache_clear()
    client = TestClient(app)

    assert client.get("/health?mode=mock").status_code == 200
    assert client.get("/v1/integration/capabilities").status_code == 401
    assert (
        client.get("/v1/integration/capabilities", headers={"X-API-Key": "wrong"}).status_code
        == 401
    )
    response = client.get("/v1/integration/capabilities", headers={"X-API-Key": "second-key"})

    assert response.status_code == 200
    assert response.json()["authentication"] == {"scheme": "X-API-Key", "required": True}
    assert response.json()["capabilities"]["text_to_graph"] is True
    assert response.json()["capabilities"]["retrospective_analysis"] is True
    get_settings.cache_clear()


def test_integration_docs_and_openapi_advertise_the_versioned_contract() -> None:
    get_settings.cache_clear()
    client = TestClient(app)

    page = client.get("/integrations")
    schema = client.get("/openapi.json")

    assert page.status_code == 200
    assert "Integration API" in page.text
    assert "/v1/text-graph/extract" in page.text
    assert "/v1/retrospective/analyses" in page.text
    assert schema.status_code == 200
    assert (
        schema.json()["components"]["securitySchemes"]["IntegrationApiKey"]["name"] == "X-API-Key"
    )
    assert schema.json()["paths"]["/v1/events"]["post"]["security"] == [{"IntegrationApiKey": []}]
