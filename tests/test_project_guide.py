from pathlib import Path

from fastapi.testclient import TestClient

from ocskg.api import app


def test_project_guide_is_publicly_available_and_linked_from_the_console() -> None:
    client = TestClient(app)

    guide = client.get("/guide")
    console = client.get("/")

    assert guide.status_code == 200
    assert "项目文档" in guide.text
    assert "/integrations" in guide.text
    assert console.status_code == 200
    assert 'href="/guide"' in console.text


def test_readme_and_project_guide_cover_the_same_core_concepts() -> None:
    readme = Path("README.md").read_text()
    guide = Path("src/ocskg/static/guide.html").read_text()

    for concept in (
        "OCSF",
        "StarRocks",
        "GraphRAG",
        "Mock",
        "Live",
        "pending_review",
        "INTEGRATION_API_KEYS",
        "retrospective",
    ):
        assert concept in readme
        assert concept in guide
