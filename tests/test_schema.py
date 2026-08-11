from pathlib import Path


def test_schema_has_individually_executable_statements() -> None:
    schema = Path("sql/schema.sql").read_text()
    statements = [part.strip() for part in schema.split(";") if part.strip()]
    executable = [
        "\n".join(line for line in statement.splitlines() if not line.startswith("--")).strip()
        for statement in statements
    ]

    assert len(executable) == 9
    assert executable[0].startswith("CREATE DATABASE")
    assert executable[1].startswith("USE ")
    assert all(statement.startswith("CREATE TABLE") for statement in executable[2:])
    assert any("text_graph_extractions" in statement for statement in executable)
    assert any("text_graph_reviews" in statement for statement in executable)
