from datetime import datetime
from typing import Any

from ocskg.detection import Rule, RuleEngine, RuleSet


class FakeRepository:
    def __init__(self) -> None:
        self.queries: list[tuple[str, tuple[Any, ...]]] = []
        self.inserted: list[dict[str, Any]] = []

    def query(self, statement: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        self.queries.append((statement, params))
        if statement.startswith("SELECT alert_id"):
            return []
        return [
            {
                "actor_user_name": "alice",
                "src_ip": "203.0.113.42",
                "event_count": 5,
                "last_seen": datetime(2026, 8, 10),
            }
        ]

    def insert_alert(self, alert: dict[str, Any]) -> None:
        self.inserted.append(alert)


def test_rule_engine_compiles_only_allowlisted_fields_and_creates_alert() -> None:
    repository = FakeRepository()
    rule = Rule(
        id="failed-auth",
        name="Failed authentication",
        threshold=5,
        group_by=["actor_user_name", "src_ip"],
        match={"class_uid": {"eq": 3002}, "status_id": {"eq": 2}},
    )
    alerts = RuleEngine(repository, RuleSet(rules=[rule])).run("demo")  # type: ignore[arg-type]

    statement, params = repository.queries[0]
    assert "class_uid = %s" in statement
    assert "GROUP BY actor_user_name, src_ip" in statement
    assert params[-3:] == (3002, 2, 5)
    assert alerts[0]["correlation_key"] == "alice|203.0.113.42"
    assert repository.inserted[0]["severity"] == "medium"


def test_rule_engine_rejects_non_allowlisted_sql_column() -> None:
    repository = FakeRepository()
    rule = Rule(id="unsafe", name="unsafe", match={"raw_event": {"contains": "drop table"}})
    engine = RuleEngine(repository, RuleSet(rules=[rule]))  # type: ignore[arg-type]

    try:
        engine.evaluate_rule(rule, "demo")
    except ValueError as error:
        assert "unsupported column" in str(error)
    else:
        raise AssertionError("expected invalid rule field to be rejected")
