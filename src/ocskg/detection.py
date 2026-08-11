"""Declarative, bounded-window correlation rules executed in StarRocks."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from .repository import StarRocksRepository


class Rule(BaseModel):
    id: str
    name: str
    severity: str = "medium"
    description: str = ""
    window_minutes: int = Field(default=15, ge=1, le=1440)
    threshold: int = Field(default=1, ge=1)
    group_by: list[str] = Field(default_factory=list)
    match: dict[str, dict[str, Any]] = Field(default_factory=dict)


class RuleSet(BaseModel):
    version: str = "1"
    rules: list[Rule]


ALLOWED_COLUMNS = {
    "class_uid",
    "category_uid",
    "type_uid",
    "activity_id",
    "severity_id",
    "status_id",
    "source_product",
    "source_vendor",
    "actor_user_uid",
    "actor_user_name",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "device_uid",
    "device_hostname",
    "resource_uid",
    "cloud_account_uid",
    "message",
}


def load_rules(path: Path) -> RuleSet:
    return RuleSet.model_validate(yaml.safe_load(path.read_text()))


class RuleEngine:
    def __init__(self, repository: StarRocksRepository, rules: RuleSet) -> None:
        self.repository = repository
        self.rules = rules

    @staticmethod
    def _where(rule: Rule, tenant_id: str) -> tuple[str, list[Any]]:
        clauses = ["tenant_id = %s", "event_time >= %s"]
        params: list[Any] = [
            tenant_id,
            datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=rule.window_minutes),
        ]
        for column, operations in rule.match.items():
            if column not in ALLOWED_COLUMNS:
                raise ValueError(f"rule {rule.id}: unsupported column {column!r}")
            if not isinstance(operations, dict) or len(operations) != 1:
                raise ValueError(f"rule {rule.id}: {column} requires exactly one operation")
            operator, value = next(iter(operations.items()))
            if operator == "eq":
                clauses.append(f"{column} = %s")
                params.append(value)
            elif operator == "gte":
                clauses.append(f"{column} >= %s")
                params.append(value)
            elif operator == "in":
                if not isinstance(value, list) or not value:
                    raise ValueError(f"rule {rule.id}: 'in' requires a nonempty list")
                clauses.append(f"{column} IN ({','.join(['%s'] * len(value))})")
                params.extend(value)
            elif operator == "contains" and column == "message":
                clauses.append("LOWER(message) LIKE %s")
                params.append(f"%{str(value).lower()}%")
            else:
                raise ValueError(f"rule {rule.id}: unsupported operation {operator!r} on {column}")
        return " AND ".join(clauses), params

    @staticmethod
    def _safe_group_by(rule: Rule) -> list[str]:
        invalid = set(rule.group_by) - ALLOWED_COLUMNS
        if invalid:
            raise ValueError(f"rule {rule.id}: unsupported group columns {sorted(invalid)}")
        return rule.group_by

    def evaluate_rule(self, rule: Rule, tenant_id: str) -> list[dict[str, Any]]:
        group_columns = self._safe_group_by(rule)
        where, params = self._where(rule, tenant_id)
        selected = ", ".join(
            group_columns + ["COUNT(*) AS event_count", "MAX(event_time) AS last_seen"]
        )
        grouping = f" GROUP BY {', '.join(group_columns)}" if group_columns else ""
        statement = (
            f"SELECT {selected} FROM ocsf_events WHERE {where}{grouping} "
            "HAVING COUNT(*) >= %s ORDER BY event_count DESC LIMIT 1000"
        )
        return self.repository.query(statement, (*params, rule.threshold))

    def run(self, tenant_id: str) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []
        for rule in self.rules.rules:
            for evidence in self.evaluate_rule(rule, tenant_id):
                correlation_key = (
                    "|".join(str(evidence.get(key, "")) for key in rule.group_by) or "global"
                )
                identity = f"{tenant_id}|{rule.id}|{correlation_key}|{evidence['last_seen']}"
                alert_id = hashlib.sha256(identity.encode()).hexdigest()[:32]
                existing = self.repository.query(
                    "SELECT alert_id FROM alerts WHERE alert_id=%s LIMIT 1", (alert_id,)
                )
                if existing:
                    continue
                title = f"{rule.name}: {correlation_key} ({evidence['event_count']} events)"
                alert = {
                    "alert_id": alert_id,
                    "created_at": datetime.now(UTC).replace(tzinfo=None),
                    "tenant_id": tenant_id,
                    "rule_id": rule.id,
                    "severity": rule.severity,
                    "title": title,
                    "status": "new",
                    "correlation_key": correlation_key,
                    "evidence": {"rule": rule.model_dump(), "aggregation": evidence},
                }
                self.repository.insert_alert(alert)
                alerts.append(alert)
        return alerts

    def explain(self) -> str:
        return json.dumps(self.rules.model_dump(), ensure_ascii=False, indent=2, default=str)
