"""Explainable, bounded retrospective clustering for OCSF event history.

This module intentionally uses no opaque model and no second analytics store.
StarRocks filters and orders the time-bounded historical event set; the small,
bounded result is then sessionised by shared OCSF entities.  The resulting
clusters are investigation candidates, not incident verdicts.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from hashlib import sha256
from math import log2
from typing import Any

_SEVERITY_NAMES = {
    0: "unknown",
    1: "informational",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
    6: "fatal",
}
_SEVERITY_VALUES = {name: value for value, name in _SEVERITY_NAMES.items()}


class _UnionFind:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def _as_utc_naive(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise ValueError("historical event time must be a datetime or ISO-8601 string")
    if parsed.tzinfo:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _severity_id(event: dict[str, Any]) -> int:
    value = event.get("severity_id", event.get("severity", 0))
    if isinstance(value, str):
        return _SEVERITY_VALUES.get(value.lower(), 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _event_time(event: dict[str, Any]) -> datetime:
    return _as_utc_naive(event.get("event_time", event.get("time")))


def _event_uid(event: dict[str, Any], position: int) -> str:
    return str(event.get("event_uid") or event.get("uid") or f"historical-event-{position}")


def event_entities(event: dict[str, Any]) -> dict[str, str]:
    """Extract stable, non-empty OCSF projections used to connect sessions."""
    candidates = {
        "user": event.get("actor_user_uid") or event.get("actor_user_name"),
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dst_ip"),
        "asset": event.get("device_uid") or event.get("device_hostname"),
        "resource": event.get("resource_uid") or event.get("resource_name"),
        "cloud_account": event.get("cloud_account_uid"),
        "trace": event.get("trace_id"),
    }
    return {
        kind: f"{kind}:{value}" for kind, value in candidates.items() if value not in (None, "")
    }


def _cluster_hypothesis(class_uids: set[int], event_count: int) -> str:
    if 6003 in class_uids and (3002 in class_uids or 4001 in class_uids):
        return "云身份/API 操作与网络或认证活动形成候选会话，建议复核权限、数据访问与会话来源。"
    if 3002 in class_uids and 4001 in class_uids:
        return "身份认证与后续网络活动在同一实体会话内相连，建议核验有效账号与异常外联链路。"
    if 1007 in class_uids and 4001 in class_uids:
        return "终端进程与网络活动形成候选执行/横向移动链路，建议结合进程树和 EDR 遥测验证。"
    if event_count >= 5:
        return "多个 OCSF 事件通过共享实体和时间邻近形成行为簇，适合作为事后调查的优先入口。"
    return "事件因共享实体和时间邻近被归入同一候选簇；需结合原始日志进一步判断业务语义。"


def _cluster_actions(class_uids: set[int]) -> list[str]:
    actions = ["按 event_uid 回看原始 OCSF raw_event，确认字段质量、时钟和采集覆盖。"]
    if 3002 in class_uids:
        actions.append("核验身份提供商、MFA、会话和地理位置基线。")
    if 4001 in class_uids:
        actions.append("关联 DNS、代理、NetFlow 和端点进程，确认网络连接用途。")
    if 6003 in class_uids:
        actions.append("审计云角色、临时凭据和对象访问范围。")
    if 1007 in class_uids:
        actions.append("保全终端进程树、命令行、父子进程和文件遥测。")
    return actions[:3]


def _class_baseline(rows: list[dict[str, Any]] | None) -> dict[int, int]:
    baseline: dict[int, int] = {}
    for row in rows or []:
        try:
            baseline[int(row["class_uid"])] = int(row["event_count"])
        except (KeyError, TypeError, ValueError):
            continue
    return baseline


def analyze_historical_events(
    events: list[dict[str, Any]],
    *,
    tenant_id: str,
    start_time: datetime,
    end_time: datetime,
    session_gap_minutes: int = 30,
    cluster_limit: int = 12,
    baseline_rows: list[dict[str, Any]] | None = None,
    truncated: bool = False,
) -> dict[str, Any]:
    """Sessionise a bounded event slice and emit explainable behavior clusters.

    Two events are joined only when they share an OCSF-projected entity and the
    most recent observation of that entity is inside ``session_gap_minutes``.
    This favors actionable time-local investigations over a global similarity
    graph that would accidentally connect every historical observation.
    """
    if end_time <= start_time:
        raise ValueError("end_time must be after start_time")
    if not 1 <= session_gap_minutes <= 240:
        raise ValueError("session_gap_minutes must be between 1 and 240")
    if not 1 <= cluster_limit <= 50:
        raise ValueError("cluster_limit must be between 1 and 50")

    prepared = [
        {"record": event, "time": _event_time(event), "uid": _event_uid(event, index)}
        for index, event in enumerate(events)
    ]
    prepared.sort(key=lambda item: (item["time"], item["uid"]))
    baseline = _class_baseline(baseline_rows)
    baseline_event_count = sum(baseline.values())
    scope_hours = max((end_time - start_time).total_seconds() / 3600, 1)

    if not prepared:
        return {
            "analysis_kind": "retrospective_behavior_clusters",
            "tenant_id": tenant_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "scope": {
                "start_time": start_time.isoformat() + "Z",
                "end_time": end_time.isoformat() + "Z",
                "session_gap_minutes": session_gap_minutes,
            },
            "coverage": {"events_examined": 0, "truncated": truncated, "distinct_entities": 0},
            "baseline": {
                "available": bool(baseline_rows),
                "event_count": baseline_event_count,
                "class_counts": baseline,
            },
            "clusters": [],
            "method": {
                "name": "time-local shared-entity sessionization",
                "description": "No events were available in the selected historical window.",
            },
            "analyst_notes": ["扩大时间范围、检查分区保留策略或确认该租户是否已摄入 OCSF 事件。"],
        }

    union_find = _UnionFind(len(prepared))
    latest_by_entity: dict[str, tuple[datetime, int]] = {}
    gap_seconds = session_gap_minutes * 60
    for index, item in enumerate(prepared):
        for entity in event_entities(item["record"]).values():
            previous = latest_by_entity.get(entity)
            if previous and (item["time"] - previous[0]).total_seconds() <= gap_seconds:
                union_find.union(index, previous[1])
            latest_by_entity[entity] = (item["time"], index)

    components: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, item in enumerate(prepared):
        components[union_find.find(index)].append(item)

    class_counts = Counter(int(item["record"].get("class_uid") or 0) for item in prepared)
    clusters: list[dict[str, Any]] = []
    for component in components.values():
        component.sort(key=lambda item: item["time"])
        component_classes = {int(item["record"].get("class_uid") or 0) for item in component}
        entity_counts = Counter(
            entity for item in component for entity in event_entities(item["record"]).values()
        )
        severity_counts = Counter(_severity_id(item["record"]) for item in component)
        critical_or_higher = sum(
            count for severity, count in severity_counts.items() if severity >= 5
        )
        high_or_higher = sum(count for severity, count in severity_counts.items() if severity >= 4)
        unseen_classes = sorted(
            class_uid for class_uid in component_classes if baseline and class_uid not in baseline
        )
        rare_scope_classes = sorted(
            class_uid for class_uid in component_classes if class_counts[class_uid] <= 2
        )
        shared_entities = [entity for entity, count in entity_counts.most_common(8) if count >= 2]
        duration_minutes = max(
            0, round((component[-1]["time"] - component[0]["time"]).total_seconds() / 60, 1)
        )
        diversity = len(component_classes)
        risk_score = min(
            100,
            round(
                12
                + min(30, log2(len(component) + 1) * 10)
                + min(22, len(entity_counts) * 2)
                + min(16, diversity * 4)
                + min(28, critical_or_higher * 14 + max(high_or_higher - critical_or_higher, 0) * 5)
                + min(14, len(unseen_classes) * 7 + len(rare_scope_classes) * 2)
            ),
        )
        signals: list[str] = []
        if critical_or_higher:
            signals.append(f"包含 {critical_or_higher} 个 critical/fatal 事件")
        elif high_or_higher:
            signals.append(f"包含 {high_or_higher} 个 high 及以上事件")
        if len(component_classes) >= 2:
            signals.append(f"跨 {len(component_classes)} 个 OCSF 事件类别")
        if len(shared_entities) >= 2:
            signals.append(f"由 {len(shared_entities)} 个重复出现的实体连接")
        if unseen_classes:
            signals.append(f"基线窗口未出现的 class_uid: {', '.join(map(str, unseen_classes))}")
        elif rare_scope_classes:
            signals.append(f"当前范围低频 class_uid: {', '.join(map(str, rare_scope_classes))}")
        if not signals:
            signals.append("共享实体与时间邻近是本簇的唯一关联依据")

        evidence = [
            {
                "event_uid": item["uid"],
                "event_time": item["time"].isoformat() + "Z",
                "class_uid": int(item["record"].get("class_uid") or 0),
                "severity": _SEVERITY_NAMES.get(_severity_id(item["record"]), "unknown"),
                "message": str(item["record"].get("message") or "")[:280],
            }
            for item in component[:20]
        ]
        cluster_identity = "|".join(item["uid"] for item in component)
        clusters.append(
            {
                "cluster_id": f"retro-{sha256(cluster_identity.encode()).hexdigest()[:16]}",
                "risk_score": risk_score,
                "start_time": component[0]["time"].isoformat() + "Z",
                "end_time": component[-1]["time"].isoformat() + "Z",
                "duration_minutes": duration_minutes,
                "event_count": len(component),
                "entity_count": len(entity_counts),
                "class_uids": sorted(component_classes),
                "shared_entities": shared_entities,
                "signals": signals,
                "hypothesis": _cluster_hypothesis(component_classes, len(component)),
                "recommended_checks": _cluster_actions(component_classes),
                "evidence": evidence,
                "baseline_comparison": {
                    "baseline_available": bool(baseline_rows),
                    "unseen_class_uids": unseen_classes,
                    "scope_low_frequency_class_uids": rare_scope_classes,
                },
            }
        )

    clusters.sort(
        key=lambda cluster: (-cluster["risk_score"], -cluster["event_count"], cluster["start_time"])
    )
    distinct_entities = len(
        {entity for item in prepared for entity in event_entities(item["record"]).values()}
    )
    notes = [
        "聚类只使用同一租户、指定时间范围、共享 OCSF 实体和会话时间间隔。",
        "簇是调查候选项；时间邻近、共用 IP 或共用资产不构成攻击归因。",
        "风险分数是可解释的优先级排序，不是模型概率或自动处置结论。",
    ]
    if truncated:
        notes.insert(
            0, "结果已受 max_events 上限截断；请缩小时间窗或离线分区批处理以获得完整覆盖。"
        )
    return {
        "analysis_kind": "retrospective_behavior_clusters",
        "tenant_id": tenant_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "scope": {
            "start_time": start_time.isoformat() + "Z",
            "end_time": end_time.isoformat() + "Z",
            "duration_hours": round(scope_hours, 2),
            "session_gap_minutes": session_gap_minutes,
        },
        "coverage": {
            "events_examined": len(prepared),
            "truncated": truncated,
            "distinct_entities": distinct_entities,
            "candidate_clusters": len(components),
            "clusters_returned": min(len(clusters), cluster_limit),
        },
        "baseline": {
            "available": bool(baseline_rows),
            "event_count": baseline_event_count,
            "class_counts": baseline,
        },
        "clusters": clusters[:cluster_limit],
        "method": {
            "name": "time-local shared-entity sessionization",
            "description": (
                "Events are connected only when an OCSF-projected user, IP, asset, resource, "
                "cloud account, or trace is seen again inside the configured session gap."
            ),
            "feature_fields": [
                "actor_user_uid/name",
                "src_ip/dst_ip",
                "device_uid/hostname",
                "resource_uid/name",
                "cloud_account_uid",
                "trace_id",
            ],
        },
        "analyst_notes": notes,
    }
