"""Small, explicit bridges from common telemetry JSON into OCSF-shaped events.

Adapters intentionally preserve the source record under ``unmapped``. They are
starter mappings, not replacements for source-specific production data quality
work or the official OCSF mapping profiles.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

SourceFormat = Literal["ocsf", "ecs", "cloudtrail", "zeek", "common_json", "auto"]
SUPPORTED_SOURCE_FORMATS = {"ocsf", "ecs", "cloudtrail", "zeek", "common_json", "auto"}


def _path(data: dict[str, Any], *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _first(*values: Any) -> Any:
    return next((value for value in values if value not in (None, "")), None)


def _as_epoch_millis(value: Any, seconds: bool = False) -> int:
    if isinstance(value, (int, float)):
        return int(value * 1000) if seconds else int(value)
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return int(parsed.timestamp() * 1000)
    return int(datetime.now(UTC).timestamp() * 1000)


def _as_int(value: Any, default: int = 0) -> int:
    if value in (None, ""):
        return default
    if isinstance(value, str):
        named_levels = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "warning": 3,
            "low": 2,
            "info": 1,
            "informational": 1,
        }
        if value.lower() in named_levels:
            return named_levels[value.lower()]
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def detect_source_format(event: dict[str, Any]) -> SourceFormat:
    if "class_uid" in event:
        return "ocsf"
    if "@timestamp" in event or "event" in event:
        return "ecs"
    if "eventTime" in event or "eventID" in event:
        return "cloudtrail"
    if isinstance(event.get("id"), dict) and "orig_h" in event["id"]:
        return "zeek"
    return "common_json"


def _metadata(uid: Any, name: str, vendor: str) -> dict[str, Any]:
    return {"uid": str(uid or ""), "product": {"name": name, "vendor_name": vendor}}


def from_ecs(event: dict[str, Any]) -> dict[str, Any]:
    categories = _path(event, "event", "category") or []
    categories = [categories] if isinstance(categories, str) else categories
    action = str(_path(event, "event", "action") or "")
    outcome = str(_path(event, "event", "outcome") or "").lower()
    is_auth = "authentication" in categories or "login" in action.lower()
    is_network = "network" in categories or bool(_path(event, "destination", "ip"))
    return {
        "metadata": _metadata(
            _path(event, "event", "id"),
            str(_first(_path(event, "observer", "product"), "ECS source")),
            str(_first(_path(event, "observer", "vendor"), "Elastic Common Schema")),
        ),
        "time": _as_epoch_millis(event.get("@timestamp")),
        "class_uid": 3002 if is_auth else 4001 if is_network else 0,
        "category_uid": 3 if is_auth else 4 if is_network else 0,
        "activity_id": 1,
        "status_id": 2 if outcome in {"failure", "failed"} else 1 if outcome == "success" else 0,
        "severity_id": _as_int(_first(event.get("severity"), _path(event, "log", "level"))),
        "actor": {
            "user": {
                "uid": str(_first(_path(event, "user", "id"), _path(event, "user", "name"), "")),
                "name": str(_path(event, "user", "name") or ""),
            }
        },
        "src_endpoint": {"ip": str(_path(event, "source", "ip") or "")},
        "dst_endpoint": {
            "ip": str(_path(event, "destination", "ip") or ""),
            "port": int(_path(event, "destination", "port") or 0),
        },
        "device": {
            "uid": str(_first(_path(event, "host", "id"), _path(event, "host", "name"), "")),
            "hostname": str(_path(event, "host", "name") or ""),
        },
        "message": str(_first(event.get("message"), action, "ECS event")),
        "unmapped": event,
    }


def from_cloudtrail(event: dict[str, Any]) -> dict[str, Any]:
    event_name = str(event.get("eventName") or "CloudTrail event")
    is_login = event_name.lower() == "consolelogin"
    failed = (
        bool(event.get("errorCode"))
        or str(event.get("responseElements", {}).get("ConsoleLogin")) == "Failure"
    )
    actor = event.get("userIdentity") if isinstance(event.get("userIdentity"), dict) else {}
    return {
        "metadata": _metadata(event.get("eventID"), "AWS CloudTrail", "AWS"),
        "time": _as_epoch_millis(event.get("eventTime")),
        "class_uid": 3002 if is_login else 0,
        "category_uid": 3 if is_login else 0,
        "activity_id": 1,
        "status_id": 2 if failed else 1,
        "severity_id": 3 if failed else 1,
        "actor": {
            "user": {
                "uid": str(_first(actor.get("principalId"), actor.get("arn"), "")),
                "name": str(_first(actor.get("userName"), actor.get("arn"), "")),
            }
        },
        "src_endpoint": {"ip": str(event.get("sourceIPAddress") or "")},
        "cloud": {"account": {"uid": str(event.get("recipientAccountId") or "")}},
        "message": " ".join(
            part for part in (event_name, str(event.get("errorCode") or "")) if part
        ),
        "unmapped": event,
    }


def from_zeek(event: dict[str, Any]) -> dict[str, Any]:
    connection = event.get("id") if isinstance(event.get("id"), dict) else {}
    return {
        "metadata": _metadata(event.get("uid"), "Zeek", "Zeek"),
        "time": _as_epoch_millis(event.get("ts"), seconds=True),
        "class_uid": 4001,
        "category_uid": 4,
        "activity_id": 1,
        "severity_id": _as_int(event.get("severity_id"), default=1),
        "src_endpoint": {"ip": str(connection.get("orig_h") or "")},
        "dst_endpoint": {
            "ip": str(connection.get("resp_h") or ""),
            "port": int(connection.get("resp_p") or 0),
        },
        "connection_info": {
            "protocol_name": str(_first(event.get("service"), event.get("proto"), ""))
        },
        "message": str(_first(event.get("note"), event.get("service"), "Zeek connection")),
        "unmapped": event,
    }


def from_common_json(event: dict[str, Any]) -> dict[str, Any]:
    outcome = str(_first(event.get("outcome"), event.get("status"), "")).lower()
    category = str(event.get("category") or "").lower()
    is_auth = category in {"auth", "authentication", "login"}
    is_network = category in {"network", "connection", "flow"} or bool(event.get("dst_ip"))
    return {
        "metadata": _metadata(
            _first(event.get("id"), event.get("event_id"), event.get("uuid")),
            str(_first(event.get("product"), event.get("source"), "common-json")),
            str(event.get("vendor") or "unknown"),
        ),
        "time": _as_epoch_millis(_first(event.get("timestamp"), event.get("time"))),
        "class_uid": 3002 if is_auth else 4001 if is_network else _as_int(event.get("class_uid")),
        "category_uid": 3 if is_auth else 4 if is_network else _as_int(event.get("category_uid")),
        "activity_id": _as_int(event.get("activity_id"), default=1),
        "status_id": 2
        if outcome in {"failure", "failed", "deny", "denied"}
        else 1
        if outcome
        else 0,
        "severity_id": _as_int(_first(event.get("severity"), event.get("severity_id"))),
        "actor": {
            "user": {
                "uid": str(_first(event.get("user_id"), event.get("user"), "")),
                "name": str(event.get("user") or ""),
            }
        },
        "src_endpoint": {"ip": str(event.get("src_ip") or event.get("source_ip") or "")},
        "dst_endpoint": {
            "ip": str(event.get("dst_ip") or event.get("destination_ip") or ""),
            "port": int(event.get("dst_port") or event.get("destination_port") or 0),
        },
        "device": {
            "uid": str(_first(event.get("host_id"), event.get("hostname"), "")),
            "hostname": str(event.get("hostname") or ""),
        },
        "message": str(_first(event.get("message"), event.get("description"), "Common JSON event")),
        "unmapped": event,
    }


def to_ocsf_event(
    event: dict[str, Any], source_format: SourceFormat | str = "auto"
) -> dict[str, Any]:
    """Map one supported source record to the OCSF-shaped intake contract."""
    if source_format not in SUPPORTED_SOURCE_FORMATS:
        raise ValueError(
            f"unsupported source format {source_format!r}; choose {sorted(SUPPORTED_SOURCE_FORMATS)}"
        )
    resolved = detect_source_format(event) if source_format == "auto" else source_format
    if resolved == "ocsf":
        return event
    if resolved == "ecs":
        return from_ecs(event)
    if resolved == "cloudtrail":
        return from_cloudtrail(event)
    if resolved == "zeek":
        return from_zeek(event)
    return from_common_json(event)
