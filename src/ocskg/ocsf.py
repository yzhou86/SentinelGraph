"""OCSF normalization boundary.

The project retains the full source document while projecting frequently used
OCSF attributes into typed columns. That means producers can evolve fields and
extensions without a schema migration, while detections stay columnar.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any


def _path(value: dict[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _as_timestamp(value: Any) -> datetime:
    if value is None:
        return datetime.now(UTC).replace(tzinfo=None)
    if isinstance(value, (int, float)):
        # OCSF time fields are epoch milliseconds.
        return datetime.fromtimestamp(value / 1000, tz=UTC).replace(tzinfo=None)
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        return (parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)).replace(
            tzinfo=None
        )
    raise ValueError("OCSF time must be epoch milliseconds or ISO-8601 text")


def _first(*values: Any) -> Any:
    return next((value for value in values if value not in (None, "")), None)


def _stable_event_uid(event: dict[str, Any]) -> str:
    explicit = _first(
        _path(event, "metadata", "uid"), event.get("uid"), event.get("event_uid"), event.get("id")
    )
    if explicit:
        return str(explicit)
    canonical = json.dumps(event, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _entity(kind: str, identifier: Any, name: Any = None) -> dict[str, str] | None:
    identifier = _first(identifier, name)
    if identifier in (None, ""):
        return None
    identifier = str(identifier)
    return {
        "entity_id": f"{kind}:{identifier}",
        "entity_type": kind,
        "name": str(name or identifier),
    }


def normalize_ocsf_event(event: dict[str, Any], tenant_id: str = "default") -> dict[str, Any]:
    """Project an OCSF event into the StarRocks event and graph contracts."""
    if not isinstance(event, dict):
        raise ValueError("each OCSF event must be a JSON object")

    event_time = _as_timestamp(_first(event.get("time"), event.get("time_dt")))
    event_uid = _stable_event_uid(event)
    actor_uid = _first(_path(event, "actor", "user", "uid"), _path(event, "user", "uid"))
    actor_name = _first(_path(event, "actor", "user", "name"), _path(event, "user", "name"))
    src_ip = _first(
        _path(event, "src_endpoint", "ip"),
        _path(event, "src_endpoint", "ip_address"),
        _path(event, "connection_info", "src_ip"),
    )
    dst_ip = _first(
        _path(event, "dst_endpoint", "ip"),
        _path(event, "dst_endpoint", "ip_address"),
        _path(event, "connection_info", "dst_ip"),
    )
    device_uid = _first(_path(event, "device", "uid"), _path(event, "endpoint", "uid"))
    device_name = _first(_path(event, "device", "hostname"), _path(event, "device", "name"))
    resource_uid = _first(_path(event, "resource", "uid"), _path(event, "resource", "name"))
    resource_name = _path(event, "resource", "name")
    cloud_account_uid = _first(
        _path(event, "cloud", "account", "uid"), _path(event, "cloud", "account_uid")
    )
    message = _first(event.get("message"), _path(event, "finding_info", "desc"), "")

    record: dict[str, Any] = {
        "event_uid": event_uid,
        "event_time": event_time,
        "event_date": event_time.date(),
        "ingest_time": datetime.now(UTC).replace(tzinfo=None),
        "class_uid": int(event.get("class_uid") or 0),
        "category_uid": int(event.get("category_uid") or 0),
        "type_uid": int(event.get("type_uid") or 0),
        "activity_id": int(event.get("activity_id") or 0),
        "severity_id": int(_first(event.get("severity_id"), _path(event, "severity", "id"), 0)),
        "status_id": int(event.get("status_id") or 0),
        "tenant_id": tenant_id,
        "source_product": str(_first(_path(event, "metadata", "product", "name"), "unknown")),
        "source_vendor": str(_first(_path(event, "metadata", "product", "vendor_name"), "unknown")),
        "actor_user_uid": str(actor_uid or ""),
        "actor_user_name": str(actor_name or ""),
        "src_ip": str(src_ip or ""),
        "dst_ip": str(dst_ip or ""),
        "dst_port": int(
            _first(
                _path(event, "dst_endpoint", "port"), _path(event, "connection_info", "dst_port"), 0
            )
        ),
        "protocol": str(
            _first(_path(event, "connection_info", "protocol_name"), event.get("protocol_name"), "")
        ),
        "device_uid": str(device_uid or ""),
        "device_hostname": str(device_name or ""),
        "resource_uid": str(resource_uid or ""),
        "resource_name": str(resource_name or ""),
        "cloud_account_uid": str(cloud_account_uid or ""),
        "trace_id": str(
            _first(_path(event, "metadata", "correlation_uid"), event.get("trace_id"), "")
        ),
        "message": str(message),
        "raw_event": json.dumps(event, ensure_ascii=False, default=str),
    }
    entities = [
        _entity("event", event_uid, f"OCSF class {record['class_uid']}"),
        _entity("user", actor_uid, actor_name),
        _entity("ip", src_ip),
        _entity("ip", dst_ip),
        _entity("asset", device_uid, device_name),
        _entity("resource", resource_uid, resource_name),
        _entity("cloud_account", cloud_account_uid),
    ]
    record["entities"] = [entity for entity in entities if entity]
    record["edges"] = [
        {
            "edge_id": hashlib.sha256(
                f"{event_uid}|observed|{entity['entity_id']}".encode()
            ).hexdigest(),
            "src_id": f"event:{event_uid}",
            "dst_id": entity["entity_id"],
            "relation": "observed",
            "event_uid": event_uid,
            "event_time": event_time,
            "tenant_id": tenant_id,
            "properties": json.dumps({"class_uid": record["class_uid"]}),
        }
        for entity in record["entities"]
        if entity["entity_type"] != "event"
    ]
    return record
