from datetime import datetime

import pytest

from ocskg.embedding import HashEmbeddingProvider
from ocskg.ocsf import normalize_ocsf_event


def test_normalizes_ocsf_event_and_builds_event_scoped_edges() -> None:
    record = normalize_ocsf_event(
        {
            "metadata": {"uid": "evt-1", "product": {"name": "sensor", "vendor_name": "acme"}},
            "time": "2026-08-10T08:00:00Z",
            "class_uid": 4001,
            "actor": {"user": {"uid": "user-1", "name": "alice"}},
            "src_endpoint": {"ip": "10.0.0.1"},
            "dst_endpoint": {"ip": "198.51.100.7", "port": 443},
            "device": {"uid": "asset-1", "hostname": "web-01"},
        },
        tenant_id="acme-prod",
    )

    assert record["event_uid"] == "evt-1"
    assert record["event_time"] == datetime(2026, 8, 10, 8, 0)
    assert record["tenant_id"] == "acme-prod"
    assert record["dst_port"] == 443
    assert {entity["entity_id"] for entity in record["entities"]} >= {
        "event:evt-1",
        "user:user-1",
        "ip:10.0.0.1",
        "asset:asset-1",
    }
    assert all(edge["src_id"] == "event:evt-1" for edge in record["edges"])


def test_rejects_invalid_event_and_parses_epoch_milliseconds() -> None:
    with pytest.raises(ValueError, match="JSON object"):
        normalize_ocsf_event([])  # type: ignore[arg-type]

    record = normalize_ocsf_event({"time": 0})
    assert record["event_time"] == datetime(1970, 1, 1)


def test_hash_embedding_is_stable_normalized_and_dimensioned() -> None:
    provider = HashEmbeddingProvider(16)
    vector = provider.embed("suspicious powershell egress")

    assert vector == provider.embed("suspicious powershell egress")
    assert len(vector) == 16
    assert pytest.approx(sum(value * value for value in vector), rel=1e-6) == 1.0
