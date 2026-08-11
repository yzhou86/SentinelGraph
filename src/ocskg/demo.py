"""A repeatable, current-time attack story for customer demonstrations."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4


def make_demo_scenario(
    run_id: str | None = None,
) -> tuple[str, list[dict[str, Any]], list[dict[str, str]]]:
    """Create a credential attack -> egress -> vulnerable asset story."""
    run_id = run_id or uuid4().hex[:10]
    now = datetime.now(UTC)
    user = {"uid": "demo-alice", "name": "alice"}
    device = {"uid": "demo-web-01", "hostname": "web-01.prod.demo"}
    attacker_ip = "203.0.113.42"
    events: list[dict[str, Any]] = []
    for index in range(5):
        events.append(
            {
                "metadata": {
                    "uid": f"demo-{run_id}-auth-{index}",
                    "product": {"name": "Demo Identity Provider", "vendor_name": "SentinelGraph"},
                },
                "time": int((now - timedelta(minutes=5 - index)).timestamp() * 1000),
                "class_uid": 3002,
                "category_uid": 3,
                "activity_id": 1,
                "status_id": 2,
                "severity_id": 3,
                "actor": {"user": user},
                "src_endpoint": {"ip": attacker_ip},
                "device": device,
                "message": "Authentication failed: invalid password",
            }
        )
    for index in range(3):
        events.append(
            {
                "metadata": {
                    "uid": f"demo-{run_id}-egress-{index}",
                    "product": {"name": "Demo Network Sensor", "vendor_name": "SentinelGraph"},
                    "correlation_uid": f"demo-{run_id}-campaign",
                },
                "time": int((now - timedelta(minutes=2 - index)).timestamp() * 1000),
                "class_uid": 4001,
                "category_uid": 4,
                "activity_id": 1,
                "severity_id": 4,
                "actor": {"user": user},
                "src_endpoint": {"ip": "10.24.8.15"},
                "dst_endpoint": {"ip": "198.51.100.9", "port": 4444},
                "device": device,
                "connection_info": {"protocol_name": "tls"},
                "message": "Repeated outbound TLS connection to unusual destination port",
            }
        )
    events.append(
        {
            "metadata": {
                "uid": f"demo-{run_id}-vulnerability",
                "product": {"name": "Demo Vulnerability Scanner", "vendor_name": "SentinelGraph"},
            },
            "time": int(now.timestamp() * 1000),
            "class_uid": 2002,
            "category_uid": 2,
            "severity_id": 5,
            "device": device,
            "resource": {"uid": "pkg:openssl", "name": "OpenSSL on web-01"},
            "message": "CVE-2025-9999 critical remote code execution exposure",
        }
    )
    documents = [
        {
            "chunk_id": f"demo-{run_id}-playbook-auth",
            "entity_id": "user:demo-alice",
            "content": "Credential attack triage: block the source IP, require password reset, review MFA and sessions.",
        },
        {
            "chunk_id": f"demo-{run_id}-playbook-egress",
            "entity_id": "asset:demo-web-01",
            "content": "Unusual TLS egress: isolate the host, capture process tree, preserve network evidence, and block C2 IP.",
        },
        {
            "chunk_id": f"demo-{run_id}-playbook-vuln",
            "entity_id": "resource:pkg:openssl",
            "content": "Critical CVE response: validate exposure, prioritize patching, apply compensating controls, and rescan.",
        },
    ]
    return run_id, events, documents
