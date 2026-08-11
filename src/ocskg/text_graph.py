"""Explainable text-to-graph extraction for security reports and playbooks.

The rules in this module deliberately produce conservative relations.  A
co-mention means only that two indicators occurred in the same sentence; it is
never represented as proof of communication, ownership, or attribution.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

_IP_PATTERN = re.compile(r"(?<![\w:.])(?:\d{1,3}\.){3}\d{1,3}(?![\w:]|\.\d)")
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
_URL_PATTERN = re.compile(r"\bhttps?://[^\s<>()\[\]{}\"']+", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(
    r"(?<![@/\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
_SHA256_PATTERN = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)
_SENTENCE_BOUNDARY = re.compile(r"[!?]+|\.(?=\s+[A-Z]|\s*$)|\n+", re.UNICODE)

_TYPE_PREFIXES = {
    "ip": "ip",
    "cve": "vulnerability",
    "email": "email",
    "url": "url",
    "domain": "domain",
    "hash": "hash",
}
_TYPE_CONFIDENCE = {
    "ip": 0.99,
    "cve": 0.99,
    "email": 0.98,
    "url": 0.97,
    "domain": 0.92,
    "hash": 0.99,
}


def _stable_id(*parts: str, prefix: str = "txt", length: int = 24) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:length]
    return f"{prefix}-{digest}"


def _canonical_value(entity_type: str, value: str) -> str:
    normalized = value.strip().rstrip(".,;:)")
    if entity_type == "cve":
        return normalized.upper()
    return normalized.lower()


def _entity_id(entity_type: str, value: str) -> str:
    return f"{_TYPE_PREFIXES[entity_type]}:{_canonical_value(entity_type, value)}"


def _spans(
    pattern: re.Pattern[str], entity_type: str, content: str
) -> Iterable[tuple[str, int, int]]:
    for match in pattern.finditer(content):
        value = _canonical_value(entity_type, match.group())
        if entity_type == "ip":
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
        yield value, match.start(), match.end()


def _sentences(content: str) -> Iterable[tuple[int, int, str]]:
    start = 0
    for boundary in _SENTENCE_BOUNDARY.finditer(content):
        end = boundary.end()
        sentence = content[start:end].strip()
        if sentence:
            yield start, end, sentence
        start = end
    sentence = content[start:].strip()
    if sentence:
        yield start, len(content), sentence


def _sentence_for(content: str, offset: int) -> str:
    for start, end, sentence in _sentences(content):
        if start <= offset < end:
            return sentence[:800]
    return content[max(0, offset - 120) : offset + 220].strip()


def extract_rule_graph(
    content: str,
    source_id: str,
    source_type: str = "security_report",
) -> dict[str, Any]:
    """Extract high-confidence indicators and explicitly conservative relations."""
    if not content.strip():
        raise ValueError("content must not be empty")
    if not source_id.strip():
        raise ValueError("source_id must not be empty")

    source_id = source_id.strip()
    document_id = f"document:{source_id}"
    candidates: list[tuple[str, str, int, int]] = []
    for entity_type, pattern in (
        ("ip", _IP_PATTERN),
        ("cve", _CVE_PATTERN),
        ("email", _EMAIL_PATTERN),
        ("url", _URL_PATTERN),
        ("domain", _DOMAIN_PATTERN),
        ("hash", _SHA256_PATTERN),
    ):
        candidates.extend(
            (entity_type, value, start, end)
            for value, start, end in _spans(pattern, entity_type, content)
        )

    entities_by_id: dict[str, dict[str, Any]] = {}
    occupied_spans: list[tuple[int, int]] = []
    for entity_type, value, start, end in sorted(
        candidates, key=lambda item: (item[2], -(item[3] - item[2]))
    ):
        # Domains inside a URL or an e-mail are already represented by their stronger IOC type.
        if entity_type == "domain" and any(
            start >= left and end <= right for left, right in occupied_spans
        ):
            continue
        if entity_type in {"url", "email"}:
            occupied_spans.append((start, end))
        entity_id = _entity_id(entity_type, value)
        occurrence = {
            "start": start,
            "end": end,
            "evidence": _sentence_for(content, start),
        }
        entity = entities_by_id.setdefault(
            entity_id,
            {
                "entity_id": entity_id,
                "entity_type": _TYPE_PREFIXES[entity_type],
                "name": value,
                "confidence": _TYPE_CONFIDENCE[entity_type],
                "occurrences": [],
            },
        )
        entity["occurrences"].append(occurrence)

    entities = list(entities_by_id.values())
    relations: list[dict[str, Any]] = []
    for entity in entities:
        evidence = entity["occurrences"][0]["evidence"]
        relations.append(
            {
                "extraction_id": _stable_id(
                    source_id, document_id, entity["entity_id"], "mentions"
                ),
                "src_id": document_id,
                "dst_id": entity["entity_id"],
                "relation": "mentions",
                "confidence": entity["confidence"],
                "evidence": evidence,
                "status": "pending_review",
                "relation_kind": "direct_indicator",
            }
        )

    # A sentence-level co-mention is useful for analyst exploration but is explicitly
    # marked as derived and lower-confidence.  It avoids hallucinating a stronger edge.
    for sentence_start, sentence_end, sentence_text in _sentences(content):
        sentence_entities = [
            entity
            for entity in entities
            if any(sentence_start <= item["start"] < sentence_end for item in entity["occurrences"])
        ]
        for index, source in enumerate(sentence_entities):
            for target in sentence_entities[index + 1 :]:
                relations.append(
                    {
                        "extraction_id": _stable_id(
                            source_id,
                            source["entity_id"],
                            target["entity_id"],
                            "co_mentioned",
                            sentence_text,
                        ),
                        "src_id": source["entity_id"],
                        "dst_id": target["entity_id"],
                        "relation": "co_mentioned_in_sentence",
                        "confidence": 0.55,
                        "evidence": sentence_text[:800],
                        "status": "pending_review",
                        "relation_kind": "derived_co_mention",
                    }
                )

    return {
        "source": {
            "source_id": source_id,
            "source_type": source_type,
            "entity_id": document_id,
        },
        "extractor": {"name": "rules", "version": "1", "requires_llm": False},
        "created_at": datetime.now(UTC),
        "entities": entities,
        "relations": relations,
        "review_guidance": "All text-derived relations start as pending_review. Co-mention is context only, not a claim of communication or attribution.",
    }


def attach_llm_relations(extraction: dict[str, Any], llm_payload: dict[str, Any]) -> dict[str, Any]:
    """Validate optional LLM-proposed relations against rule-extracted entities.

    The model may only link existing high-confidence entities.  This keeps the
    evidence surface bounded and ensures a reviewer can reject every proposal.
    """
    allowed_relations = {
        "communicates_with",
        "targets",
        "hosted_on",
        "uses",
        "affects",
        "associated_with",
    }
    entities_by_id = {entity["entity_id"]: entity for entity in extraction["entities"]}
    additions: list[dict[str, Any]] = []
    for item in llm_payload.get("relations", []):
        if not isinstance(item, dict):
            continue
        source = str(item.get("source_id", "")).strip()
        target = str(item.get("target_id", "")).strip()
        relation = str(item.get("relation", "")).strip().lower()
        evidence = str(item.get("evidence", "")).strip()[:800]
        confidence = item.get("confidence", 0.5)
        if source not in entities_by_id or target not in entities_by_id or source == target:
            continue
        if relation not in allowed_relations or not evidence:
            continue
        try:
            confidence = max(0.0, min(float(confidence), 1.0))
        except (TypeError, ValueError):
            confidence = 0.5
        additions.append(
            {
                "extraction_id": _stable_id(
                    extraction["source"]["source_id"], source, target, relation, evidence
                ),
                "src_id": source,
                "dst_id": target,
                "relation": relation,
                "confidence": confidence,
                "evidence": evidence,
                "status": "pending_review",
                "relation_kind": "llm_proposed",
            }
        )
    extraction["relations"].extend(additions)
    extraction["extractor"] = {"name": "rules+llm", "version": "1", "requires_llm": True}
    return extraction
