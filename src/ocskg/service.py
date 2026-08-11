"""Application services that compose OCSF, graph, detection, and RAG contracts."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any
from uuid import uuid4

from .adapters import SourceFormat, to_ocsf_event
from .config import Settings
from .demo import make_demo_scenario
from .detection import RuleEngine, load_rules
from .embedding import EmbeddingProvider, HashEmbeddingProvider
from .llm import OpenAICompatibleClient
from .ocsf import normalize_ocsf_event
from .repository import StarRocksRepository
from .retrospective import analyze_historical_events
from .text_graph import attach_llm_relations, extract_rule_graph


class SecurityGraphService:
    def __init__(
        self,
        repository: StarRocksRepository,
        settings: Settings,
        embedding_provider: EmbeddingProvider | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.embedding_provider = embedding_provider or HashEmbeddingProvider(
            settings.vector_dimension
        )

    def ingest(self, events: Iterable[dict[str, Any]], tenant_id: str) -> int:
        normalized = [normalize_ocsf_event(event, tenant_id) for event in events]
        return self.repository.ingest(normalized)

    def ingest_source(
        self, events: Iterable[dict[str, Any]], source_format: SourceFormat | str, tenant_id: str
    ) -> int:
        return self.ingest((to_ocsf_event(event, source_format) for event in events), tenant_id)

    def run_detections(self, tenant_id: str) -> list[dict[str, Any]]:
        return RuleEngine(self.repository, load_rules(self.settings.rules_path)).run(tenant_id)

    def add_document(
        self, content: str, tenant_id: str, entity_id: str, chunk_id: str | None = None
    ) -> str:
        chunk_id = chunk_id or uuid4().hex
        embedding = self.embedding_provider.embed(content)
        self.repository.add_document(chunk_id, tenant_id, entity_id, content, embedding)
        return chunk_id

    def extract_text_graph(
        self,
        content: str,
        tenant_id: str,
        source_id: str | None = None,
        source_type: str = "security_report",
        extractor: str = "rules",
        persist: bool = True,
    ) -> dict[str, Any]:
        """Turn report indicators into reviewable graph evidence.

        Rules always identify the entity set.  An optional compatible LLM may
        propose only whitelisted relations between those entities, and every
        relation remains pending review before it can be treated as a finding.
        """
        if extractor not in {"rules", "llm"}:
            raise ValueError("extractor must be either 'rules' or 'llm'")
        source_id = source_id or f"text-{uuid4().hex[:20]}"
        extraction = extract_rule_graph(content, source_id, source_type)
        if extractor == "llm" and extraction["entities"]:
            proposal = OpenAICompatibleClient(self.settings).extract_text_relations(
                content, extraction["entities"]
            )
            extraction = attach_llm_relations(extraction, proposal["proposal"])
            extraction["extractor"]["provider"] = proposal["provider"]
            extraction["extractor"]["model"] = proposal["model"]
        if persist:
            self.repository.persist_text_graph(tenant_id, extraction)
        extraction["tenant_id"] = tenant_id
        extraction["persisted"] = persist
        return extraction

    def load_demo(self, tenant_id: str, run_id: str | None = None) -> dict[str, Any]:
        """Load a complete, current-time detection story without external services."""
        run_id, events, documents = make_demo_scenario(run_id)
        event_count = self.ingest(events, tenant_id)
        document_ids = [
            self.add_document(
                content=document["content"],
                tenant_id=tenant_id,
                entity_id=document["entity_id"],
                chunk_id=document["chunk_id"],
            )
            for document in documents
        ]
        alerts = self.run_detections(tenant_id)
        return {
            "run_id": run_id,
            "tenant_id": tenant_id,
            "ingested_events": event_count,
            "document_ids": document_ids,
            "created_alerts": alerts,
            "demo_entities": {
                "user": "user:demo-alice",
                "asset": "asset:demo-web-01",
                "attacker_ip": "ip:203.0.113.42",
            },
            "next_step": "Open /v1/graph/user:demo-alice or submit /v1/agent/investigations.",
        }

    def investigate(
        self,
        entity_id: str,
        question: str,
        tenant_id: str,
        depth: int | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        depth = min(depth or self.settings.graph_max_depth, self.settings.graph_max_depth)
        graph = self.repository.graph_context(entity_id, tenant_id, depth, limit)
        linked_events = self.repository.event_summary(
            [node["entity_id"] for node in graph["nodes"]], tenant_id, limit
        )
        semantic_context: list[dict[str, Any]] = []
        if self.settings.vector_search_enabled and question.strip():
            semantic_context = self.repository.semantic_search(
                tenant_id, self.embedding_provider.embed(question), min(limit, 20)
            )
        return {
            "question": question,
            "graph": graph,
            "events": linked_events,
            "retrieved_context": semantic_context,
            "agent_instruction": (
                "Treat OCSF raw_event as source evidence. Cite event_uid and alert_id in any conclusion; "
                "do not treat vector similarity as proof of compromise."
            ),
        }

    def analyze_history(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        baseline_start_time: datetime,
        session_gap_minutes: int,
        max_events: int,
        cluster_limit: int,
    ) -> dict[str, Any]:
        """Build bounded, explainable investigation candidates from historical OCSF data."""
        events = self.repository.historical_events(tenant_id, start_time, end_time, max_events)
        baseline_rows = self.repository.historical_class_baseline(
            tenant_id, baseline_start_time, start_time
        )
        result = analyze_historical_events(
            events,
            tenant_id=tenant_id,
            start_time=start_time,
            end_time=end_time,
            session_gap_minutes=session_gap_minutes,
            cluster_limit=cluster_limit,
            baseline_rows=baseline_rows,
            truncated=len(events) >= max_events,
        )
        result["mode"] = "live"
        result["query_guardrails"] = {
            "max_events": max_events,
            "partition_pruning": "tenant_id + event_date + event_time",
            "baseline": "class-level aggregate before the analysis window",
        }
        return result
