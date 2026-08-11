"""StarRocks persistence adapter.

All graph traversal, detection aggregation, and semantic retrieval stay in
StarRocks SQL; this module deliberately does not introduce a second graph or
vector database.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

import pymysql
from pymysql.cursors import DictCursor

from .config import Settings
from .embedding import starrocks_vector_literal

_DEFAULT_DATABASE = object()


class StarRocksRepository:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @contextmanager
    def connection(
        self, database: str | None | object = _DEFAULT_DATABASE
    ) -> Iterator[pymysql.connections.Connection]:
        options: dict[str, Any] = {
            "host": self.settings.starrocks_host,
            "port": self.settings.starrocks_port,
            "user": self.settings.starrocks_user,
            "password": self.settings.starrocks_password,
            "connect_timeout": self.settings.starrocks_connect_timeout_seconds,
            "autocommit": True,
            "cursorclass": DictCursor,
        }
        if database is _DEFAULT_DATABASE:
            options["database"] = self.settings.starrocks_database
        elif database is not None:
            options["database"] = database
        if self.settings.starrocks_ssl_enabled:
            ssl_options: dict[str, Any] = {"check_hostname": self.settings.starrocks_ssl_verify}
            if self.settings.starrocks_ssl_ca:
                ssl_options["ca"] = str(self.settings.starrocks_ssl_ca)
            options["ssl"] = ssl_options
        connection = pymysql.connect(**options)
        try:
            yield connection
        finally:
            connection.close()

    def ping(self) -> bool:
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT 1 AS ok")
            return cursor.fetchone()["ok"] == 1

    def connection_info(self) -> dict[str, Any]:
        """Return the active profile without exposing a password or certificate path."""
        return {
            "host": self.settings.starrocks_host,
            "port": self.settings.starrocks_port,
            "user": self.settings.starrocks_user,
            "database": self.settings.starrocks_database,
            "tls": {
                "enabled": self.settings.starrocks_ssl_enabled,
                "verify_server": self.settings.starrocks_ssl_verify,
                "custom_ca_configured": bool(self.settings.starrocks_ssl_ca),
            },
            "connect_timeout_seconds": self.settings.starrocks_connect_timeout_seconds,
        }

    def diagnose(self) -> dict[str, Any]:
        """Run a minimal read-only handshake against an active or supplied StarRocks cluster."""
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT VERSION() AS version, CURRENT_USER() AS current_user, DATABASE() AS database"
            )
            server = cursor.fetchone()
        return {"connected": True, "server": server, "profile": self.connection_info()}

    def execute(self, statement: str, params: Sequence[Any] | None = None) -> int:
        with self.connection() as connection, connection.cursor() as cursor:
            return cursor.execute(statement, params)

    def query(self, statement: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.execute(statement, params)
            return list(cursor.fetchall())

    def execute_script(self, path: Path, database: str | None = None) -> None:
        """Execute project SQL files; project scripts intentionally contain no procedural SQL."""
        self.execute_statements(path.read_text(), database=database)

    def execute_statements(self, script: str, database: str | None = None) -> None:
        statements = [part.strip() for part in script.split(";") if part.strip()]
        with self.connection(database=database) as connection, connection.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)

    def bootstrap(self, sql_dir: Path, vector_index: bool = False) -> None:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.settings.starrocks_database):
            raise ValueError("STARROCKS_DATABASE must be a simple SQL identifier")
        schema_sql = (
            (sql_dir / "schema.sql")
            .read_text()
            .replace("{{DATABASE}}", self.settings.starrocks_database)
        )
        self.execute_statements(schema_sql, database=None)
        # This flag is required by StarRocks before vector DDL and ANNS queries.
        if vector_index:
            try:
                self.execute(
                    'ADMIN SET FRONTEND CONFIG ("enable_experimental_vector" = "true")', ()
                )
            except pymysql.MySQLError as error:
                raise RuntimeError(
                    "could not enable StarRocks vector index; use a shared-nothing v3.4+ cluster "
                    "or bootstrap without --vector-index"
                ) from error
            indexes = self.query("SHOW INDEX FROM security_documents")
            if any(
                "security_document_hnsw" in {str(value) for value in index.values()}
                for index in indexes
            ):
                return
            vector_sql = (
                (sql_dir / "vector_index.sql")
                .read_text()
                .replace("{{VECTOR_DIMENSION}}", str(self.settings.vector_dimension))
            )
            self.execute_statements(vector_sql)

    def ingest(self, records: Iterable[dict[str, Any]]) -> int:
        events = list(records)
        if not events:
            return 0
        event_columns = (
            "event_uid,event_time,event_date,ingest_time,class_uid,category_uid,type_uid,activity_id,"
            "severity_id,status_id,tenant_id,source_product,source_vendor,actor_user_uid,actor_user_name,"
            "src_ip,dst_ip,dst_port,protocol,device_uid,device_hostname,resource_uid,resource_name,"
            "cloud_account_uid,trace_id,message,raw_event"
        )
        event_sql = f"INSERT INTO ocsf_events ({event_columns}) VALUES ({','.join(['%s'] * 27)})"
        event_rows = [tuple(record[key] for key in event_columns.split(",")) for record in events]
        entity_rows = [
            (
                entity["entity_id"],
                entity["entity_type"],
                record["tenant_id"],
                entity["name"],
                record["event_time"],
            )
            for record in events
            for entity in record["entities"]
        ]
        edge_rows = [
            (
                edge["edge_id"],
                edge["src_id"],
                edge["dst_id"],
                edge["relation"],
                edge["event_uid"],
                edge["event_time"],
                edge["event_time"].date(),
                edge["tenant_id"],
                edge["properties"],
            )
            for record in events
            for edge in record["edges"]
        ]
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.executemany(event_sql, event_rows)
            if entity_rows:
                cursor.executemany(
                    "INSERT INTO kg_entity_observations "
                    "(entity_id,entity_type,tenant_id,name,seen_time) VALUES (%s,%s,%s,%s,%s)",
                    entity_rows,
                )
            if edge_rows:
                cursor.executemany(
                    "INSERT INTO kg_edges "
                    "(edge_id,src_id,dst_id,relation,event_uid,event_time,event_date,tenant_id,properties) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    edge_rows,
                )
        return len(events)

    def insert_alert(self, alert: dict[str, Any]) -> None:
        self.execute(
            "INSERT INTO alerts "
            "(alert_id,created_at,tenant_id,rule_id,severity,title,status,correlation_key,evidence) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                alert["alert_id"],
                alert["created_at"],
                alert["tenant_id"],
                alert["rule_id"],
                alert["severity"],
                alert["title"],
                alert["status"],
                alert["correlation_key"],
                json.dumps(alert["evidence"], ensure_ascii=False, default=str),
            ),
        )

    def list_alerts(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        return self.query(
            "SELECT alert_id,created_at,tenant_id,rule_id,severity,title,status,correlation_key,evidence "
            "FROM alerts WHERE tenant_id=%s ORDER BY created_at DESC LIMIT %s",
            (tenant_id, limit),
        )

    def graph_context(
        self, entity_id: str, tenant_id: str, depth: int, limit: int = 200
    ) -> dict[str, Any]:
        """Return a bounded event-centered neighborhood without recursive graph scans."""
        frontier = {entity_id}
        all_edges: dict[str, dict[str, Any]] = {}
        for _ in range(depth):
            if not frontier:
                break
            placeholders = ",".join(["%s"] * len(frontier))
            rows = self.query(
                "SELECT edge_id,src_id,dst_id,relation,event_uid,event_time,properties "
                f"FROM kg_edges WHERE tenant_id=%s AND (src_id IN ({placeholders}) OR dst_id IN ({placeholders})) "
                "ORDER BY event_time DESC LIMIT %s",
                (tenant_id, *frontier, *frontier, limit),
            )
            next_frontier: set[str] = set()
            for row in rows:
                all_edges[row["edge_id"]] = row
                next_frontier.update((row["src_id"], row["dst_id"]))
            frontier = next_frontier - {entity_id}
        node_ids = {
            node for edge in all_edges.values() for node in (edge["src_id"], edge["dst_id"])
        }
        nodes: list[dict[str, Any]] = []
        if node_ids:
            placeholders = ",".join(["%s"] * len(node_ids))
            nodes = self.query(
                "SELECT entity_id,entity_type,name,MAX(seen_time) AS last_seen "
                "FROM kg_entity_observations WHERE tenant_id=%s "
                f"AND entity_id IN ({placeholders}) GROUP BY entity_id,entity_type,name",
                (tenant_id, *node_ids),
            )
        return {"seed": entity_id, "nodes": nodes, "edges": list(all_edges.values())}

    def add_document(
        self, chunk_id: str, tenant_id: str, entity_id: str, content: str, embedding: list[float]
    ) -> None:
        if len(embedding) != self.settings.vector_dimension:
            raise ValueError(
                f"embedding dimension must be {self.settings.vector_dimension}, got {len(embedding)}"
            )
        vector_literal = starrocks_vector_literal(embedding)
        self.execute(
            "INSERT INTO security_documents "
            "(chunk_id,tenant_id,entity_id,content,embedding,created_at) "
            f"VALUES (%s,%s,%s,%s,{vector_literal},NOW())",
            (chunk_id, tenant_id, entity_id, content),
        )

    def persist_text_graph(self, tenant_id: str, extraction: dict[str, Any]) -> None:
        """Persist reviewable text evidence into the same entity/edge graph.

        Text-derived edges use a synthetic source UID rather than pretending to
        be OCSF events.  Provenance, confidence, and review status remain in
        both the graph edge properties and the append-only extraction ledger.
        """
        source = extraction["source"]
        created_at = extraction["created_at"]
        source_id = source["source_id"]
        source_entity = {
            "entity_id": source["entity_id"],
            "entity_type": "document",
            "name": source_id,
        }
        entities = [source_entity, *extraction["entities"]]
        entity_rows = [
            (
                entity["entity_id"],
                entity["entity_type"],
                tenant_id,
                entity["name"],
                created_at,
            )
            for entity in entities
        ]
        source_uid = f"text-{sha256(source_id.encode()).hexdigest()[:20]}"
        edge_rows = []
        ledger_rows = []
        for relation in extraction["relations"]:
            properties = {
                "source_id": source_id,
                "source_type": source["source_type"],
                "extractor": extraction["extractor"],
                "confidence": relation["confidence"],
                "status": relation["status"],
                "relation_kind": relation["relation_kind"],
                "evidence": relation["evidence"],
            }
            edge_rows.append(
                (
                    relation["extraction_id"],
                    relation["src_id"],
                    relation["dst_id"],
                    relation["relation"],
                    source_uid,
                    created_at,
                    created_at.date(),
                    tenant_id,
                    json.dumps(properties, ensure_ascii=False, default=str),
                )
            )
            ledger_rows.append(
                (
                    relation["extraction_id"],
                    created_at,
                    tenant_id,
                    source_id,
                    source["source_type"],
                    extraction["extractor"]["name"],
                    relation["src_id"],
                    relation["dst_id"],
                    relation["relation"],
                    relation["relation_kind"],
                    relation["confidence"],
                    relation["status"],
                    json.dumps({"text": relation["evidence"]}, ensure_ascii=False),
                )
            )
        with self.connection() as connection, connection.cursor() as cursor:
            cursor.executemany(
                "INSERT INTO kg_entity_observations "
                "(entity_id,entity_type,tenant_id,name,seen_time) VALUES (%s,%s,%s,%s,%s)",
                entity_rows,
            )
            if edge_rows:
                cursor.executemany(
                    "INSERT INTO kg_edges "
                    "(edge_id,src_id,dst_id,relation,event_uid,event_time,event_date,tenant_id,properties) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    edge_rows,
                )
                cursor.executemany(
                    "INSERT INTO text_graph_extractions "
                    "(extraction_id,created_at,tenant_id,source_id,source_type,extractor,src_id,dst_id,"
                    "relation,relation_kind,confidence,status,evidence) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    ledger_rows,
                )

    def list_text_graph_extractions(
        self, tenant_id: str, source_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        if source_id:
            return self.query(
                "SELECT extraction_id,created_at,source_id,source_type,extractor,src_id,dst_id,relation,"
                "relation_kind,confidence,status,evidence FROM text_graph_extractions "
                "WHERE tenant_id=%s AND source_id=%s ORDER BY created_at DESC LIMIT %s",
                (tenant_id, source_id, limit),
            )
        return self.query(
            "SELECT extraction_id,created_at,source_id,source_type,extractor,src_id,dst_id,relation,"
            "relation_kind,confidence,status,evidence FROM text_graph_extractions "
            "WHERE tenant_id=%s ORDER BY created_at DESC LIMIT %s",
            (tenant_id, limit),
        )

    def record_text_graph_review(
        self,
        extraction_id: str,
        tenant_id: str,
        decision: str,
        reviewer: str,
        note: str,
    ) -> None:
        review_id = sha256(
            f"{extraction_id}|{tenant_id}|{decision}|{reviewer}|{note}".encode()
        ).hexdigest()[:32]
        self.execute(
            "INSERT INTO text_graph_reviews "
            "(review_id,reviewed_at,tenant_id,extraction_id,decision,reviewer,note) "
            "VALUES (%s,NOW(),%s,%s,%s,%s,%s)",
            (review_id, tenant_id, extraction_id, decision, reviewer, note),
        )

    def semantic_search(
        self, tenant_id: str, vector: list[float], limit: int = 8
    ) -> list[dict[str, Any]]:
        # The literal is generated only by our embedding provider, never user supplied.
        if len(vector) != self.settings.vector_dimension:
            raise ValueError(
                f"query embedding dimension must be {self.settings.vector_dimension}, got {len(vector)}"
            )
        vector_literal = starrocks_vector_literal(vector)
        return self.query(
            "SELECT /*+ SET_VAR (ann_params='{efsearch=128}') */ "
            f"chunk_id,entity_id,content,approx_cosine_similarity(embedding,{vector_literal}) AS score "
            "FROM security_documents WHERE tenant_id=%s "
            f"ORDER BY approx_cosine_similarity(embedding,{vector_literal}) DESC LIMIT %s",
            (tenant_id, limit),
        )

    def event_summary(
        self, entity_ids: list[str], tenant_id: str, limit: int = 50
    ) -> list[dict[str, Any]]:
        event_ids = [
            entity.removeprefix("event:") for entity in entity_ids if entity.startswith("event:")
        ]
        if not event_ids:
            return []
        placeholders = ",".join(["%s"] * len(event_ids))
        return self.query(
            "SELECT event_uid,event_time,class_uid,severity_id,actor_user_name,src_ip,dst_ip,message,raw_event "
            "FROM ocsf_events WHERE tenant_id=%s "
            f"AND event_uid IN ({placeholders}) ORDER BY event_time DESC LIMIT %s",
            (tenant_id, *event_ids, limit),
        )

    def historical_events(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Read a partition-pruned, bounded historical slice for post-incident analysis.

        The caller must supply a bounded time range and row limit.  ``event_date``
        is included in addition to the precise timestamp predicate so StarRocks
        can prune dynamic date partitions before performing the ordered read.
        """
        return self.query(
            "SELECT event_uid,event_time,class_uid,category_uid,type_uid,activity_id,severity_id,"
            "status_id,source_product,actor_user_uid,actor_user_name,src_ip,dst_ip,dst_port,"
            "protocol,device_uid,device_hostname,resource_uid,resource_name,cloud_account_uid,"
            "trace_id,message "
            "FROM ocsf_events WHERE tenant_id=%s AND event_date >= %s AND event_date <= %s "
            "AND event_time >= %s AND event_time < %s ORDER BY event_time ASC LIMIT %s",
            (tenant_id, start_time.date(), end_time.date(), start_time, end_time, limit),
        )

    def historical_class_baseline(
        self, tenant_id: str, start_time: datetime, end_time: datetime
    ) -> list[dict[str, Any]]:
        """Small class-level baseline used only to explain retrospective ranking."""
        return self.query(
            "SELECT class_uid,COUNT(*) AS event_count FROM ocsf_events "
            "WHERE tenant_id=%s AND event_date >= %s AND event_date <= %s "
            "AND event_time >= %s AND event_time < %s GROUP BY class_uid",
            (tenant_id, start_time.date(), end_time.date(), start_time, end_time),
        )
