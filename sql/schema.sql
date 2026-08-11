CREATE DATABASE IF NOT EXISTS {{DATABASE}};

USE {{DATABASE}};

-- OCSF projection: full raw JSON is kept for extension attributes and audit.
CREATE TABLE IF NOT EXISTS ocsf_events (
    event_uid VARCHAR(128) NOT NULL,
    event_time DATETIME NOT NULL,
    event_date DATE NOT NULL,
    ingest_time DATETIME NOT NULL,
    class_uid INT NOT NULL,
    category_uid INT NOT NULL,
    type_uid BIGINT NOT NULL,
    activity_id INT NOT NULL,
    severity_id INT NOT NULL,
    status_id INT NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    source_product VARCHAR(256) NOT NULL,
    source_vendor VARCHAR(256) NOT NULL,
    actor_user_uid VARCHAR(256) NOT NULL,
    actor_user_name VARCHAR(512) NOT NULL,
    src_ip VARCHAR(64) NOT NULL,
    dst_ip VARCHAR(64) NOT NULL,
    dst_port INT NOT NULL,
    protocol VARCHAR(64) NOT NULL,
    device_uid VARCHAR(256) NOT NULL,
    device_hostname VARCHAR(512) NOT NULL,
    resource_uid VARCHAR(512) NOT NULL,
    resource_name VARCHAR(1024) NOT NULL,
    cloud_account_uid VARCHAR(256) NOT NULL,
    trace_id VARCHAR(256) NOT NULL,
    message STRING NOT NULL,
    raw_event JSON NOT NULL
)
ENGINE=OLAP
DUPLICATE KEY(event_uid, event_date)
PARTITION BY RANGE(event_date) ()
DISTRIBUTED BY HASH(event_uid) BUCKETS 8
PROPERTIES (
    "replication_num" = "1",
    "dynamic_partition.enable" = "true",
    "dynamic_partition.time_unit" = "DAY",
    "dynamic_partition.start" = "-30",
    "dynamic_partition.end" = "3",
    "dynamic_partition.prefix" = "p",
    "dynamic_partition.buckets" = "8",
    "compression" = "LZ4"
);

-- Entity observations are append-only. This avoids write contention on a global node record.
CREATE TABLE IF NOT EXISTS kg_entity_observations (
    entity_id VARCHAR(768) NOT NULL,
    entity_type VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    name VARCHAR(1024) NOT NULL,
    seen_time DATETIME NOT NULL
)
ENGINE=OLAP
DUPLICATE KEY(entity_id, tenant_id, seen_time)
DISTRIBUTED BY HASH(entity_id) BUCKETS 8
PROPERTIES ("replication_num" = "1", "compression" = "LZ4");

-- Edges are event-scoped facts, enabling time-windowed graph exploration.
CREATE TABLE IF NOT EXISTS kg_edges (
    edge_id VARCHAR(128) NOT NULL,
    src_id VARCHAR(768) NOT NULL,
    dst_id VARCHAR(768) NOT NULL,
    relation VARCHAR(128) NOT NULL,
    event_uid VARCHAR(128) NOT NULL,
    event_time DATETIME NOT NULL,
    event_date DATE NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    properties JSON NOT NULL
)
ENGINE=OLAP
DUPLICATE KEY(edge_id, event_date)
PARTITION BY RANGE(event_date) ()
DISTRIBUTED BY HASH(src_id) BUCKETS 8
PROPERTIES (
    "replication_num" = "1",
    "dynamic_partition.enable" = "true",
    "dynamic_partition.time_unit" = "DAY",
    "dynamic_partition.start" = "-30",
    "dynamic_partition.end" = "3",
    "dynamic_partition.prefix" = "p",
    "dynamic_partition.buckets" = "8"
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    rule_id VARCHAR(128) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    title VARCHAR(1024) NOT NULL,
    status VARCHAR(32) NOT NULL,
    correlation_key VARCHAR(1024) NOT NULL,
    evidence JSON NOT NULL
)
ENGINE=OLAP
DUPLICATE KEY(alert_id, created_at)
DISTRIBUTED BY HASH(alert_id) BUCKETS 4
PROPERTIES ("replication_num" = "1", "compression" = "LZ4");

-- Security playbooks, incident notes, and threat reports for Agent retrieval.
CREATE TABLE IF NOT EXISTS security_documents (
    chunk_id VARCHAR(128) NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    entity_id VARCHAR(768) NOT NULL,
    content STRING NOT NULL,
    embedding ARRAY<FLOAT> NOT NULL,
    created_at DATETIME NOT NULL
)
ENGINE=OLAP
DUPLICATE KEY(chunk_id)
DISTRIBUTED BY HASH(chunk_id) BUCKETS 4
PROPERTIES ("replication_num" = "1", "compression" = "LZ4");

-- Text-derived graph facts remain separately auditable from OCSF event facts.
-- `status` starts as pending_review and review decisions are append-only below.
CREATE TABLE IF NOT EXISTS text_graph_extractions (
    extraction_id VARCHAR(64) NOT NULL,
    created_at DATETIME NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    source_id VARCHAR(128) NOT NULL,
    source_type VARCHAR(64) NOT NULL,
    extractor VARCHAR(64) NOT NULL,
    src_id VARCHAR(768) NOT NULL,
    dst_id VARCHAR(768) NOT NULL,
    relation VARCHAR(128) NOT NULL,
    relation_kind VARCHAR(64) NOT NULL,
    confidence FLOAT NOT NULL,
    status VARCHAR(32) NOT NULL,
    evidence JSON NOT NULL
)
ENGINE=OLAP
DUPLICATE KEY(extraction_id, created_at)
DISTRIBUTED BY HASH(extraction_id) BUCKETS 4
PROPERTIES ("replication_num" = "1", "compression" = "LZ4");

CREATE TABLE IF NOT EXISTS text_graph_reviews (
    review_id VARCHAR(64) NOT NULL,
    reviewed_at DATETIME NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    extraction_id VARCHAR(64) NOT NULL,
    decision VARCHAR(32) NOT NULL,
    reviewer VARCHAR(256) NOT NULL,
    note STRING NOT NULL
)
ENGINE=OLAP
DUPLICATE KEY(review_id, reviewed_at)
DISTRIBUTED BY HASH(extraction_id) BUCKETS 4
PROPERTIES ("replication_num" = "1", "compression" = "LZ4");
