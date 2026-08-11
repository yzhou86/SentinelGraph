-- Apply this once to an existing security_lakehouse database.
-- Replace the database name if you configured STARROCKS_DATABASE differently.
USE security_lakehouse;

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
