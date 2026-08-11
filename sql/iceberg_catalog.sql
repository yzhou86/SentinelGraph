-- Optional cold tier. Fill in your Iceberg REST/HMS endpoint and credentials.
-- StarRocks can join this catalog with hot OCSF events in a single query.
CREATE EXTERNAL CATALOG IF NOT EXISTS security_iceberg
PROPERTIES (
    "type" = "iceberg",
    "iceberg.catalog.type" = "rest",
    "iceberg.catalog.uri" = "http://iceberg-rest:8181",
    "iceberg.catalog.warehouse" = "s3://security-lakehouse/warehouse"
)

-- Example batch/stream convergence query after a compaction job writes OCSF Parquet.
-- SELECT * FROM ocsf_events
-- UNION ALL
-- SELECT * FROM security_iceberg.ocsf.events_archive;
