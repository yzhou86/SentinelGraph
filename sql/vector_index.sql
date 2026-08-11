-- StarRocks v3.4+ shared-nothing deployment required. See README for prerequisites.
CREATE INDEX security_document_hnsw
ON security_documents (embedding)
USING VECTOR (
    "index_type" = "hnsw",
    "metric_type" = "cosine_similarity",
    "is_vector_normed" = "true",
    "dim" = "{{VECTOR_DIMENSION}}",
    "M" = "16",
    "efconstruction" = "128"
)
