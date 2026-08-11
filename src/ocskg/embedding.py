"""Small deterministic embedding provider used for a dependency-free demo.

Replace ``HashEmbeddingProvider`` in production with a governed embedding model.
The vector dimension remains an explicit contract with the StarRocks HNSW index.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Protocol


class EmbeddingProvider(Protocol):
    dimension: int

    def embed(self, text: str) -> list[float]: ...


class HashEmbeddingProvider:
    """A stable local embedding suitable for demos and repeatable tests only."""

    def __init__(self, dimension: int = 64) -> None:
        self.dimension = dimension

    def embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        for token in re.findall(r"[\w.-]+", text.lower()):
            digest = hashlib.blake2b(token.encode(), digest_size=8).digest()
            bucket = int.from_bytes(digest[:4], "big") % self.dimension
            direction = 1.0 if digest[4] & 1 else -1.0
            vector[bucket] += direction
        magnitude = math.sqrt(sum(value * value for value in vector))
        return vector if magnitude == 0 else [value / magnitude for value in vector]


def starrocks_vector_literal(vector: list[float]) -> str:
    """Render an ARRAY<FLOAT> literal from trusted, internally-produced floats."""
    if not vector or not all(math.isfinite(value) for value in vector):
        raise ValueError("embedding must contain finite values")
    return "[" + ",".join(f"{value:.8f}" for value in vector) + "]"
