"""Operational CLI for schema bootstrap, batch backfill, and rule execution."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import mock
from .adapters import SUPPORTED_SOURCE_FORMATS, to_ocsf_event
from .config import get_settings
from .detection import RuleEngine, load_rules
from .ocsf import normalize_ocsf_event
from .repository import StarRocksRepository
from .service import SecurityGraphService


def _load_events(path: Path) -> list[dict[str, Any]]:
    text = path.read_text().strip()
    if not text:
        return []
    if text.startswith("["):
        payload = json.loads(text)
        if not isinstance(payload, list):
            raise ValueError("JSON batch input must be an array")
        return payload
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinelgraph", description="SentinelGraph")
    subcommands = parser.add_subparsers(dest="command", required=True)
    bootstrap = subcommands.add_parser(
        "bootstrap", help="create StarRocks tables and optional HNSW index"
    )
    bootstrap.add_argument(
        "--vector-index", action="store_true", help="enable experimental StarRocks HNSW index"
    )
    ingest = subcommands.add_parser(
        "ingest", help="backfill a JSON array or JSONL file of OCSF events"
    )
    ingest.add_argument("path", type=Path)
    ingest.add_argument("--tenant", default="default")
    ingest.add_argument("--format", choices=sorted(SUPPORTED_SOURCE_FORMATS), default="auto")
    detect = subcommands.add_parser("detect", help="run declarative correlation rules")
    detect.add_argument("--tenant", default="default")
    demo = subcommands.add_parser("demo", help="load a current-time customer demo scenario")
    demo.add_argument("--tenant", default="demo")
    demo.add_argument("--run-id", default=None)
    mock_demo = subcommands.add_parser("mock-demo", help="print a no-database, no-LLM demo result")
    mock_demo.add_argument("--tenant", default="demo")
    mock_demo.add_argument("--run-id", default=None)
    subcommands.add_parser("check-connection", help="verify the configured StarRocks profile")

    args = parser.parse_args()
    settings = get_settings()
    repository = StarRocksRepository(settings)
    if args.command == "bootstrap":
        repository.bootstrap(Path("sql"), vector_index=args.vector_index)
        print("StarRocks schema bootstrapped")
    elif args.command == "ingest":
        records = [
            normalize_ocsf_event(to_ocsf_event(event, args.format), args.tenant)
            for event in _load_events(args.path)
        ]
        print(json.dumps({"ingested": repository.ingest(records), "tenant": args.tenant}))
    elif args.command == "detect":
        alerts = RuleEngine(repository, load_rules(settings.rules_path)).run(args.tenant)
        print(
            json.dumps({"created": len(alerts), "alerts": alerts}, default=str, ensure_ascii=False)
        )
    elif args.command == "demo":
        result = SecurityGraphService(repository, settings).load_demo(args.tenant, args.run_id)
        print(json.dumps(result, default=str, ensure_ascii=False))
    elif args.command == "mock-demo":
        print(json.dumps(mock.load_demo(args.tenant, args.run_id), default=str, ensure_ascii=False))
    elif args.command == "check-connection":
        print(json.dumps(repository.diagnose(), default=str, ensure_ascii=False))


if __name__ == "__main__":
    main()
