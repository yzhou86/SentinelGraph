# Contributing

Issues and pull requests are welcome. Please keep source adapters OCSF-compatible and avoid committing customer logs, credentials, or indicators that are not safe to disclose.

Before opening a pull request, run:

```bash
pip install -e '.[dev]'
ruff check .
pytest -q
```

New ingestion mappings should retain the original source document in `raw_event`, add focused normalization tests, and use OCSF field names where they exist. New detections should be declarative YAML rules unless they need a new generally useful engine primitive.
