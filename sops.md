# Operating Procedures

## Tech Stack
- Language: Python 3.12+
- Testing: pytest
- Linting: ruff
- Type checking: mypy (strict mode)
- CLI: click
- Data models: pydantic >= 2.0
- Config: PyYAML
- Telemetry: opentelemetry-api, opentelemetry-sdk

## Standards
- Type annotations on all public functions
- Prefer composition over inheritance
- Use Pydantic models for all structured data (trust events, findings, signals, config)
- Follow PEP 8 naming conventions
- All file I/O via pathlib
- UTC timestamps everywhere (datetime.now(timezone.utc))
- No async — synchronous CLI and OTLP processing appropriate for sidecar

## Domain Rules
- Trust and authority are distinct: never conflate them
- Trust is earned (computed from ledger), authority is declared (from manifests)
- The adapter layer is ground truth; node self-reports are claims
- The trust ledger is append-only — no updates, no deletes
- All policy calculations use raw trust score, never display tiers
- Canary patterns must be recognizable as synthetic (never plausible real data)

## Verification
- All functions must have at least one test
- Tests must be runnable without external services (mock OTLP, mock registry)
- Trust score computation must be deterministic given the same ledger input
- No task is done until its contract tests pass

## Preferences
- Prefer standard library over third-party packages
- Keep files under 300 lines
- Error messages must include the specific node, field, or domain that caused the error
- Use enum for trust tiers, data classification tiers, finding severities

## Implementation Notes
- Trust ledger: JSONL with SHA256 checksum line after every N entries. Treat like a financial ledger.
- Field classifier: use fnmatch or regex against classification registry field_pattern rules
- OTLP subscriber: gRPC server via opentelemetry-sdk and grpcio
- Canary fingerprints: structurally valid for tier, globally unique per run, impossible in real data (UUIDs in domain-shaped strings)
- All HTTP API responses: JSON with machine-readable error_code + human-readable message
- Blast radius traversal: BFS/DFS over access graph edges. Keep efficient for large circuits.
- Cold start target: arbiter watch ready in under 3 seconds
