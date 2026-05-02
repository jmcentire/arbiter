# Arbiter

Access auditing, consistency analysis, blast-radius classification, and trust enforcement for the Pact/Baton stack. Arbiter is the trust enforcement layer that sits between Pact-built components and Baton-orchestrated circuits. It watches, compares, scores, and gates.

## Context

Arbiter fills the trust enforcement gap in the Pact/Baton stack. Currently, Pact builds components against contracts and Baton orchestrates them into circuits, but nothing continuously verifies that nodes access only the data they declared, that their self-reported behavior matches observed I/O, or that proposed changes have quantified blast radius. Arbiter is a standalone sidecar service that receives OTLP spans from Baton's adapter layer, compares observed behavior against Pact's access graphs, maintains an append-only trust ledger, and gates deployments based on trust scores, data classification tiers, and canary soak results.

## Constraints

- C001 (must): All node I/O operations must be observable through the adapter layer — without adapter visibility, access auditing is impossible
- C002 (must): Trust scores must be computed only from append-only ledger entries — trust manipulation would undermine the entire enforcement model
- C003 (must): Canary data escape must immediately set taint_factor to 0.0 — canary escape indicates complete data boundary failure
- C004 (must): Each data domain must have exactly one authoritative node — prevents authority conflicts and data consistency issues
- C005 (must): Node's OpenAPI schema must not expose data tiers beyond declared data_access — declaration gaps indicate unauthorized access paths
- C006 (must): Trust ledger must be append-only and external to all monitored nodes — mutable audit trail would allow trust score manipulation
- C007 (must): Adapter-observed I/O must be compared against node self-reported audit events — detects nodes violating their declared behavior contracts
- C008 (must): Low-trust authoritative nodes must always require human review — high-privilege nodes with degraded trust pose maximum risk
- C009 (must): Conflicts must follow three-step protocol: authority check, trust arbitration, human escalation — ensures consistent and auditable conflict resolution
- C010 (should): Trust scores must remain between 0.1 (floor) and 1.0 (ceiling) — maintains mathematical consistency in trust calculations
- C011 (should): Soak duration must factor trust score, data tier, and volume confidence — ensures deployment safety proportional to risk profile
- C012 (should): OTLP spans should be enriched with trust and access metadata — enables downstream systems to make trust-aware decisions

## Requirements

### Trust and Authority

- `trust_score(node)` computes `base_weight * age_factor * consistency_factor * taint_factor * review_factor * decay_factor`
- Trust floor defaults to 0.1, ceiling is 1.0 (asymptotic via decay_factor)
- Display tiers: PROBATIONARY (0.0-0.25), LOW (0.26-0.50), ESTABLISHED (0.51-0.75), HIGH (0.76-0.90), TRUSTED (0.91-1.0) — labels only, all policy uses raw score
- Authority is declared per node manifest, domain-specific, exclusive (one node per domain), does not decay
- Registering a second node as authoritative for an already-owned domain is a hard registration failure

### Trust x Authority Matrix

- High trust + Authoritative: short soak, wins conflicts unconditionally for declared domains, human gate only at FINANCIAL/AUTH/COMPLIANCE tier
- High trust + Non-authoritative: moderate soak, defers to authoritative node, human gate per blast-radius tier
- Low trust + Authoritative: long soak always, hard stop on first consistency violation during soak, wins conflicts only if trust > authority-override floor (default 0.4), human gate always
- Low trust + Non-authoritative: standard soak, defers to authority or highest-trust node, human gate per blast-radius tier

### Canary Soak

- `soak_duration(node, tier) = base_duration(tier) * trust_multiplier(score) * volume_confidence_factor(rate)`
- `trust_multiplier(t) = 2.0 - t` (lower trust = longer soak)
- `volume_confidence_factor(rate) = max(1.0, sqrt(target_requests / observed_rate))`
- Base durations configurable per tier: PUBLIC=1h, PII=6h, FINANCIAL=24h, AUTH=48h, COMPLIANCE=72h
- Computed soak duration is a first-class artifact in the Arbiter report

### Consistency Analysis

- Adapter span I/O (ground truth) compared against node audit events (claims)
- Unexplained output fields (observed but not declared/claimed) produce findings
- HIGH severity inconsistency during soak is a hard stop
- Consistency outcomes feed into trust score update cycle

### Data Classification Registry

- Field patterns mapped to tiers: PUBLIC, PII, FINANCIAL, AUTH, COMPLIANCE
- Each classification includes field_pattern, tier, authoritative_node, canary_pattern
- Registry authoritative_node must match node manifest authority declaration

### Conflict Resolution

- Step 1: Authority check — authoritative node wins if trust > override floor, else human review
- Step 2: Trust arbitration — higher-trust node wins if trust delta > threshold (default 0.2)
- Step 3: Unresolvable — flag to human, emit to Stigmergy as high-weight signal, block deploy if protected tier

### OpenAPI Integration

- At adapter slot time, walk OpenAPI response schema and map fields to classification registry
- Produce structural access profile (superset of tiers the node can return)
- Flag DECLARATION_GAP and BLOCK_SLOT if structural profile includes undeclared tiers

### OpenTelemetry Integration

- Enrich adapter spans with: arbiter.access.declared, arbiter.access.observed, arbiter.consistency, arbiter.trust.score, arbiter.trust.tier, arbiter.authority.domains, arbiter.taint.detected, arbiter.blast.tier, arbiter.conflict

### Stigmergy Integration

- Emit findings as Signal objects: source="arbiter", type (consistency_violation, taint_escape, access_violation, conflict_unresolvable, trust_degradation), actor, content, weight, timestamp

### Trust Ledger

- Append-only, durable, external to all nodes
- JSONL format: ts, node, event, weight, score_before, score_after, plus event-specific fields
- Trust score at any point reproducible by replaying ledger from start

### CLI

- `arbiter init` — initialize registry, config, trust ledger
- `arbiter register <access_graph.json>` — ingest Pact access graph
- `arbiter trust show <node>` — current score and history
- `arbiter trust reset-taint <node> --review <id>` — clear taint lock after human review
- `arbiter authority show` — full authority map
- `arbiter blast-radius <node> <version>` — compute blast radius
- `arbiter soak compute <node> <tier>` — compute soak duration
- `arbiter report --run <run_id>` — generate feedback report
- `arbiter canary inject --tiers <tier>` — seed canary data
- `arbiter canary results --run <run_id>` — taint escape report
- `arbiter watch` — continuous OTLP subscriber mode
- `arbiter findings --node <node>` — consistency findings
- `arbiter conflicts --unresolved` — list unresolved conflicts

### Feedback Report

- Trust summary: per-node score, tier label, authority domains
- Consistency: pass/warn/fail per node with unexplained field details
- Access: pass/warn per node with structural gap details
- Conflicts: detected conflicts and resolution status
- Taint: canary escape results
- Blast radius: for proposed changes, computed soak duration, human gate status
- Overall verdict: PROCEED / HOLD / BLOCK with required actions

### Architecture

```
src/arbiter/
  cli/              # Click CLI entry point
  registry/         # Trust ledger, authority map, access graph store
  subscriber/       # OTLP span subscriber (receives from Baton)
  consistency/      # Consistency analysis engine
  access/           # Access auditing engine
  taint/            # Canary corpus and taint detection
  blast/            # Blast radius computation
  trust/            # Trust score computation and ledger writes
  report/           # Feedback report generation
  api/              # HTTP API for Pact phase 8.5 and Baton slot validation
  config/           # arbiter.yaml loading and validation
```

### Configuration (arbiter.yaml)

- `registry.path`: directory for ledger, authority map, access graph (default: `.arbiter/registry/`)
- `registry.append_only`: true (ledger writes never update-in-place)
- `trust.floor`: 0.10
- `trust.authority_override_floor`: 0.40
- `trust.decay_lambda`: 0.05
- `trust.conflict_trust_delta_threshold`: 0.20
- `trust.taint_lock_tiers`: [PII, FINANCIAL, AUTH, COMPLIANCE]
- `soak.base_durations`: PUBLIC=3600s, PII=21600s, FINANCIAL=86400s, AUTH=172800s, COMPLIANCE=259200s
- `soak.target_requests`: 1000
- `otlp.listen_port`: 4317 (gRPC), `otlp.http_port`: 4318 (optional)
- `api.port`: 7700
- `classification_registry`: path to classifications.yaml
- `human_gate.webhook_url`: null (POST findings on gate trigger)
- `human_gate.block_on_gate`: true

### HTTP API (port 7700)

- `POST /register` — ingest access_graph.json, returns warnings
- `POST /blast-radius` — compute blast radius for {component_id, version}
- `GET /trust/<node_id>` — score, tier, last 20 ledger events
- `POST /trust/reset-taint` — clear taint lock with {node_id, review_id}
- `GET /authority` — full authority map
- `POST /canary/inject` — seed canary corpus for given tiers and run_id
- `GET /canary/results/<run_id>` — taint escape report
- `GET /report/<run_id>` — full feedback report
- `POST /findings` — receive OTLP span JSON from Baton adapter
- All responses JSON with machine-readable `error_code` on errors

### Blast Radius Classification Rules

- PUBLIC only → AUTO_MERGE
- PUBLIC + PII → SOAK (compute duration)
- any FINANCIAL or AUTH → HUMAN_GATE
- any COMPLIANCE → HUMAN_GATE + legal_flag
- unauthorized tier in path → HUMAN_GATE regardless
- LOW_TRUST_AUTHORITATIVE → HUMAN_GATE regardless

## Functional Assertions

- FA-A-001: `arbiter init` creates registry directory, empty trust ledger, default config
- FA-A-002: `arbiter register` accepts valid access_graph.json and returns no errors
- FA-A-003: `arbiter register` rejects access_graph.json where two components claim authority for overlapping domains
- FA-A-004: Trust ledger is append-only — no existing entry is ever modified or deleted
- FA-A-005: New node starts with trust score equal to configured floor
- FA-A-006: Trust score is fully reproducible by replaying the ledger from scratch
- FA-A-007: Taint escape on a locked tier sets trust score to 0.0 immediately
- FA-A-008: `reset-taint` without `--review` is rejected
- FA-A-009: Soak duration increases as trust score decreases (monotonic in trust)
- FA-A-010: Soak duration increases as request_rate decreases (monotonic in volume)
- FA-A-011: HUMAN_GATE is returned for any FINANCIAL, AUTH, or COMPLIANCE tier change
- FA-A-012: HUMAN_GATE is returned for any LOW_TRUST_AUTHORITATIVE node
- FA-A-013: Consistency analysis returns INCONSISTENT when span output contains fields not mentioned in audit events
- FA-A-014: Consistency analysis returns CONSISTENT when all observed fields are claimed
- FA-A-015: Access violation is recorded when observed output tier exceeds declared reads
- FA-A-016: Canary fingerprint in unauthorized node output triggers TAINT_ESCAPE finding
- FA-A-017: Canary fingerprint in authorized node output does not trigger finding
- FA-A-018: Conflict with authoritative node above floor resolves to authoritative value
- FA-A-019: Conflict with authoritative node below floor escalates to human review
- FA-A-020: Unresolvable conflict (no authority, small trust delta) escalates
- FA-A-021: `/register` HTTP endpoint accepts access_graph.json and returns 200
- FA-A-022: `/blast-radius` returns correct tier for each data classification scenario
- FA-A-023: Stigmergy emission is fire-and-forget — Stigmergy unavailability does not affect Arbiter operation
- FA-A-024: `arbiter watch` starts OTLP receiver and API server in a single process
- FA-A-025: All ledger writes are flushed to disk before API response is returned
- FA-A-026: Feedback report contains TRUST SUMMARY, CONSISTENCY, ACCESS, CONFLICTS, TAINT, BLAST RADIUS, and OVERALL sections
- FA-A-027: `arbiter report` is deterministic — same inputs produce same report
- FA-A-028: Trust decay is applied when idle cycles exceed zero
- FA-A-029: Authority-override floor is enforced — trust below floor means auth node loses conflict resolution
- FA-A-030: `arbiter register` validates that authority_map entries match authority declarations in access_graph.json components
