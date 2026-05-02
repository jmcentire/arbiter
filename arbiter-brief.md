# ARBITER — Claude Code Brief

## Role in the Stack

Arbiter is the trust enforcement layer. It sits between Pact-built components and
Baton-orchestrated circuits. It receives the `access_graph.json` from Pact, subscribes
to OpenTelemetry spans from Baton's adapter layer, and performs continuous analysis:

1. **Access auditing**: did this node touch data it was permitted to touch?
2. **Consistency analysis**: does the node's self-reported event log match what the
   adapter observed at its I/O boundary?
3. **Blast radius classification**: for a proposed change, what data tiers are affected
   and what validation is required?
4. **Trust scoring**: continuous score [0.0, 1.0] per node, earned and lost through
   observed behavior, maintained in an append-only trust ledger.

Arbiter does not route traffic, build components, or make deployment decisions. It
classifies, gates where trust or tier requires it, and escalates everything else.

## This Is a New Tool

Arbiter does not exist yet. Build it from scratch. The arbiter.md design document
provides the full specification. This brief is the Claude Code operational version
of that document with implementation guidance added.

## Architecture

```
arbiter/
  cli/              # CLI entry point
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

## Configuration

```yaml
# arbiter.yaml

version: "1.0"

registry:
  path: ".arbiter/registry/"    # where ledger, authority map, access graph live
  append_only: true             # ledger writes are append-only, never update-in-place

trust:
  floor: 0.10
  authority_override_floor: 0.40
  decay_lambda: 0.05
  conflict_trust_delta_threshold: 0.20
  taint_lock_tiers: [PII, FINANCIAL, AUTH, COMPLIANCE]

soak:
  base_durations:
    PUBLIC: 3600        # seconds
    PII: 21600
    FINANCIAL: 86400
    AUTH: 172800
    COMPLIANCE: 259200
  target_requests: 1000

otlp:
  listen_port: 4317             # OTLP gRPC receiver
  http_port: 4318               # OTLP HTTP receiver (optional)

api:
  port: 7700                    # Arbiter HTTP API port

classification_registry: "./classifications.yaml"  # or inline

human_gate:
  webhook_url: null             # POST findings here when human gate triggered
  block_on_gate: true           # if false, log but don't block
```

## Trust Model

### Score Formula

```python
def compute_trust(node_id: str, ledger: list[LedgerEntry]) -> float:
    floor = config.trust.floor

    age_factor = compute_age_factor(ledger)          # [floor, 1.0], grows with clean cycles
    consistency_factor = compute_consistency(ledger)  # rolling weighted avg of checks
    taint_factor = compute_taint(ledger)             # 0.0 if locked, else [floor, 1.0]
    review_factor = compute_review(ledger)           # weighted by human review outcomes
    decay_factor = compute_decay(ledger)             # exp(-lambda * idle_cycles)

    raw = age_factor * consistency_factor * taint_factor * review_factor * decay_factor
    return max(floor, min(1.0, raw))
```

### Display Tiers (overlay only — never use for policy decisions)

```python
TRUST_TIERS = {
    (0.0, 0.25):  "PROBATIONARY",
    (0.26, 0.50): "LOW",
    (0.51, 0.75): "ESTABLISHED",
    (0.76, 0.90): "HIGH",
    (0.91, 1.00): "TRUSTED",
}
```

### Trust Ledger Format

Every trust event is appended to `registry/trust_ledger.jsonl`. Never update or delete.

```jsonl
{"ts": "ISO8601", "node": "node_id", "event": "consistency_pass|consistency_fail|taint_escape|taint_unlock|human_approve|human_reject|decay", "weight": float, "tier": "PII|null", "score_before": float, "score_after": float, "run_id": "uuid", "span_id": "hex|null"}
```

### Taint Lock

When a `taint_escape` event is recorded for a tier in `taint_lock_tiers`:
- `taint_factor` is set to 0.0 for that node
- This is recorded in the ledger as `taint_factor_locked: true`
- The lock persists until a `taint_unlock` event is recorded
- `taint_unlock` requires a `review_id` referencing a human review record
- Only `arbiter trust reset-taint <node> --review <id>` can write a `taint_unlock` event

## Soak Duration Computation

```python
def compute_soak(node_id: str, tier: str, request_rate: float) -> int:
    """Returns soak duration in seconds."""
    trust_score = get_trust_score(node_id)
    base = config.soak.base_durations[tier]
    trust_multiplier = 2.0 - trust_score          # [1.0, 2.0]
    volume_factor = max(1.0, math.sqrt(
        config.soak.target_requests / max(1.0, request_rate)
    ))
    return math.ceil(base * trust_multiplier * volume_factor)
```

## Blast Radius Computation

```python
def compute_blast_radius(changed_component_id: str, new_version: str) -> BlastRadiusReport:
    # 1. Load access graph
    # 2. Find changed node
    # 3. Traverse all edges touching that node, transitively
    # 4. Collect union of data_access.reads and data_access.writes tiers
    # 5. Check if any traversed edge reaches a tier the changed node lacks declaration for
    # 6. Determine validation tier:
    #      PUBLIC only                  → AUTO_MERGE
    #      PUBLIC + PII                 → SOAK (compute duration)
    #      any FINANCIAL or AUTH        → HUMAN_GATE
    #      any COMPLIANCE               → HUMAN_GATE + legal_flag
    #      unauthorized tier in path    → HUMAN_GATE regardless
    #      LOW_TRUST_AUTHORITATIVE      → HUMAN_GATE regardless
    # 7. Return BlastRadiusReport
```

## Consistency Analysis Engine

The adapter layer is ground truth. The node's audit events are a claim.

```python
def analyze_consistency(span: OTLPSpan, audit_events: list[AuditEvent]) -> ConsistencyResult:
    # Extract observed I/O from span
    observed_input_fields = extract_classified_fields(span.request_body)
    observed_output_fields = extract_classified_fields(span.response_body)

    # Extract claimed I/O from audit events
    claimed_output_fields = extract_from_events(audit_events)

    # Compute unexplained fields
    unexplained = observed_output_fields - claimed_output_fields

    if not unexplained:
        return ConsistencyResult(verdict=CONSISTENT, severity=None)

    # Score severity by highest classification tier in unexplained fields
    max_tier = max(unexplained, key=lambda f: TIER_SEVERITY[classify_field(f)])
    severity = TIER_SEVERITY[max_tier]

    return ConsistencyResult(
        verdict=INCONSISTENT,
        severity=severity,
        unexplained_fields=unexplained,
        unexplained_tiers=[classify_field(f) for f in unexplained]
    )
```

A HIGH severity inconsistency (PII or above in unexplained fields) is a hard stop
during canary soak. Write to trust ledger immediately.

## Access Auditing

```python
def audit_access(node_id: str, span: OTLPSpan) -> AccessResult:
    declared_reads = get_declared_reads(node_id)   # from access graph
    observed_output_tiers = set(span.attributes.get("baton.response.classifications", []))

    unauthorized = observed_output_tiers - set(declared_reads)
    if unauthorized:
        return AccessResult(
            verdict=ACCESS_VIOLATION,
            unauthorized_tiers=unauthorized,
            severity=max(TIER_SEVERITY[t] for t in unauthorized)
        )
    return AccessResult(verdict=ACCESS_GRANTED)
```

## Canary Taint Detection

```python
def scan_for_taint(span: OTLPSpan, canary_corpus: CanaryCorpus) -> TaintResult:
    response_body = span.response_body_str
    for canary in canary_corpus.active_canaries:
        if canary.fingerprint in response_body:
            authorized = is_authorized_node(span.node_id, canary.classification)
            if not authorized:
                return TaintResult(
                    escaped=True,
                    canary_id=canary.id,
                    classification=canary.classification,
                    node=span.node_id
                )
    return TaintResult(escaped=False)
```

## Conflict Resolution

```python
def resolve_conflict(field: str, observations: list[FieldObservation]) -> ConflictResult:
    authoritative_node = get_authoritative_node(field)

    if authoritative_node:
        auth_obs = next((o for o in observations if o.node == authoritative_node), None)
        if auth_obs:
            auth_trust = get_trust_score(authoritative_node)
            if auth_trust >= config.trust.authority_override_floor:
                return ConflictResult(winner=authoritative_node, method=AUTHORITY, value=auth_obs.value)
            else:
                return ConflictResult(winner=None, method=ESCALATE,
                                      reason="authoritative node trust below floor")

    # No authoritative node — trust arbitration
    sorted_obs = sorted(observations, key=lambda o: get_trust_score(o.node), reverse=True)
    delta = get_trust_score(sorted_obs[0].node) - get_trust_score(sorted_obs[1].node)

    if delta > config.trust.conflict_trust_delta_threshold:
        return ConflictResult(winner=sorted_obs[0].node, method=TRUST, value=sorted_obs[0].value)
    else:
        return ConflictResult(winner=None, method=ESCALATE, reason="trust delta below threshold")
```

## HTTP API

Arbiter exposes an HTTP API on port 7700 (configurable).

```
POST /register
  Body: access_graph.json content
  Response: { "status": "ok", "warnings": [...] }

POST /blast-radius
  Body: { "component_id": "...", "version": "..." }
  Response: BlastRadiusReport JSON

GET  /trust/<node_id>
  Response: { "score": float, "tier": str, "history": [...last 20 events] }

POST /trust/reset-taint
  Body: { "node_id": "...", "review_id": "..." }
  Response: { "status": "ok", "new_score": float }

GET  /authority
  Response: full authority map

POST /canary/inject
  Body: { "tiers": [...], "run_id": "..." }
  Response: { "canaries_injected": int, "corpus_id": "..." }

GET  /canary/results/<run_id>
  Response: { "escapes": [...], "clean": bool }

GET  /report/<run_id>
  Response: full feedback report text

POST /findings
  Body: OTLP span JSON (called by Baton adapter)
  Response: { "findings": [...] }
```

## Stigmergy Integration

```python
def emit_to_stigmergy(finding: Finding):
    signal = {
        "source": "arbiter",
        "type": finding.type,   # consistency_violation, taint_escape, access_violation,
                                 # conflict_unresolvable, trust_degradation
        "actor": finding.node_id,
        "content": finding.to_dict(),
        "weight": finding.severity_score,
        "timestamp": finding.timestamp.isoformat()
    }
    if config.stigmergy_endpoint:
        requests.post(config.stigmergy_endpoint + "/signals", json=signal, timeout=2)
        # Fire-and-forget. Never block on Stigmergy.
```

## CLI

```bash
arbiter init                                     # initialize registry, config, trust ledger
arbiter register <path/to/access_graph.json>     # ingest Pact access graph
arbiter trust show <node_id>                     # score, tier, last 20 ledger events
arbiter trust reset-taint <node_id> --review <id>
arbiter authority show                           # full authority map
arbiter blast-radius <node_id> <version>         # compute and print blast radius report
arbiter soak compute <node_id> <tier>            # compute soak duration
arbiter report --run <run_id>                    # generate and print feedback report
arbiter canary inject --tiers PII,FINANCIAL      # seed canary corpus
arbiter canary results --run <run_id>            # taint escape report
arbiter watch                                    # start OTLP subscriber + API server
arbiter findings --node <node_id>                # list consistency findings for node
arbiter conflicts --unresolved                   # list unresolved conflicts
arbiter serve                                    # start API server only (no OTLP)
```

## Functional Assertions

- FA-A-001: `arbiter init` creates registry directory, empty trust ledger, default config
- FA-A-002: `arbiter register` accepts valid access_graph.json and returns no errors
- FA-A-003: `arbiter register` rejects access_graph.json where two components claim
             authority for overlapping domains
- FA-A-004: Trust ledger is append-only — no existing entry is ever modified or deleted
- FA-A-005: New node starts with trust score equal to configured floor
- FA-A-006: Trust score is fully reproducible by replaying the ledger from scratch
- FA-A-007: Taint escape on a locked tier sets trust score to 0.0 immediately
- FA-A-008: `reset-taint` without `--review` is rejected
- FA-A-009: Soak duration increases as trust score decreases (monotonic in trust)
- FA-A-010: Soak duration increases as request_rate decreases (monotonic in volume)
- FA-A-011: HUMAN_GATE is returned for any FINANCIAL, AUTH, or COMPLIANCE tier change
- FA-A-012: HUMAN_GATE is returned for any LOW_TRUST_AUTHORITATIVE node
- FA-A-013: Consistency analysis returns INCONSISTENT when span output contains fields
             not mentioned in audit events
- FA-A-014: Consistency analysis returns CONSISTENT when all observed fields are claimed
- FA-A-015: Access violation is recorded when observed output tier exceeds declared reads
- FA-A-016: Canary fingerprint in unauthorized node output triggers TAINT_ESCAPE finding
- FA-A-017: Canary fingerprint in authorized node output does not trigger finding
- FA-A-018: Conflict with authoritative node above floor resolves to authoritative value
- FA-A-019: Conflict with authoritative node below floor escalates to human review
- FA-A-020: Unresolvable conflict (no authority, small trust delta) escalates
- FA-A-021: `/register` HTTP endpoint accepts access_graph.json and returns 200
- FA-A-022: `/blast-radius` returns correct tier for each data classification scenario
- FA-A-023: Stigmergy emission is fire-and-forget — Stigmergy unavailability does not
             affect Arbiter operation
- FA-A-024: `arbiter watch` starts OTLP receiver and API server in a single process
- FA-A-025: All ledger writes are flushed to disk before API response is returned
- FA-A-026: Feedback report contains TRUST SUMMARY, CONSISTENCY, ACCESS, CONFLICTS,
             TAINT, BLAST RADIUS, and OVERALL sections
- FA-A-027: `arbiter report` is deterministic — same inputs produce same report
- FA-A-028: Trust decay is applied when idle cycles exceed zero
- FA-A-029: Authority-override floor is enforced — trust below floor means auth node
             loses conflict resolution
- FA-A-030: `arbiter register` validates that authority_map entries in trust_policy.yaml
             (if present) match authority declarations in access_graph.json components

## Artifact Contracts

### Consumes
- `access_graph.json` from Pact: component access declarations, authority, edge topology
- `trust_policy.yaml` from Constrain (optional, via access_graph.json passthrough):
  classification registry, soak config, authority map
- OTLP spans from Baton adapter: I/O data for consistency and access analysis
- Audit events from node event logs: self-reported behavior claims
- Human review records: for taint unlock and review_factor updates

### Produces
- Trust ledger (`registry/trust_ledger.jsonl`): append-only event log
- Blast radius reports: consumed by Pact phase 8.5 and Baton slot validation
- Feedback reports: consumed by human reviewers and stored as deploy artifacts
- Canary corpus: managed internally, seeded into Baton test mode
- Findings signals: emitted to Stigmergy

## Notes for Claude Code

- The trust ledger is the most critical data structure. Treat it like a financial ledger:
  append-only, checksummed, never modified. Consider JSONL with a SHA256 checksum line
  after every N entries.
- The consistency engine needs a field classifier that maps response body fields to the
  classification registry. This is a fuzzy match problem — use the field_pattern rules
  from the classification registry with fnmatch or regex.
- The OTLP subscriber should be a gRPC server implementing the OpenTelemetry Protocol
  collector service. Use the `opentelemetry-sdk` and `grpcio` packages.
- Canary fingerprints must be designed to be: (a) structurally valid for their tier,
  (b) globally unique per injection run, (c) impossible to appear in real data by
  coincidence. UUIDs embedded in domain-shaped strings work well.
- All HTTP API responses must be JSON. All errors must include a machine-readable
  `error_code` field alongside a human-readable `message`.
- The blast radius traversal is a graph BFS/DFS over the access graph edges. Use
  networkx or implement a simple adjacency list traversal. The graph can be large
  in a mature circuit — keep it efficient.
- Arbiter must start in under 3 seconds from cold with `arbiter watch`. The OTLP
  receiver and API server should be ready before the first span arrives.
