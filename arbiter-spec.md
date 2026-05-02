# Arbiter

**Access auditing, consistency analysis, blast-radius classification, and trust enforcement for the Pact/Baton stack.**

---

## What Arbiter Is

Arbiter is the trust enforcement layer that sits between Pact-built components and Baton-orchestrated circuits. It answers four questions continuously:

1. **Access**: Did this node touch data it was permitted to touch?
2. **Consistency**: Does what the node *claims* it did match what it *actually* did?
3. **Blast radius**: Given a proposed change, what does it touch, and who needs to know?
4. **Trust**: Has this node earned the right to be treated as reliable, and who owns what?

Arbiter does not write code, route traffic, or coordinate agents. It watches, compares, scores, and gates.

---

## Where Arbiter Lives

```
constrain → pact → [arbiter] → baton → production
                       ↑
                  stigmergy (analysis)
```

Arbiter is a standalone service with four integration surfaces:

- **Pact**: consumes contracts at build time, extracts data classification and authority declarations, registers the access graph and trust baseline
- **Baton**: attaches as an OpenTelemetry subscriber at the adapter layer, receives all I/O spans
- **Stigmergy**: emits structured findings as signals; Stigmergy's ART mesh correlates patterns across the circuit over time
- **Arbiter registry**: maintains the trust ledger, authority map, and canary corpus as durable, append-only state

At runtime, Arbiter is a sidecar to Baton — not in the hot path, not a proxy. It receives a copy of every span the Baton adapter emits via OTLP and processes asynchronously. Findings are written to an append-only audit log that no node can write to directly.

---

## Trust and Authority

These are distinct properties. Confusing them produces incorrect access decisions.

### Authority

Authority is the relationship between a node and a data domain. An authoritative node owns the canonical record for that domain. It arbitrates conflicts. Its version of the data wins.

- Authority is **narrow and domain-specific**. A node is authoritative for exactly the domains declared in its manifest, and non-authoritative for everything else.
- Authority does not decay. It is declared, versioned, and changed only through an explicit human-gated manifest update.
- Only one node may be authoritative for a given domain at a time. Arbiter enforces this at registration — a second node claiming authority for an already-owned domain is a hard registration failure.

```yaml
# In Pact contract or Baton node manifest
authority:
  domains: ["user.profile", "user.preferences"]
  rationale: "Canonical source for user identity data"
```

### Trust

Trust is a property of the node itself, independent of what it owns. It is a continuous score in the range [0.0, 1.0] that reflects the node's demonstrated reliability over its operational history.

Trust is not declared — it is earned and lost through observed behavior.

**Trust score computation:**

```
trust(node) = base_weight
            * age_factor
            * consistency_factor
            * taint_factor
            * review_factor
            * decay_factor
```

Where:

- `age_factor`: increases with circuit tenure. A node deployed today starts at the floor. Age is measured in clean deployment cycles, not wall-clock time.
- `consistency_factor`: ratio of clean consistency checks to total checks over a rolling window. Each unexplained output field reduces this. Recovers as the node accumulates clean runs.
- `taint_factor`: binary penalty on any taint escape. A single canary escape sets this to 0.0 and it requires a human review to reset. The severity of the escape (which classification tier) determines the recovery cost.
- `review_factor`: human review outcomes. An approving reviewer adds weight. A reviewer who finds a problem automated checks missed reduces weight.
- `decay_factor`: trust decays toward the floor when a node is idle. Stale nodes are not trusted simply because they have not failed recently.

**Trust floor**: configurable globally, defaults to 0.1. New nodes start at the floor.
**Trust ceiling**: 1.0. No node reaches it — the decay factor prevents it. High-performing nodes asymptote toward it.

### Display Tiers

Trust scores are displayed as labeled tiers for human readability. These labels are overlays on the continuous value — all policy calculations use the raw score.

| Score range | Display label |
|-------------|---------------|
| 0.0 – 0.25  | PROBATIONARY  |
| 0.26 – 0.50 | LOW           |
| 0.51 – 0.75 | ESTABLISHED   |
| 0.76 – 0.90 | HIGH          |
| 0.91 – 1.0  | TRUSTED       |

---

## Trust × Authority Interaction Matrix

### High trust + Authoritative
The canonical case. The node owns the data and has demonstrated reliability.

- Canary soak: short (trust-derived)
- Consistency violations: alert, do not hard-stop below threshold
- Conflict resolution: wins unconditionally for its declared domains
- Human gate: only at FINANCIAL/AUTH/COMPLIANCE tier or explicit blast-radius escalation

### High trust + Non-authoritative
A reliable consumer. Does not own the data but has a clean record handling it.

- Canary soak: moderate
- Consistency violations: alert, accumulate toward threshold
- Conflict resolution: defers to authoritative node; if none, trust arbitrates
- Human gate: per blast-radius tier

### Low trust + Authoritative
The dangerous case. A node that owns a data domain but has not yet demonstrated reliability.

- Canary soak: long, regardless of blast-radius tier
- Consistency violations: hard stop at first violation during soak
- Conflict resolution: wins for declared domains **only if** trust exceeds the authority-override floor (default: 0.4). Below that, conflicts escalate to human review even for owned domains.
- Human gate: always, regardless of data tier

### Low trust + Non-authoritative
A new or degraded consumer. Standard treatment.

- Canary soak: per trust-derived formula
- Consistency violations: accumulate toward threshold
- Conflict resolution: defers to authoritative node; if none, defers to highest-trust node
- Human gate: per blast-radius tier

---

## Canary Soak Duration

Soak duration is a function of node trust score, data classification tier, and a configurable base duration.

```
soak_duration(node, tier) =
    base_duration(tier)
    * trust_multiplier(node.trust_score)
    * volume_confidence_factor(node.request_rate)
```

**Base duration by tier** (configurable):

```yaml
# arbiter.yaml
soak:
  base_durations:
    PUBLIC: 1h
    PII: 6h
    FINANCIAL: 24h
    AUTH: 48h
    COMPLIANCE: 72h
```

**Trust multiplier** — inverse: lower trust = longer soak:

```
trust_multiplier(t) = 2.0 - t   # t in [0,1]
# trust=1.0 → 1.0x  (no extension)
# trust=0.5 → 1.5x  (50% longer)
# trust=0.1 → 1.9x  (90% longer)
```

**Volume confidence factor** — low-traffic nodes need longer soaks for statistical coverage:

```
volume_confidence_factor(rate) =
    max(1.0, sqrt(target_requests / observed_rate))
# target_requests: configurable, default 1000
```

**Example**:

```
Node: carousel, trust: 0.62, tier: PII, rate: 500 req/h, target: 1000

base             = 6h
trust_multiplier = 2.0 - 0.62 = 1.38
volume_factor    = sqrt(1000/500) = 1.41
soak_duration    = 6h * 1.38 * 1.41 ≈ 12h
```

The computed soak duration is recorded in the Arbiter report as a first-class artifact.

---

## Conflict Resolution Protocol

When two nodes emit contradictory observations about the same data field:

**Step 1: Authority check**
- Authoritative node present and trust > authority-override floor → wins, conflict logged as informational
- Authoritative node present but trust below floor → escalate to human review
- No authoritative node → step 2

**Step 2: Trust arbitration**
- Trust delta > threshold (default: 0.2) → higher-trust node wins, conflict logged as warning
- Trust delta ≤ threshold → unresolvable

**Step 3: Unresolvable conflict**
Flag to human review. Emit to Stigmergy as high-weight signal. Block deploy if field is in protected classification tier.

---

## Consistency Analysis

The adapter layer is ground truth. The node's internal event log is a claim.

```
Adapter span (ground truth):
  IN  = {user_id: 123, product_ids: [4,5,6]}
  OUT = {carousel_html: "...", user.email: "alice@example.com"}

Node audit events (self-reported):
  "fetched product catalog for user 123"
  "rendered carousel with 3 items"

Analysis:
  claimed_output  = {carousel_html}
  observed_output = {carousel_html, user.email}
  unexplained     = {user.email}  ← PII, not declared

  verdict: INCONSISTENT + ACCESS_VIOLATION
  severity: HIGH
  trust impact: immediate, pending ledger write
```

HIGH severity inconsistency during soak is a hard stop. Consistency outcomes feed directly into the trust score update cycle.

---

## Data Classification Registry

```yaml
classifications:
  - field_pattern: "user.email"
    tier: PII
    authoritative_node: user_service
    canary_pattern: "arbiter-{uuid}@canary.invalid"

  - field_pattern: "user.*"
    tier: PII
    authoritative_node: user_service
    canary_pattern: null

  - field_pattern: "payment.card_*"
    tier: FINANCIAL
    authoritative_node: payment_service
    canary_pattern: "4000-0000-0000-{rand4}"

  - field_pattern: "session.token"
    tier: AUTH
    authoritative_node: auth_service
    canary_pattern: null  # never seeded as canary

  - field_pattern: "product.*"
    tier: PUBLIC
    authoritative_node: catalog_service
    canary_pattern: "arbiter-canary-product-{uuid}"
```

The `authoritative_node` in the registry must match the node declaring authority in its manifest. Arbiter enforces this at registration.

---

## OpenAPI Integration

At adapter slot time, Arbiter walks the OpenAPI response schema and maps fields to the classification registry, producing a **structural access profile** — the superset of data tiers the node is capable of returning based on its declared interface.

If the structural access profile includes tiers not in the node's `data_access.reads` declaration, Arbiter flags a **declaration gap** and blocks the slot:

```
DECLARATION_GAP
  node: carousel
  openapi_capable_tiers: [PUBLIC, PII]
  declared_reads: [PUBLIC]
  action: BLOCK_SLOT
```

Declaration gaps are caught before the node runs. No runtime surprise.

---

## OpenTelemetry Integration

Arbiter enriches every adapter span with trust and access metadata:

```
baton.response.classifications: ["PUBLIC", "PII"]
baton.request.classifications: ["PUBLIC"]
arbiter.access.declared: ["PUBLIC"]
arbiter.access.observed: ["PUBLIC", "PII"]
arbiter.consistency: INCONSISTENT
arbiter.trust.score: 0.62
arbiter.trust.tier: ESTABLISHED
arbiter.authority.domains: []
arbiter.taint.detected: false
arbiter.blast.tier: HUMAN_GATE
arbiter.conflict: none
```

These attributes flow into any standard observability stack (Grafana, Jaeger, etc.) alongside Baton's existing metrics.

---

## Stigmergy Integration

Arbiter emits findings as normalized Signal objects:

```python
Signal(
    source="arbiter",
    type="consistency_violation",  # taint_escape, access_violation,
                                   # conflict_unresolvable, trust_degradation
    actor=node_id,
    content=finding_json,
    weight=severity_score,
    timestamp=span_timestamp
)
```

Stigmergy surfaces patterns Arbiter cannot see in individual spans: nodes consistently inconsistent under specific conditions, trust degradation clusters, canary escapes correlating with deploy windows. Arbiter produces facts. Stigmergy produces patterns.

---

## Trust Ledger

Append-only, durable, external to all nodes:

```jsonl
{"ts": "2026-03-15T14:32:00Z", "node": "carousel", "event": "consistency_pass", "weight": 1.0, "score_before": 0.61, "score_after": 0.62}
{"ts": "2026-03-15T18:11:00Z", "node": "carousel", "event": "human_approve", "weight": 2.0, "score_before": 0.62, "score_after": 0.65}
{"ts": "2026-03-16T02:44:00Z", "node": "carousel", "event": "taint_escape", "tier": "PII", "score_before": 0.65, "score_after": 0.0, "taint_factor_locked": true}
```

The trust score at any point is fully reproducible from the ledger. There is no mutable trust state.

---

## The Feedback Report

```
ARBITER REPORT — run 2026-03-15T14:32:00Z

TRUST SUMMARY
  user_service      0.94  TRUSTED       authoritative: user.*, user.preferences
  auth_service      0.88  HIGH          authoritative: session.*
  carousel          0.62  ESTABLISHED   authoritative: none
  recommend_engine  0.31  LOW           authoritative: none  ← flag

CONSISTENCY
  user_service      PASS    0 unexplained fields
  auth_service      PASS    0 unexplained fields
  carousel          PASS    0 unexplained fields
  recommend_engine  WARN    1 unexplained field
                            field: user.click_history (tier: PII)
                            not mentioned in audit log, 2/10 requests
                            trust impact: -0.04 pending

ACCESS
  carousel          PASS    reads PUBLIC (declared: PUBLIC)
  recommend_engine  WARN    reads PII via indirect path (declared: PUBLIC only)
                            structural gap in OpenAPI schema

CONFLICTS       none detected
TAINT           no canary escapes detected

BLAST RADIUS (proposed: carousel v1.2.0)
  node trust: 0.62 (ESTABLISHED)
  tier: PII (indirect read via user_context)
  base soak: 6h  |  trust multiplier: 1.38  |  volume factor: 1.41
  computed soak: 12h
  human gate: not required

OVERALL: PROCEED — 12h canary soak required
         recommend_engine ACCESS_VIOLATION requires resolution before next deploy
```

---

## Changes Required to Pact

**1. Add `data_access` and `authority` to contract schema** — both required fields, quality gate rejects contracts missing either.

**2. Typed side-effects include classification tier.**

**3. Emit `access_graph.json` post-build** — first-class output artifact alongside contracts and tests.

**4. Pipeline phase 8.5: `arbiter_register`** — after integration, before Sentinel. Pushes access graph, receives blast radius report and trust summary. Pauses on HUMAN_GATE or LOW_TRUST_AUTHORITATIVE.

---

## Changes Required to Baton

**1. Add `data_access` and `authority` to node manifest** — Baton refuses to slot nodes whose declarations diverge from Pact's registered graph.

**2. OpenAPI field-to-classification mapping at adapter** — structural access profile attached to spans at slot time.

**3. OTLP span forwarding to Arbiter** — configuration addition, not architectural change.

**4. Canary injection test mode** — `baton test --canary --tiers PII --duration 12h`.

**5. Adapter-only telemetry enforcement** — services cannot emit spans directly; documented and tested.

**6. Trust-gated slot validation** — Baton queries Arbiter trust score at slot time; requires human confirmation for LOW_TRUST_AUTHORITATIVE nodes.

---

## Arbiter CLI

```bash
arbiter init                                     # initialize registry, config, trust ledger
arbiter register pact/access_graph.json          # ingest Pact access graph
arbiter trust show <node>                        # current score and history
arbiter trust reset-taint <node> --review <id>  # clear taint lock after human review
arbiter authority show                           # full authority map
arbiter blast-radius <node> <version>            # compute blast radius
arbiter soak compute <node> <tier>               # compute soak duration
arbiter report --run <run_id>                    # generate feedback report
arbiter canary inject --tiers PII                # seed canary data
arbiter canary results --run <run_id>            # taint escape report
arbiter watch                                    # continuous OTLP subscriber mode
arbiter findings --node <node>                   # consistency findings
arbiter conflicts --unresolved                   # list unresolved conflicts
```

---

## What Arbiter Does Not Do

- Route traffic (Baton), build components (Pact), elicit constraints (Constrain), correlate patterns over time (Stigmergy), or make deployment decisions.
- Resolve unresolvable conflicts — it escalates them.
- Approve deployments — it clears the ones that do not require human judgment. Everything else waits.

---

## Stack Summary

```
constrain  → elicit constraints, produce constraints.yaml
    ↓
pact       → contract-first build, access graph + authority artifact, hard gates
    ↓
arbiter    → register graph, compute blast radius, assign soak, gate
    ↓
baton      → slot with trust validation, adapter classification, OTLP emit
    ↓
arbiter    → consistency analysis, taint detection, access audit, trust update
    ↓
stigmergy  → pattern analysis across trust events and findings over time
    ↓
sentinel   → production attribution, contract tightening, trust ledger updated
```

Each layer owns one concern. No layer reaches across.

---

*MIT License · Part of the Pact/Baton/Constrain/Stigmergy stack*
