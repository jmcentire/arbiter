# Arbiter Trust Enforcement Layer

## System Context

Arbiter is the trust enforcement component in a distributed system stack that includes Pact (contract system) and Baton (orchestration). It sits between these systems as a continuous monitoring layer that answers four critical questions: "Who can access what?", "Are nodes doing what they claim?", "How big is the blast radius?", and "Can this node be trusted?"

Platform engineers use Arbiter to deploy changes with confidence. Security teams rely on it for data access auditing. Operations teams depend on its blast radius calculations for safe rollouts. The system watches all node I/O through adapter layers, compares observed behavior against declared contracts, tracks trust scores over time, and gates high-risk operations for human review.

## Consequence Map

**CATASTROPHIC**: Canary data escapes to production undetected - regulatory violations, customer data exposure, complete trust system failure
**SEVERE**: Authority conflicts allow duplicate ownership - data corruption, inconsistent enforcement, security boundary collapse  
**SEVERE**: Trust score manipulation - nodes game their reliability metrics, undermining the entire trust model
**HIGH**: Access violations go undetected - unauthorized data access, compliance failures, audit trail gaps
**HIGH**: Consistency analysis false negatives - nodes silently violate contracts without detection
**MEDIUM**: Stale trust scores - idle nodes retain high scores they haven't earned, skewing deployment decisions
**MEDIUM**: False positives under load - legitimate operations blocked due to span drops or timing issues
**LOW**: Arbiter unavailability - temporary loss of monitoring, fallback to manual processes

## Failure Archaeology

The system evolved from painful lessons about trust in distributed systems. Early attempts relied on self-reported metrics - nodes would claim to be trustworthy, and we believed them. This led to cascading failures when nodes lied or degraded silently. 

The current approach emerged from recognizing that trust must be earned through observable behavior, not declared through configuration. The taint tracking system came from a specific incident where test data leaked into customer reports - now canary escapes permanently zero trust scores until human intervention.

Authority conflicts were initially handled with "last writer wins" logic, which created race conditions and data corruption. The current exclusive ownership model prevents these races but requires careful domain modeling up front.

## Dependency Landscape

**Upstream Dependencies**:
- Pact contracts provide build-time access graphs and authority declarations
- Baton orchestration forwards OpenTelemetry spans from adapter layers  
- OpenAPI schemas define structural access capabilities
- External trust ledger stores append-only audit trail

**Downstream Consumers**:
- Stigmergy analyzes patterns across Arbiter's signal emissions
- Sentinel uses trust ledger for production attribution and contract tightening
- Human reviewers act on high-risk deployment gates
- Platform engineers read reports and deployment recommendations

**Critical Invariants**:
- All node I/O must flow through adapters (ground truth assumption)
- Trust ledger must remain external and append-only
- Authority ownership must be exclusive per data domain

## Boundary Conditions

**In Scope**: Trust enforcement, access auditing, consistency analysis, blast radius calculation, deployment gating, canary taint tracking

**Out of Scope**: Traffic routing, component building, final deployment decisions, long-term pattern correlation (that's Stigmergy), agent coordination, application code generation

**Constraints**: Cannot resolve unresolvable conflicts (escalates to humans), cannot make changes without observable evidence, cannot trust self-reported metrics without verification

## Success Shape

A good solution makes trust tangible and verifiable. Platform engineers should feel confident deploying because they know exactly what data will be accessed and by whom. Trust should be earned through consistent good behavior, not granted through configuration. When something goes wrong, the audit trail should make the failure path obvious.

The system should be "boring" in operation - most decisions should be automatic based on clear rules. Human intervention should be rare and reserved for genuinely ambiguous situations. Trust scores should reflect reality, not hopes.

## Done When

- [ ] All access violations detected and logged with full context
- [ ] Trust scores reproducible from ledger at any historical point  
- [ ] Canary data escape immediately zeros trust factor (0.0)
- [ ] Authority conflicts prevent node registration (hard failure)
- [ ] Declaration gaps block node slotting before runtime
- [ ] Blast radius computed from trust + tier + volume factors
- [ ] Low-trust authoritative nodes always trigger human gates
- [ ] Consistency analysis detects unexplained output fields
- [ ] OTLP spans enriched with trust and access metadata
- [ ] Soak duration calculated using trust multipliers and volume confidence
- [ ] Three-step conflict resolution protocol implemented (authority → trust → human)
- [ ] Trust ledger remains append-only and external to all nodes
- [ ] Trust formula components all implemented (base weight, age, consistency, taint, review, decay)