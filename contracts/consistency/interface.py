# === Consistency Analyzer (consistency) v1 ===
# Compares adapter-observed span I/O (ground truth) against node self-reported audit events (claims) per C007. For each span, extracts output field set from adapter observation and compares against the node's audit event field set. Unexplained fields (observed but not declared/claimed) produce INCONSISTENT findings with field details. All observed fields claimed = CONSISTENT. Missing claims produce MISSING_CLAIM findings (not exceptions). HIGH severity inconsistency during soak is a hard stop. Findings are persisted via FindingStore and queryable by node/span. Consistency outcomes feed into trust engine (consistency_factor updates). Provides findings list for report generation and CLI `arbiter findings`. Serialization uses JSONL with sorted field arrays, ISO 8601 UTC timestamps, and schema_version field.

# Module invariants:
#   - Trust is earned (computed from ledger), authority is declared (from manifests) — never conflated
#   - Adapter observations are ground truth; node self-reports are claims
#   - ConsistencyFinding.unexplained_fields == observed_fields - claimed_fields (set difference)
#   - ConsistencyFinding.overclaimed_fields == claimed_fields - observed_fields (set difference)
#   - ConsistencyFinding.outcome == CONSISTENT iff unexplained_fields is empty AND overclaimed_fields is empty AND both observation and claim are present
#   - ConsistencyFinding.outcome == MISSING_CLAIM when observation is present but claim is None
#   - ConsistencyFinding.outcome == MISSING_OBSERVATION when claim is present but observation is None
#   - All timestamps are UTC (datetime with timezone.utc)
#   - Field names use canonical dot-notation (e.g. 'user.email', 'response.body.token')
#   - Finding severity is computed deterministically from outcome and unexplained field count — never from display tiers
#   - FindingStore is append-only for persist operations — no updates, no deletes
#   - analyze_span with both observation=None and claim=None is invalid and raises ConsistencyAnalysisError
#   - analyze_span with empty observed_fields and empty claimed_fields (both present) produces CONSISTENT with NONE severity (vacuous truth)
#   - schema_version on ConsistencyFinding is always 1 for this contract version
#   - get_by_node and get_by_span return findings in chronological order (oldest first) by analyzed_at
#   - has_high_severity returns False when no findings exist for the given node_id
#   - Error messages always include the specific node_id, span_id, or field that caused the error

NodeId = primitive  # NewType wrapper over str identifying a unique node in the Pact/Baton circuit. Non-empty, typically dot-separated path.

SpanId = primitive  # NewType wrapper over str identifying a unique OTLP span. Non-empty, hex-encoded 16-byte identifier.

TraceId = primitive  # NewType wrapper over str identifying a unique OTLP trace. Non-empty, hex-encoded 32-byte identifier.

Timestamp = primitive  # ISO 8601 UTC datetime string (e.g. '2024-01-15T12:00:00Z'). Always timezone-aware UTC.

FieldSet = list[str]
# A set of canonical dot-notation field names. Represented as frozenset[str] in Python. Serialized as a sorted JSON array.

class ConsistencyOutcome(Enum):
    """The outcome of comparing adapter observation against node audit claim for a single span."""
    CONSISTENT = "CONSISTENT"
    INCONSISTENT = "INCONSISTENT"
    MISSING_CLAIM = "MISSING_CLAIM"
    MISSING_OBSERVATION = "MISSING_OBSERVATION"

class FindingSeverity(Enum):
    """Severity level for a consistency finding. Shared enum expected to live in a common module. NONE = no issue, LOW = minor overclaim only, MEDIUM = small unexplained set, HIGH = significant unexplained fields or missing claim."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class AdapterObservation:
    """Frozen Pydantic v2 model representing the adapter's ground-truth observation of a span's I/O fields. The adapter layer is authoritative."""
    span_id: SpanId                          # required, length(min=1), The OTLP span identifier this observation covers.
    trace_id: TraceId                        # required, length(min=1), The OTLP trace identifier this span belongs to.
    node_id: NodeId                          # required, length(min=1), The circuit node that produced this span.
    observed_fields: FieldSet                # required, Canonical dot-notation field names observed in the span output by the adapter. May be empty (vacuous case).
    timestamp: Timestamp                     # required, UTC timestamp when the adapter captured this observation.

class NodeAuditClaim:
    """Frozen Pydantic v2 model representing a node's self-reported audit event declaring which fields it accessed or produced."""
    span_id: SpanId                          # required, length(min=1), The OTLP span identifier this claim covers.
    trace_id: TraceId                        # required, length(min=1), The OTLP trace identifier this span belongs to.
    node_id: NodeId                          # required, length(min=1), The circuit node making this audit claim.
    claimed_fields: FieldSet                 # required, Canonical dot-notation field names the node claims it accessed/produced. May be empty.
    timestamp: Timestamp                     # required, UTC timestamp when the node emitted this audit event.

class ConsistencyFinding:
    """Frozen Pydantic v2 model representing the result of comparing one adapter observation against one node audit claim (or absence thereof) for a single span. This is the primary output artifact of consistency analysis."""
    schema_version: int                      # required, Schema version for serialization compatibility. Always 1 for this contract version.
    node_id: NodeId                          # required, The node this finding pertains to.
    span_id: SpanId                          # required, The span this finding pertains to.
    trace_id: TraceId                        # required, The trace this finding pertains to.
    outcome: ConsistencyOutcome              # required, The consistency verdict for this span comparison.
    severity: FindingSeverity                # required, Severity derived deterministically from outcome and field differences. NONE for CONSISTENT, HIGH for MISSING_CLAIM, LOW for overclaim-only, MEDIUM/HIGH for unexplained fields by count.
    observed_fields: FieldSet                # required, Fields the adapter observed (ground truth). Empty list if observation was absent (MISSING_OBSERVATION).
    claimed_fields: FieldSet                 # required, Fields the node claimed. Empty list if claim was absent (MISSING_CLAIM).
    unexplained_fields: FieldSet             # required, Fields observed by adapter but NOT claimed by node: observed_fields - claimed_fields. Non-empty implies INCONSISTENT.
    overclaimed_fields: FieldSet             # required, Fields claimed by node but NOT observed by adapter: claimed_fields - observed_fields. Indicates node claims more than reality.
    analyzed_at: Timestamp                   # required, UTC timestamp when this analysis was performed. Set by the analyzer at computation time.
    details: str = None                      # optional, Optional human-readable detail string providing additional context about the finding.

OptionalNodeAuditClaim = NodeAuditClaim | None

OptionalAdapterObservation = AdapterObservation | None

class AnalysisPair:
    """A paired observation and claim for batch analysis. At least one of observation or claim must be non-None."""
    observation: OptionalAdapterObservation  # required, The adapter observation, or None if missing.
    claim: OptionalNodeAuditClaim            # required, The node audit claim, or None if missing.

AnalysisPairList = list[AnalysisPair]
# A sequence of observation/claim pairs for batch analysis.

ConsistencyFindingList = list[ConsistencyFinding]
# An ordered list of ConsistencyFinding results.

OptionalTimestamp = Timestamp | None

class ConsistencyAnalysisError:
    """Exception raised for malformed or invalid inputs to analysis functions. Always includes context identifying the problematic node, span, or field."""
    node_id: str                             # required, The node_id associated with the error, or empty string if not applicable.
    span_id: str                             # required, The span_id associated with the error, or empty string if not applicable.
    detail: str                              # required, Human-readable description of what went wrong, including the specific field or domain that caused the error.

def analyze_span(
    observation: OptionalAdapterObservation,
    claim: OptionalNodeAuditClaim,
) -> ConsistencyFinding:
    """
    Compares a single adapter observation against a single node audit claim for one span. If observation is present and claim is None, produces MISSING_CLAIM finding. If claim is present and observation is None, produces MISSING_OBSERVATION finding. If both present, computes set differences to determine CONSISTENT or INCONSISTENT outcome. Severity is derived deterministically from outcome and unexplained field count. Both None raises ConsistencyAnalysisError. When both present, span_id and node_id on observation and claim must match or ConsistencyAnalysisError is raised.

    Preconditions:
      - At least one of observation or claim must be non-None
      - If both are non-None, observation.span_id == claim.span_id
      - If both are non-None, observation.node_id == claim.node_id
      - If both are non-None, observation.trace_id == claim.trace_id
      - All field names in observed_fields and claimed_fields are valid dot-notation identifiers

    Postconditions:
      - result.outcome == MISSING_CLAIM if observation is not None and claim is None
      - result.outcome == MISSING_OBSERVATION if claim is not None and observation is None
      - result.outcome == CONSISTENT if both present and unexplained_fields is empty and overclaimed_fields is empty
      - result.outcome == INCONSISTENT if both present and (unexplained_fields is non-empty or overclaimed_fields is non-empty)
      - result.unexplained_fields == observed_fields - claimed_fields (as sets)
      - result.overclaimed_fields == claimed_fields - observed_fields (as sets)
      - result.severity == NONE when outcome == CONSISTENT
      - result.severity == HIGH when outcome == MISSING_CLAIM
      - result.analyzed_at is a valid UTC timestamp at or after invocation time
      - result.schema_version == 1

    Errors:
      - both_none (ConsistencyAnalysisError): Both observation and claim are None
          detail: analyze_span requires at least one of observation or claim; both were None
      - span_id_mismatch (ConsistencyAnalysisError): Both observation and claim are non-None but observation.span_id != claim.span_id
          detail: span_id mismatch between observation ({observation.span_id}) and claim ({claim.span_id})
      - node_id_mismatch (ConsistencyAnalysisError): Both observation and claim are non-None but observation.node_id != claim.node_id
          detail: node_id mismatch between observation ({observation.node_id}) and claim ({claim.node_id})
      - trace_id_mismatch (ConsistencyAnalysisError): Both observation and claim are non-None but observation.trace_id != claim.trace_id
          detail: trace_id mismatch between observation ({observation.trace_id}) and claim ({claim.trace_id})
      - malformed_observation (ConsistencyAnalysisError): Observation contains invalid field names (not valid dot-notation identifiers)
          detail: Malformed field name in observation for node {node_id}, span {span_id}: {field_name}
      - malformed_claim (ConsistencyAnalysisError): Claim contains invalid field names (not valid dot-notation identifiers)
          detail: Malformed field name in claim for node {node_id}, span {span_id}: {field_name}

    Side effects: none
    Idempotent: yes
    """
    ...

def analyze_batch(
    pairs: AnalysisPairList,
) -> ConsistencyFindingList:
    """
    Analyzes a sequence of observation/claim pairs, returning one ConsistencyFinding per pair. Each pair is analyzed independently using the same logic as analyze_span. If any pair has both observation and claim as None, that pair raises ConsistencyAnalysisError. Processing continues for valid pairs; the batch call is not atomic (partial results are not returned on error — the error propagates).

    Preconditions:
      - pairs is not empty
      - For each pair, at least one of observation or claim is non-None
      - For each pair where both are non-None, span_id, node_id, and trace_id must match

    Postconditions:
      - len(result) == len(pairs)
      - result[i] corresponds to pairs[i] for all valid indices
      - Each result element satisfies all postconditions of analyze_span
      - Results are ordered to match input pair ordering

    Errors:
      - empty_batch (ConsistencyAnalysisError): pairs is an empty sequence
          detail: analyze_batch called with empty pairs sequence
      - pair_both_none (ConsistencyAnalysisError): Any pair has both observation and claim as None
          detail: Pair at index {i} has both observation and claim as None
      - pair_id_mismatch (ConsistencyAnalysisError): Any pair where both are non-None has mismatched span_id, node_id, or trace_id
          detail: ID mismatch in pair at index {i}: {details}

    Side effects: none
    Idempotent: yes
    """
    ...

def persist(
    finding: ConsistencyFinding,
) -> None:
    """
    Appends a single ConsistencyFinding to the finding store. The store is append-only; findings are never updated or deleted. Serialization uses JSONL format with sorted field arrays and ISO 8601 UTC timestamps. This is the only write path into the finding store.

    Preconditions:
      - finding is a valid ConsistencyFinding with all required fields populated
      - finding.schema_version == 1
      - finding.analyzed_at is a valid UTC timestamp

    Postconditions:
      - The finding is durably stored and will appear in subsequent get_by_node and get_by_span queries
      - The finding store size has increased by exactly one entry
      - If has_high_severity was False before and finding.severity == HIGH, has_high_severity returns True after

    Errors:
      - io_error (ConsistencyAnalysisError): Underlying storage is unavailable or write fails
          detail: Failed to persist finding for node {node_id}, span {span_id}: {io_error}
      - serialization_error (ConsistencyAnalysisError): Finding cannot be serialized to JSONL format
          detail: Serialization failed for finding node {node_id}, span {span_id}: {ser_error}

    Side effects: none
    Idempotent: no
    """
    ...

def get_by_node(
    node_id: NodeId,           # length(min=1)
) -> ConsistencyFindingList:
    """
    Retrieves all persisted ConsistencyFindings for a given node_id, ordered chronologically by analyzed_at (oldest first). Used by trust engine to compute consistency_factor and by CLI `arbiter findings` for per-node queries.

    Preconditions:
      - node_id is a non-empty string

    Postconditions:
      - All returned findings have finding.node_id == node_id
      - Results are ordered by analyzed_at ascending (oldest first)
      - Returns empty list if no findings exist for the given node_id

    Errors:
      - io_error (ConsistencyAnalysisError): Underlying storage is unavailable or read fails
          detail: Failed to read findings for node {node_id}: {io_error}
      - deserialization_error (ConsistencyAnalysisError): Stored finding data is corrupt or has incompatible schema_version
          detail: Deserialization failed for finding in node {node_id} store: {deser_error}

    Side effects: none
    Idempotent: yes
    """
    ...

def get_by_span(
    span_id: SpanId,           # length(min=1)
) -> ConsistencyFindingList:
    """
    Retrieves all persisted ConsistencyFindings for a given span_id, ordered chronologically by analyzed_at (oldest first). Typically returns zero or one finding per span, but the list type accommodates re-analysis scenarios.

    Preconditions:
      - span_id is a non-empty string

    Postconditions:
      - All returned findings have finding.span_id == span_id
      - Results are ordered by analyzed_at ascending (oldest first)
      - Returns empty list if no findings exist for the given span_id

    Errors:
      - io_error (ConsistencyAnalysisError): Underlying storage is unavailable or read fails
          detail: Failed to read findings for span {span_id}: {io_error}
      - deserialization_error (ConsistencyAnalysisError): Stored finding data is corrupt or has incompatible schema_version
          detail: Deserialization failed for finding in span {span_id} store: {deser_error}

    Side effects: none
    Idempotent: yes
    """
    ...

def has_high_severity(
    node_id: NodeId,           # length(min=1)
    since: OptionalTimestamp = None,
) -> bool:
    """
    Checks whether any HIGH severity ConsistencyFinding exists for the given node_id, optionally filtered to findings analyzed at or after a given timestamp. Used by the soak policy layer to enforce hard-stop on HIGH severity inconsistencies during soak. Returns False when no findings exist for the node.

    Preconditions:
      - node_id is a non-empty string
      - If since is provided, it is a valid UTC timestamp

    Postconditions:
      - Returns True iff at least one ConsistencyFinding exists with finding.node_id == node_id AND finding.severity == HIGH AND (since is None OR finding.analyzed_at >= since)
      - Returns False if no findings exist for the given node_id
      - Returns False if findings exist but none have HIGH severity in the time range

    Errors:
      - io_error (ConsistencyAnalysisError): Underlying storage is unavailable or read fails
          detail: Failed to check high severity for node {node_id}: {io_error}

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['FieldSet', 'ConsistencyOutcome', 'FindingSeverity', 'AdapterObservation', 'NodeAuditClaim', 'ConsistencyFinding', 'OptionalNodeAuditClaim', 'OptionalAdapterObservation', 'AnalysisPair', 'AnalysisPairList', 'ConsistencyFindingList', 'OptionalTimestamp', 'ConsistencyAnalysisError', 'analyze_span', 'analyze_batch', 'persist', 'get_by_node', 'get_by_span', 'has_high_severity']
