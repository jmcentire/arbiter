# === Shared Data Models & Enums (models) v1 ===
# All Pydantic models, enums, and type definitions shared across Arbiter. Pure data definitions with Pydantic validation — no business logic. Organized as arbiter/models/ package with sub-modules: enums.py, types.py, trust.py, graph.py, findings.py, api.py, canary.py, signals.py, and __init__.py re-exports. All structured data boundaries in the system are defined here. Enforces frozen immutability on ledger/finding models, strict extra='forbid' on API inputs, trust/authority separation via module boundaries, and deterministic serialization for JSONL compatibility.

# Module invariants:
#   - All models with frozen=True config are immutable after construction — no attribute reassignment allowed
#   - All models with extra='forbid' reject unexpected fields during construction
#   - Trust is earned (computed from ledger via TrustScore), authority is declared (from manifests via AuthorityDomain) — these are distinct type aliases and never conflated
#   - The trust ledger is append-only: TrustLedgerEntry and LedgerCheckpoint are frozen, no update or delete operations exist
#   - All policy calculations use raw TrustScore (float), never TrustTier — tier is for display only
#   - TrustScore values are raw IEEE 754 floats in [0.0, 1.0] with no application-level rounding
#   - All timestamps are UTC ISO 8601 strings ending with 'Z' or '+00:00' — no local times
#   - AccessGraph referential integrity: every edge target in every node must exist as a key in AccessGraph.nodes
#   - Canary fingerprints must contain a UUID v4 segment making them recognizable as synthetic and impossible in real data
#   - Error messages and ErrorResponse instances must include the specific node, field, or domain that caused the error
#   - LedgerLine is a discriminated union: every JSONL line is exactly one of TrustLedgerEntry or LedgerCheckpoint
#   - Sequence numbers are monotonically increasing within a ledger — never reused or decremented
#   - Node self-reports are claims (Claim type), the adapter layer is ground truth — these are structurally distinct
#   - ClassificationRule evaluation is order-dependent: first matching rule wins
#   - All enum types use StrEnum with explicit string values for stable serialization across versions

class TrustTier(Enum):
    """StrEnum for trust classification tiers. No ordering operators — policy must use raw TrustScore, never tier comparisons. Explicit string values for stable serialization."""
    PROBATIONARY = "PROBATIONARY"
    LOW = "LOW"
    ESTABLISHED = "ESTABLISHED"
    HIGH = "HIGH"
    TRUSTED = "TRUSTED"

class DataTier(Enum):
    """StrEnum for data classification tiers. Determines sensitivity level and handling requirements."""
    PUBLIC = "PUBLIC"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    AUTH = "AUTH"
    COMPLIANCE = "COMPLIANCE"

class BlastTier(Enum):
    """StrEnum for blast-radius classification tiers. Determines rollout strategy for changes."""
    AUTO_MERGE = "AUTO_MERGE"
    SOAK = "SOAK"
    HUMAN_GATE = "HUMAN_GATE"

class FindingSeverity(Enum):
    """StrEnum for finding severity levels in audit results."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

NodeId = primitive  # Annotated[str] constrained type alias for node identifiers. Non-empty string, max 255 chars, must match pattern [a-zA-Z0-9._-]+. Transparent to mypy.

TrustScore = primitive  # Annotated[float] constrained type alias for trust scores. Range [0.0, 1.0] inclusive. Raw IEEE 754 float with no application-level rounding. Policy calculations always use this raw value, never display tiers.

Sha256Hex = primitive  # Annotated[str] constrained type alias for SHA-256 hex digest strings. Exactly 64 lowercase hex characters. Regex: ^[0-9a-f]{64}$.

UtcDatetime = primitive  # Annotated[str] constrained type alias for UTC ISO 8601 timestamps. Must end with 'Z' or '+00:00'. Produced via datetime.now(timezone.utc).isoformat(). Stored as string for JSONL round-trip fidelity.

AuthorityDomain = primitive  # Annotated[str] constrained type alias for authority domain identifiers. Non-empty, max 255 chars, must match pattern [a-zA-Z0-9._/-]+. Authority is declared (from manifests), distinct from trust.

SequenceNumber = primitive  # Annotated[int] constrained type alias for ledger sequence numbers. Non-negative integer (>= 0). Monotonically increasing within a ledger.

class TrustEventType(Enum):
    """StrEnum for trust event categories recorded in the ledger."""
    AUDIT_PASS = "AUDIT_PASS"
    AUDIT_FAIL = "AUDIT_FAIL"
    CONSISTENCY_CHECK = "CONSISTENCY_CHECK"
    ACCESS_VIOLATION = "ACCESS_VIOLATION"
    TAINT_DETECTED = "TAINT_DETECTED"
    CANARY_TRIGGERED = "CANARY_TRIGGERED"
    MANUAL_OVERRIDE = "MANUAL_OVERRIDE"
    DECAY = "DECAY"
    INITIAL = "INITIAL"

class TrustLedgerEntry:
    """A single immutable trust event in the append-only ledger. ConfigDict(frozen=True, extra='forbid'). Represents one trust-affecting event for a specific node. The ledger is treated like a financial ledger — no updates, no deletes."""
    ts: UtcDatetime                          # required, UTC timestamp when the event occurred.
    node: NodeId                             # required, The node this trust event pertains to.
    event: TrustEventType                    # required, Category of the trust event.
    weight: float                            # required, range(-1.0 <= value <= 1.0), Signed weight of this event's impact on trust score. Positive increases trust, negative decreases.
    score_before: TrustScore                 # required, Trust score of the node immediately before this event was applied.
    score_after: TrustScore                  # required, Trust score of the node immediately after this event was applied.
    sequence_number: SequenceNumber          # required, Monotonically increasing sequence number within the ledger.
    detail: str                              # required, Human-readable detail about the event. Must include the specific node, field, or domain that caused it.

class LedgerCheckpoint:
    """SHA-256 checksum line inserted into the JSONL ledger after every N entries. ConfigDict(frozen=True, extra='forbid'). Used for integrity verification of the append-only ledger."""
    ts: UtcDatetime                          # required, UTC timestamp when the checkpoint was created.
    sequence_number: SequenceNumber          # required, Sequence number of the last entry covered by this checkpoint.
    checksum: Sha256Hex                      # required, SHA-256 hex digest of all ledger entries from the previous checkpoint (or start) up to and including sequence_number.
    entry_count: int                         # required, range(value >= 1), Number of entries covered by this checkpoint.

LedgerLine = TrustLedgerEntry | LedgerCheckpoint

class AccessGraphNode:
    """A node in the access graph representing a component/service. ConfigDict(frozen=True, extra='forbid'). Edges are string-based NodeId references (adjacency list) — no circular Pydantic references."""
    id: NodeId                               # required, Unique identifier for this node in the access graph.
    data_access: list                        # required, List of DataTier values this node has access to.
    authority_domains: list                  # required, List of AuthorityDomain values declared for this node (from manifests). Authority is declared, not earned.
    edges: list                              # required, List of NodeId references to adjacent nodes in the access graph. String-based for adjacency list representation.
    trust_tier: TrustTier = "PROBATIONARY"   # optional, Current trust tier classification of this node. Display only — policy must use raw TrustScore.
    metadata: dict = {}                      # optional, Optional metadata key-value pairs for this node.

class AccessGraph:
    """Container for the full access graph. Mutable (not frozen) to allow incremental construction. Has a model validator ensuring referential integrity: all edge targets must exist as keys in nodes dict. Uses dict[NodeId, AccessGraphNode] for O(1) node lookup."""
    nodes: dict                              # required, Mapping from NodeId to AccessGraphNode. All edge targets in any node must exist as keys in this dict (enforced by model validator).
    version: str                             # required, Schema version string for the access graph.

class ConsistencyFinding:
    """A finding from consistency analysis between adapter-reported ground truth and node self-reports. ConfigDict(frozen=True, extra='forbid')."""
    ts: UtcDatetime                          # required, UTC timestamp when the finding was produced.
    node: NodeId                             # required, The node where inconsistency was detected.
    severity: FindingSeverity                # required, Severity level of this finding.
    field: str                               # required, The specific field that is inconsistent.
    adapter_value: str                       # required, The ground-truth value from the adapter layer.
    claimed_value: str                       # required, The self-reported value claimed by the node.
    detail: str                              # required, Human-readable explanation including the specific node, field, or domain.

class AccessFinding:
    """A finding from access audit analysis. ConfigDict(frozen=True, extra='forbid')."""
    ts: UtcDatetime                          # required, UTC timestamp when the finding was produced.
    node: NodeId                             # required, The node with the access issue.
    severity: FindingSeverity                # required, Severity level of this finding.
    data_tier: DataTier                      # required, The data tier involved in the access issue.
    authority_domain: AuthorityDomain        # required, The authority domain relevant to the finding.
    violation_type: str                      # required, Type of access violation (e.g. 'unauthorized_access', 'excessive_privilege', 'missing_authority').
    detail: str                              # required, Human-readable explanation including the specific node, field, or domain.

class TaintFinding:
    """A finding from taint/data-flow analysis. ConfigDict(frozen=True, extra='forbid')."""
    ts: UtcDatetime                          # required, UTC timestamp when the finding was produced.
    source_node: NodeId                      # required, The node where tainted data originated.
    sink_node: NodeId                        # required, The node where tainted data arrived.
    severity: FindingSeverity                # required, Severity level of this finding.
    data_tier: DataTier                      # required, The data classification tier of the tainted data.
    path: list                               # required, Ordered list of NodeIds representing the taint propagation path from source to sink.
    detail: str                              # required, Human-readable explanation including the specific nodes, fields, or domains.

class ConflictRecord:
    """A record of a detected conflict between nodes or authority claims. ConfigDict(frozen=True, extra='forbid')."""
    ts: UtcDatetime                          # required, UTC timestamp when the conflict was detected.
    conflict_id: str                         # required, Unique identifier for this conflict.
    nodes: list                              # required, length(len(value) >= 2), List of NodeIds involved in the conflict.
    authority_domain: AuthorityDomain        # required, The authority domain where the conflict exists.
    conflict_type: str                       # required, Category of conflict (e.g. 'overlapping_authority', 'contradictory_claims').
    detail: str                              # required, Human-readable description including the specific nodes and domain.
    resolved: bool                           # required, Whether this conflict has been resolved.

class StigmerySignal:
    """A stigmergic coordination signal for indirect communication between Arbiter components. ConfigDict(frozen=True, extra='forbid')."""
    ts: UtcDatetime                          # required, UTC timestamp when the signal was emitted.
    signal_id: str                           # required, Unique identifier for this signal.
    source_node: NodeId                      # required, The node that emitted this signal.
    signal_type: str                         # required, Type/category of the stigmergy signal.
    payload: dict                            # required, Arbitrary key-value payload for the signal.
    ttl_seconds: int                         # required, range(value >= 1), Time-to-live in seconds for this signal. Must be positive.

class CanaryRecord:
    """A record of a canary (synthetic test data) injection and its status. ConfigDict(frozen=True, extra='forbid'). Canary fingerprints must be structurally valid for their tier but globally unique per run and impossible in real data (UUID-in-domain-string pattern)."""
    ts: UtcDatetime                          # required, UTC timestamp when the canary was deployed.
    canary_id: str                           # required, Unique identifier for this canary instance.
    fingerprint: str                         # required, regex(.*[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}.*), Canary fingerprint: structurally valid for its data tier but contains embedded UUID making it recognizable as synthetic and impossible in real data. Must match pattern containing a UUID v4 segment.
    data_tier: DataTier                      # required, The data classification tier this canary is designed for.
    target_node: NodeId                      # required, The node where this canary was injected.
    triggered: bool                          # required, Whether this canary has been triggered (detected at an unexpected location).
    triggered_at: str = ""                   # optional, UTC timestamp when the canary was triggered, empty if not triggered.
    triggered_by_node: str = ""              # optional, NodeId of the node that triggered the canary, empty if not triggered.

class FeedbackReportSection:
    """A single section within a feedback report. ConfigDict(frozen=True, extra='forbid')."""
    section_name: str                        # required, Name/title of this report section.
    content: str                             # required, Textual content of this section.
    findings_count: int                      # required, range(value >= 0), Number of findings summarized in this section.
    metadata: dict                           # required, Optional section metadata.

class FeedbackReport:
    """A complete feedback report containing multiple sections. ConfigDict(frozen=True, extra='forbid')."""
    ts: UtcDatetime                          # required, UTC timestamp when the report was generated.
    report_id: str                           # required, Unique identifier for this report.
    sections: list                           # required, Ordered list of report sections.
    total_findings: int                      # required, range(value >= 0), Total findings across all sections.
    generated_by: NodeId                     # required, The node/component that generated this report.

class ErrorResponse:
    """Standard HTTP API error response. All API error responses use this structure. Machine-readable error_code plus human-readable message plus optional details including the offending node/field/domain."""
    error_code: str                          # required, Machine-readable error code (e.g. 'INVALID_NODE_ID', 'LEDGER_INTEGRITY_ERROR').
    message: str                             # required, Human-readable error message including the specific node, field, or domain that caused the error.
    details: dict                            # required, Optional structured details. Should include 'node', 'field', or 'domain' keys identifying the offending entity.

class TrustScoreRequest:
    """HTTP API request to query a node's trust score. ConfigDict(extra='forbid')."""
    node: NodeId                             # required, The node whose trust score is being requested.

class TrustScoreResponse:
    """HTTP API response containing a node's trust score and tier."""
    node: NodeId                             # required, The node this score pertains to.
    score: TrustScore                        # required, The raw trust score. Policy calculations use this value.
    tier: TrustTier                          # required, Display tier classification. For display only — never use for policy decisions.
    ledger_sequence: SequenceNumber          # required, The ledger sequence number at which this score was computed.

class BlastRadiusRequest:
    """HTTP API request to compute blast radius for a node. ConfigDict(extra='forbid')."""
    node: NodeId                             # required, The node to compute blast radius for.
    max_depth: int = 10                      # optional, range(1 <= value <= 100), Maximum traversal depth for BFS/DFS over access graph edges.

class BlastRadiusResponse:
    """HTTP API response containing blast radius analysis results."""
    node: NodeId                             # required, The node analyzed.
    blast_tier: BlastTier                    # required, Computed blast tier classification determining rollout strategy.
    affected_nodes: list                     # required, List of NodeIds reachable within the blast radius.
    affected_data_tiers: list                # required, Data classification tiers reachable in the blast radius.
    depth_reached: int                       # required, Actual traversal depth reached.

class FindingsRequest:
    """HTTP API request to query findings. ConfigDict(extra='forbid')."""
    node: NodeId = ""                        # optional, Optional node filter. If provided, only findings for this node are returned.
    severity_min: FindingSeverity = "INFO"   # optional, Minimum severity to include.
    limit: int = 100                         # optional, range(1 <= value <= 1000), Maximum number of findings to return.

class FindingsResponse:
    """HTTP API response containing queried findings."""
    consistency_findings: list               # required, Consistency findings matching the query.
    access_findings: list                    # required, Access findings matching the query.
    taint_findings: list                     # required, Taint findings matching the query.
    total_count: int                         # required, Total number of findings matching the query (may exceed returned count if limit applied).

class HealthResponse:
    """HTTP API response for health check endpoint."""
    status: str                              # required, Health status: 'healthy' or 'degraded'.
    version: str                             # required, Arbiter version string.
    ledger_sequence: SequenceNumber          # required, Current ledger sequence number.
    uptime_seconds: float                    # required, Uptime in seconds since startup.

class Claim:
    """Generic wrapper for self-reported data from a node. Marks data as a claim (not ground truth). Trust is earned (computed from ledger), but node self-reports are claims that must be verified against the adapter layer."""
    source_node: NodeId                      # required, The node making this claim.
    claimed_at: UtcDatetime                  # required, UTC timestamp when the claim was made.
    claim_type: str                          # required, Type/category of the claim for dispatch.
    payload: dict                            # required, The claimed data as a dict. Structure depends on claim_type.
    verified: bool                           # required, Whether this claim has been verified against adapter ground truth.
    verification_ts: str = ""                # optional, UTC timestamp of verification, empty if unverified.

class ClassificationRule:
    """A field classification rule from the classification registry. Uses fnmatch or regex patterns. ConfigDict(frozen=True, extra='forbid')."""
    field_pattern: str                       # required, fnmatch or regex pattern to match field names against.
    data_tier: DataTier                      # required, The data tier to assign when the pattern matches.
    is_regex: bool                           # required, If true, field_pattern is a regex; if false, it is an fnmatch pattern.
    description: str                         # required, Human-readable description of what this rule classifies.

class ValidationErrorDetail:
    """Detailed information about a single validation error for structured error reporting."""
    field: str                               # required, The field that failed validation.
    value: str                               # required, String representation of the invalid value.
    constraint: str                          # required, The constraint that was violated.
    message: str                             # required, Human-readable error message.

def create_trust_ledger_entry(
    node: NodeId,
    event: TrustEventType,
    weight: float,             # range(-1.0 <= value <= 1.0)
    score_before: TrustScore,
    sequence_number: SequenceNumber,
    detail: str,
) -> TrustLedgerEntry:
    """
    Factory function to create a validated TrustLedgerEntry with automatic timestamp. Ensures all invariants are met: score_after must equal score_before + weight clamped to [0.0, 1.0], timestamp is UTC, and detail is non-empty for AUDIT_FAIL and ACCESS_VIOLATION events.

    Preconditions:
      - score_before is a valid TrustScore in [0.0, 1.0]
      - sequence_number >= 0
      - weight is in [-1.0, 1.0]
      - For AUDIT_FAIL and ACCESS_VIOLATION events, detail must be non-empty

    Postconditions:
      - Returned entry.score_after == clamp(score_before + weight, 0.0, 1.0)
      - Returned entry.ts is a valid UTC ISO 8601 timestamp
      - Returned entry is frozen (immutable)
      - Returned entry.sequence_number == input sequence_number

    Errors:
      - invalid_node_id (ValidationError): node does not match NodeId pattern [a-zA-Z0-9._-]+
          error_code: INVALID_NODE_ID
      - weight_out_of_range (ValidationError): weight is outside [-1.0, 1.0]
          error_code: INVALID_WEIGHT
      - score_out_of_range (ValidationError): score_before is outside [0.0, 1.0]
          error_code: INVALID_SCORE
      - missing_detail_for_critical_event (ValueError): event is AUDIT_FAIL or ACCESS_VIOLATION and detail is empty
          error_code: MISSING_DETAIL
      - negative_sequence (ValidationError): sequence_number < 0
          error_code: INVALID_SEQUENCE

    Side effects: none
    Idempotent: yes
    """
    ...

def create_ledger_checkpoint(
    sequence_number: SequenceNumber,
    checksum: Sha256Hex,
    entry_count: int,          # range(value >= 1)
) -> LedgerCheckpoint:
    """
    Factory function to create a validated LedgerCheckpoint. Computes no checksum itself — caller must provide the pre-computed SHA-256 checksum. Validates all fields and returns a frozen instance.

    Preconditions:
      - sequence_number >= 0
      - checksum is a valid 64-character lowercase hex string
      - entry_count >= 1

    Postconditions:
      - Returned checkpoint is frozen (immutable)
      - Returned checkpoint.ts is a valid UTC ISO 8601 timestamp

    Errors:
      - invalid_checksum_format (ValidationError): checksum does not match ^[0-9a-f]{64}$
          error_code: INVALID_CHECKSUM
      - zero_entry_count (ValidationError): entry_count < 1
          error_code: INVALID_ENTRY_COUNT
      - negative_sequence (ValidationError): sequence_number < 0
          error_code: INVALID_SEQUENCE

    Side effects: none
    Idempotent: yes
    """
    ...

def build_access_graph(
    nodes: dict,
) -> AccessGraph:
    """
    Constructs a validated AccessGraph from a dict of AccessGraphNode instances. Performs referential integrity validation: all edge targets in every node must exist as keys in the nodes dict. Returns an AccessGraph or raises on integrity violation.

    Preconditions:
      - All keys in nodes are valid NodeIds
      - Each node's id field matches its key in the dict
      - All edge targets in every node reference keys that exist in nodes

    Postconditions:
      - Returned AccessGraph passes referential integrity: for all nodes, all edges point to existing nodes
      - Returned AccessGraph.nodes has same cardinality as input
      - Each node's id matches its dict key

    Errors:
      - dangling_edge (ValueError): A node's edge list contains a NodeId that does not exist in the nodes dict
          error_code: DANGLING_EDGE
      - id_key_mismatch (ValueError): A node's id field does not match its key in the dict
          error_code: ID_KEY_MISMATCH
      - invalid_node_id (ValidationError): A key in the dict is not a valid NodeId
          error_code: INVALID_NODE_ID
      - empty_graph (ValueError): nodes dict is empty
          error_code: EMPTY_GRAPH

    Side effects: none
    Idempotent: yes
    """
    ...

def parse_ledger_line(
    line: str,
) -> LedgerLine:
    """
    Parses a single JSONL line from the trust ledger into the appropriate LedgerLine variant (TrustLedgerEntry or LedgerCheckpoint). Uses discriminated union deserialization. The line must be valid JSON and conform to one of the two schemas.

    Preconditions:
      - line is a non-empty string
      - line is valid JSON

    Postconditions:
      - Returned value is either a TrustLedgerEntry or LedgerCheckpoint
      - All fields pass Pydantic validation
      - Float trust scores round-trip exactly (IEEE 754 fidelity)

    Errors:
      - invalid_json (ValueError): line is not valid JSON
          error_code: INVALID_JSON
      - unknown_schema (ValidationError): JSON does not match TrustLedgerEntry or LedgerCheckpoint schema
          error_code: UNKNOWN_LEDGER_LINE_SCHEMA
      - empty_line (ValueError): line is empty or whitespace-only
          error_code: EMPTY_LINE
      - validation_failure (ValidationError): JSON matches a schema but field values fail validation
          error_code: FIELD_VALIDATION_FAILED

    Side effects: none
    Idempotent: yes
    """
    ...

def serialize_ledger_line(
    entry: LedgerLine,
) -> str:
    """
    Serializes a LedgerLine (TrustLedgerEntry or LedgerCheckpoint) to a JSON string suitable for appending to a JSONL file. Ensures deterministic serialization order and IEEE 754 float fidelity for trust scores.

    Preconditions:
      - entry is a valid TrustLedgerEntry or LedgerCheckpoint

    Postconditions:
      - Output is a single-line valid JSON string (no embedded newlines)
      - parse_ledger_line(serialize_ledger_line(entry)) produces a value equal to entry
      - Float values have full IEEE 754 round-trip fidelity
      - JSON keys are in deterministic (sorted) order

    Errors:
      - invalid_entry_type (TypeError): entry is not a TrustLedgerEntry or LedgerCheckpoint
          error_code: INVALID_ENTRY_TYPE

    Side effects: none
    Idempotent: yes
    """
    ...

def create_error_response(
    error_code: str,
    message: str,
    node: str = "",
    field: str = "",
    domain: str = "",
) -> ErrorResponse:
    """
    Factory function to create a standardized ErrorResponse. Ensures error messages include the specific node, field, or domain that caused the error as required by project standards.

    Preconditions:
      - error_code is non-empty
      - message is non-empty
      - At least one of node, field, or domain should be provided for specificity

    Postconditions:
      - Returned ErrorResponse.error_code == input error_code
      - Returned ErrorResponse.details contains non-empty 'node', 'field', and/or 'domain' keys for any provided values
      - Returned ErrorResponse.message is non-empty

    Errors:
      - empty_error_code (ValueError): error_code is empty
          error_code: EMPTY_ERROR_CODE
      - empty_message (ValueError): message is empty
          error_code: EMPTY_MESSAGE

    Side effects: none
    Idempotent: yes
    """
    ...

def validate_canary_fingerprint(
    fingerprint: str,
) -> bool:
    """
    Validates that a canary fingerprint contains an embedded UUID v4, making it recognizable as synthetic data that is impossible in real data. Returns True if valid, raises ValueError otherwise.

    Preconditions:
      - fingerprint is a non-empty string

    Postconditions:
      - Returns True only if fingerprint contains a valid UUID v4 segment matching [0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}

    Errors:
      - missing_uuid (ValueError): fingerprint does not contain a UUID v4 segment
          error_code: INVALID_CANARY_FINGERPRINT
      - empty_fingerprint (ValueError): fingerprint is empty
          error_code: EMPTY_FINGERPRINT

    Side effects: none
    Idempotent: yes
    """
    ...

def score_to_tier(
    score: TrustScore,
) -> TrustTier:
    """
    Converts a raw TrustScore to its display TrustTier. This is for display/reporting ONLY — all policy calculations must use the raw score, never the tier. Tier boundaries: [0.0, 0.2) -> PROBATIONARY, [0.2, 0.4) -> LOW, [0.4, 0.6) -> ESTABLISHED, [0.6, 0.8) -> HIGH, [0.8, 1.0] -> TRUSTED.

    Preconditions:
      - score is in [0.0, 1.0]

    Postconditions:
      - Returned tier corresponds to the correct bracket for the input score
      - This function is deterministic: same input always yields same output

    Errors:
      - score_out_of_range (ValueError): score < 0.0 or score > 1.0
          error_code: INVALID_SCORE

    Side effects: none
    Idempotent: yes
    """
    ...

def classify_field(
    field_name: str,
    rules: list,
) -> DataTier:
    """
    Classifies a field name against a list of ClassificationRule instances, returning the matching DataTier. Uses fnmatch or regex depending on the rule's is_regex flag. Returns the first matching rule's data_tier. If no rule matches, returns DataTier.PUBLIC as the default.

    Preconditions:
      - field_name is a non-empty string
      - rules is a list (may be empty)

    Postconditions:
      - If any rule matches, returns the data_tier of the first matching rule
      - If no rule matches, returns DataTier.PUBLIC
      - Rules are evaluated in order; first match wins

    Errors:
      - empty_field_name (ValueError): field_name is empty
          error_code: EMPTY_FIELD_NAME
      - invalid_regex_pattern (ValueError): A rule with is_regex=True has an invalid regex pattern
          error_code: INVALID_REGEX_PATTERN

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['TrustTier', 'DataTier', 'BlastTier', 'FindingSeverity', 'TrustEventType', 'TrustLedgerEntry', 'LedgerCheckpoint', 'LedgerLine', 'AccessGraphNode', 'AccessGraph', 'ConsistencyFinding', 'AccessFinding', 'TaintFinding', 'ConflictRecord', 'StigmerySignal', 'CanaryRecord', 'FeedbackReportSection', 'FeedbackReport', 'ErrorResponse', 'TrustScoreRequest', 'TrustScoreResponse', 'BlastRadiusRequest', 'BlastRadiusResponse', 'FindingsRequest', 'FindingsResponse', 'HealthResponse', 'Claim', 'ClassificationRule', 'ValidationErrorDetail', 'create_trust_ledger_entry', 'ValidationError', 'create_ledger_checkpoint', 'build_access_graph', 'parse_ledger_line', 'serialize_ledger_line', 'create_error_response', 'validate_canary_fingerprint', 'score_to_tier', 'classify_field']
