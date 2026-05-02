# === Conflict Resolver (conflicts) v1 ===
#  Dependencies: trust_ledger, authority_registry, stigmergy, field_classifier
# Detects and resolves conflicts following the three-step protocol (C009). Detection: two or more nodes produce different values for the same field within the same domain during the same circuit execution, identified by correlating OTLP spans by execution ID with buffering/windowing (rabbit hole patch — configurable window timeout). Step 1: authority check — authoritative node wins if trust > authority_override_floor (0.4), else human review. Step 2: trust arbitration — higher-trust node wins if trust delta > threshold (0.2). Step 3: unresolvable — flag to human, emit to Stigmergy as high-weight signal, block deploy if protected tier. Maintains append-only conflict records with resolution status in JSONL format with SHA256 checksums. Provides unresolved conflict list for CLI and report. Supports N-way conflicts (not just pairwise). Trust scores are snapshotted at detection time for deterministic resolution.

# Module invariants:
#   - The conflict log is append-only: records are never modified or deleted in place. Resolution is appended as a new log entry referencing the original conflict_id.
#   - Trust scores in NodeValue.trust_score_snapshot are immutable after detection — they reflect the trust state at detection time, not current trust.
#   - Resolution is deterministic: given the same ConflictRecord (with snapshotted trust scores and authority flags) and the same ConflictResolverConfig, resolve() always produces the same result.
#   - A conflict requires at least 2 competing values with distinct value_serialized — a single value or all-identical values never produce a conflict.
#   - Status transitions are strictly ordered: DETECTED -> (AUTHORITY_RESOLVED | TRUST_RESOLVED | UNRESOLVABLE) -> HUMAN_REVIEWED. No other transitions are valid.
#   - HUMAN_REVIEWED is only reachable from UNRESOLVABLE. AUTHORITY_RESOLVED and TRUST_RESOLVED are terminal states.
#   - blocks_deploy is True only when data_tier is in protected_tiers AND status is DETECTED or UNRESOLVABLE. Human review clears the deploy block.
#   - SHA256 checksum lines appear in the conflict log every checkpoint_interval entries, matching the trust ledger checksum pattern.
#   - All timestamps are UTC ISO-8601 strings. No local time is ever stored or compared.
#   - Trust is earned (from ledger), authority is declared (from registry) — the resolver never conflates them. Authority check uses is_authoritative AND trust_score_snapshot; trust arbitration uses only trust_score_snapshot.
#   - Error messages always include the specific conflict_id, node_id, domain, or field that caused the error, per operating procedures.
#   - For N-way conflicts (>2 nodes), Step 1 authority check requires exactly one authoritative node among competitors. Step 2 trust arbitration compares the top-2 trust scores regardless of N.

class ResolutionStatus(Enum):
    """Lifecycle status of a conflict record. Transitions: DETECTED -> (AUTHORITY_RESOLVED | TRUST_RESOLVED | UNRESOLVABLE) -> HUMAN_REVIEWED (only from UNRESOLVABLE)."""
    DETECTED = "DETECTED"
    AUTHORITY_RESOLVED = "AUTHORITY_RESOLVED"
    TRUST_RESOLVED = "TRUST_RESOLVED"
    UNRESOLVABLE = "UNRESOLVABLE"
    HUMAN_REVIEWED = "HUMAN_REVIEWED"

class ResolutionStrategy(Enum):
    """Which step of the three-step protocol resolved the conflict."""
    AUTHORITY = "AUTHORITY"
    TRUST_ARBITRATION = "TRUST_ARBITRATION"
    HUMAN = "HUMAN"

class ConflictErrorCode(Enum):
    """Machine-readable error codes for all conflict resolver error responses. Included in all error payloads per operating procedures."""
    CONFLICT_NOT_FOUND = "CONFLICT_NOT_FOUND"
    CONFLICT_ALREADY_RESOLVED = "CONFLICT_ALREADY_RESOLVED"
    INVALID_EXECUTION_ID = "INVALID_EXECUTION_ID"
    WINDOW_TIMEOUT_EXPIRED = "WINDOW_TIMEOUT_EXPIRED"
    TRUST_LOOKUP_FAILED = "TRUST_LOOKUP_FAILED"
    AUTHORITY_LOOKUP_FAILED = "AUTHORITY_LOOKUP_FAILED"
    SIGNAL_EMISSION_FAILED = "SIGNAL_EMISSION_FAILED"
    STORE_WRITE_FAILED = "STORE_WRITE_FAILED"
    STORE_READ_FAILED = "STORE_READ_FAILED"
    CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"
    INVALID_CONFIG = "INVALID_CONFIG"
    INVALID_HUMAN_REVIEW = "INVALID_HUMAN_REVIEW"
    DUPLICATE_SPAN = "DUPLICATE_SPAN"
    TIER_LOOKUP_FAILED = "TIER_LOOKUP_FAILED"
    EMPTY_COMPETING_VALUES = "EMPTY_COMPETING_VALUES"
    NO_CONFLICT_DETECTED = "NO_CONFLICT_DETECTED"

class NodeValue:
    """A single node's reported value for a contested field, with trust score snapshotted at detection time. Value is serialized as a JSON-compatible string to ensure deterministic comparison and storage."""
    node_id: str                             # required, length(min=1), Unique identifier of the reporting node.
    value_serialized: str                    # required, JSON-serialized value reported by this node. Serialized at ingestion for deterministic comparison.
    trust_score_snapshot: float              # required, range(0.0 <= value <= 1.0), Trust score of the node at conflict detection time, snapshotted from trust ledger.
    is_authoritative: bool                   # required, Whether this node is declared authoritative for the domain+field per the authority registry.
    span_id: str                             # required, OTLP span ID from which this value was extracted, for traceability.

class Resolution:
    """The outcome of conflict resolution: which strategy was used, who won, and rationale."""
    strategy: ResolutionStrategy             # required, Which step of the three-step protocol produced this resolution.
    winner_node_id: str                      # required, Node ID of the winning node. Empty string if strategy is HUMAN and not yet decided.
    resolved_at: str                         # required, UTC ISO-8601 timestamp when resolution was determined. Must be UTC per operating procedures.
    rationale: str                           # required, Human-readable explanation of why this resolution was chosen, including specific node IDs, trust scores, and thresholds.
    reviewed_by: str = None                  # optional, Identity of human reviewer if strategy is HUMAN. Empty string if not human-reviewed.

class ConflictRecord:
    """A single conflict instance: N nodes producing different values for the same (execution_id, domain, field) tuple. Append-only — once written to the conflict log, records are never modified in place; resolution is appended as a new log entry referencing the conflict_id."""
    conflict_id: str                         # required, regex(^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$), Globally unique conflict identifier (UUID4 string).
    execution_id: str                        # required, length(min=1), Circuit execution ID that produced the conflicting values.
    domain: str                              # required, length(min=1), Domain in which the conflict occurred.
    field: str                               # required, length(min=1), Field name that has conflicting values.
    data_tier: str                           # required, Classification tier of the field from the field classifier, used for deploy-blocking decisions. Empty string if tier lookup failed (degraded mode).
    competing_values: list[NodeValue]        # required, length(min=2), All competing node values. Must contain at least 2 entries (a conflict requires disagreement).
    detected_at: str                         # required, UTC ISO-8601 timestamp when the conflict was detected.
    status: ResolutionStatus                 # required, Current lifecycle status of this conflict.
    resolution: Resolution = None            # optional, Resolution details. Only present when status is not DETECTED.
    blocks_deploy: bool                      # required, True if this conflict blocks deployment. Set based on data_tier being a protected tier and status being UNRESOLVABLE or DETECTED.

class ConflictResolverConfig:
    """Configuration for the conflict resolver. Loaded from YAML config per operating procedures. All thresholds validated to [0.0, 1.0]."""
    window_timeout_seconds: float            # required, range(0.1 <= value <= 3600.0), How long to buffer spans for a given (execution_id, domain, field) window before closing it and checking for conflicts. Lazy timeout — checked on next ingest or explicit flush.
    authority_override_floor: float = 0.4    # optional, range(0.0 <= value <= 1.0), Minimum trust score an authoritative node must have to win via authority check (Step 1). Below this, conflict goes to human review.
    trust_delta_threshold: float = 0.2       # optional, range(0.0 <= value <= 1.0), Minimum trust score difference between the highest and second-highest trust nodes for trust arbitration to win (Step 2).
    checkpoint_interval: int = 100           # optional, range(1 <= value <= 100000), Number of conflict log entries between SHA256 checksum lines in the JSONL conflict log. Matches trust ledger pattern.
    conflict_log_path: str                   # required, length(min=1), Path to the append-only JSONL conflict log file. Must use pathlib internally.
    protected_tiers: list[str] = []          # optional, List of data classification tier names that block deploy when unresolved conflicts exist.

class ConflictSignal:
    """Signal emitted to Stigmergy for unresolvable conflicts. High-weight signal per C009 spec."""
    signal_type: str                         # required, regex(^conflict_unresolvable$), Always 'conflict_unresolvable'.
    conflict_id: str                         # required, References the ConflictRecord.conflict_id.
    execution_id: str                        # required, Circuit execution ID.
    domain: str                              # required, Domain of the conflict.
    field: str                               # required, Contested field name.
    competing_node_ids: list[str]            # required, Node IDs of all competing nodes.
    max_trust_score: float                   # required, Highest trust score among competing nodes.
    trust_delta: float                       # required, Difference between highest and second-highest trust scores.
    weight: float                            # required, range(value == 1.0), Signal weight. Always 1.0 for unresolvable conflicts (high-weight).
    emitted_at: str                          # required, UTC ISO-8601 timestamp.
    blocks_deploy: bool                      # required, Whether this conflict blocks deployment.

class SpanFieldReport:
    """Extracted field report from an OTLP span. This is the input to the conflict detector. Produced by the OTLP subscriber layer."""
    span_id: str                             # required, length(min=1), OTLP span ID.
    execution_id: str                        # required, length(min=1), Circuit execution ID extracted from span attributes.
    node_id: str                             # required, length(min=1), Node that produced this span.
    domain: str                              # required, length(min=1), Domain of the reported field.
    field: str                               # required, length(min=1), Field name.
    value_serialized: str                    # required, JSON-serialized field value reported by the node.
    reported_at: str                         # required, UTC ISO-8601 timestamp from the span.

class ConflictSummary:
    """Summary statistics for CLI and reporting."""
    total_conflicts: int                     # required, Total number of conflict records.
    unresolved_count: int                    # required, Number of conflicts with status DETECTED or UNRESOLVABLE.
    authority_resolved_count: int            # required, Conflicts resolved by authority check.
    trust_resolved_count: int                # required, Conflicts resolved by trust arbitration.
    human_reviewed_count: int                # required, Conflicts resolved by human review.
    deploy_blocking_count: int               # required, Number of conflicts currently blocking deployment.
    domains_affected: list[str]              # required, Distinct domains with unresolved conflicts.

class TrustLookup:
    """Protocol type for trust score lookup dependency. Implemented via composition, not inheritance."""
    lookup_trust_score: str                  # required, Callable protocol: (node_id: str) -> float. Returns raw trust score from ledger.

class AuthorityLookup:
    """Protocol type for authority registry dependency. Implemented via composition, not inheritance."""
    is_authoritative: str                    # required, Callable protocol: (node_id: str, domain: str, field: str) -> bool. Returns whether node is declared authoritative.

class SignalEmitter:
    """Protocol type for stigmergy signal emission dependency. Implemented via composition, not inheritance."""
    emit_signal: str                         # required, Callable protocol: (signal: ConflictSignal) -> None. Emits to Stigmergy.

class ConflictStore:
    """Protocol type for conflict persistence. Append-only JSONL store with SHA256 checksums at checkpoint_interval boundaries. Matches trust ledger pattern."""
    append: str                              # required, Callable protocol: (record: ConflictRecord) -> None. Appends record to JSONL log.
    load_all: str                            # required, Callable protocol: () -> list[ConflictRecord]. Loads and verifies all records from log.
    verify_checksums: str                    # required, Callable protocol: () -> bool. Verifies all SHA256 checksum lines in the log.

def ingest(
    span_report: SpanFieldReport,
) -> list[ConflictRecord]:
    """
    Ingests a span field report into the conflict detection buffer. Buffers by (execution_id, domain, field) key. When a window closes (lazy timeout checked on each ingest call), emits any detected conflicts where 2+ distinct values exist for the same key. Deduplicates by (node_id, span_id) to handle retransmitted spans. If only one distinct value exists after window close, no conflict is emitted.

    Preconditions:
      - span_report passes all field validators
      - ConflictDetector has been initialized with valid ConflictResolverConfig
      - TrustLookup and AuthorityLookup dependencies are available for snapshot at detection time

    Postconditions:
      - Returned list contains only newly detected conflicts (status=DETECTED) from windows that closed during this call
      - Each returned ConflictRecord has competing_values.length >= 2
      - Each NodeValue.trust_score_snapshot reflects the trust score at detection time, not ingestion time
      - Each NodeValue.is_authoritative reflects current authority registry state
      - All returned ConflictRecords have been persisted to the conflict store
      - span_report is buffered if its window has not yet closed
      - Duplicate spans (same node_id + span_id) are silently dropped

    Errors:
      - trust_lookup_failed (ConflictResolutionError): Trust ledger lookup fails for a node during conflict detection snapshot
          error_code: TRUST_LOOKUP_FAILED
          node_id: the node whose trust could not be looked up
      - authority_lookup_failed (ConflictResolutionError): Authority registry lookup fails for a node during conflict detection snapshot
          error_code: AUTHORITY_LOOKUP_FAILED
          node_id: the node whose authority could not be looked up
      - store_write_failed (ConflictStoreError): Conflict store append fails during persistence
          error_code: STORE_WRITE_FAILED
          conflict_id: the conflict that failed to persist
      - duplicate_span (None): Span with same node_id + span_id already in buffer (not an error, silently ignored)
          error_code: DUPLICATE_SPAN
      - tier_lookup_failed (None): Field classifier tier lookup fails; conflict is still detected with empty data_tier (degraded mode)
          error_code: TIER_LOOKUP_FAILED
          domain: affected domain
          field: affected field

    Side effects: Buffers span data in memory, Persists detected ConflictRecords to JSONL conflict log, Snapshots trust scores from trust ledger, Queries authority registry
    Idempotent: no
    """
    ...

def flush() -> list[ConflictRecord]:
    """
    Force-closes all open detection windows regardless of timeout, emitting any detected conflicts. Used during shutdown, circuit completion, or manual CLI trigger. After flush, the buffer is empty.

    Preconditions:
      - ConflictDetector has been initialized with valid ConflictResolverConfig

    Postconditions:
      - All open windows are closed and evaluated for conflicts
      - Returned list contains all newly detected conflicts from flushed windows
      - In-memory buffer is empty after flush completes
      - All returned ConflictRecords have been persisted to the conflict store
      - Windows with only one distinct value produce no conflict

    Errors:
      - trust_lookup_failed (ConflictResolutionError): Trust ledger lookup fails for a node during flush
          error_code: TRUST_LOOKUP_FAILED
      - authority_lookup_failed (ConflictResolutionError): Authority registry lookup fails during flush
          error_code: AUTHORITY_LOOKUP_FAILED
      - store_write_failed (ConflictStoreError): Conflict store append fails during flush persistence
          error_code: STORE_WRITE_FAILED

    Side effects: Clears in-memory buffer, Persists detected ConflictRecords to JSONL conflict log
    Idempotent: yes
    """
    ...

def resolve(
    conflict: ConflictRecord,
) -> ConflictRecord:
    """
    Runs the three-step conflict resolution protocol on a detected conflict. Step 1: Authority check — if exactly one authoritative node exists and its trust > authority_override_floor, it wins (AUTHORITY_RESOLVED). If authoritative node trust <= floor, skip to Step 3. Step 2: Trust arbitration — sort competing nodes by trust_score_snapshot descending; if delta between #1 and #2 > trust_delta_threshold, #1 wins (TRUST_RESOLVED). For N-way conflicts, only the top-2 trust scores matter for the delta check. Step 3: Unresolvable — set status to UNRESOLVABLE, emit ConflictSignal to stigmergy, set blocks_deploy if data_tier is protected. Returns the updated ConflictRecord. The original DETECTED record and the resolved record are both in the append-only log.

    Preconditions:
      - conflict.status == DETECTED
      - conflict.competing_values.length >= 2
      - All NodeValue.trust_score_snapshot values are already populated (snapshotted at detection)
      - ConflictResolver has been initialized with valid config and all Protocol dependencies

    Postconditions:
      - Returned ConflictRecord.status is one of: AUTHORITY_RESOLVED, TRUST_RESOLVED, UNRESOLVABLE
      - Returned ConflictRecord.resolution is populated with strategy, winner_node_id, resolved_at (UTC), and rationale
      - If status is AUTHORITY_RESOLVED: resolution.strategy == AUTHORITY and winner is the authoritative node
      - If status is TRUST_RESOLVED: resolution.strategy == TRUST_ARBITRATION and winner is the highest-trust node
      - If status is UNRESOLVABLE: resolution.strategy == HUMAN and a ConflictSignal has been emitted to stigmergy
      - If status is UNRESOLVABLE and data_tier in protected_tiers: blocks_deploy == True
      - Resolution is deterministic given the same conflict record and config
      - Updated record has been appended to the conflict store (append-only log)
      - rationale includes specific node IDs, trust scores, and threshold values used in the decision

    Errors:
      - already_resolved (ConflictResolutionError): conflict.status is not DETECTED
          error_code: CONFLICT_ALREADY_RESOLVED
          conflict_id: the conflict_id
          current_status: the current status
      - signal_emission_failed (ConflictResolutionError): Stigmergy signal emission fails during Step 3 (unresolvable)
          error_code: SIGNAL_EMISSION_FAILED
          conflict_id: the conflict_id
      - store_write_failed (ConflictStoreError): Conflict store append fails when persisting resolution
          error_code: STORE_WRITE_FAILED
          conflict_id: the conflict_id
      - empty_competing_values (ConflictResolutionError): conflict.competing_values has fewer than 2 entries (should not happen if preconditions hold)
          error_code: EMPTY_COMPETING_VALUES
          conflict_id: the conflict_id

    Side effects: Persists resolved ConflictRecord to JSONL log, Emits ConflictSignal to stigmergy if unresolvable
    Idempotent: no
    """
    ...

def submit_human_review(
    conflict_id: str,
    winner_node_id: str,
    reviewed_by: str,          # length(min=1)
    rationale: str,            # length(min=1)
) -> ConflictRecord:
    """
    Records a human review decision for an UNRESOLVABLE conflict. Transitions the conflict from UNRESOLVABLE to HUMAN_REVIEWED with the selected winner node and reviewer identity. Only valid for conflicts with status UNRESOLVABLE.

    Preconditions:
      - Conflict with conflict_id exists in the store
      - Conflict status is UNRESOLVABLE
      - winner_node_id is one of the competing node IDs in the conflict

    Postconditions:
      - Returned ConflictRecord.status == HUMAN_REVIEWED
      - Returned ConflictRecord.resolution.strategy == HUMAN
      - Returned ConflictRecord.resolution.winner_node_id == winner_node_id
      - Returned ConflictRecord.resolution.reviewed_by == reviewed_by
      - Returned ConflictRecord.blocks_deploy == False (human review clears deploy block)
      - Updated record has been appended to the conflict store
      - If previous record had blocks_deploy == True, the deploy block is now cleared

    Errors:
      - conflict_not_found (ConflictNotFoundError): No conflict with the given conflict_id exists
          error_code: CONFLICT_NOT_FOUND
          conflict_id: the requested conflict_id
      - invalid_status (ConflictResolutionError): Conflict status is not UNRESOLVABLE
          error_code: INVALID_HUMAN_REVIEW
          conflict_id: the conflict_id
          current_status: the current status
      - invalid_winner (ConflictResolutionError): winner_node_id is not among the competing node IDs
          error_code: INVALID_HUMAN_REVIEW
          conflict_id: the conflict_id
          winner_node_id: the invalid winner_node_id
      - store_write_failed (ConflictStoreError): Conflict store append fails
          error_code: STORE_WRITE_FAILED
          conflict_id: the conflict_id

    Side effects: Persists human-reviewed ConflictRecord to JSONL log
    Idempotent: no
    """
    ...

def get_unresolved(
    domain: str = None,
) -> list[ConflictRecord]:
    """
    Returns all conflicts that are not yet fully resolved (status DETECTED or UNRESOLVABLE), optionally filtered by domain. Used by CLI and report generation. Returns newest-first ordering.

    Postconditions:
      - All returned records have status DETECTED or UNRESOLVABLE
      - If domain is non-empty, all returned records have matching domain
      - Results are ordered by detected_at descending (newest first)
      - Result is a snapshot — new conflicts detected after this call are not included

    Errors:
      - store_read_failed (ConflictStoreError): Conflict store read fails
          error_code: STORE_READ_FAILED

    Side effects: none
    Idempotent: yes
    """
    ...

def has_blocking_conflicts(
    domain: str,               # length(min=1)
) -> bool:
    """
    Checks whether any unresolved conflicts in the given domain block deployment. A conflict blocks deploy if blocks_deploy == True (determined by data_tier being in protected_tiers and status being DETECTED or UNRESOLVABLE). Used as a deploy gate.

    Preconditions:
      - domain is a non-empty string

    Postconditions:
      - Returns True if and only if at least one conflict exists with domain == domain AND blocks_deploy == True AND status in (DETECTED, UNRESOLVABLE)
      - Returns False if no such conflict exists or domain has no conflicts

    Errors:
      - store_read_failed (ConflictStoreError): Conflict store read fails
          error_code: STORE_READ_FAILED

    Side effects: none
    Idempotent: yes
    """
    ...

def get_summary() -> ConflictSummary:
    """
    Returns aggregate conflict statistics for CLI display and reporting. Provides counts by resolution status, deploy-blocking count, and list of affected domains.

    Postconditions:
      - total_conflicts == sum of all status counts
      - unresolved_count == count of DETECTED + UNRESOLVABLE
      - deploy_blocking_count == count of records where blocks_deploy == True AND status in (DETECTED, UNRESOLVABLE)
      - domains_affected contains only domains with unresolved conflicts, deduplicated and sorted

    Errors:
      - store_read_failed (ConflictStoreError): Conflict store read fails
          error_code: STORE_READ_FAILED

    Side effects: none
    Idempotent: yes
    """
    ...

def verify_log_integrity() -> bool:
    """
    Verifies the SHA256 checksums in the append-only JSONL conflict log. Returns True if all checksum lines are valid, False otherwise. Used for audit and startup integrity checks.

    Preconditions:
      - Conflict log file exists at conflict_log_path

    Postconditions:
      - Returns True if and only if every SHA256 checksum line in the log matches the hash of the preceding N entries (where N is checkpoint_interval)
      - Returns True if log is empty (vacuously true)
      - Does not modify the log file

    Errors:
      - store_read_failed (ConflictStoreError): Conflict log file cannot be read
          error_code: STORE_READ_FAILED
          conflict_log_path: the configured path
      - checksum_mismatch (None): A checksum line does not match the computed hash (returns False, does not raise)
          error_code: CHECKSUM_MISMATCH

    Side effects: none
    Idempotent: yes
    """
    ...

def load_config(
    config_path: str,          # length(min=1)
) -> ConflictResolverConfig:
    """
    Loads and validates ConflictResolverConfig from a YAML file. All threshold validators are applied. Returns a validated config instance.

    Preconditions:
      - File at config_path exists and is readable
      - File content is valid YAML

    Postconditions:
      - Returned config passes all ConflictResolverConfig validators
      - All threshold values are within [0.0, 1.0]
      - checkpoint_interval is >= 1
      - window_timeout_seconds is >= 0.1

    Errors:
      - file_not_found (FileNotFoundError): Config file does not exist at config_path
          config_path: the requested path
      - invalid_yaml (ConflictConfigError): File content is not valid YAML
          error_code: INVALID_CONFIG
          config_path: the requested path
      - invalid_config (ConflictConfigError): YAML content fails Pydantic validation for ConflictResolverConfig
          error_code: INVALID_CONFIG
          validation_errors: pydantic validation error details

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['ResolutionStatus', 'ResolutionStrategy', 'ConflictErrorCode', 'NodeValue', 'Resolution', 'ConflictRecord', 'ConflictResolverConfig', 'ConflictSignal', 'SpanFieldReport', 'ConflictSummary', 'TrustLookup', 'AuthorityLookup', 'SignalEmitter', 'ConflictStore', 'ingest', 'ConflictResolutionError', 'ConflictStoreError', 'flush', 'resolve', 'submit_human_review', 'ConflictNotFoundError', 'get_unresolved', 'has_blocking_conflicts', 'get_summary', 'verify_log_integrity', 'load_config', 'ConflictConfigError']
