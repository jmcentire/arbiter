# === OTLP Span Subscriber (otlp_subscriber) v1 ===
#  Dependencies: consistency_analyzer, access_auditor, taint_detector, conflict_resolver
# gRPC server on configured port (default 4317) receiving OTLP spans from Baton's adapter layer. Uses grpcio thread pool (AS002 — threading OK, no asyncio). On span receipt: enriches with arbiter.* attributes (C012 — arbiter.access.declared, arbiter.access.observed, arbiter.consistency, arbiter.trust.score, arbiter.trust.tier, arbiter.authority.domains, arbiter.taint.detected, arbiter.blast.tier, arbiter.conflict), then dispatches to consistency analyzer, access auditor, taint detector, and conflict resolver. Defines expected span schema contract with Baton (rabbit hole patch — validates span structure, logs warnings on unexpected format). Manages execution-ID correlation buffer for conflict detection windowing. Seven-layer design: (1) gRPC Transport with TraceServiceServicer, ThreadPoolExecutor, partial_success semantics, health checking; (2) Anti-Corruption/Schema Validation with BatonSpanContract Pydantic model, protobuf→domain conversion at handler boundary, custom TraceId/SpanId/ExecutionId types, structured warning logging, explicit default-value handling; (3) Enrichment Model with frozen ArbiterEnrichment composed into EnrichedSpan; (4) Protocol-based Dispatcher with SpanAnalyzer Protocol, 4 registered analyzers with failure isolation, result aggregation; (5) Correlation Buffer with bounded dict, threading.Lock, lazy+periodic eviction, metrics; (6) Configuration via OtlpSubscriberConfig Pydantic model from YAML; (7) Lifecycle with start/stop/is_ready and 3-second cold start target.

# Module invariants:
#   - Trust and authority are distinct: trust is earned (computed from ledger), authority is declared (from manifests) — never conflated in any enrichment or analysis
#   - The adapter layer is ground truth; node self-reports are claims — baton_node_id from adapter attributes is authoritative
#   - All policy calculations use raw trust_score (float), never trust_tier (enum) — trust_tier is display/enrichment only
#   - Partial success semantics: the server never rejects an entire ExportTraceServiceRequest batch — valid spans are always processed even if some spans in the batch fail validation
#   - The correlation buffer is append-only within a window: spans are never modified after insertion, only evicted by age or capacity
#   - Failure isolation: a single analyzer failure never prevents other analyzers from processing the same span — all 4 are always invoked
#   - All timestamps are UTC, represented as nanoseconds since Unix epoch — no local time, no timezone-naive datetimes
#   - Protobuf default-value ambiguity is handled explicitly: 0 for int fields and empty string for string fields are treated as 'unset' where semantically appropriate (e.g. start_time_unix_nano == 0 is invalid)
#   - The correlation buffer is bounded: it never exceeds buffer_max_size keys — lazy eviction on insert plus periodic sweep guarantee this
#   - All protobuf-to-domain conversion happens at the handler boundary — no protobuf types leak past parse_and_validate_spans
#   - Server transitions to SERVING only when all 4 analyzers are registered and gRPC is accepting connections — is_ready() reflects this
#   - Error messages always include the specific node, field, or domain that caused the error per project standards
#   - Thread safety: correlation buffer operations are serialized via threading.Lock — no asyncio (AS002)
#   - Cold start: server accepting connections in under 3 seconds from start() invocation

TraceId = primitive  # 32-character lowercase hexadecimal string representing an OpenTelemetry trace ID. Must be exactly 32 hex chars and not all zeros.

SpanId = primitive  # 16-character lowercase hexadecimal string representing an OpenTelemetry span ID. Must be exactly 16 hex chars and not all zeros.

ExecutionId = primitive  # Non-empty string identifying a Baton execution context. Used as correlation key for conflict detection windowing. Typically a UUID or structured identifier from the adapter layer.

class TrustTier(Enum):
    """Trust tier enum. Used only for display/enrichment labeling — all policy calculations use raw trust score, never tiers (domain rule)."""
    FULL = "FULL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"

class BlastTier(Enum):
    """Blast radius classification tier for enrichment."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CONTAINED = "CONTAINED"
    UNKNOWN = "UNKNOWN"

class AnalyzerKind(Enum):
    """Identifies which of the 4 registered downstream analyzers produced a result or error."""
    CONSISTENCY = "CONSISTENCY"
    ACCESS = "ACCESS"
    TAINT = "TAINT"
    CONFLICT = "CONFLICT"

class ServerStatus(Enum):
    """gRPC server lifecycle status for health checking."""
    NOT_STARTED = "NOT_STARTED"
    STARTING = "STARTING"
    SERVING = "SERVING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"

class ValidationSeverity(Enum):
    """Severity of span schema validation issues."""
    WARNING = "WARNING"
    ERROR = "ERROR"

class OtlpSubscriberConfig:
    """Pydantic model for OTLP subscriber configuration. Loaded from YAML via project config layer."""
    port: int = 4317                         # optional, range(1 <= value <= 65535), gRPC listen port.
    max_workers: int = 10                    # optional, range(1 <= value <= 200), ThreadPoolExecutor max_workers for gRPC server (AS002 — threading, no asyncio).
    buffer_max_size: int = 10000             # optional, range(100 <= value <= 1000000), Maximum number of ExecutionId keys in the correlation buffer before eviction is forced.
    buffer_window_seconds: float = 30.0      # optional, range(1.0 <= value <= 300.0), Duration in seconds to retain spans in correlation buffer for conflict detection windowing.
    grace_shutdown_seconds: float = 5.0      # optional, range(0.0 <= value <= 60.0), Grace period in seconds for gRPC server shutdown. Allows in-flight RPCs to complete.
    eviction_sweep_interval_seconds: float = 5.0 # optional, range(0.5 <= value <= 60.0), Interval in seconds between periodic eviction sweeps of the correlation buffer by daemon thread.
    max_batch_size: int = 512                # optional, range(1 <= value <= 10000), Maximum number of spans accepted per ExportTraceServiceRequest. Batches exceeding this are partially accepted.
    bind_address: str = 0.0.0.0              # optional, Network address to bind the gRPC server to.

class SpanAttribute:
    """A single key-value attribute from an OTLP span, converted from protobuf AnyValue to a Python-native representation."""
    key: str                                 # required, Attribute key.
    value: str                               # required, Attribute value coerced to string representation. Protobuf default-value ambiguity handled: empty string means explicitly empty, None means attribute was absent.
    original_type: str                       # required, Original protobuf AnyValue type name (string_value, int_value, bool_value, double_value, array_value, kvlist_value, bytes_value) for downstream type recovery.

class SpanLink:
    """A link from one span to another, preserving trace/span context."""
    trace_id: TraceId                        # required, Trace ID of the linked span.
    span_id: SpanId                          # required, Span ID of the linked span.
    attributes: SpanAttributeList = []       # optional, Attributes on the link.

class SpanEvent:
    """A timestamped event within a span."""
    name: str                                # required, Event name.
    timestamp_unix_nano: int                 # required, Event timestamp in nanoseconds since Unix epoch (UTC).
    attributes: SpanAttributeList = []       # optional, Attributes on the event.

SpanAttributeList = list[SpanAttribute]
# List of SpanAttribute.

SpanLinkList = list[SpanLink]
# List of SpanLink.

SpanEventList = list[SpanEvent]
# List of SpanEvent.

class ValidationIssue:
    """A single schema validation issue found when converting a protobuf span to domain types. Includes specific node/field per project error message standards."""
    severity: ValidationSeverity             # required, Whether this is a warning (span still processable) or error (span rejected).
    field: str                               # required, Dot-path to the problematic field (e.g. 'attributes.baton.node_id').
    message: str                             # required, Human-readable description of the issue, must include specific node/field/domain.
    span_id: str = None                      # optional, SpanId of the problematic span if available, empty string if not yet parsed.
    node_id: str = None                      # optional, Baton node ID if identifiable from span context, empty string otherwise.

ValidationIssueList = list[ValidationIssue]
# List of ValidationIssue.

class BatonSpanContract:
    """Pydantic model defining the expected schema for Baton-originated spans at the anti-corruption boundary. Protobuf is converted to this model at the handler boundary; all downstream code uses domain types only. Handles protobuf default-value ambiguity: 0/empty != unset via Optional wrappers."""
    trace_id: TraceId                        # required, regex(^[0-9a-f]{32}$), custom(value != '00000000000000000000000000000000'), 32-char hex trace ID from OTLP span.
    span_id: SpanId                          # required, regex(^[0-9a-f]{16}$), custom(value != '0000000000000000'), 16-char hex span ID from OTLP span.
    parent_span_id: OptionalSpanId = None    # optional, Parent span ID if this span has a parent. None for root spans.
    name: str                                # required, length(1 <= len(value) <= 1024), Span operation name.
    start_time_unix_nano: int                # required, range(value > 0), Span start time in nanoseconds since Unix epoch (UTC). Must be positive (not protobuf default 0).
    end_time_unix_nano: int                  # required, range(value > 0), Span end time in nanoseconds since Unix epoch (UTC). Must be >= start_time_unix_nano.
    attributes: SpanAttributeList            # required, All span attributes converted from protobuf AnyValue to SpanAttribute.
    events: SpanEventList = []               # optional, Span events (timeline annotations).
    links: SpanLinkList = []                 # optional, Span links to other trace contexts.
    baton_node_id: str                       # required, length(len(value) >= 1), Baton adapter node identifier extracted from span attributes. Error if missing — adapter layer is ground truth.
    baton_execution_id: ExecutionId          # required, length(len(value) >= 1), Execution context ID from Baton adapter for correlation buffer keying.
    baton_component_id: str = None           # optional, Optional Pact component identifier from adapter attributes.
    baton_circuit_id: str = None             # optional, Optional Pact circuit identifier from adapter attributes.
    resource_attributes: SpanAttributeList = [] # optional, Resource-level attributes from the OTLP ResourceSpans envelope.

OptionalSpanId = SpanId | None

class ParsedSpan:
    """Domain model for a validated and parsed Baton span, produced from BatonSpanContract after schema validation passes. This is the type consumed by all downstream analyzers."""
    trace_id: TraceId                        # required, Validated trace ID.
    span_id: SpanId                          # required, Validated span ID.
    parent_span_id: OptionalSpanId = None    # optional, Parent span ID or None for root.
    name: str                                # required, Span operation name.
    start_time_unix_nano: int                # required, Span start timestamp in nanoseconds since Unix epoch (UTC).
    end_time_unix_nano: int                  # required, Span end timestamp in nanoseconds since Unix epoch (UTC).
    duration_ns: int                         # required, Computed span duration in nanoseconds (end - start). Always >= 0.
    attributes: SpanAttributeList            # required, Span attributes in domain form.
    events: SpanEventList = []               # optional, Span events.
    links: SpanLinkList = []                 # optional, Span links.
    baton_node_id: str                       # required, Baton adapter node ID — ground truth.
    baton_execution_id: ExecutionId          # required, Execution context ID for correlation.
    baton_component_id: str = None           # optional, Pact component ID if present.
    baton_circuit_id: str = None             # optional, Pact circuit ID if present.
    resource_attributes: SpanAttributeList = [] # optional, Resource-level attributes.
    validation_issues: ValidationIssueList = [] # optional, Non-fatal validation issues (warnings) encountered during parsing. Empty if clean.
    received_at_unix_nano: int               # required, Timestamp when this span was received by the subscriber, in nanoseconds since Unix epoch (UTC). Set at handler boundary.

class AnalysisResult:
    """Result from a single SpanAnalyzer. Each analyzer populates the fields relevant to its domain; other fields remain at defaults. Composed into ArbiterEnrichment by the dispatcher."""
    analyzer_kind: AnalyzerKind              # required, Which analyzer produced this result.
    success: bool                            # required, Whether the analyzer completed without internal error.
    error_message: str = None                # optional, Error detail if success is false. Includes specific node/field per project standards.
    consistency_score: OptionalFloat = None  # optional, Consistency score from consistency analyzer. Range [0.0, 1.0].
    access_declared: str = None              # optional, Declared access pattern from access auditor.
    access_observed: str = None              # optional, Observed access pattern from access auditor.
    authority_domains: StringList = []       # optional, Authority domains from access auditor. Authority is declared, distinct from trust.
    trust_score: OptionalFloat = None        # optional, Raw trust score. All policy calculations use raw score, never display tiers.
    trust_tier: OptionalTrustTier = None     # optional, Trust tier for display/enrichment only — never used in policy calculations.
    taint_detected: OptionalBool = None      # optional, Whether taint was detected by taint detector.
    taint_details: str = None                # optional, Detail of taint if detected.
    blast_tier: OptionalBlastTier = None     # optional, Blast radius tier classification.
    conflict_description: str = None         # optional, Conflict description from conflict resolver if a conflict is detected.
    conflict_detected: OptionalBool = None   # optional, Whether a conflict was detected by conflict resolver.

OptionalFloat = float | None

OptionalBool = bool | None

OptionalTrustTier = TrustTier | None

OptionalBlastTier = BlastTier | None

StringList = list[str]
# List of strings.

class ArbiterEnrichment:
    """Frozen Pydantic model containing all 9 arbiter.* enrichment attributes (C012). Composed (not inherited) with ParsedSpan into EnrichedSpan. Aggregated from AnalysisResult instances from all 4 analyzers."""
    access_declared: str                     # required, arbiter.access.declared — declared access pattern from manifest/authority.
    access_observed: str                     # required, arbiter.access.observed — observed access pattern from adapter ground truth.
    consistency: float                       # required, range(0.0 <= value <= 1.0), arbiter.consistency — consistency score in range [0.0, 1.0].
    trust_score: float                       # required, range(0.0 <= value <= 1.0), arbiter.trust.score — raw trust score used for all policy calculations. Trust is earned, computed from ledger.
    trust_tier: TrustTier                    # required, arbiter.trust.tier — display tier only, never used in policy calculations.
    authority_domains: StringList            # required, arbiter.authority.domains — declared authority domains. Authority is declared, distinct from trust.
    taint_detected: bool                     # required, arbiter.taint.detected — whether taint propagation was detected.
    blast_tier: BlastTier                    # required, arbiter.blast.tier — blast radius classification tier.
    conflict: str                            # required, arbiter.conflict — conflict description if detected, empty string if no conflict.

class EnrichedSpan:
    """Composition of ParsedSpan + ArbiterEnrichment. This is the final output of the subscriber pipeline, ready for downstream consumers. Composition over inheritance per project standards."""
    span: ParsedSpan                         # required, The original parsed and validated Baton span.
    enrichment: ArbiterEnrichment            # required, All 9 arbiter.* enrichment attributes computed by the analyzer pipeline.
    enriched_at_unix_nano: int               # required, Timestamp when enrichment completed, nanoseconds since Unix epoch (UTC).
    analyzer_errors: AnalyzerErrorList = []  # optional, Errors from individual analyzers that failed. Enrichment still produced with defaults for failed analyzers.

class AnalyzerError:
    """Record of a single analyzer failure during dispatch. Failure isolation: one analyzer failure does not block others."""
    analyzer_kind: AnalyzerKind              # required, Which analyzer failed.
    error_type: str                          # required, Exception class name.
    error_message: str                       # required, Error detail including specific node/field/domain per project standards.
    span_id: SpanId                          # required, SpanId of the span that caused the failure.
    node_id: str                             # required, Baton node ID from the span for error context.

AnalyzerErrorList = list[AnalyzerError]
# List of AnalyzerError.

ParsedSpanList = list[ParsedSpan]
# List of ParsedSpan.

EnrichedSpanList = list[EnrichedSpan]
# List of EnrichedSpan.

class ExportResult:
    """Result of processing an ExportTraceServiceRequest batch. Maps to ExportTraceServiceResponse partial_success semantics: never reject entire batches."""
    accepted_count: int                      # required, Number of spans successfully parsed, enriched, and dispatched.
    rejected_count: int                      # required, Number of spans rejected due to validation errors (not warnings).
    enriched_spans: EnrichedSpanList         # required, Successfully enriched spans.
    validation_issues: ValidationIssueList   # required, All validation issues (warnings and errors) across the batch.
    partial_success_message: str = None      # optional, Human-readable summary for ExportTraceServiceResponse.partial_success.error_message.

class BufferStats:
    """Metrics snapshot from the ExecutionCorrelationBuffer for observability."""
    current_size: int                        # required, Number of ExecutionId keys currently in the buffer.
    total_spans: int                         # required, Total number of ParsedSpan instances across all buffer entries.
    max_size: int                            # required, Configured maximum number of keys.
    total_evictions: int                     # required, Cumulative count of keys evicted since buffer creation.
    total_window_misses: int                 # required, Cumulative count of lookups that found an execution ID but all its spans had expired.
    oldest_entry_age_seconds: OptionalFloat = None # optional, Age of oldest entry in seconds. None if buffer is empty.

AnalysisResultList = list[AnalysisResult]
# List of AnalysisResult from all dispatched analyzers.

def load_config(
    config_path: str,
) -> OtlpSubscriberConfig:
    """
    Load OtlpSubscriberConfig from a YAML file via pathlib. Validates all fields via Pydantic. Returns default config if path does not exist or is empty.

    Preconditions:
      - config_path is a non-empty string

    Postconditions:
      - Returned config has all fields populated (defaults applied where not specified in YAML)
      - All validator constraints are satisfied on the returned config

    Errors:
      - invalid_yaml (ConfigLoadError): File exists but contains invalid YAML syntax
          includes: file path and parse error detail
      - validation_failure (ConfigValidationError): YAML parses but field values fail Pydantic validation
          includes: specific field name and constraint that failed
      - permission_denied (ConfigLoadError): File exists but is not readable
          includes: file path and OS error

    Side effects: none
    Idempotent: yes
    """
    ...

def start(
    config: OtlpSubscriberConfig,
    analyzers: AnalyzerRegistration,
) -> None:
    """
    Start the gRPC server, correlation buffer eviction daemon, and begin accepting OTLP span exports. Binds to configured address:port. Transitions status from NOT_STARTED or STOPPED to SERVING. Registers TraceServiceServicer and gRPC health checking service. Target: accepting connections in under 3 seconds.

    Preconditions:
      - Server status is NOT_STARTED or STOPPED
      - analyzers contains all 4 AnalyzerKind entries (CONSISTENCY, ACCESS, TAINT, CONFLICT)
      - config has passed Pydantic validation

    Postconditions:
      - gRPC server is listening on config.bind_address:config.port
      - Server status is SERVING
      - gRPC health check reports SERVING
      - Correlation buffer eviction daemon thread is running
      - ThreadPoolExecutor has config.max_workers threads

    Errors:
      - port_in_use (ServerStartError): Configured port is already bound by another process
          includes: port number and bind address
      - already_running (ServerLifecycleError): Server status is STARTING or SERVING
          includes: current server status
      - missing_analyzer (ConfigValidationError): One or more of the 4 required AnalyzerKind entries is missing from analyzers
          includes: list of missing AnalyzerKind values
      - bind_failure (ServerStartError): Cannot bind to specified address (e.g. invalid address, permission denied)
          includes: bind_address, port, and OS error detail

    Side effects: none
    Idempotent: no
    """
    ...

def stop(
    grace: OptionalFloat = None,
) -> None:
    """
    Gracefully stop the gRPC server. Drains correlation buffer, waits for in-flight RPCs up to grace period, then forces shutdown. Transitions status to STOPPED.

    Preconditions:
      - Server status is SERVING or STARTING

    Postconditions:
      - Server status is STOPPED
      - gRPC server is no longer accepting connections
      - ThreadPoolExecutor is shut down
      - Correlation buffer eviction daemon has stopped
      - All buffered spans have been drained (best-effort)

    Errors:
      - not_running (ServerLifecycleError): Server status is NOT_STARTED or STOPPED
          includes: current server status
      - shutdown_timeout (ShutdownTimeoutWarning): In-flight RPCs did not complete within grace period
          includes: number of in-flight RPCs, grace period seconds

    Side effects: none
    Idempotent: no
    """
    ...

def is_ready() -> bool:
    """
    Check whether the subscriber is ready to accept spans. Returns true only when server status is SERVING and all 4 analyzers are registered.

    Postconditions:
      - Return value is true if and only if server status is SERVING and all 4 analyzers are registered

    Side effects: none
    Idempotent: yes
    """
    ...

def get_server_status() -> ServerStatus:
    """
    Return the current ServerStatus of the gRPC server.

    Postconditions:
      - Returned status reflects the actual current lifecycle state

    Side effects: none
    Idempotent: yes
    """
    ...

def parse_and_validate_spans(
    raw_spans: list,
    resource_attributes: SpanAttributeList = [],
) -> ParseValidationResult:
    """
    Anti-corruption layer: convert raw protobuf span data (represented as list of dicts from OTLP deserialization) into validated ParsedSpan domain models. Performs BatonSpanContract schema validation. Logs structured warnings for unexpected/missing attributes with specific node, field, domain. Does not crash on validation warnings — only validation errors cause span rejection. Handles protobuf default-value ambiguity (0/empty != unset).

    Preconditions:
      - raw_spans is a list (may be empty)

    Postconditions:
      - Every span in parsed_spans has passed BatonSpanContract validation (possibly with warnings)
      - Every span in rejected_spans has at least one ERROR-severity ValidationIssue
      - parsed_spans.length + rejected_count == raw_spans.length
      - All timestamps in parsed spans are positive (not protobuf default 0)
      - duration_ns == end_time_unix_nano - start_time_unix_nano for every parsed span
      - received_at_unix_nano is set to current UTC time at parse boundary

    Errors:
      - malformed_protobuf (SpanParseError): A raw span dict is structurally invalid (not a dict, missing required top-level keys)
          includes: index in batch, available keys
      - trace_id_invalid (SpanValidationError): trace_id is not 32 hex chars or is all zeros
          includes: raw trace_id value, span index
      - span_id_invalid (SpanValidationError): span_id is not 16 hex chars or is all zeros
          includes: raw span_id value, span index
      - missing_baton_node_id (SpanValidationError): Required baton.node_id attribute is absent from span
          includes: span_id, available attribute keys
      - missing_baton_execution_id (SpanValidationError): Required baton.execution_id attribute is absent from span
          includes: span_id, node_id if available
      - timestamp_zero (SpanValidationError): start_time_unix_nano or end_time_unix_nano is 0 (protobuf default, not explicitly set)
          includes: span_id, which timestamp field is zero

    Side effects: none
    Idempotent: no
    """
    ...

def dispatch_to_analyzers(
    span: ParsedSpan,
) -> AnalysisResultList:
    """
    Dispatch a ParsedSpan to all 4 registered analyzers (consistency, access, taint, conflict) with failure isolation. Each analyzer is invoked independently; if one throws an exception, it is caught, logged, and processing continues with the remaining analyzers. Returns aggregated AnalysisResult list.

    Preconditions:
      - All 4 analyzers are registered (CONSISTENCY, ACCESS, TAINT, CONFLICT)
      - span has passed validation (is a valid ParsedSpan)

    Postconditions:
      - Returned list has exactly 4 entries, one per AnalyzerKind
      - For each analyzer that threw an exception: success=false, error_message populated with node/field detail
      - For each analyzer that completed: success=true, relevant fields populated
      - No exception is propagated to caller — all failures are captured in results

    Side effects: none
    Idempotent: no
    """
    ...

def aggregate_enrichment(
    results: AnalysisResultList,
) -> ArbiterEnrichment:
    """
    Aggregate AnalysisResult instances from all 4 analyzers into a single ArbiterEnrichment (frozen Pydantic model). Applies defaults for any analyzer that failed. Enrichment is always produced even if some analyzers errored.

    Preconditions:
      - results has exactly 4 entries
      - Each AnalyzerKind appears exactly once in results

    Postconditions:
      - All 9 arbiter.* attributes are populated
      - consistency is in [0.0, 1.0]
      - trust_score is in [0.0, 1.0]
      - trust_tier is for display only — reflects trust_score but is never used in policy
      - For failed analyzers: corresponding fields have safe defaults (0.0 for scores, UNKNOWN for tiers, empty for strings, false for booleans)

    Errors:
      - wrong_result_count (EnrichmentAggregationError): results does not have exactly 4 entries
          includes: actual count, expected 4
      - duplicate_analyzer_kind (EnrichmentAggregationError): Two or more results have the same AnalyzerKind
          includes: duplicated AnalyzerKind value

    Side effects: none
    Idempotent: yes
    """
    ...

def build_enriched_span(
    span: ParsedSpan,
    enrichment: ArbiterEnrichment,
    analyzer_errors: AnalyzerErrorList = [],
) -> EnrichedSpan:
    """
    Compose a ParsedSpan and ArbiterEnrichment into an EnrichedSpan. Records enrichment timestamp and any analyzer errors. Pure function — no side effects.

    Postconditions:
      - enriched_span.span is the input span (identity)
      - enriched_span.enrichment is the input enrichment (identity)
      - enriched_span.enriched_at_unix_nano is set to current UTC time
      - enriched_span.analyzer_errors matches input analyzer_errors

    Side effects: none
    Idempotent: yes
    """
    ...

def handle_export_request(
    raw_spans: list,
    resource_attributes: SpanAttributeList = [],
) -> ExportResult:
    """
    Top-level handler for ExportTraceServiceRequest. Orchestrates the full pipeline: parse → buffer → dispatch → aggregate → enrich. Returns ExportResult with partial_success semantics — never rejects entire batches. This is the entry point called by the gRPC TraceServiceServicer.Export method.

    Preconditions:
      - Server status is SERVING
      - All 4 analyzers are registered

    Postconditions:
      - accepted_count + rejected_count == len(raw_spans)
      - Each accepted span is enriched with all 9 arbiter.* attributes
      - Each accepted span has been added to the correlation buffer
      - Each accepted span has been dispatched to all 4 analyzers
      - Partial success: if some spans fail validation, remaining spans are still processed
      - validation_issues contains all issues across the batch (warnings and errors)

    Errors:
      - server_not_ready (ServerNotReadyError): Server status is not SERVING
          includes: current server status
      - batch_too_large (BatchSizeExceededError): raw_spans length exceeds config.max_batch_size
          includes: actual size, max_batch_size — excess spans are rejected, rest processed
      - empty_batch (EmptyBatchWarning): raw_spans is empty
          includes: warning only, returns ExportResult with zero counts

    Side effects: none
    Idempotent: no
    """
    ...

def buffer_add(
    span: ParsedSpan,
) -> None:
    """
    Add a parsed span to the ExecutionCorrelationBuffer, keyed by its baton_execution_id. Thread-safe via threading.Lock. Triggers lazy eviction if buffer exceeds max_size.

    Preconditions:
      - span.baton_execution_id is a non-empty string

    Postconditions:
      - Span is retrievable via buffer_get(span.baton_execution_id) until evicted
      - If buffer_max_size was exceeded, at least one expired or oldest entry was evicted
      - Buffer size metrics are updated

    Errors:
      - buffer_full_no_evictable (BufferCapacityError): Buffer is at max_size and no entries are eligible for eviction (all within window)
          includes: current size, max_size, oldest entry age

    Side effects: none
    Idempotent: no
    """
    ...

def buffer_get(
    execution_id: ExecutionId,
) -> ParsedSpanList:
    """
    Retrieve all buffered spans for a given execution ID from the correlation buffer. Thread-safe. Returns empty list if execution ID not found or all spans expired.

    Preconditions:
      - execution_id is a non-empty string

    Postconditions:
      - Returned list contains only spans within the configured window_duration_seconds
      - Returned list is ordered by received_at_unix_nano ascending
      - If execution_id not in buffer, returns empty list
      - Window miss metric incremented if key exists but all spans expired

    Side effects: none
    Idempotent: yes
    """
    ...

def buffer_get_stats() -> BufferStats:
    """
    Return a snapshot of correlation buffer metrics for observability.

    Postconditions:
      - Returned stats reflect buffer state at time of call
      - current_size <= max_size

    Side effects: none
    Idempotent: yes
    """
    ...

def buffer_drain() -> ParsedSpanList:
    """
    Drain all entries from the correlation buffer. Called during graceful shutdown. Returns all buffered spans for final processing.

    Postconditions:
      - Buffer is empty after drain
      - All previously buffered spans are in the returned list
      - Buffer stats show current_size == 0

    Side effects: none
    Idempotent: no
    """
    ...

def buffer_evict_expired() -> int:
    """
    Evict all buffer entries whose spans have all aged past window_duration_seconds. Called lazily on insert and periodically by the daemon sweep thread. Thread-safe.

    Postconditions:
      - All entries where every span is older than window_duration_seconds have been removed
      - total_evictions metric incremented by returned count
      - Returned int is the number of execution_id keys evicted

    Side effects: none
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['TrustTier', 'BlastTier', 'AnalyzerKind', 'ServerStatus', 'ValidationSeverity', 'OtlpSubscriberConfig', 'SpanAttribute', 'SpanLink', 'SpanEvent', 'SpanAttributeList', 'SpanLinkList', 'SpanEventList', 'ValidationIssue', 'ValidationIssueList', 'BatonSpanContract', 'OptionalSpanId', 'ParsedSpan', 'AnalysisResult', 'OptionalFloat', 'OptionalBool', 'OptionalTrustTier', 'OptionalBlastTier', 'StringList', 'ArbiterEnrichment', 'EnrichedSpan', 'AnalyzerError', 'AnalyzerErrorList', 'ParsedSpanList', 'EnrichedSpanList', 'ExportResult', 'BufferStats', 'AnalysisResultList', 'load_config', 'ConfigLoadError', 'ConfigValidationError', 'start', 'ServerStartError', 'ServerLifecycleError', 'stop', 'ShutdownTimeoutWarning', 'is_ready', 'get_server_status', 'parse_and_validate_spans', 'SpanParseError', 'SpanValidationError', 'dispatch_to_analyzers', 'aggregate_enrichment', 'EnrichmentAggregationError', 'build_enriched_span', 'handle_export_request', 'ServerNotReadyError', 'BatchSizeExceededError', 'EmptyBatchWarning', 'buffer_add', 'BufferCapacityError', 'buffer_get', 'buffer_get_stats', 'buffer_drain', 'buffer_evict_expired']
