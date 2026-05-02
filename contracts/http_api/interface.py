# === HTTP API Server (http_api) v1 ===
#  Dependencies: trust_ledger, blast_radius_engine, trust_engine, authority_engine, canary_engine, report_engine, findings_engine, field_classifier
# JSON HTTP API on configured port (default 7700). Provides endpoints for access graph registration, blast radius computation, trust score queries, taint reset, authority mapping, canary injection/results, full feedback reports, and OTLP findings ingestion. Uses Flask as the HTTP framework (justified exception to stdlib preference: manual routing on http.server would exceed 300 lines and introduce bugs in request parsing, content negotiation, and error handling). All responses are JSON with Content-Type: application/json. Error responses use a machine-readable ErrorResponse envelope with StrEnum error codes. The HTTP layer is strictly a translation layer — zero business logic — delegating all computation to engine Protocol interfaces injected via a ServerContext. Three-module structure: server.py (app factory, routes, startup/shutdown), models.py (Pydantic v2 request/response models), errors.py (ErrorCode enum, global error handlers, ValidationError translation).

# Module invariants:
#   - All HTTP responses have Content-Type: application/json
#   - All error responses conform to the ErrorResponse schema with a machine-readable error_code from ErrorCode enum
#   - Zero business logic in the HTTP layer — all computation delegated to engine Protocol interfaces
#   - No endpoint exposes ledger mutation (edit/delete); only append operations via reset-taint
#   - All datetime fields are UTC with ISO 8601 serialization
#   - Error messages always include the specific node_id, field, run_id, or domain that caused the error
#   - Trust and authority response types are never shared or conflated
#   - All policy calculations use raw trust score (float), never display tiers for computation
#   - The trust ledger is append-only — reset-taint appends a reset event, never mutates existing entries
#   - Server binds to configured port (default 7700) and serves synchronously with threading

NodeId = primitive  # Type-safe string identifier for a node in the access graph. NewType over str.

RunId = primitive  # Type-safe string identifier for a canary or report run. NewType over str.

ReviewId = primitive  # Type-safe string identifier for a review that authorizes taint reset. NewType over str.

TrustScore = primitive  # Float in [0.0, 1.0] representing raw computed trust. Annotated[float, Field(ge=0.0, le=1.0)].

class ErrorCode(Enum):
    """Machine-readable error codes returned in all error responses. StrEnum."""
    INVALID_JSON = "INVALID_JSON"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NODE_NOT_FOUND = "NODE_NOT_FOUND"
    RUN_NOT_FOUND = "RUN_NOT_FOUND"
    REVIEW_NOT_FOUND = "REVIEW_NOT_FOUND"
    ACCESS_GRAPH_INVALID = "ACCESS_GRAPH_INVALID"
    BLAST_RADIUS_FAILED = "BLAST_RADIUS_FAILED"
    TRUST_COMPUTATION_FAILED = "TRUST_COMPUTATION_FAILED"
    TAINT_RESET_FAILED = "TAINT_RESET_FAILED"
    AUTHORITY_UNAVAILABLE = "AUTHORITY_UNAVAILABLE"
    CANARY_INJECTION_FAILED = "CANARY_INJECTION_FAILED"
    CANARY_RESULTS_UNAVAILABLE = "CANARY_RESULTS_UNAVAILABLE"
    REPORT_NOT_FOUND = "REPORT_NOT_FOUND"
    FINDINGS_INGESTION_FAILED = "FINDINGS_INGESTION_FAILED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    CONTENT_TYPE_UNSUPPORTED = "CONTENT_TYPE_UNSUPPORTED"

class TrustTier(Enum):
    """Display tier derived from raw trust score. Used only for display, never for policy calculations. StrEnum."""
    FULL = "FULL"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    LOW = "LOW"
    NONE = "NONE"
    TAINTED = "TAINTED"

class DataClassificationTier(Enum):
    """Classification tier for data sensitivity. StrEnum."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

class FindingSeverity(Enum):
    """Severity level for findings reported via OTLP adapter. StrEnum."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ErrorResponse:
    """Standard error envelope for all HTTP error responses."""
    error_code: ErrorCode                    # required, Machine-readable error code from ErrorCode enum.
    message: str                             # required, Human-readable error message including the specific node, field, or domain that caused the error.
    details: dict = {}                       # optional, Optional additional structured error context (e.g., field names, validation errors).

class ServerConfig:
    """Configuration for the HTTP API server. Loaded from YAML config file."""
    host: str                                # required, Bind address for the HTTP server.
    port: int                                # required, range(1 <= value <= 65535), Port number for the HTTP server.
    debug: bool                              # required, Enable Flask debug mode. Must be false in production.
    max_request_size_bytes: int              # required, range(1024 <= value <= 104857600), Maximum request body size in bytes (default 10MB).

class ServerContext:
    """Dependency injection container holding references to all engine Protocol instances. Passed to the Flask app factory to wire routes to engines. Composition over inheritance."""
    config: ServerConfig                     # required, Server configuration.
    trust_engine: any                        # required, Protocol-typed trust engine instance for score queries and taint reset.
    blast_radius_engine: any                 # required, Protocol-typed blast radius computation engine.
    authority_engine: any                    # required, Protocol-typed authority map engine.
    canary_engine: any                       # required, Protocol-typed canary injection and results engine.
    report_engine: any                       # required, Protocol-typed report generation engine.
    findings_engine: any                     # required, Protocol-typed OTLP findings ingestion engine.

class AccessGraphPayload:
    """Request body for POST /register — an access graph in JSON form."""
    nodes: AccessGraphNodeList               # required, List of nodes in the access graph.
    edges: AccessGraphEdgeList               # required, List of edges (access relationships) in the access graph.
    metadata: dict = {}                      # optional, Optional metadata about the access graph source.

class AccessGraphNode:
    """A single node in the access graph."""
    node_id: NodeId                          # required, Unique identifier for this node.
    node_type: str                           # required, Type of node (e.g., service, database, user, role).
    labels: dict = {}                        # optional, Key-value labels for the node.

AccessGraphNodeList = list[AccessGraphNode]
# List of access graph nodes.

class AccessGraphEdge:
    """A directed edge representing an access relationship between two nodes."""
    source: NodeId                           # required, Source node of the access relationship.
    target: NodeId                           # required, Target node of the access relationship.
    access_type: str                         # required, Type of access (e.g., read, write, admin).
    classification: DataClassificationTier = INTERNAL # optional, Data classification tier for this edge.

AccessGraphEdgeList = list[AccessGraphEdge]
# List of access graph edges.

class RegisterResponse:
    """Response body for POST /register."""
    node_count: int                          # required, Number of nodes ingested.
    edge_count: int                          # required, Number of edges ingested.
    registered_at: str                       # required, ISO 8601 UTC timestamp of registration.

class BlastRadiusRequest:
    """Request body for POST /blast-radius."""
    node_id: NodeId                          # required, Starting node for blast radius computation.
    max_depth: int = 10                      # optional, range(1 <= value <= 100), Maximum BFS/DFS traversal depth.
    classification_filter: DataClassificationTier = None # optional, If set, only include edges at or above this classification tier.

class BlastRadiusNode:
    """A node in the blast radius result with its distance from the origin."""
    node_id: NodeId                          # required, Node identifier.
    node_type: str                           # required, Type of node.
    depth: int                               # required, BFS distance from the origin node.
    max_classification: DataClassificationTier # required, Highest data classification tier on the path to this node.
    trust_score: TrustScore                  # required, Current raw trust score for this node.

BlastRadiusNodeList = list[BlastRadiusNode]
# List of nodes in the blast radius.

class BlastRadiusResponse:
    """Response body for POST /blast-radius."""
    origin_node_id: NodeId                   # required, The starting node of the blast radius computation.
    affected_nodes: BlastRadiusNodeList      # required, List of nodes within the blast radius.
    total_affected: int                      # required, Total number of affected nodes.
    max_depth_reached: int                   # required, Maximum depth actually reached during traversal.
    computed_at: str                         # required, ISO 8601 UTC timestamp of computation.

class LedgerEvent:
    """A single trust ledger event. Append-only, never mutated."""
    event_id: str                            # required, Unique identifier for this ledger event.
    node_id: NodeId                          # required, Node this event pertains to.
    event_type: str                          # required, Type of ledger event (e.g., score_update, taint_set, taint_reset).
    trust_score: TrustScore                  # required, Trust score at the time of this event.
    timestamp: str                           # required, ISO 8601 UTC timestamp of the event.
    details: dict = {}                       # optional, Additional event-specific data.

LedgerEventList = list[LedgerEvent]
# List of ledger events.

class TrustResponse:
    """Response body for GET /trust/<node_id>."""
    node_id: NodeId                          # required, The queried node identifier.
    trust_score: TrustScore                  # required, Current raw trust score for this node.
    trust_tier: TrustTier                    # required, Display-only tier derived from trust score. Not used for policy calculations.
    is_tainted: bool                         # required, Whether the node currently has a taint lock.
    recent_events: LedgerEventList           # required, Last 20 ledger events for this node, most recent first.
    queried_at: str                          # required, ISO 8601 UTC timestamp of the query.

class TaintResetRequest:
    """Request body for POST /trust/reset-taint."""
    node_id: NodeId                          # required, Node to clear taint lock on.
    review_id: ReviewId                      # required, Identifier of the review authorizing this reset.
    reason: str                              # required, length(1 <= len(value) <= 2000), Human-readable justification for clearing taint.

class TaintResetResponse:
    """Response body for POST /trust/reset-taint."""
    node_id: NodeId                          # required, The node whose taint was reset.
    review_id: ReviewId                      # required, The review_id that authorized the reset.
    previous_trust_score: TrustScore         # required, Trust score before taint reset.
    new_trust_score: TrustScore              # required, Trust score after taint reset.
    ledger_event_id: str                     # required, The event_id of the appended taint_reset ledger event.
    reset_at: str                            # required, ISO 8601 UTC timestamp of the reset.

class AuthorityEntry:
    """A single entry in the authority map. Authority is declared (from manifests), not computed."""
    node_id: NodeId                          # required, Node identifier.
    authority_source: str                    # required, Source manifest or declaration that grants authority.
    granted_permissions: GrantedPermissionsList # required, Permissions granted by this authority declaration.
    declared_at: str                         # required, ISO 8601 UTC timestamp when authority was declared.

GrantedPermissionsList = list[str]
# List of granted permission strings.

AuthorityEntryList = list[AuthorityEntry]
# List of authority entries.

class AuthorityResponse:
    """Response body for GET /authority."""
    entries: AuthorityEntryList              # required, Full authority map.
    total_entries: int                       # required, Total number of authority entries.
    queried_at: str                          # required, ISO 8601 UTC timestamp of the query.

class CanaryInjectRequest:
    """Request body for POST /canary/inject."""
    run_id: RunId                            # required, Unique identifier for this canary injection run.
    target_tiers: CanaryTargetTierList       # required, Data classification tiers to seed canaries into.
    canary_count: int                        # required, range(1 <= value <= 1000), Number of canary records to inject per tier.

CanaryTargetTierList = list[DataClassificationTier]
# List of data classification tiers for canary targeting.

class CanaryInjectResponse:
    """Response body for POST /canary/inject."""
    run_id: RunId                            # required, The run identifier for this injection.
    injected_count: int                      # required, Total number of canaries injected.
    tiers_seeded: CanaryTargetTierList       # required, Tiers that were actually seeded.
    injected_at: str                         # required, ISO 8601 UTC timestamp of injection.

class CanaryEscapeEvent:
    """A detected canary escape — a canary fingerprint observed outside its expected tier."""
    canary_id: str                           # required, Unique identifier of the escaped canary.
    expected_tier: DataClassificationTier    # required, Tier the canary was injected into.
    observed_tier: DataClassificationTier    # required, Tier where the canary was observed.
    observed_node_id: NodeId                 # required, Node where the escape was detected.
    detected_at: str                         # required, ISO 8601 UTC timestamp of detection.

CanaryEscapeEventList = list[CanaryEscapeEvent]
# List of canary escape events.

class CanaryResultsResponse:
    """Response body for GET /canary/results/<run_id>."""
    run_id: RunId                            # required, The queried run identifier.
    status: str                              # required, Run status (e.g., 'pending', 'complete', 'partial').
    total_injected: int                      # required, Total canaries injected in this run.
    total_escaped: int                       # required, Number of canaries that escaped their tier.
    escapes: CanaryEscapeEventList           # required, Detailed list of escape events.
    queried_at: str                          # required, ISO 8601 UTC timestamp of the query.

class Finding:
    """A single finding from the OTLP adapter (Baton). Adapter layer is ground truth."""
    finding_id: str                          # required, Unique identifier for this finding.
    node_id: NodeId                          # required, Node this finding pertains to.
    severity: FindingSeverity                # required, Severity of the finding.
    category: str                            # required, Category of finding (e.g., 'access_anomaly', 'policy_violation').
    message: str                             # required, Human-readable finding description.
    span_context: dict = {}                  # optional, OTLP span context data (trace_id, span_id, etc.).
    timestamp: str                           # required, ISO 8601 UTC timestamp of the finding.

FindingsList = list[Finding]
# List of findings.

class FindingsRequest:
    """Request body for POST /findings."""
    findings: FindingsList                   # required, List of findings to ingest.
    source: str                              # required, Source adapter identifier (e.g., 'baton-adapter-v1').

class FindingsResponse:
    """Response body for POST /findings."""
    accepted_count: int                      # required, Number of findings accepted.
    rejected_count: int                      # required, Number of findings rejected (e.g., duplicate, malformed).
    ingested_at: str                         # required, ISO 8601 UTC timestamp of ingestion.

class ReportResponse:
    """Response body for GET /report/<run_id>. Full feedback report for a run."""
    run_id: RunId                            # required, The queried run identifier.
    status: str                              # required, Report status (e.g., 'complete', 'in_progress').
    trust_summary: dict                      # required, Summary of trust scores across the run.
    findings_summary: dict                   # required, Summary of findings by severity and category.
    canary_summary: dict                     # required, Summary of canary escape results if applicable.
    blast_radius_summary: dict               # required, Summary of blast radius computations if applicable.
    generated_at: str                        # required, ISO 8601 UTC timestamp of report generation.

class HealthResponse:
    """Response body for GET /health — server health and readiness."""
    status: str                              # required, Health status ('ok' or 'degraded').
    version: str                             # required, Server version string.
    uptime_seconds: float                    # required, Seconds since server started.
    engines_ready: bool                      # required, Whether all engine dependencies are initialized.

def create_app(
    context: ServerContext,
) -> any:
    """
    Flask app factory. Creates and configures the Flask application, registers all route blueprints, wires engine dependencies from the ServerContext, and registers global error handlers. Returns a configured Flask app ready to serve.

    Preconditions:
      - context.config is a valid ServerConfig with port in [1, 65535]
      - All engine references in context are non-None and implement their respective Protocol interfaces
      - No Flask app has been created from this context yet (single app per context)

    Postconditions:
      - Returned Flask app has all 10 routes registered (9 endpoints + /health)
      - Global error handlers are registered for ValidationError, domain exceptions, and unexpected exceptions
      - Content-Type defaults to application/json for all responses
      - App is not yet running (caller must invoke run_server or app.run)

    Errors:
      - missing_engine (ValueError): One or more engine references in context is None
          detail: All engine Protocol instances must be provided in ServerContext
      - invalid_config (ValidationError): ServerConfig fails Pydantic validation
          detail: ServerConfig validation failed

    Side effects: none
    Idempotent: no
    """
    ...

def run_server(
    context: ServerContext,
) -> None:
    """
    Start the HTTP server on the configured host and port. Blocks the calling thread. Uses Flask's built-in threaded server (appropriate for sidecar use case, not production internet-facing).

    Preconditions:
      - context.config.port is available and not already bound
      - All engines are initialized and ready

    Postconditions:
      - Server was listening on context.config.host:context.config.port until shutdown
      - All open connections are closed on return

    Errors:
      - port_in_use (OSError): The configured port is already bound by another process
          detail: Port already in use
      - startup_timeout (TimeoutError): Server fails to bind within 3 seconds
          detail: Cold start exceeded 3-second target

    Side effects: none
    Idempotent: no
    """
    ...

def handle_register(
    request_body: AccessGraphPayload,
) -> RegisterResponse:
    """
    POST /register — Ingest an access_graph.json payload. Validates the AccessGraphPayload, delegates to the blast_radius_engine for graph storage, returns node/edge counts and registration timestamp.

    Preconditions:
      - request_body has been deserialized and validated as AccessGraphPayload
      - All node_ids referenced in edges exist in the nodes list
      - No duplicate node_ids in the nodes list

    Postconditions:
      - Access graph is stored and available for blast radius queries
      - RegisterResponse.node_count == len(request_body.nodes)
      - RegisterResponse.edge_count == len(request_body.edges)
      - RegisterResponse.registered_at is a valid ISO 8601 UTC timestamp

    Errors:
      - invalid_json (ErrorResponse): Request body is not valid JSON
          error_code: INVALID_JSON
          http_status: 400
      - validation_error (ErrorResponse): Request body fails Pydantic model validation
          error_code: VALIDATION_ERROR
          http_status: 400
      - graph_invalid (ErrorResponse): Edges reference node_ids not present in nodes list, or duplicate node_ids found
          error_code: ACCESS_GRAPH_INVALID
          http_status: 422
      - engine_failure (ErrorResponse): Blast radius engine raises an unexpected exception during graph storage
          error_code: INTERNAL_ERROR
          http_status: 500

    Side effects: none
    Idempotent: yes
    """
    ...

def handle_blast_radius(
    request_body: BlastRadiusRequest,
) -> BlastRadiusResponse:
    """
    POST /blast-radius — Compute the blast radius from a given node. Validates the BlastRadiusRequest, delegates to blast_radius_engine for BFS/DFS traversal, returns affected nodes with depth and classification data.

    Preconditions:
      - An access graph has been registered via POST /register
      - request_body.node_id exists in the registered access graph

    Postconditions:
      - BlastRadiusResponse.origin_node_id == request_body.node_id
      - All affected nodes are reachable from origin within max_depth hops
      - BlastRadiusResponse.total_affected == len(BlastRadiusResponse.affected_nodes)
      - BlastRadiusResponse.max_depth_reached <= request_body.max_depth
      - BlastRadiusResponse.computed_at is a valid ISO 8601 UTC timestamp

    Errors:
      - invalid_json (ErrorResponse): Request body is not valid JSON
          error_code: INVALID_JSON
          http_status: 400
      - validation_error (ErrorResponse): Request body fails Pydantic model validation
          error_code: VALIDATION_ERROR
          http_status: 400
      - node_not_found (ErrorResponse): request_body.node_id is not in the registered access graph
          error_code: NODE_NOT_FOUND
          http_status: 404
      - computation_failed (ErrorResponse): Blast radius engine raises an error during traversal
          error_code: BLAST_RADIUS_FAILED
          http_status: 500

    Side effects: none
    Idempotent: yes
    """
    ...

def handle_get_trust(
    node_id: NodeId,
) -> TrustResponse:
    """
    GET /trust/<node_id> — Retrieve the current trust score, display tier, taint status, and last 20 ledger events for a node. Delegates to trust_engine.

    Preconditions:
      - node_id is a non-empty string

    Postconditions:
      - TrustResponse.node_id == node_id
      - TrustResponse.trust_score is in [0.0, 1.0]
      - TrustResponse.recent_events has at most 20 entries, ordered most recent first
      - TrustResponse.trust_tier is derived from trust_score for display only
      - TrustResponse.queried_at is a valid ISO 8601 UTC timestamp

    Errors:
      - node_not_found (ErrorResponse): node_id is not known to the trust engine
          error_code: NODE_NOT_FOUND
          http_status: 404
      - trust_computation_failed (ErrorResponse): Trust engine raises an error during score computation
          error_code: TRUST_COMPUTATION_FAILED
          http_status: 500

    Side effects: none
    Idempotent: yes
    """
    ...

def handle_reset_taint(
    request_body: TaintResetRequest,
) -> TaintResetResponse:
    """
    POST /trust/reset-taint — Clear taint lock on a node with a review_id. Appends a taint_reset event to the ledger (never mutates existing entries). Delegates to trust_engine.

    Preconditions:
      - request_body.node_id exists in the trust engine
      - request_body.node_id currently has a taint lock
      - request_body.review_id is a valid, non-empty review identifier
      - request_body.reason is between 1 and 2000 characters

    Postconditions:
      - A new taint_reset event has been appended to the trust ledger (append-only, no mutations)
      - The node's taint lock is cleared
      - TaintResetResponse.ledger_event_id is the ID of the newly appended event
      - TaintResetResponse.new_trust_score reflects the score after taint reset
      - TaintResetResponse.reset_at is a valid ISO 8601 UTC timestamp

    Errors:
      - invalid_json (ErrorResponse): Request body is not valid JSON
          error_code: INVALID_JSON
          http_status: 400
      - validation_error (ErrorResponse): Request body fails Pydantic model validation
          error_code: VALIDATION_ERROR
          http_status: 400
      - node_not_found (ErrorResponse): request_body.node_id is not known to the trust engine
          error_code: NODE_NOT_FOUND
          http_status: 404
      - review_not_found (ErrorResponse): request_body.review_id does not correspond to a valid review
          error_code: REVIEW_NOT_FOUND
          http_status: 404
      - taint_reset_failed (ErrorResponse): Trust engine fails during taint reset (e.g., node not tainted)
          error_code: TAINT_RESET_FAILED
          http_status: 409
      - ledger_write_failure (ErrorResponse): Ledger append fails due to I/O or checksum error
          error_code: INTERNAL_ERROR
          http_status: 500

    Side effects: none
    Idempotent: no
    """
    ...

def handle_get_authority() -> AuthorityResponse:
    """
    GET /authority — Retrieve the full authority map. Authority is declared from manifests, distinct from trust (which is computed from the ledger). Delegates to authority_engine.

    Postconditions:
      - AuthorityResponse.total_entries == len(AuthorityResponse.entries)
      - AuthorityResponse.queried_at is a valid ISO 8601 UTC timestamp
      - Authority entries reflect declared authority from manifests, not computed trust

    Errors:
      - authority_unavailable (ErrorResponse): Authority engine is not initialized or manifests not loaded
          error_code: AUTHORITY_UNAVAILABLE
          http_status: 503

    Side effects: none
    Idempotent: yes
    """
    ...

def handle_canary_inject(
    request_body: CanaryInjectRequest,
) -> CanaryInjectResponse:
    """
    POST /canary/inject — Seed a canary corpus into the system. Canary fingerprints are structurally valid for their tier, globally unique per run, and impossible in real data (UUIDs in domain-shaped strings). Delegates to canary_engine.

    Preconditions:
      - request_body.run_id is unique and has not been used before
      - request_body.target_tiers is non-empty
      - request_body.canary_count is between 1 and 1000

    Postconditions:
      - CanaryInjectResponse.run_id == request_body.run_id
      - CanaryInjectResponse.injected_count == request_body.canary_count * len(request_body.target_tiers)
      - All injected canaries are recognizable as synthetic (never plausible real data)
      - All injected canaries contain UUIDs in domain-shaped strings
      - CanaryInjectResponse.injected_at is a valid ISO 8601 UTC timestamp

    Errors:
      - invalid_json (ErrorResponse): Request body is not valid JSON
          error_code: INVALID_JSON
          http_status: 400
      - validation_error (ErrorResponse): Request body fails Pydantic model validation
          error_code: VALIDATION_ERROR
          http_status: 400
      - injection_failed (ErrorResponse): Canary engine fails during injection
          error_code: CANARY_INJECTION_FAILED
          http_status: 500

    Side effects: none
    Idempotent: no
    """
    ...

def handle_canary_results(
    run_id: RunId,
) -> CanaryResultsResponse:
    """
    GET /canary/results/<run_id> — Retrieve the taint escape report for a canary run. Shows which canaries escaped their expected tier. Delegates to canary_engine.

    Preconditions:
      - run_id is a non-empty string

    Postconditions:
      - CanaryResultsResponse.run_id == run_id
      - CanaryResultsResponse.total_escaped == len(CanaryResultsResponse.escapes)
      - CanaryResultsResponse.queried_at is a valid ISO 8601 UTC timestamp

    Errors:
      - run_not_found (ErrorResponse): run_id does not correspond to a known canary injection run
          error_code: RUN_NOT_FOUND
          http_status: 404
      - results_unavailable (ErrorResponse): Canary engine fails to compute or retrieve results
          error_code: CANARY_RESULTS_UNAVAILABLE
          http_status: 500

    Side effects: none
    Idempotent: yes
    """
    ...

def handle_get_report(
    run_id: RunId,
) -> ReportResponse:
    """
    GET /report/<run_id> — Retrieve the full feedback report for a given run. Includes trust summary, findings summary, canary summary, and blast radius summary. Delegates to report_engine.

    Preconditions:
      - run_id is a non-empty string

    Postconditions:
      - ReportResponse.run_id == run_id
      - ReportResponse.generated_at is a valid ISO 8601 UTC timestamp
      - Report reflects the state of all engines at query time

    Errors:
      - run_not_found (ErrorResponse): run_id does not correspond to any known run
          error_code: RUN_NOT_FOUND
          http_status: 404
      - report_not_found (ErrorResponse): Report generation fails or report data is unavailable
          error_code: REPORT_NOT_FOUND
          http_status: 404

    Side effects: none
    Idempotent: yes
    """
    ...

def handle_ingest_findings(
    request_body: FindingsRequest,
) -> FindingsResponse:
    """
    POST /findings — Receive OTLP span JSON from the Baton adapter. The adapter layer is ground truth; node self-reports are claims. Validates findings, delegates to findings_engine for processing and ledger updates.

    Preconditions:
      - request_body.findings is non-empty
      - request_body.source is a non-empty string identifying the adapter

    Postconditions:
      - FindingsResponse.accepted_count + FindingsResponse.rejected_count == len(request_body.findings)
      - Accepted findings have been persisted and may trigger trust score updates
      - FindingsResponse.ingested_at is a valid ISO 8601 UTC timestamp

    Errors:
      - invalid_json (ErrorResponse): Request body is not valid JSON
          error_code: INVALID_JSON
          http_status: 400
      - validation_error (ErrorResponse): Request body fails Pydantic model validation
          error_code: VALIDATION_ERROR
          http_status: 400
      - ingestion_failed (ErrorResponse): Findings engine raises an error during ingestion
          error_code: FINDINGS_INGESTION_FAILED
          http_status: 500

    Side effects: none
    Idempotent: no
    """
    ...

def handle_health() -> HealthResponse:
    """
    GET /health — Server health and readiness check. Returns status, version, uptime, and engine readiness. Used for cold start verification (target: ready in under 3 seconds).

    Postconditions:
      - HealthResponse.status is 'ok' or 'degraded'
      - HealthResponse.uptime_seconds >= 0
      - HealthResponse.engines_ready reflects actual engine initialization state

    Side effects: none
    Idempotent: yes
    """
    ...

def handle_error(
    exception: any,
) -> ErrorResponse:
    """
    Global error handler registered on the Flask app. Catches ValidationError (from Pydantic), known domain exceptions (NodeNotFound, RunNotFound, etc.), and unexpected exceptions. Transforms all exceptions into ErrorResponse JSON with appropriate HTTP status code, machine-readable error_code, and human-readable message including the specific entity that caused the error.

    Postconditions:
      - Returned ErrorResponse has a valid ErrorCode
      - ErrorResponse.message includes the specific node_id, field, run_id, or domain that caused the error
      - Malformed JSON bodies produce error_code INVALID_JSON with HTTP 400, not HTTP 500
      - Unexpected exceptions produce error_code INTERNAL_ERROR with HTTP 500
      - ValidationError produces error_code VALIDATION_ERROR with HTTP 400 and field-level details

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['ErrorCode', 'TrustTier', 'DataClassificationTier', 'FindingSeverity', 'ErrorResponse', 'ServerConfig', 'ServerContext', 'AccessGraphPayload', 'AccessGraphNode', 'AccessGraphNodeList', 'AccessGraphEdge', 'AccessGraphEdgeList', 'RegisterResponse', 'BlastRadiusRequest', 'BlastRadiusNode', 'BlastRadiusNodeList', 'BlastRadiusResponse', 'LedgerEvent', 'LedgerEventList', 'TrustResponse', 'TaintResetRequest', 'TaintResetResponse', 'AuthorityEntry', 'GrantedPermissionsList', 'AuthorityEntryList', 'AuthorityResponse', 'CanaryInjectRequest', 'CanaryTargetTierList', 'CanaryInjectResponse', 'CanaryEscapeEvent', 'CanaryEscapeEventList', 'CanaryResultsResponse', 'Finding', 'FindingsList', 'FindingsRequest', 'FindingsResponse', 'ReportResponse', 'HealthResponse', 'create_app', 'ValidationError', 'run_server', 'TimeoutError', 'handle_register', 'handle_blast_radius', 'handle_get_trust', 'handle_reset_taint', 'handle_get_authority', 'handle_canary_inject', 'handle_canary_results', 'handle_get_report', 'handle_ingest_findings', 'handle_health', 'handle_error']
