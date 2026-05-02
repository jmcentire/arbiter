# === CLI Entry Point (cli) v1 ===
#  Dependencies: trust_engine, authority_engine, blast_radius_engine, soak_engine, report_engine, canary_engine, findings_engine, conflicts_engine, registry, config, otlp_subscriber, http_api
# Click-based CLI surface for all arbiter commands. Thin adapter layer that validates inputs via custom ParamTypes, constructs Pydantic request models, delegates to engine functions, formats Pydantic response models, and outputs results with appropriate exit codes. Top-level `arbiter` Click group with sub-groups `trust` and `canary`, plus top-level commands `init`, `register`, `authority`, `blast-radius`, `soak`, `report`, `watch`, `findings`, `conflicts`. Shared CliContext on ctx.obj carries registry_path, config, and output_format. Custom ArbiterGroup.invoke() wraps super().invoke() in try/except for centralized error handling with node/field context in messages. All errors to stderr. JSON output is .model_dump(mode='json') of response models. Text output is human-readable formatted string. --format supports text|json with TTY auto-detection.

# Module invariants:
#   - CLI is a thin adapter layer — all business logic is delegated to engine dependencies
#   - Trust and authority are never conflated: trust commands use trust_engine, authority commands use authority_engine
#   - Trust is earned (computed from ledger), authority is declared (from manifests)
#   - All policy calculations use raw trust score, never display tiers
#   - The trust ledger is append-only — no updates, no deletes
#   - Canary patterns are always recognizable as synthetic (never plausible real data)
#   - All errors written to stderr, all normal output to stdout
#   - JSON output is always .model_dump(mode='json') of the Pydantic response model
#   - Error messages always include the specific node, field, or domain that caused the error
#   - Exit codes are deterministic for a given error condition
#   - CliContext.output_format is never 'auto' after resolution in group callback
#   - All timestamps are UTC (datetime.now(timezone.utc))
#   - All file I/O uses pathlib
#   - No async — all operations are synchronous
#   - Every command is testable via CliRunner with mocked engine dependencies
#   - Each CLI module file is under 300 lines
#   - Custom ParamTypes (NodeIdType, RunIdType, TierType, VersionType) delegate validation to corresponding Pydantic types/enums
#   - ArbiterGroup.invoke() wraps super().invoke() in try/except for centralized error handling
#   - Watch command cold start completes in under 3 seconds

class ExitCode(Enum):
    """CLI exit codes. Every command contract specifies which subset it can produce."""
    SUCCESS_0 = "SUCCESS_0"
    DOMAIN_ERROR_1 = "DOMAIN_ERROR_1"
    USAGE_ERROR_2 = "USAGE_ERROR_2"
    IO_ERROR_3 = "IO_ERROR_3"
    NOT_FOUND_4 = "NOT_FOUND_4"

class OutputFormat(Enum):
    """Output format for CLI responses. 'auto' detects TTY (text if TTY, json otherwise)."""
    text = "text"
    json = "json"
    auto = "auto"

class ArbiterConfig:
    """Top-level arbiter configuration loaded from YAML. Delegated from config component."""
    registry_path: str                       # required, Path to the registry directory.
    ledger_checksum_interval: int            # required, Number of ledger entries between SHA256 checksum lines.
    http_port: int                           # required, Default HTTP API port for watch mode.
    otlp_port: int                           # required, Default OTLP gRPC port for watch mode.
    cold_start_timeout_s: float              # required, Maximum seconds for watch cold start.

class CliContext:
    """Shared CLI context attached to click ctx.obj. Loaded in the top-level group callback. Available to all subcommands via @click.pass_obj."""
    registry_path: str                       # required, Resolved absolute path to the registry directory.
    config: ArbiterConfig                    # required, Loaded arbiter configuration.
    output_format: OutputFormat              # required, Resolved output format (never 'auto' after resolution).

NodeId = primitive  # Opaque string identifying a node in the access graph. Validated by NodeIdType ParamType: non-empty, matches ^[a-zA-Z0-9_.-]+$ pattern.

RunId = primitive  # Opaque string identifying a run (canary run, report run). Validated by RunIdType ParamType: non-empty UUID v4 format.

TierName = primitive  # String name of a data classification tier. Validated by TierType ParamType against the classification registry enum.

VersionTag = primitive  # Semver-compatible version string. Validated by VersionType ParamType: matches ^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$ pattern.

ReviewId = primitive  # Opaque string identifying a review for taint reset. Non-empty string.

class InitRequest:
    """Request model for `arbiter init`."""
    registry_path: str                       # required, Path where the registry directory should be created.
    force: bool                              # required, If true, re-initialize even if registry exists.

class InitResponse:
    """Response model for `arbiter init`."""
    registry_path: str                       # required, Absolute path to the initialized registry directory.
    created_files: CreatedFilesList          # required, List of files created during initialization.
    message: str                             # required, Human-readable success message.

CreatedFilesList = list[str]
# List of file paths created during initialization.

class RegisterRequest:
    """Request model for `arbiter register`."""
    access_graph_path: str                   # required, Path to the access_graph.json file to ingest.

class RegisterResponse:
    """Response model for `arbiter register`."""
    nodes_ingested: int                      # required, Number of nodes ingested from the access graph.
    edges_ingested: int                      # required, Number of edges ingested from the access graph.
    message: str                             # required, Human-readable success message.

class TrustShowRequest:
    """Request model for `arbiter trust show`."""
    node_id: NodeId                          # required, The node to query trust for.

class TrustScoreEntry:
    """A single trust score entry from the ledger history."""
    timestamp: str                           # required, UTC ISO 8601 timestamp of the entry.
    raw_score: float                         # required, Raw trust score value.
    event_type: str                          # required, Type of trust event that produced this score.
    tainted: bool                            # required, Whether the node was tainted at this point.

TrustHistory = list[TrustScoreEntry]
# Ordered list of trust score entries, oldest first.

class TrustShowResponse:
    """Response model for `arbiter trust show`."""
    node_id: NodeId                          # required, The queried node.
    current_score: float                     # required, Current raw trust score.
    tainted: bool                            # required, Whether the node is currently tainted.
    history: TrustHistory                    # required, Trust score history entries.

class TrustResetTaintRequest:
    """Request model for `arbiter trust reset-taint`."""
    node_id: NodeId                          # required, The node to clear taint on.
    review_id: ReviewId                      # required, The review ID authorizing the taint reset.

class TrustResetTaintResponse:
    """Response model for `arbiter trust reset-taint`."""
    node_id: NodeId                          # required, The node whose taint was cleared.
    review_id: ReviewId                      # required, The review ID used.
    previous_score: float                    # required, Trust score before taint reset.
    new_score: float                         # required, Trust score after taint reset.
    message: str                             # required, Human-readable confirmation message.

class AuthorityShowResponse:
    """Response model for `arbiter authority show`."""
    authority_map: AuthorityEntryList        # required, Full authority map from manifests.
    total_entries: int                       # required, Total number of authority entries.

class AuthorityEntry:
    """A single authority declaration from a manifest."""
    node_id: NodeId                          # required, The node with declared authority.
    authority_scope: str                     # required, Scope of authority (e.g., resource path pattern).
    declared_by: str                         # required, Manifest or source that declared this authority.
    timestamp: str                           # required, UTC ISO 8601 timestamp of declaration.

AuthorityEntryList = list[AuthorityEntry]
# List of authority entries.

class BlastRadiusRequest:
    """Request model for `arbiter blast-radius`."""
    node_id: NodeId                          # required, The node to compute blast radius from.
    version: VersionTag                      # required, The version of the node to evaluate.

class BlastRadiusNode:
    """A node within the blast radius result."""
    node_id: NodeId                          # required, The affected node.
    depth: int                               # required, Graph distance from the origin node.
    data_tier: str                           # required, Data classification tier of this node.
    trust_score: float                       # required, Current raw trust score of this node.

BlastRadiusNodeList = list[BlastRadiusNode]
# List of blast radius nodes.

class BlastRadiusResponse:
    """Response model for `arbiter blast-radius`."""
    origin_node: NodeId                      # required, The origin node of the blast radius computation.
    version: VersionTag                      # required, Version evaluated.
    affected_nodes: BlastRadiusNodeList      # required, All nodes within blast radius, ordered by depth.
    total_affected: int                      # required, Total number of affected nodes.
    max_depth: int                           # required, Maximum depth reached in traversal.

class SoakComputeRequest:
    """Request model for `arbiter soak compute`."""
    node_id: NodeId                          # required, The node to compute soak duration for.
    tier: TierName                           # required, The data classification tier.

class SoakComputeResponse:
    """Response model for `arbiter soak compute`."""
    node_id: NodeId                          # required, The node evaluated.
    tier: TierName                           # required, The data classification tier used.
    soak_duration_hours: float               # required, Computed soak duration in hours.
    trust_score: float                       # required, Trust score used in computation.
    message: str                             # required, Human-readable summary.

class ReportRequest:
    """Request model for `arbiter report`."""
    run_id: RunId                            # required, The run ID to generate a report for.

class ReportResponse:
    """Response model for `arbiter report`."""
    run_id: RunId                            # required, The run ID.
    generated_at: str                        # required, UTC ISO 8601 timestamp of report generation.
    summary: str                             # required, Human-readable report summary.
    findings_count: int                      # required, Total findings in the report.
    report_path: str                         # required, Path to the generated report file.

class CanaryInjectRequest:
    """Request model for `arbiter canary inject`."""
    tiers: TierNameList                      # required, List of data classification tiers to inject canary data for.

TierNameList = list[TierName]
# List of tier names.

class CanaryInjectResponse:
    """Response model for `arbiter canary inject`."""
    run_id: RunId                            # required, The canary run ID generated for this injection.
    injected_count: int                      # required, Number of canary records injected.
    tiers_covered: TierNameList              # required, Tiers that received canary data.
    message: str                             # required, Human-readable summary.

class CanaryResultsRequest:
    """Request model for `arbiter canary results`."""
    run_id: RunId                            # required, The canary run ID to get results for.

class TaintEscape:
    """A single taint escape finding from canary analysis."""
    canary_id: str                           # required, Unique ID of the canary that escaped.
    source_tier: TierName                    # required, Tier the canary was injected into.
    found_at_node: NodeId                    # required, Node where the canary was detected.
    found_at_tier: str                       # required, Tier classification of the location where canary was found.
    timestamp: str                           # required, UTC ISO 8601 timestamp of detection.

TaintEscapeList = list[TaintEscape]
# List of taint escape findings.

class CanaryResultsResponse:
    """Response model for `arbiter canary results`."""
    run_id: RunId                            # required, The canary run ID.
    escapes: TaintEscapeList                 # required, All taint escape findings.
    total_escapes: int                       # required, Total number of escapes detected.
    total_canaries: int                      # required, Total canaries injected in this run.
    escape_rate: float                       # required, Fraction of canaries that escaped (0.0 to 1.0).

class WatchRequest:
    """Request model for `arbiter watch`."""
    http_port: int                           # required, Port for the HTTP API server.
    otlp_port: int                           # required, Port for the OTLP gRPC subscriber.

class WatchStatus:
    """Status snapshot of the watch process (used in readiness checks, not a terminal response)."""
    http_port: int                           # required, Active HTTP API port.
    otlp_port: int                           # required, Active OTLP gRPC port.
    started_at: str                          # required, UTC ISO 8601 timestamp of watch start.
    ready: bool                              # required, Whether both servers are ready to accept connections.
    cold_start_ms: float                     # required, Time in milliseconds from invocation to ready state.

class Finding:
    """A consistency finding for a node."""
    finding_id: str                          # required, Unique finding identifier.
    node_id: NodeId                          # required, Node the finding pertains to.
    severity: FindingSeverity                # required, Severity of the finding.
    category: str                            # required, Category of the consistency check.
    message: str                             # required, Human-readable finding description.
    timestamp: str                           # required, UTC ISO 8601 timestamp.

class FindingSeverity(Enum):
    """Severity levels for findings."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

FindingsList = list[Finding]
# List of findings.

class FindingsRequest:
    """Request model for `arbiter findings`."""
    node_id: NodeId                          # required, The node to query findings for.

class FindingsResponse:
    """Response model for `arbiter findings`."""
    node_id: NodeId                          # required, The queried node.
    findings: FindingsList                   # required, Consistency findings for the node.
    total: int                               # required, Total number of findings.

class Conflict:
    """A conflict between trust and authority or between declarations."""
    conflict_id: str                         # required, Unique conflict identifier.
    node_ids: NodeIdList                     # required, Nodes involved in the conflict.
    conflict_type: str                       # required, Type of conflict (e.g., trust_authority_mismatch, overlapping_authority).
    message: str                             # required, Human-readable conflict description.
    resolved: bool                           # required, Whether the conflict has been resolved.
    timestamp: str                           # required, UTC ISO 8601 timestamp of detection.

NodeIdList = list[NodeId]
# List of node IDs.

ConflictList = list[Conflict]
# List of conflicts.

class ConflictsRequest:
    """Request model for `arbiter conflicts`."""
    unresolved_only: bool                    # required, If true, return only unresolved conflicts.

class ConflictsResponse:
    """Response model for `arbiter conflicts`."""
    conflicts: ConflictList                  # required, Matching conflicts.
    total: int                               # required, Total number of matching conflicts.
    unresolved_only: bool                    # required, Whether filter was applied.

class CliError:
    """Structured error output written to stderr in JSON mode."""
    error_code: str                          # required, Machine-readable error code.
    message: str                             # required, Human-readable error message including node/field/domain context.
    exit_code: int                           # required, The exit code that will be used.
    node_id: str = None                      # optional, Node ID involved, if applicable.
    field: str = None                        # optional, Field involved, if applicable.

def arbiter_group(
    config_path: str,
    registry_path: str,
    format: OutputFormat,
) -> CliContext:
    """
    Top-level Click group callback. Loads config from --config path (default: ./arbiter.yaml), resolves --registry-path, resolves --format (auto → text if TTY, json otherwise), constructs CliContext and attaches to ctx.obj. Uses custom ArbiterGroup class whose invoke() wraps super().invoke() in try/except to catch all domain exceptions, format CliError, write to stderr, and sys.exit with mapped ExitCode.

    Preconditions:
      - config_path must point to a readable YAML file or not exist (defaults used)
      - If registry_path is provided, it must be a valid directory path

    Postconditions:
      - CliContext is fully initialized with resolved output_format (never 'auto')
      - CliContext is attached to click ctx.obj
      - Config is loaded and validated as ArbiterConfig

    Errors:
      - config_not_found (IO_ERROR): Config file path does not exist and is not the default
          exit_code: 3
      - config_invalid_yaml (USAGE_ERROR): Config file is not valid YAML or fails ArbiterConfig validation
          exit_code: 2
      - registry_path_invalid (IO_ERROR): Explicit registry_path does not exist or is not a directory
          exit_code: 3

    Side effects: none
    Idempotent: yes
    """
    ...

def cmd_init(
    ctx: CliContext,
    force: bool,
) -> InitResponse:
    """
    Command: `arbiter init [--force]`. Initializes registry directory, empty trust ledger (JSONL with checksum), and default config (FA-A-001). Delegates to registry.initialize_registry.

    Preconditions:
      - CliContext is initialized
      - Parent directory of registry_path must be writable

    Postconditions:
      - Registry directory exists at registry_path
      - Empty trust ledger file exists within registry
      - Default config file exists within registry
      - Exit code is SUCCESS_0

    Errors:
      - already_initialized (DOMAIN_ERROR): Registry directory exists and force is false
          exit_code: 1
          error_code: REGISTRY_EXISTS
      - permission_denied (IO_ERROR): Cannot create registry directory due to filesystem permissions
          exit_code: 3
          error_code: PERMISSION_DENIED
      - parent_not_found (IO_ERROR): Parent directory of registry_path does not exist
          exit_code: 3
          error_code: PARENT_DIR_NOT_FOUND

    Side effects: none
    Idempotent: no
    """
    ...

def cmd_register(
    ctx: CliContext,
    access_graph_path: str,
) -> RegisterResponse:
    """
    Command: `arbiter register <access_graph_path>`. Ingests an access graph JSON file into the registry. Delegates to registry.ingest_access_graph.

    Preconditions:
      - Registry must be initialized (arbiter init has been run)
      - access_graph_path must point to a readable JSON file
      - JSON must conform to access graph schema

    Postconditions:
      - Access graph nodes and edges are stored in registry
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry directory does not exist or is missing required files
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED
      - file_not_found (IO_ERROR): access_graph_path does not exist
          exit_code: 3
          error_code: FILE_NOT_FOUND
      - invalid_json (USAGE_ERROR): File is not valid JSON
          exit_code: 2
          error_code: INVALID_JSON
      - schema_violation (DOMAIN_ERROR): JSON does not conform to the access graph schema
          exit_code: 1
          error_code: SCHEMA_VIOLATION
      - permission_denied (IO_ERROR): Cannot read the access graph file
          exit_code: 3
          error_code: PERMISSION_DENIED

    Side effects: none
    Idempotent: no
    """
    ...

def cmd_trust_show(
    ctx: CliContext,
    node_id: NodeId,
) -> TrustShowResponse:
    """
    Command: `arbiter trust show <node>`. Displays current trust score and history for a node. Delegates to trust_engine.compute_trust_score and trust_engine.get_trust_history.

    Preconditions:
      - Registry must be initialized
      - node_id must exist in the registered access graph

    Postconditions:
      - Response contains current raw trust score (never display tier)
      - History is ordered oldest-first
      - Trust score computation is deterministic given same ledger input
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED
      - node_not_found (NOT_FOUND): node_id does not exist in the access graph
          exit_code: 4
          error_code: NODE_NOT_FOUND
      - ledger_corrupted (DOMAIN_ERROR): Trust ledger checksum validation fails
          exit_code: 1
          error_code: LEDGER_CORRUPTED

    Side effects: none
    Idempotent: yes
    """
    ...

def cmd_trust_reset_taint(
    ctx: CliContext,
    node_id: NodeId,
    review_id: ReviewId,
) -> TrustResetTaintResponse:
    """
    Command: `arbiter trust reset-taint <node> --review <id>`. Clears taint lock on a node, appending a reset event to the trust ledger. Delegates to trust_engine.reset_taint.

    Preconditions:
      - Registry must be initialized
      - node_id must exist in the access graph
      - Node must currently be tainted
      - review_id must be non-empty

    Postconditions:
      - Taint reset event is appended to trust ledger (append-only)
      - Node is no longer tainted
      - Trust score is recomputed
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED
      - node_not_found (NOT_FOUND): node_id does not exist
          exit_code: 4
          error_code: NODE_NOT_FOUND
      - not_tainted (DOMAIN_ERROR): Node is not currently tainted
          exit_code: 1
          error_code: NODE_NOT_TAINTED
      - empty_review_id (USAGE_ERROR): review_id is empty string
          exit_code: 2
          error_code: EMPTY_REVIEW_ID
      - ledger_corrupted (DOMAIN_ERROR): Trust ledger checksum validation fails
          exit_code: 1
          error_code: LEDGER_CORRUPTED

    Side effects: none
    Idempotent: no
    """
    ...

def cmd_authority_show(
    ctx: CliContext,
) -> AuthorityShowResponse:
    """
    Command: `arbiter authority show`. Displays the full authority map declared from manifests. Delegates to authority_engine.get_authority_map.

    Preconditions:
      - Registry must be initialized

    Postconditions:
      - Response contains all authority declarations from manifests
      - Authority is distinct from trust (declared, not computed)
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED

    Side effects: none
    Idempotent: yes
    """
    ...

def cmd_blast_radius(
    ctx: CliContext,
    node_id: NodeId,
    version: VersionTag,
) -> BlastRadiusResponse:
    """
    Command: `arbiter blast-radius <node> <version>`. Computes blast radius via BFS/DFS over access graph edges. Delegates to blast_radius_engine.compute_blast_radius.

    Preconditions:
      - Registry must be initialized
      - Access graph must be registered
      - node_id must exist in the access graph

    Postconditions:
      - affected_nodes is ordered by depth ascending
      - total_affected equals len(affected_nodes)
      - max_depth equals max depth among affected_nodes or 0 if empty
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED
      - node_not_found (NOT_FOUND): node_id does not exist in the access graph
          exit_code: 4
          error_code: NODE_NOT_FOUND
      - no_access_graph (DOMAIN_ERROR): No access graph has been registered
          exit_code: 1
          error_code: NO_ACCESS_GRAPH

    Side effects: none
    Idempotent: yes
    """
    ...

def cmd_soak_compute(
    ctx: CliContext,
    node_id: NodeId,
    tier: TierName,
) -> SoakComputeResponse:
    """
    Command: `arbiter soak compute <node> <tier>`. Computes soak duration for a node at a given data classification tier. Delegates to soak_engine.compute_soak_duration.

    Preconditions:
      - Registry must be initialized
      - node_id must exist in the access graph
      - tier must be a valid classification tier

    Postconditions:
      - soak_duration_hours >= 0
      - Computation uses raw trust score (not display tiers)
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED
      - node_not_found (NOT_FOUND): node_id does not exist
          exit_code: 4
          error_code: NODE_NOT_FOUND
      - invalid_tier (USAGE_ERROR): tier is not a recognized classification tier
          exit_code: 2
          error_code: INVALID_TIER

    Side effects: none
    Idempotent: yes
    """
    ...

def cmd_report(
    ctx: CliContext,
    run_id: RunId,
) -> ReportResponse:
    """
    Command: `arbiter report --run <run_id>`. Generates a feedback report for a given run. Delegates to report_engine.generate_report.

    Preconditions:
      - Registry must be initialized
      - run_id must correspond to a known run

    Postconditions:
      - Report file is written to registry reports directory
      - generated_at is a valid UTC ISO 8601 timestamp
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED
      - run_not_found (NOT_FOUND): run_id does not match any known run
          exit_code: 4
          error_code: RUN_NOT_FOUND
      - write_failure (IO_ERROR): Cannot write report file
          exit_code: 3
          error_code: WRITE_FAILURE

    Side effects: none
    Idempotent: yes
    """
    ...

def cmd_canary_inject(
    ctx: CliContext,
    tiers: TierNameList,
) -> CanaryInjectResponse:
    """
    Command: `arbiter canary inject --tiers <tier>[,<tier>...]`. Seeds canary data for the specified tiers. Canary fingerprints are structurally valid for tier, globally unique per run, and impossible in real data (UUIDs in domain-shaped strings). Delegates to canary_engine.inject_canaries.

    Preconditions:
      - Registry must be initialized
      - tiers must be non-empty
      - Each tier must be a valid classification tier

    Postconditions:
      - Canary data is injected for all specified tiers
      - Each canary is recognizable as synthetic (never plausible real data)
      - Each canary is globally unique per run
      - run_id is a new UUID v4
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED
      - empty_tiers (USAGE_ERROR): No tiers specified
          exit_code: 2
          error_code: EMPTY_TIERS
      - invalid_tier (USAGE_ERROR): One or more tiers not recognized
          exit_code: 2
          error_code: INVALID_TIER

    Side effects: none
    Idempotent: no
    """
    ...

def cmd_canary_results(
    ctx: CliContext,
    run_id: RunId,
) -> CanaryResultsResponse:
    """
    Command: `arbiter canary results --run <run_id>`. Produces a taint escape report for a canary run. Delegates to canary_engine.get_canary_results.

    Preconditions:
      - Registry must be initialized
      - run_id must correspond to a canary run

    Postconditions:
      - total_escapes equals len(escapes)
      - escape_rate equals total_escapes / total_canaries (or 0.0 if total_canaries is 0)
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED
      - run_not_found (NOT_FOUND): run_id does not correspond to a canary run
          exit_code: 4
          error_code: RUN_NOT_FOUND

    Side effects: none
    Idempotent: yes
    """
    ...

def cmd_watch(
    ctx: CliContext,
    http_port: int,            # range(1024 <= value <= 65535)
    otlp_port: int,            # range(1024 <= value <= 65535)
) -> WatchStatus:
    """
    Command: `arbiter watch [--http-port PORT] [--otlp-port PORT]`. Starts OTLP subscriber and HTTP API in a single process. Blocking command that handles SIGINT/SIGTERM for graceful shutdown. Cold-start target: ready in under 3 seconds. Delegates to otlp_subscriber and http_api components.

    Preconditions:
      - Registry must be initialized
      - http_port and otlp_port must be different
      - Ports must not be in use

    Postconditions:
      - OTLP subscriber is listening on otlp_port
      - HTTP API is listening on http_port
      - WatchStatus.ready is true before cold_start_timeout_s
      - On SIGINT/SIGTERM, both servers shut down gracefully
      - Exit code is SUCCESS_0 on clean shutdown

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED
      - port_in_use (IO_ERROR): One or both ports are already bound
          exit_code: 3
          error_code: PORT_IN_USE
      - port_conflict (USAGE_ERROR): http_port and otlp_port are the same
          exit_code: 2
          error_code: PORT_CONFLICT
      - cold_start_timeout (DOMAIN_ERROR): Servers not ready within cold_start_timeout_s
          exit_code: 1
          error_code: COLD_START_TIMEOUT

    Side effects: none
    Idempotent: no
    """
    ...

def cmd_findings(
    ctx: CliContext,
    node_id: NodeId,
) -> FindingsResponse:
    """
    Command: `arbiter findings --node <node>`. Lists consistency findings for a specific node. Delegates to findings_engine.get_findings.

    Preconditions:
      - Registry must be initialized
      - node_id must exist in the access graph

    Postconditions:
      - total equals len(findings)
      - Each finding includes node_id, severity, and human-readable message
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED
      - node_not_found (NOT_FOUND): node_id does not exist in the access graph
          exit_code: 4
          error_code: NODE_NOT_FOUND

    Side effects: none
    Idempotent: yes
    """
    ...

def cmd_conflicts(
    ctx: CliContext,
    unresolved_only: bool,
) -> ConflictsResponse:
    """
    Command: `arbiter conflicts [--unresolved]`. Lists conflicts, optionally filtered to only unresolved ones. Delegates to conflicts_engine.list_conflicts.

    Preconditions:
      - Registry must be initialized

    Postconditions:
      - total equals len(conflicts)
      - If unresolved_only is true, all returned conflicts have resolved=false
      - Exit code is SUCCESS_0

    Errors:
      - registry_not_initialized (DOMAIN_ERROR): Registry is not initialized
          exit_code: 1
          error_code: REGISTRY_NOT_INITIALIZED

    Side effects: none
    Idempotent: yes
    """
    ...

def format_output(
    response: any,
    output_format: OutputFormat,
) -> str:
    """
    Pure helper that formats a Pydantic response model for CLI output. In JSON mode, calls .model_dump(mode='json') and serializes. In text mode, produces a human-readable formatted string. Used by all commands after receiving engine response.

    Preconditions:
      - output_format is 'text' or 'json' (never 'auto')
      - response is a Pydantic BaseModel instance

    Postconditions:
      - If json: output is valid JSON matching response.model_dump(mode='json')
      - If text: output is non-empty human-readable string
      - No trailing newline added (caller handles)

    Side effects: none
    Idempotent: yes
    """
    ...

def format_error(
    error: CliError,
    output_format: OutputFormat,
) -> str:
    """
    Pure helper that formats a CliError for stderr output. In JSON mode, serializes the CliError model. In text mode, produces 'Error [{error_code}]: {message}' with optional node/field context.

    Preconditions:
      - output_format is 'text' or 'json' (never 'auto')

    Postconditions:
      - If json: output is valid JSON matching error.model_dump(mode='json')
      - If text: output includes error_code and message, plus node_id/field if non-empty
      - Error messages include the specific node, field, or domain that caused the error

    Side effects: none
    Idempotent: yes
    """
    ...

def map_exception_to_exit_code(
    exception: any,
) -> ExitCode:
    """
    Pure function used by ArbiterGroup.invoke() to map domain exceptions to ExitCode values. Maps known exception types to their corresponding exit codes per the ExitCode enum.

    Postconditions:
      - Returns DOMAIN_ERROR_1 for domain logic exceptions
      - Returns USAGE_ERROR_2 for validation/input exceptions
      - Returns IO_ERROR_3 for filesystem/network exceptions
      - Returns NOT_FOUND_4 for entity-not-found exceptions
      - Returns DOMAIN_ERROR_1 for unrecognized exceptions (safe default)

    Side effects: none
    Idempotent: yes
    """
    ...

def resolve_output_format(
    requested_format: OutputFormat,
    is_tty: bool,
) -> OutputFormat:
    """
    Pure function that resolves OutputFormat.auto to text or json based on TTY detection. Called during CliContext construction.

    Postconditions:
      - If requested_format is 'text' or 'json', returns it unchanged
      - If requested_format is 'auto' and is_tty is true, returns 'text'
      - If requested_format is 'auto' and is_tty is false, returns 'json'
      - Return value is never 'auto'

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['ExitCode', 'OutputFormat', 'ArbiterConfig', 'CliContext', 'InitRequest', 'InitResponse', 'CreatedFilesList', 'RegisterRequest', 'RegisterResponse', 'TrustShowRequest', 'TrustScoreEntry', 'TrustHistory', 'TrustShowResponse', 'TrustResetTaintRequest', 'TrustResetTaintResponse', 'AuthorityShowResponse', 'AuthorityEntry', 'AuthorityEntryList', 'BlastRadiusRequest', 'BlastRadiusNode', 'BlastRadiusNodeList', 'BlastRadiusResponse', 'SoakComputeRequest', 'SoakComputeResponse', 'ReportRequest', 'ReportResponse', 'CanaryInjectRequest', 'TierNameList', 'CanaryInjectResponse', 'CanaryResultsRequest', 'TaintEscape', 'TaintEscapeList', 'CanaryResultsResponse', 'WatchRequest', 'WatchStatus', 'Finding', 'FindingSeverity', 'FindingsList', 'FindingsRequest', 'FindingsResponse', 'Conflict', 'NodeIdList', 'ConflictList', 'ConflictsRequest', 'ConflictsResponse', 'CliError', 'arbiter_group', 'IO_ERROR', 'USAGE_ERROR', 'cmd_init', 'DOMAIN_ERROR', 'cmd_register', 'cmd_trust_show', 'NOT_FOUND', 'cmd_trust_reset_taint', 'cmd_authority_show', 'cmd_blast_radius', 'cmd_soak_compute', 'cmd_report', 'cmd_canary_inject', 'cmd_canary_results', 'cmd_watch', 'cmd_findings', 'cmd_conflicts', 'format_output', 'format_error', 'map_exception_to_exit_code', 'resolve_output_format']
