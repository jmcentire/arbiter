# === Access Auditor & OpenAPI Integration (access_auditor) v1 ===
# Walks OpenAPI response schemas at adapter slot time, maps each field against the classification registry using fnmatch/regex patterns, and produces a structural access profile (superset of data tiers the node can return). Compares structural profile against the node's declared data_access from the access graph. Flags DECLARATION_GAP if structural profile includes undeclared tiers (C005). Produces BLOCK_SLOT if undeclared tiers are present and block_on_gate is configured. Records access violation findings when observed output tier exceeds declared reads (FA-A-015). Handles missing OpenAPI schemas gracefully by recording an INCOMPLETE_SCHEMA warning (rabbit hole patch). Composed of four concerns: schema_walker (pure DFS traversal), classifier (pure field→tier mapping), auditor orchestrator (composition + gating), and shared models/types.

# Module invariants:
#   - DataTier ordering is PUBLIC(0) < INTERNAL(1) < CONFIDENTIAL(2) < RESTRICTED(3); integer comparison determines severity
#   - The trust ledger is append-only — no updates, no deletes; all findings appended via LedgerWriter protocol
#   - Trust and authority are distinct: structural profiles are computed (earned), declared_access is declared (authority)
#   - All timestamps are UTC (datetime.now(timezone.utc))
#   - Structural profiles use frozenset[DataTier] — immutable and hashable, enabling caching per schema version
#   - Missing or empty OpenAPI schemas are treated as RESTRICTED tier (assume-worst fail-safe)
#   - All findings carry the specific node_id, field path, and domain that caused the error in the message field
#   - Deterministic serialization: Pydantic model_dump(mode='json') with sorted keys for all ledger entries
#   - Classification of unmatched fields defaults to PUBLIC (DataTier.PUBLIC = 0)
#   - Schema walker cycle detection prevents infinite recursion on circular $ref chains
#   - FindingCode values are stable string identifiers: C005 for DECLARATION_GAP, FA_A_015 for observed access violation
#   - Pure functions (walk_response_schema, classify_fields) have no side effects and are deterministic given same input
#   - SlotDecision.decision is BLOCK if and only if at least one finding code is in GateConfig.block_on_codes
#   - Protocol-based interfaces (ClassificationRegistry, LedgerWriter, AccessGraph) use structural subtyping — no inheritance required

class DataTier(Enum):
    """IntEnum representing data classification tiers. Integer value determines ordering/severity. PUBLIC(0) < INTERNAL(1) < CONFIDENTIAL(2) < RESTRICTED(3). Used for natural ordering comparisons in access auditing."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

class FindingCode(Enum):
    """StrEnum of well-known finding codes emitted by the access auditor. Stable string identifiers used for gating decisions and ledger records."""
    C005 = "C005"
    FA_A_015 = "FA_A_015"
    INCOMPLETE_SCHEMA = "INCOMPLETE_SCHEMA"

class FindingSeverity(Enum):
    """IntEnum representing finding severity levels. Integer value determines ordering. INFO(0) < WARNING(1) < ERROR(2) < CRITICAL(3)."""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class SlotDecisionVerdict(Enum):
    """Literal verdict for a slot gating decision. ALLOW permits the slot; BLOCK prevents it."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"

NodeId = primitive  # NewType over str. Identifies a unique node in the access graph. Must not be empty. Prevents accidental mixing with other string-typed identifiers under strict mypy.

FieldPath = primitive  # NewType over str. Dot-separated JSON path to a leaf field in an OpenAPI response schema (e.g. 'response.user.email'). Must not be empty.

AdapterSlotId = primitive  # NewType over str. Identifies a unique adapter slot being audited. Must not be empty.

class FieldEntry:
    """A single leaf field discovered by the schema walker. Represents one terminal node in the DFS traversal of an OpenAPI response schema."""
    path: FieldPath                          # required, Dot-separated path from schema root to this leaf field.
    field_type: str                          # required, OpenAPI type string for this field (e.g. 'string', 'integer', 'boolean', 'array').
    nullable: bool                           # required, Whether the field is marked nullable in the schema.
    format_hint: str                         # required, Optional OpenAPI format hint (e.g. 'email', 'date-time', 'uuid'). Empty string if not specified.

class SchemaWarning:
    """A warning generated during schema walking when the schema is incomplete, missing, or contains unresolvable references."""
    code: FindingCode                        # required, Always INCOMPLETE_SCHEMA for schema walker warnings.
    path: str                                # required, The JSON path or $ref URI where the issue was encountered. Empty string if schema was entirely missing.
    message: str                             # required, Human-readable description including the specific location and nature of the incompleteness.

class WalkResult:
    """Result of walking an OpenAPI response schema. Contains discovered leaf fields and any warnings about schema incompleteness."""
    fields: list                             # required, All leaf FieldEntry instances discovered by DFS traversal.
    warnings: list                           # required, Schema warnings encountered during traversal (missing schemas, unresolvable $refs, cycles).

class ClassifiedField:
    """A field entry paired with its resolved data classification tier from the registry."""
    path: FieldPath                          # required, The field path that was classified.
    tier: DataTier                           # required, The data classification tier assigned to this field.
    matched_pattern: str                     # required, The fnmatch/regex pattern from the registry that matched this field. Empty string if defaulted to PUBLIC.

class ClassificationResult:
    """Result of classifying a list of field entries against the classification registry."""
    classified_fields: list                  # required, All fields with their assigned data tier.
    tier_set: list                           # required, Deduplicated set of all DataTier values present in classified_fields. Serialized as sorted list; in-memory representation is frozenset[DataTier].

class StructuralProfile:
    """The structural access profile for a node at a given endpoint. Represents the superset of data tiers the node can return based on its OpenAPI response schema. Pydantic model with deterministic serialization."""
    node_id: NodeId                          # required, The node whose schema was analyzed.
    adapter_slot_id: AdapterSlotId           # required, The adapter slot at which the schema was inspected.
    endpoint: str                            # required, The OpenAPI endpoint path that was analyzed (e.g. '/api/v1/users').
    tiers: list                              # required, All data tiers present in the response schema. In-memory: frozenset[DataTier]. Serialized as sorted list of tier names.
    classified_fields: list                  # required, Complete mapping of each discovered field path to its classification tier.
    warnings: list                           # required, Any schema warnings encountered during profile computation.
    schema_complete: bool                    # required, True if the schema was fully resolved with no warnings. False triggers assume-worst behavior.
    computed_at: str                         # required, ISO 8601 UTC timestamp of when this profile was computed.

class AccessFinding:
    """A finding produced by the access auditor. Immutable record of a detected access violation or gap. All fields required for ledger append. Message always includes the specific node_id, field, and domain."""
    code: FindingCode                        # required, The finding code (C005, FA_A_015, INCOMPLETE_SCHEMA).
    severity: FindingSeverity                # required, The severity level of this finding.
    node_id: NodeId                          # required, The node that triggered this finding.
    adapter_slot_id: AdapterSlotId           # required, The adapter slot context for this finding.
    message: str                             # required, length(len(value) >= 10), Human-readable description. Must include specific node_id, field path, and/or domain that caused the error per operating procedures.
    evidence: AccessFindingEvidence          # required, Structured evidence supporting this finding.
    timestamp: str                           # required, ISO 8601 UTC timestamp of when this finding was produced.

class AccessFindingEvidence:
    """Structured evidence attached to an AccessFinding. Contains the data needed to reproduce and understand the finding."""
    structural_tiers: list                   # required, The tiers found in the structural profile.
    declared_tiers: list                     # required, The tiers declared by the node in the access graph.
    undeclared_tiers: list                   # required, The set difference: structural_tiers - declared_tiers.
    fields_by_undeclared_tier: dict          # required, Mapping of undeclared tier name → list of field paths at that tier. JSON-serializable dict[str, list[str]].
    endpoint: str                            # required, The endpoint being audited.

class GateConfig:
    """Configuration for slot gating decisions. Determines which finding codes trigger a BLOCK verdict."""
    block_on_codes: list                     # required, Set of FindingCode values that trigger BLOCK_SLOT. If any finding's code is in this set, the slot is blocked. In-memory: set[FindingCode]. Serialized as sorted list.
    assume_worst_on_incomplete: bool         # required, If true (default), missing/incomplete schemas cause the profile to include RESTRICTED tier.

class SlotDecision:
    """The gating decision for an adapter slot. Contains the verdict (ALLOW or BLOCK) and all findings that contributed to the decision."""
    decision: SlotDecisionVerdict            # required, ALLOW if no blocking findings; BLOCK if any finding code is in GateConfig.block_on_codes.
    adapter_slot_id: AdapterSlotId           # required, The adapter slot this decision applies to.
    node_id: NodeId                          # required, The node this decision applies to.
    findings: list                           # required, All findings produced during slot auditing. May be empty for ALLOW with no issues.
    blocking_codes: list                     # required, The subset of finding codes that triggered the BLOCK decision. Empty if ALLOW.
    profile: StructuralProfile               # required, The structural profile computed for this slot.
    decided_at: str                          # required, ISO 8601 UTC timestamp of when the decision was made.

class DeclaredAccess:
    """The declared data access for a node as extracted from the access graph. Represents the node's authority claim about what tiers it accesses."""
    node_id: NodeId                          # required, The node making the declaration.
    declared_read_tiers: list                # required, The data tiers the node declares it reads. In-memory: frozenset[DataTier].
    declared_write_tiers: list               # required, The data tiers the node declares it writes. In-memory: frozenset[DataTier].

class ClassificationRegistryEntry:
    """A single entry in the classification registry mapping a field pattern to a data tier. Used by ClassificationRegistry.match()."""
    field_pattern: str                       # required, length(len(value) >= 1), An fnmatch glob or regex pattern to match against field paths.
    tier: DataTier                           # required, The data tier to assign to fields matching this pattern.
    pattern_type: str                        # required, custom(value in ('fnmatch', 'regex')), Either 'fnmatch' or 'regex'. Determines matching strategy.
    description: str = None                  # optional, Human-readable description of what this pattern classifies.

class ObservedOutput:
    """Runtime observation of actual data tiers present in a node's output. Used for FA-A-015 runtime violation detection."""
    node_id: NodeId                          # required, The node that produced the output.
    adapter_slot_id: AdapterSlotId           # required, The adapter slot where the output was observed.
    observed_tiers: list                     # required, Data tiers actually present in the observed output. In-memory: frozenset[DataTier].
    observed_fields: list                    # required, The classified fields from the observed output.
    observed_at: str                         # required, ISO 8601 UTC timestamp of observation.

RefResolver = primitive  # Protocol/Callable type: (ref_uri: str) → dict. Resolves a $ref URI to the referenced schema dict. Implementations may read from file or in-memory cache.

def walk_response_schema(
    schema: dict,
    ref_resolver: RefResolver,
    root_path: str = response,
    max_depth: int = 64,       # range(1 <= value <= 256)
) -> WalkResult:
    """
    Pure function. DFS-traverses an OpenAPI response schema, resolves $ref references via the provided resolver with cycle detection (visited set), flattens allOf/anyOf/oneOf with union semantics, and emits a FieldEntry for every leaf field. Returns INCOMPLETE_SCHEMA warnings for missing/empty schemas or unresolvable $refs. Does not perform classification — only structural discovery.

    Preconditions:
      - ref_resolver is a callable accepting a single str argument and returning dict
      - max_depth >= 1

    Postconditions:
      - Every FieldEntry in result.fields has a non-empty path starting with root_path
      - If schema is empty or None-equivalent, result.warnings contains at least one INCOMPLETE_SCHEMA warning
      - No circular $ref chains cause infinite recursion — cycles are detected and emitted as INCOMPLETE_SCHEMA warnings
      - result.fields contains only leaf fields (no intermediate object/array nodes)
      - Function is pure: same inputs always produce same outputs

    Errors:
      - invalid_schema_type (SchemaWalkError): schema is not a dict (after None-check) and not a recognized schema type
          detail: schema must be a dict or None, got {type}
      - ref_resolver_failure (RefResolutionError): ref_resolver raises an exception for a $ref URI
          ref_uri: the failing $ref URI
          detail: underlying error message
      - max_depth_exceeded (SchemaDepthExceededError): Traversal depth exceeds max_depth without reaching a leaf
          path: current traversal path
          max_depth: configured limit

    Side effects: none
    Idempotent: yes
    """
    ...

def classify_fields(
    fields: list,
    registry_entries: list,
) -> ClassificationResult:
    """
    Pure function. Takes a list of FieldEntry and a ClassificationRegistry, matches each field path against the registry's fnmatch/regex patterns, and returns a ClassificationResult with each field mapped to a DataTier. Unmatched fields default to PUBLIC. The tier_set is the frozenset of all unique tiers found.

    Preconditions:
      - All FieldEntry in fields have non-empty path
      - All ClassificationRegistryEntry in registry_entries have valid pattern_type ('fnmatch' or 'regex')
      - Regex patterns in registry_entries are valid and compilable

    Postconditions:
      - len(result.classified_fields) == len(fields)
      - Every field in fields appears exactly once in result.classified_fields
      - result.tier_set == frozenset(cf.tier for cf in result.classified_fields)
      - Fields matching no pattern are assigned DataTier.PUBLIC
      - If a field matches multiple patterns, the pattern yielding the highest DataTier wins
      - Function is pure: same inputs always produce same outputs

    Errors:
      - invalid_regex_pattern (ClassificationRegistryError): A registry entry with pattern_type='regex' has an invalid regex expression
          pattern: the invalid regex
          detail: regex compilation error
      - empty_field_path (ClassificationInputError): A FieldEntry has an empty path string
          detail: FieldEntry.path must not be empty

    Side effects: none
    Idempotent: yes
    """
    ...

def compute_structural_profile(
    node_id: NodeId,           # length(len(value) >= 1)
    adapter_slot_id: AdapterSlotId, # length(len(value) >= 1)
    endpoint: str,             # length(len(value) >= 1)
    schema: dict,
    ref_resolver: RefResolver,
    registry_entries: list,
    gate_config: GateConfig,
) -> StructuralProfile:
    """
    Orchestrator function. Composes walk_response_schema and classify_fields to produce a complete StructuralProfile for a node at a given adapter slot. If the schema is missing or incomplete and GateConfig.assume_worst_on_incomplete is true, RESTRICTED tier is injected into the profile. Records the profile computation timestamp in UTC.

    Preconditions:
      - node_id is not empty
      - adapter_slot_id is not empty
      - endpoint is not empty
      - ref_resolver is callable
      - gate_config is a valid GateConfig

    Postconditions:
      - result.node_id == node_id
      - result.adapter_slot_id == adapter_slot_id
      - result.endpoint == endpoint
      - result.computed_at is a valid ISO 8601 UTC timestamp
      - If schema is empty and gate_config.assume_worst_on_incomplete is True, DataTier.RESTRICTED is in result.tiers
      - result.schema_complete == (len(result.warnings) == 0)
      - result.classified_fields is consistent with result.tiers

    Errors:
      - schema_walk_failure (ProfileComputationError): walk_response_schema raises SchemaWalkError or RefResolutionError
          node_id: the node being profiled
          endpoint: the endpoint
          detail: underlying error
      - classification_failure (ProfileComputationError): classify_fields raises ClassificationRegistryError
          node_id: the node being profiled
          detail: classification error

    Side effects: none
    Idempotent: yes
    """
    ...

def audit_slot(
    profile: StructuralProfile,
    declared_access: DeclaredAccess,
    gate_config: GateConfig,
) -> SlotDecision:
    """
    Core auditing function. Compares a structural profile's tiers against the node's declared access from the access graph. Produces DECLARATION_GAP (C005) findings for any tier in the structural profile not present in declared access. Returns a SlotDecision with BLOCK verdict if any C005 finding code is in gate_config.block_on_codes. Also includes INCOMPLETE_SCHEMA findings from the profile warnings. Appends all findings to the ledger via LedgerWriter.

    Preconditions:
      - profile.node_id == declared_access.node_id
      - profile is a valid StructuralProfile with computed_at set
      - gate_config is a valid GateConfig

    Postconditions:
      - result.node_id == profile.node_id
      - result.adapter_slot_id == profile.adapter_slot_id
      - result.profile == profile
      - result.decision == BLOCK if and only if any finding.code is in gate_config.block_on_codes
      - result.decision == ALLOW if result.blocking_codes is empty
      - For each tier in (profile.tiers - declared_access.declared_read_tiers), exactly one C005 finding exists in result.findings
      - All findings have severity >= WARNING for C005, >= INFO for INCOMPLETE_SCHEMA
      - Every finding message includes the node_id and specific undeclared tier(s)
      - result.decided_at is a valid ISO 8601 UTC timestamp
      - All findings are appended to the ledger via LedgerWriter before return

    Errors:
      - node_id_mismatch (AuditInputError): profile.node_id != declared_access.node_id
          profile_node_id: from profile
          declared_node_id: from declared_access
          detail: node_id mismatch between profile and declared access
      - ledger_write_failure (LedgerWriteError): LedgerWriter fails to append findings
          node_id: the node
          detail: underlying I/O or checksum error

    Side effects: none
    Idempotent: no
    """
    ...

def audit_observed_output(
    observed: ObservedOutput,
    declared_access: DeclaredAccess,
) -> list:
    """
    Runtime observation auditor. Compares actually observed data tiers in a node's output against the node's declared read tiers. Produces FA-A-015 findings when observed tiers exceed declared reads. This catches runtime violations that structural analysis alone cannot detect. Appends findings to the ledger via LedgerWriter.

    Preconditions:
      - observed.node_id == declared_access.node_id
      - observed.observed_at is a valid ISO 8601 UTC timestamp
      - observed.observed_tiers is consistent with observed.observed_fields

    Postconditions:
      - For each tier in (observed.observed_tiers - declared_access.declared_read_tiers), exactly one FA_A_015 finding exists in the result
      - If observed.observed_tiers is a subset of declared_access.declared_read_tiers, result is an empty list
      - Every finding has code == FA_A_015
      - Every finding has severity >= ERROR
      - Every finding message includes the node_id, the specific undeclared tier, and the field paths at that tier
      - All findings are appended to the ledger via LedgerWriter before return
      - Each finding timestamp is >= observed.observed_at

    Errors:
      - node_id_mismatch (AuditInputError): observed.node_id != declared_access.node_id
          observed_node_id: from observed
          declared_node_id: from declared_access
          detail: node_id mismatch between observed output and declared access
      - ledger_write_failure (LedgerWriteError): LedgerWriter fails to append findings
          node_id: the node
          detail: underlying I/O or checksum error

    Side effects: none
    Idempotent: no
    """
    ...

def load_gate_config(
    config_source: dict,
) -> GateConfig:
    """
    Loads and validates a GateConfig from a YAML configuration file or dict. Provides sensible defaults: block_on_codes=[C005], assume_worst_on_incomplete=true.

    Preconditions:
      - config_source is a dict

    Postconditions:
      - result is a valid GateConfig
      - If 'block_on_codes' is missing from config_source, result.block_on_codes defaults to [C005]
      - If 'assume_worst_on_incomplete' is missing, result.assume_worst_on_incomplete defaults to True
      - All values in result.block_on_codes are valid FindingCode variants

    Errors:
      - invalid_finding_code (GateConfigError): A value in config_source['block_on_codes'] is not a valid FindingCode
          invalid_code: the unrecognized code string
          valid_codes: list of valid FindingCode values
      - invalid_config_type (GateConfigError): config_source is not a dict
          detail: config_source must be a dict

    Side effects: none
    Idempotent: yes
    """
    ...

def load_classification_registry(
    registry_source: list,
) -> list:
    """
    Loads and validates classification registry entries from a YAML file or dict list. Pre-compiles regex patterns for performance. Validates all patterns are syntactically correct and all tiers are valid DataTier values.

    Preconditions:
      - registry_source is a list of dicts
      - Each dict in registry_source has at least 'field_pattern', 'tier', and 'pattern_type' keys

    Postconditions:
      - len(result) == len(registry_source)
      - All regex patterns in result have been validated as compilable
      - All tier values in result are valid DataTier variants
      - All pattern_type values are 'fnmatch' or 'regex'

    Errors:
      - invalid_tier (ClassificationRegistryError): A registry entry has a tier value that is not a valid DataTier name
          entry_index: index in source list
          invalid_tier: the bad tier value
          valid_tiers: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
      - invalid_regex (ClassificationRegistryError): A registry entry with pattern_type='regex' has an un-compilable regex
          entry_index: index in source list
          pattern: the invalid regex
          detail: regex compilation error message
      - missing_required_key (ClassificationRegistryError): A registry entry dict is missing 'field_pattern', 'tier', or 'pattern_type'
          entry_index: index in source list
          missing_key: the missing key name
      - invalid_pattern_type (ClassificationRegistryError): A registry entry has pattern_type not in ('fnmatch', 'regex')
          entry_index: index in source list
          invalid_pattern_type: the bad value

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['DataTier', 'FindingCode', 'FindingSeverity', 'SlotDecisionVerdict', 'FieldEntry', 'SchemaWarning', 'WalkResult', 'ClassifiedField', 'ClassificationResult', 'StructuralProfile', 'AccessFinding', 'AccessFindingEvidence', 'GateConfig', 'SlotDecision', 'DeclaredAccess', 'ClassificationRegistryEntry', 'ObservedOutput', 'walk_response_schema', 'SchemaWalkError', 'RefResolutionError', 'SchemaDepthExceededError', 'classify_fields', 'ClassificationRegistryError', 'ClassificationInputError', 'compute_structural_profile', 'ProfileComputationError', 'audit_slot', 'AuditInputError', 'LedgerWriteError', 'audit_observed_output', 'load_gate_config', 'GateConfigError', 'load_classification_registry']
