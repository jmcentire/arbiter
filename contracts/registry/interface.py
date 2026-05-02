# === Access Graph Store & Authority Map (registry) v1 ===
# Manages ingested access_graph.json and the derived authority map. Access graph store: validates and persists the access graph, enforces that no two nodes claim authority for the same domain (C004, FA-A-003). Authority map: exclusive domain-to-node mapping, queryable by domain or node. Validates that classification registry authoritative_node entries match access graph authority declarations (FA-A-030). Provides graph traversal primitives (neighbors, BFS/DFS iterators) for blast radius computation. Handles re-registration by replacing the full graph atomically (with authority exclusivity re-checked). Loads classification registry from classifications.yaml with field_pattern/tier/authoritative_node/canary_pattern entries.

# Module invariants:
#   - No two nodes in the access graph may declare authority for the same domain (exclusivity invariant, C004/FA-A-003)
#   - The AuthorityMap is always a derived artifact of the current AccessGraph snapshot; it is never independently mutated
#   - The trust ledger is append-only — the registry never modifies or deletes previously persisted graph snapshots except by atomic full replacement
#   - Authority is declared (from manifests/graph), never computed from trust scores — trust and authority are distinct
#   - All timestamps are UTC (datetime with timezone.utc)
#   - AccessGraph, GraphNode, Edge, AuthorityMap, ClassificationRule, and ClassificationRegistry are frozen Pydantic models — immutable after construction
#   - Re-registration replaces the full graph atomically: validate-then-swap guarantees the store is never in a partially updated state
#   - BFS/DFS traversals are cycle-safe via visited-set tracking
#   - Classification registry cross-validation (FA-A-030) ensures every authoritative_node in classification rules exists and declares the expected authority in the access graph
#   - All error objects carry structured context (node_id, domain, field) for machine-readable diagnostics

class DataClassificationTier(Enum):
    """Data classification tiers with integer ordering. Higher ordinal = more sensitive. Used in classification rules and blast radius calculations."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

class FindingSeverity(Enum):
    """Severity levels for findings/violations discovered during validation or auditing."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RelationType(Enum):
    """The type of relationship represented by an edge in the access graph."""
    READS = "READS"
    WRITES = "WRITES"
    CALLS = "CALLS"
    DEPENDS_ON = "DEPENDS_ON"
    MANAGES = "MANAGES"

class Edge:
    """A directed edge in the access graph from the owning node to a target node. Frozen Pydantic model."""
    target: str                              # required, length(min=1), The node_id of the edge target.
    relation_type: RelationType              # required, The type of relationship this edge represents.

class GraphNode:
    """A node in the access graph representing a component/service. Frozen Pydantic model. Each node declares zero or more authority_domains it is authoritative for."""
    node_id: str                             # required, length(min=1), Unique identifier for this node within the access graph.
    authority_domains: list                  # required, List of domain strings this node declares authority over. May be empty.
    edges: list                              # required, Outgoing edges from this node. List of Edge structs.
    metadata: dict = {}                      # optional, Arbitrary key-value metadata associated with this node.

class AccessGraph:
    """The complete access graph snapshot. Frozen Pydantic model with a model_validator that enforces domain authority exclusivity across all nodes. Contains a dict of node_id -> GraphNode plus metadata."""
    nodes: dict                              # required, Mapping of node_id (str) to GraphNode. Keys must match each GraphNode's node_id field.
    graph_version: str                       # required, Version string for this graph snapshot (e.g. SHA256 of source file or monotonic counter).
    created_at: str                          # required, ISO 8601 UTC timestamp of when this graph was ingested.
    metadata: dict = {}                      # optional, Arbitrary key-value metadata for the graph.

class AuthorityMap:
    """Derived, frozen mapping of domain -> authoritative node_id. Built during AccessGraph validation. Provides O(1) domain-to-node and O(n) node-to-domains lookups."""
    domain_to_node: dict                     # required, Mapping of domain string to the single node_id that holds authority. Exclusivity guaranteed by construction.
    node_to_domains: dict                    # required, Reverse mapping of node_id to list of domain strings it is authoritative for.

class ClassificationRule:
    """A single classification rule from classifications.yaml. Frozen Pydantic model. Maps a field pattern to a classification tier, an authoritative node, and an optional canary pattern."""
    field_pattern: str                       # required, length(min=1), fnmatch/regex pattern to match field names against.
    tier: DataClassificationTier             # required, The data classification tier for fields matching this pattern.
    authoritative_node: str                  # required, length(min=1), The node_id that should be authoritative for data matching this rule.
    canary_pattern: str = None               # optional, Optional pattern for generating canary fingerprints for this rule. Empty string if not applicable.

class ClassificationRegistry:
    """Collection of classification rules loaded from classifications.yaml. Frozen Pydantic model."""
    rules: list                              # required, Ordered list of ClassificationRule entries. Earlier rules take precedence on pattern overlap.
    source_path: str = None                  # optional, Path to the classifications.yaml file this registry was loaded from. Empty string for in-memory constructed registries.

class GraphSnapshot:
    """An atomic snapshot of the current store state: the validated AccessGraph and its derived AuthorityMap, held together as a single unit for atomic swap on re-registration."""
    access_graph: AccessGraph                # required, The validated access graph.
    authority_map: AuthorityMap              # required, The derived authority map for the access graph.

class TraversalResult:
    """Result from a BFS or DFS traversal: the ordered list of visited node_ids and the edges traversed."""
    visited_nodes: list                      # required, Ordered list of node_id strings in visitation order.
    traversed_edges: list                    # required, List of Edge structs traversed during the walk, in traversal order.
    depth_map: dict                          # required, Mapping of node_id to its depth (int) from the start node.

class NeighborEntry:
    """A single neighbor of a node: the target node_id and the edge connecting them."""
    node_id: str                             # required, The neighbor's node_id.
    edge: Edge                               # required, The edge from the source node to this neighbor.

class ValidationFinding:
    """A single finding from cross-validation of classification registry against the access graph (FA-A-030)."""
    severity: FindingSeverity                # required, Severity of this finding.
    rule_index: int                          # required, Index of the ClassificationRule in the registry that triggered this finding.
    field_pattern: str                       # required, The field_pattern of the offending rule.
    authoritative_node: str                  # required, The authoritative_node referenced by the rule.
    message: str                             # required, Human-readable description of the finding including specific node/domain context.
    error_code: str                          # required, Machine-readable error code (e.g. FA-A-030).

class RegistryError:
    """Base error type for all registry errors. Carries structured context for diagnostics."""
    message: str                             # required, Human-readable error message including specific node/domain/field context.
    error_code: str                          # required, Machine-readable error code.
    context: dict = {}                       # optional, Structured context: node_id, domain, field, etc.

class DuplicateAuthorityError:
    """Error raised when two or more nodes declare authority for the same domain (C004/FA-A-003)."""
    message: str                             # required, Human-readable error message.
    error_code: str                          # required, Machine-readable error code, always 'C004'.
    domain: str                              # required, The domain that has conflicting authority declarations.
    claiming_nodes: list                     # required, List of node_id strings that all claim authority for the domain.

class NodeNotFoundError:
    """Error raised when a referenced node_id does not exist in the access graph."""
    message: str                             # required, Human-readable error message.
    error_code: str                          # required, Machine-readable error code.
    node_id: str                             # required, The node_id that was not found.

class AuthorityMismatchError:
    """Error raised during classification cross-validation (FA-A-030) when a classification rule's authoritative_node does not match graph authority declarations."""
    message: str                             # required, Human-readable error message.
    error_code: str                          # required, Machine-readable error code, always 'FA-A-030'.
    rule_index: int                          # required, Index of the offending rule in the classification registry.
    authoritative_node: str                  # required, The authoritative_node declared in the classification rule.
    expected_domains: list                   # required, Domains the rule expects the node to be authoritative for.

class InvalidGraphError:
    """Error raised when the access graph fails structural validation (dangling edges, missing node_ids, etc.)."""
    message: str                             # required, Human-readable error message.
    error_code: str                          # required, Machine-readable error code.
    details: list                            # required, List of specific validation failure description strings.

class ClassificationRegistryError:
    """Error raised when the classification registry YAML is malformed or fails schema validation."""
    message: str                             # required, Human-readable error message.
    error_code: str                          # required, Machine-readable error code.
    source_path: str                         # required, Path to the classifications.yaml file that failed validation.
    details: list                            # required, List of specific validation failure description strings.

TraversalPredicate = primitive  # A callable (GraphNode) -> bool used as an optional predicate for early termination in BFS/DFS. When it returns False for a node, that node's subtree is pruned.

def register_graph(
    graph_data: dict,
) -> GraphSnapshot:
    """
    Validates and atomically registers a new access graph into the store. Parses the input dict into an AccessGraph model, enforces structural validity (no dangling edges, node_id key consistency), builds the AuthorityMap with exclusivity checking (C004/FA-A-003), and performs an atomic validate-then-swap to replace the current snapshot. If validation fails, the previous snapshot remains unchanged.

    Preconditions:
      - graph_data is a non-empty dict
      - graph_data contains a 'nodes' key with at least one node entry

    Postconditions:
      - The store's current snapshot is the newly validated GraphSnapshot
      - The AuthorityMap in the snapshot has no duplicate domain assignments
      - All edge targets in the graph reference existing node_ids
      - The previous snapshot is fully replaced (atomic swap)

    Errors:
      - duplicate_authority (DuplicateAuthorityError): Two or more nodes in graph_data declare authority for the same domain
          domain: the contested domain
          claiming_nodes: list of conflicting node_ids
      - invalid_graph_structure (InvalidGraphError): Graph has dangling edges (target node_id not in nodes dict) or node_id key mismatches
          details: list of specific structural failures
      - empty_graph (InvalidGraphError): graph_data is empty or contains no nodes
          details: ['Graph must contain at least one node']
      - schema_validation_error (InvalidGraphError): graph_data does not conform to AccessGraph Pydantic schema
          details: Pydantic validation error details

    Side effects: Replaces the current graph snapshot in the store (mutable state)
    Idempotent: yes
    """
    ...

def register_graph_from_file(
    file_path: str,            # length(min=1)
) -> GraphSnapshot:
    """
    Loads access_graph.json from the given file path and delegates to register_graph. Thin I/O wrapper that reads JSON via pathlib, then calls register_graph with the parsed dict.

    Preconditions:
      - file_path points to an existing, readable JSON file

    Postconditions:
      - The store's current snapshot is the newly validated GraphSnapshot from the file
      - All register_graph postconditions hold

    Errors:
      - file_not_found (RegistryError): The file at file_path does not exist
          error_code: FILE_NOT_FOUND
          context: {'file_path': '<path>'}
      - file_not_readable (RegistryError): The file at file_path is not readable or is not valid JSON
          error_code: FILE_READ_ERROR
          context: {'file_path': '<path>'}
      - duplicate_authority (DuplicateAuthorityError): Delegated from register_graph
      - invalid_graph_structure (InvalidGraphError): Delegated from register_graph

    Side effects: none
    Idempotent: yes
    """
    ...

def get_authority(
    domain: str,               # length(min=1)
) -> str:
    """
    Returns the node_id that holds exclusive authority for the given domain, or None if no node is authoritative for that domain.

    Preconditions:
      - A graph has been registered (current snapshot is not None)

    Postconditions:
      - If a node is authoritative, returns that node_id; otherwise returns empty string to represent no authority (caller checks for empty)
      - The store state is unchanged

    Errors:
      - no_graph_registered (RegistryError): No graph has been registered yet (store has no current snapshot)
          error_code: NO_GRAPH
          message: No access graph has been registered

    Side effects: none
    Idempotent: yes
    """
    ...

def get_domains_for_node(
    node_id: str,              # length(min=1)
) -> list:
    """
    Returns the list of domains that a given node is authoritative for. Returns an empty list if the node exists but has no authority domains.

    Preconditions:
      - A graph has been registered (current snapshot is not None)

    Postconditions:
      - Returns a list of domain strings (possibly empty) that the given node is authoritative for
      - The store state is unchanged

    Errors:
      - no_graph_registered (RegistryError): No graph has been registered yet
          error_code: NO_GRAPH
      - node_not_found (NodeNotFoundError): node_id does not exist in the current access graph
          node_id: the missing node_id

    Side effects: none
    Idempotent: yes
    """
    ...

def get_node(
    node_id: str,              # length(min=1)
) -> GraphNode:
    """
    Returns the GraphNode for a given node_id from the current access graph snapshot.

    Preconditions:
      - A graph has been registered (current snapshot is not None)

    Postconditions:
      - Returns the GraphNode with the given node_id
      - The store state is unchanged

    Errors:
      - no_graph_registered (RegistryError): No graph has been registered yet
          error_code: NO_GRAPH
      - node_not_found (NodeNotFoundError): node_id does not exist in the current access graph
          node_id: the missing node_id

    Side effects: none
    Idempotent: yes
    """
    ...

def get_all_node_ids() -> list:
    """
    Returns a list of all node_ids in the current access graph.

    Preconditions:
      - A graph has been registered (current snapshot is not None)

    Postconditions:
      - Returns a list of all node_id strings in the current graph
      - The store state is unchanged

    Errors:
      - no_graph_registered (RegistryError): No graph has been registered yet
          error_code: NO_GRAPH

    Side effects: none
    Idempotent: yes
    """
    ...

def neighbors(
    node_id: str,              # length(min=1)
) -> list:
    """
    Returns the list of direct neighbors (outgoing edges) for a given node_id. Each entry includes the target node_id and the connecting edge.

    Preconditions:
      - A graph has been registered (current snapshot is not None)

    Postconditions:
      - Returns a list of NeighborEntry structs for all outgoing edges from the given node
      - The store state is unchanged

    Errors:
      - no_graph_registered (RegistryError): No graph has been registered yet
          error_code: NO_GRAPH
      - node_not_found (NodeNotFoundError): node_id does not exist in the current access graph
          node_id: the missing node_id

    Side effects: none
    Idempotent: yes
    """
    ...

def bfs(
    start_node_id: str,        # length(min=1)
    max_depth: int = -1,       # range(min=-1)
    relation_types: list = [],
) -> TraversalResult:
    """
    Performs breadth-first traversal from a start node. Uses a visited-set for cycle detection. Supports optional max_depth to limit traversal depth, and an optional predicate for early termination (prune subtrees where predicate returns False). Returns a TraversalResult with visited nodes in BFS order, traversed edges, and depth map.

    Preconditions:
      - A graph has been registered (current snapshot is not None)
      - start_node_id exists in the current access graph

    Postconditions:
      - visited_nodes[0] == start_node_id
      - All nodes in visited_nodes are reachable from start_node_id within max_depth (if specified)
      - No node appears more than once in visited_nodes (cycle-safe)
      - depth_map[start_node_id] == 0
      - If max_depth >= 0, all depths in depth_map are <= max_depth
      - The store state is unchanged

    Errors:
      - no_graph_registered (RegistryError): No graph has been registered yet
          error_code: NO_GRAPH
      - start_node_not_found (NodeNotFoundError): start_node_id does not exist in the current access graph
          node_id: the missing start_node_id

    Side effects: none
    Idempotent: yes
    """
    ...

def dfs(
    start_node_id: str,        # length(min=1)
    max_depth: int = -1,       # range(min=-1)
    relation_types: list = [],
) -> TraversalResult:
    """
    Performs depth-first traversal from a start node. Uses a visited-set for cycle detection. Supports optional max_depth to limit traversal depth, and an optional predicate for early termination (prune subtrees where predicate returns False). Returns a TraversalResult with visited nodes in DFS order, traversed edges, and depth map.

    Preconditions:
      - A graph has been registered (current snapshot is not None)
      - start_node_id exists in the current access graph

    Postconditions:
      - visited_nodes[0] == start_node_id
      - All nodes in visited_nodes are reachable from start_node_id within max_depth (if specified)
      - No node appears more than once in visited_nodes (cycle-safe)
      - depth_map[start_node_id] == 0
      - If max_depth >= 0, all depths in depth_map are <= max_depth
      - The store state is unchanged

    Errors:
      - no_graph_registered (RegistryError): No graph has been registered yet
          error_code: NO_GRAPH
      - start_node_not_found (NodeNotFoundError): start_node_id does not exist in the current access graph
          node_id: the missing start_node_id

    Side effects: none
    Idempotent: yes
    """
    ...

def load_classification_registry(
    file_path: str,            # length(min=1)
) -> ClassificationRegistry:
    """
    Loads and validates a ClassificationRegistry from a classifications.yaml file. Parses YAML via PyYAML, validates each rule against the ClassificationRule Pydantic model, and returns a frozen ClassificationRegistry. Does NOT cross-validate against the access graph — use validate_classifications_against_graph for that.

    Preconditions:
      - file_path points to an existing, readable YAML file

    Postconditions:
      - The returned ClassificationRegistry contains all rules from the file in order
      - Every rule has a non-empty field_pattern, a valid DataClassificationTier, and a non-empty authoritative_node
      - The store state is unchanged (classification registry is returned, not stored internally)

    Errors:
      - file_not_found (ClassificationRegistryError): The file at file_path does not exist
          source_path: <path>
          details: ['File not found']
      - file_not_readable (ClassificationRegistryError): The file at file_path is not readable or is not valid YAML
          source_path: <path>
          details: ['YAML parse error: ...']
      - schema_validation_error (ClassificationRegistryError): One or more rules do not conform to ClassificationRule schema
          source_path: <path>
          details: list of validation errors

    Side effects: none
    Idempotent: yes
    """
    ...

def validate_classifications_against_graph(
    classification_registry: ClassificationRegistry,
    strict: bool = true,
) -> list:
    """
    Cross-validates a ClassificationRegistry against the current access graph (FA-A-030). For each classification rule, checks that the authoritative_node exists in the graph and that the node actually declares authority for at least one domain. Returns a list of ValidationFinding structs. Raises AuthorityMismatchError if any CRITICAL findings are found (strict mode) or returns all findings for caller evaluation (lenient mode).

    Preconditions:
      - A graph has been registered (current snapshot is not None)
      - classification_registry is a valid ClassificationRegistry

    Postconditions:
      - Returns a list of ValidationFinding structs (possibly empty if all rules pass)
      - If strict=true and any CRITICAL finding exists, an AuthorityMismatchError is raised instead of returning
      - The store state is unchanged

    Errors:
      - no_graph_registered (RegistryError): No graph has been registered yet
          error_code: NO_GRAPH
      - authority_mismatch_strict (AuthorityMismatchError): strict=true and a classification rule references a node that does not exist in the graph or does not declare expected authority
          rule_index: index of offending rule
          authoritative_node: the mismatched node_id

    Side effects: none
    Idempotent: yes
    """
    ...

def get_current_snapshot() -> GraphSnapshot:
    """
    Returns the current GraphSnapshot (AccessGraph + AuthorityMap) or None if no graph has been registered yet.

    Postconditions:
      - Returns the current GraphSnapshot if a graph has been registered, or raises if none registered
      - The store state is unchanged

    Errors:
      - no_graph_registered (RegistryError): No graph has been registered yet
          error_code: NO_GRAPH

    Side effects: none
    Idempotent: yes
    """
    ...

def build_authority_map(
    access_graph: AccessGraph,
) -> AuthorityMap:
    """
    Builds an AuthorityMap from an AccessGraph by scanning all nodes' authority_domains. Enforces domain exclusivity: if any domain is claimed by multiple nodes, raises DuplicateAuthorityError. This is a pure function (classmethod/staticmethod) used internally by register_graph and can be called standalone for testing.

    Preconditions:
      - access_graph is a valid AccessGraph model

    Postconditions:
      - Every domain in every node's authority_domains appears exactly once in domain_to_node
      - node_to_domains is the exact inverse of domain_to_node
      - len(domain_to_node) == total number of unique authority domain declarations across all nodes

    Errors:
      - duplicate_authority (DuplicateAuthorityError): Two or more nodes declare authority for the same domain
          domain: the contested domain
          claiming_nodes: list of conflicting node_ids

    Side effects: none
    Idempotent: yes
    """
    ...

def classify_field(
    field_name: str,           # length(min=1)
    classification_registry: ClassificationRegistry,
) -> ClassificationRule:
    """
    Matches a field name against the classification registry rules using fnmatch/regex patterns. Returns the first matching ClassificationRule, or None if no rule matches. Rules are evaluated in order; first match wins.

    Preconditions:
      - classification_registry is a valid ClassificationRegistry

    Postconditions:
      - If a match is found, returns the first matching ClassificationRule (by rule order)
      - If no match is found, returns None (the output type is effectively Optional[ClassificationRule])
      - No state is mutated

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['DataClassificationTier', 'FindingSeverity', 'RelationType', 'Edge', 'GraphNode', 'AccessGraph', 'AuthorityMap', 'ClassificationRule', 'ClassificationRegistry', 'GraphSnapshot', 'TraversalResult', 'NeighborEntry', 'ValidationFinding', 'RegistryError', 'DuplicateAuthorityError', 'NodeNotFoundError', 'AuthorityMismatchError', 'InvalidGraphError', 'ClassificationRegistryError', 'register_graph', 'register_graph_from_file', 'get_authority', 'get_domains_for_node', 'get_node', 'get_all_node_ids', 'neighbors', 'bfs', 'dfs', 'load_classification_registry', 'validate_classifications_against_graph', 'get_current_snapshot', 'build_authority_map', 'classify_field']
