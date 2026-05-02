# === Blast Radius & Soak Computation (blast) v1 ===
# Blast radius: BFS/DFS traversal of access graph edges from a changed node, collecting all reachable nodes and their data tiers. Classifies result per rules: PUBLIC-only→AUTO_MERGE, PUBLIC+PII→SOAK, any FINANCIAL/AUTH→HUMAN_GATE, any COMPLIANCE→HUMAN_GATE+legal_flag, unauthorized tier→HUMAN_GATE, LOW_TRUST_AUTHORITATIVE→HUMAN_GATE. Traversal is bounded by visited-set to handle cycles efficiently (rabbit hole patch). Soak computation: soak_duration = base_duration(tier) * (2.0 - trust_score) * max(1.0, sqrt(target_requests / observed_rate_rps)). Monotonic in both trust and volume (FA-A-009, FA-A-010). Fires human gate webhook when HUMAN_GATE triggered.

# Module invariants:
#   - trust_score is always in the closed interval [0.0, 1.0] for every NodeMetadata instance
#   - DataTier has a total severity order: PUBLIC < PII < FINANCIAL < AUTH < COMPLIANCE
#   - ActionCategory has a total severity order: AUTO_MERGE < SOAK < HUMAN_GATE
#   - Classification is max over per-node ActionCategory values — the highest severity wins
#   - legal_flag is True if and only if action == HUMAN_GATE and at least one reachable node has DataTier.COMPLIANCE
#   - soak_duration is None when action != SOAK; soak_duration is a positive timedelta when action == SOAK
#   - BFS traversal terminates even on cyclic graphs due to visited-set bounding (rabbit hole patch)
#   - soak_duration is monotonically non-decreasing as trust_score decreases (FA-A-009)
#   - soak_duration is monotonically non-decreasing as (target_requests / observed_rate_rps) increases (FA-A-010)
#   - All datetime fields are UTC (tzinfo == timezone.utc)
#   - The trust ledger is append-only — trust_score values are computed from the ledger, never mutated here
#   - observed_rate_rps is always strictly positive (floored to epsilon = 1e-9 if necessary)
#   - BlastResult.reachable_nodes always includes at least the origin node
#   - AccessGraph adjacency and metadata are consistent: every node in adjacency keys/values exists in metadata
#   - Policy calculations use raw trust_score float, never display tiers

class DataTier(Enum):
    """Data classification tier with a total severity order. PUBLIC < PII < FINANCIAL < AUTH < COMPLIANCE. Used in blast radius classification to determine action category."""
    PUBLIC = "PUBLIC"
    PII = "PII"
    FINANCIAL = "FINANCIAL"
    AUTH = "AUTH"
    COMPLIANCE = "COMPLIANCE"

class ActionCategory(Enum):
    """Blast radius action classification with a total severity order. AUTO_MERGE < SOAK < HUMAN_GATE. The final action for a blast result is max over all per-node actions."""
    AUTO_MERGE = "AUTO_MERGE"
    SOAK = "SOAK"
    HUMAN_GATE = "HUMAN_GATE"

NodeId = primitive  # Type-safe node identifier. NewType('NodeId', str). Must be a non-empty string uniquely identifying a node in the access graph.

Timedelta = primitive  # Python datetime.timedelta representing a duration. Used for soak durations and base durations.

Datetime = primitive  # Python datetime.datetime. Must always carry tzinfo=timezone.utc.

class NodeMetadata:
    """Immutable metadata for a single node in the access graph. Frozen Pydantic v2 model."""
    node_id: NodeId                          # required, length(min=1), Unique identifier for this node in the access graph.
    data_tier: DataTier                      # required, The data classification tier of this node.
    trust_score: float                       # required, range(min=0.0,max=1.0), Raw trust score computed from the trust ledger. Must be in [0.0, 1.0]. Policy calculations use this raw value, never display tiers.
    authorized_tiers: list                   # required, Set of DataTier values this node is authorized to access. If the node's data_tier is not in authorized_tiers, it triggers HUMAN_GATE.
    is_authoritative: bool                   # required, Whether this node is authoritative (declared via manifest). Trust is earned, authority is declared — these are distinct concepts.

class AccessGraphEdge:
    """A directed edge in the access graph from source to target."""
    source: NodeId                           # required, Source node of the directed edge.
    target: NodeId                           # required, Target node of the directed edge.

class AccessGraph:
    """Mutable access graph with adjacency list and node metadata. Builder pattern — not frozen. Adjacency is a dict mapping NodeId to list of NodeId (neighbors). Metadata is a dict mapping NodeId to NodeMetadata. Invariant: every node referenced in adjacency must have a corresponding metadata entry."""
    adjacency: dict                          # required, Adjacency list: maps each NodeId to the list of NodeIds it can reach via directed edges.
    metadata: dict                           # required, Maps each NodeId to its NodeMetadata. Every node in adjacency keys and values must exist in this dict.

class NodeBlastDetail:
    """Per-node detail within a blast radius result. Frozen Pydantic v2 model."""
    node_id: NodeId                          # required, The node this detail describes.
    data_tier: DataTier                      # required, Data classification tier of this node.
    trust_score: float                       # required, Raw trust score of this node.
    is_authoritative: bool                   # required, Whether this node is authoritative.
    is_authorized_for_tier: bool             # required, Whether this node's data_tier is within its authorized_tiers.
    node_action: ActionCategory              # required, The action classification for this individual node before max-over-nodes aggregation.
    depth: int                               # required, range(min=0), BFS depth from the origin node. Origin has depth 0.

class TraversalResult:
    """Result of BFS traversal of the access graph from an origin node. Frozen Pydantic v2 model. Contains all reachable nodes with their metadata and depth."""
    origin: NodeId                           # required, The starting node for the traversal.
    reachable_nodes: list                    # required, Frozenset of all reachable NodeIds including the origin.
    node_details: list                       # required, Per-node traversal details including metadata and BFS depth.
    highest_data_tier: DataTier              # required, The maximum DataTier among all reachable nodes by severity order.
    max_depth_reached: int                   # required, The maximum BFS depth reached during traversal.
    cycle_detected: bool                     # required, True if the traversal encountered at least one back-edge (cycle) during BFS.

class ClassificationResult:
    """Result of blast radius classification. Frozen Pydantic v2 model. Contains the action category and legal_flag."""
    action: ActionCategory                   # required, The aggregated action category (max over all per-node actions).
    legal_flag: bool                         # required, True if any reachable node has DataTier.COMPLIANCE and action is HUMAN_GATE.
    contributing_nodes: list                 # required, NodeIds of nodes that contributed to the highest action classification.

class SoakParams:
    """Parameters for soak duration computation. Frozen Pydantic v2 model. base_durations maps each DataTier to its base soak timedelta."""
    base_durations: dict                     # required, Maps each DataTier to its base soak duration (timedelta). All five DataTier values must have an entry.
    target_requests: float                   # required, range(min=0.0,exclusive_min=true), Target number of requests that should be observed during soak. Must be positive.
    observed_rate_rps: float                 # required, range(min=0.0,exclusive_min=true), Observed request rate in requests per second. Must be strictly positive. Floored to epsilon (1e-9) internally to prevent division by zero.
    low_trust_threshold: float = 0.3         # optional, range(min=0.0,max=1.0), Trust score threshold below which an authoritative node triggers HUMAN_GATE (LOW_TRUST_AUTHORITATIVE rule). Must be in [0.0, 1.0].

class BlastResult:
    """Complete blast radius evaluation result. Frozen Pydantic v2 model. Aggregates traversal, classification, and soak computation into a single immutable result."""
    origin_node: NodeId                      # required, The origin node from which blast radius was computed.
    reachable_nodes: list                    # required, Frozenset of all reachable NodeIds including the origin.
    highest_data_tier: DataTier              # required, The maximum DataTier among all reachable nodes by severity order.
    action: ActionCategory                   # required, The final aggregated action category for this blast radius.
    legal_flag: bool                         # required, True only when action == HUMAN_GATE and at least one reachable node has DataTier.COMPLIANCE.
    soak_duration: Timedelta = None          # optional, Computed soak duration. Present (positive timedelta) only when action == SOAK. None otherwise.
    per_node_details: list                   # required, Detailed per-node blast radius information.
    computed_at: Datetime                    # required, UTC timestamp of when this result was computed. Must have tzinfo=timezone.utc.
    cycle_detected: bool                     # required, Whether cycles were detected during traversal.
    max_depth_reached: int                   # required, Maximum BFS depth reached during traversal.
    contributing_nodes: list                 # required, NodeIds that contributed to the highest action classification.

class HumanGateNotifier:
    """Protocol (typing.Protocol) for human gate webhook dispatch. Implementations must define notify(result: BlastResult) -> None. Injectable via dependency injection for testability — tests provide a mock notifier with no network calls."""
    notify: str                              # required, Protocol method signature: def notify(self, result: BlastResult) -> None. Dispatches a human gate notification webhook for the given blast result.

def compute_blast_radius(
    graph: AccessGraph,
    origin: NodeId,
    max_depth: int = None,     # range(min=0)
) -> TraversalResult:
    """
    Pure BFS traversal of the access graph from an origin node. Collects all reachable nodes with their metadata and BFS depth. Uses a visited-set to handle cycles efficiently (rabbit hole patch). Optionally bounded by max_depth. Returns a TraversalResult with all reachable nodes, per-node details, highest data tier, and cycle detection flag.

    Preconditions:
      - origin must exist in graph.metadata
      - graph.adjacency and graph.metadata must be consistent: every node in adjacency keys/values must have a metadata entry
      - If max_depth is provided, it must be >= 0

    Postconditions:
      - result.origin == origin
      - origin is in result.reachable_nodes
      - len(result.reachable_nodes) == len(result.node_details)
      - All nodes in result.reachable_nodes have corresponding entries in result.node_details
      - result.highest_data_tier is the maximum DataTier by severity order among all reachable nodes
      - result.max_depth_reached <= max_depth if max_depth is not None
      - If cycle_detected is True, at least one back-edge was encountered during BFS

    Errors:
      - origin_not_found (NodeNotFoundError): origin does not exist in graph.metadata
          node_id: The NodeId that was not found in the graph
      - inconsistent_graph (GraphInconsistencyError): A node referenced in adjacency has no corresponding metadata entry
          missing_node_id: The NodeId missing from metadata
          referenced_by: The NodeId whose adjacency list references the missing node
      - invalid_max_depth (ValueError): max_depth is provided and is negative
          max_depth: The invalid max_depth value provided

    Side effects: none
    Idempotent: yes
    """
    ...

def classify_blast(
    traversal: TraversalResult,
    soak_params: SoakParams,
) -> ClassificationResult:
    """
    Pure classification function. Takes a TraversalResult and SoakParams (for low_trust_threshold) and determines the ActionCategory and legal_flag using max-over-nodes rule. Classification rules per node: PUBLIC-only→AUTO_MERGE, PII→SOAK, FINANCIAL/AUTH→HUMAN_GATE, COMPLIANCE→HUMAN_GATE+legal_flag, unauthorized tier→HUMAN_GATE, LOW_TRUST_AUTHORITATIVE (trust_score < low_trust_threshold and is_authoritative)→HUMAN_GATE. Final action is max over all per-node actions.

    Preconditions:
      - traversal.reachable_nodes is non-empty (always contains at least origin)
      - traversal.node_details has one entry per reachable node

    Postconditions:
      - result.action is the maximum ActionCategory over all per-node classifications
      - result.legal_flag is True only when result.action == HUMAN_GATE and at least one node has DataTier.COMPLIANCE
      - result.legal_flag is False when result.action != HUMAN_GATE
      - result.contributing_nodes is non-empty and contains only nodes whose per-node action equals the final action
      - If all reachable nodes have DataTier.PUBLIC and are authorized and none are low-trust authoritative, result.action == AUTO_MERGE

    Errors:
      - empty_traversal (ValueError): traversal.reachable_nodes is empty (should never happen if preconditions hold)
          origin: The origin node of the traversal

    Side effects: none
    Idempotent: yes
    """
    ...

def compute_soak_duration(
    tier: DataTier,
    trust_score: float,        # range(min=0.0,max=1.0)
    soak_params: SoakParams,
) -> Timedelta:
    """
    Pure function computing soak duration using the formula: soak_duration = base_duration(tier) * (2.0 - trust_score) * max(1.0, sqrt(target_requests / observed_rate_rps)). trust_score is clamped to [0.0, 1.0]. observed_rate_rps is floored to epsilon (1e-9) to prevent division by zero. The result is monotonically non-decreasing as trust_score decreases (FA-A-009) and as (target_requests / observed_rate_rps) increases (FA-A-010).

    Preconditions:
      - tier must have an entry in soak_params.base_durations
      - trust_score is in [0.0, 1.0]
      - soak_params.observed_rate_rps > 0
      - soak_params.target_requests > 0

    Postconditions:
      - result is a positive timedelta (> 0 seconds)
      - result == base_duration(tier) * (2.0 - clamped_trust_score) * max(1.0, sqrt(target_requests / floored_rps))
      - Monotonically non-decreasing as trust_score decreases for fixed tier, target_requests, observed_rate_rps
      - Monotonically non-decreasing as (target_requests / observed_rate_rps) increases for fixed tier, trust_score

    Errors:
      - missing_base_duration (KeyError): tier does not have an entry in soak_params.base_durations
          tier: The DataTier that was not found in base_durations
      - invalid_trust_score (ValueError): trust_score is NaN or infinite
          trust_score: The invalid trust_score value

    Side effects: none
    Idempotent: yes
    """
    ...

def evaluate_blast(
    graph: AccessGraph,
    origin: NodeId,
    soak_params: SoakParams,
    notifier: HumanGateNotifier = None,
    max_depth: int = None,     # range(min=0)
) -> BlastResult:
    """
    Orchestrator function that composes traversal, classification, soak computation, and optional human gate notification into a single BlastResult. Calls compute_blast_radius, then classify_blast, then compute_soak_duration (if action==SOAK), then optionally fires the HumanGateNotifier if action==HUMAN_GATE. This is the primary entry point for blast radius evaluation.

    Preconditions:
      - origin must exist in graph.metadata
      - graph must be consistent (all adjacency references have metadata)
      - soak_params.base_durations must contain entries for all DataTier values

    Postconditions:
      - result.origin_node == origin
      - result.computed_at has tzinfo == timezone.utc
      - result.legal_flag == True implies result.action == HUMAN_GATE
      - result.soak_duration is not None implies result.action == SOAK
      - result.soak_duration is None implies result.action != SOAK
      - result.reachable_nodes contains origin
      - If action == HUMAN_GATE and notifier is not None, notifier.notify() was called exactly once with the result
      - If action != HUMAN_GATE or notifier is None, notifier.notify() was not called

    Errors:
      - origin_not_found (NodeNotFoundError): origin does not exist in graph.metadata
          node_id: The NodeId that was not found in the graph
      - inconsistent_graph (GraphInconsistencyError): A node referenced in adjacency has no corresponding metadata entry
          missing_node_id: The NodeId missing from metadata
          referenced_by: The NodeId whose adjacency list references the missing node
      - missing_base_duration (KeyError): The highest data tier for the blast radius has no entry in soak_params.base_durations (when action==SOAK)
          tier: The DataTier that was not found in base_durations
      - notification_failure (NotificationError): notifier.notify() raises an exception during HUMAN_GATE notification dispatch
          origin_node: The origin node of the blast result
          action: HUMAN_GATE
          underlying_error: String representation of the underlying exception

    Side effects: none
    Idempotent: no
    """
    ...

def add_node(
    graph: AccessGraph,
    metadata: NodeMetadata,
) -> AccessGraph:
    """
    Adds a node with its metadata to the AccessGraph. Builder pattern method on AccessGraph. If the node already exists, its metadata is replaced.

    Preconditions:
      - metadata.node_id is a non-empty string
      - metadata.trust_score is in [0.0, 1.0]

    Postconditions:
      - metadata.node_id is in graph.metadata after the call
      - If metadata.node_id was not previously in graph.adjacency, it is now present with an empty neighbor list
      - The returned graph is the same object as the input graph (builder pattern)

    Errors:
      - invalid_metadata (ValidationError): metadata fails Pydantic validation (e.g., trust_score out of range)
          node_id: The node_id in the invalid metadata
          field: The field that failed validation

    Side effects: none
    Idempotent: yes
    """
    ...

def add_edge(
    graph: AccessGraph,
    source: NodeId,
    target: NodeId,
) -> AccessGraph:
    """
    Adds a directed edge from source to target in the AccessGraph. Builder pattern method. Both source and target must already exist in graph.metadata.

    Preconditions:
      - source exists in graph.metadata
      - target exists in graph.metadata

    Postconditions:
      - target is in graph.adjacency[source]
      - The returned graph is the same object as the input graph (builder pattern)
      - No duplicate edges: if target was already in adjacency[source], no change

    Errors:
      - source_not_found (NodeNotFoundError): source does not exist in graph.metadata
          node_id: The source NodeId that was not found
      - target_not_found (NodeNotFoundError): target does not exist in graph.metadata
          node_id: The target NodeId that was not found

    Side effects: none
    Idempotent: yes
    """
    ...

def classify_node(
    detail: NodeBlastDetail,
    metadata: NodeMetadata,
    low_trust_threshold: float = 0.3, # range(min=0.0,max=1.0)
) -> ActionCategory:
    """
    Pure function that classifies a single node's ActionCategory based on its metadata and the low_trust_threshold. This is the per-node classification building block used by classify_blast. Rules: PUBLIC+authorized+not low_trust_authoritative→AUTO_MERGE, PII+authorized+not low_trust_authoritative→SOAK, FINANCIAL/AUTH→HUMAN_GATE, COMPLIANCE→HUMAN_GATE, unauthorized_tier→HUMAN_GATE, low_trust_authoritative→HUMAN_GATE.

    Preconditions:
      - detail.node_id == metadata.node_id
      - low_trust_threshold is in [0.0, 1.0]

    Postconditions:
      - If metadata.data_tier in (FINANCIAL, AUTH, COMPLIANCE), result >= HUMAN_GATE
      - If metadata.data_tier not in metadata.authorized_tiers, result == HUMAN_GATE
      - If metadata.is_authoritative and metadata.trust_score < low_trust_threshold, result == HUMAN_GATE
      - If metadata.data_tier == PUBLIC and authorized and not low_trust_authoritative, result == AUTO_MERGE
      - If metadata.data_tier == PII and authorized and not low_trust_authoritative, result == SOAK

    Errors:
      - node_id_mismatch (ValueError): detail.node_id != metadata.node_id
          detail_node_id: NodeId from detail
          metadata_node_id: NodeId from metadata

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['DataTier', 'ActionCategory', 'NodeMetadata', 'AccessGraphEdge', 'AccessGraph', 'NodeBlastDetail', 'TraversalResult', 'ClassificationResult', 'SoakParams', 'BlastResult', 'HumanGateNotifier', 'compute_blast_radius', 'NodeNotFoundError', 'GraphInconsistencyError', 'classify_blast', 'compute_soak_duration', 'evaluate_blast', 'NotificationError', 'add_node', 'ValidationError', 'add_edge', 'classify_node']
