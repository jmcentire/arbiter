"""Module-level graph store with atomic snapshot swap and authority map building."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .errors import (
    DuplicateAuthorityError,
    InvalidGraphError,
    NodeNotFoundError,
    RegistryError,
)
from .models import (
    AccessGraph,
    AuthorityMap,
    GraphNode,
    GraphSnapshot,
)

# ---------------------------------------------------------------------------
# Module-level mutable state
# ---------------------------------------------------------------------------
_snapshot: GraphSnapshot | None = None


def _require_snapshot() -> GraphSnapshot:
    """Return the current snapshot or raise if none registered."""
    if _snapshot is None:
        raise RegistryError(
            message="No access graph has been registered",
            error_code="NO_GRAPH",
        )
    return _snapshot


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_authority_map(access_graph: AccessGraph) -> AuthorityMap:
    """Build an AuthorityMap from an AccessGraph, enforcing domain exclusivity.

    Pure function -- no side effects. Raises DuplicateAuthorityError on
    duplicate domain claims.
    """
    domain_to_node: dict[str, str] = {}
    node_to_domains: dict[str, list[str]] = {}

    for node_id, node in access_graph.nodes.items():
        for domain in node.authority_domains:
            if domain in domain_to_node:
                existing = domain_to_node[domain]
                raise DuplicateAuthorityError(
                    message=(
                        f"Domain '{domain}' claimed by nodes "
                        f"'{existing}' and '{node_id}'"
                    ),
                    error_code="C004",
                    domain=domain,
                    claiming_nodes=sorted([existing, node_id]),
                )
            domain_to_node[domain] = node_id
        if node.authority_domains:
            node_to_domains[node_id] = list(node.authority_domains)

    return AuthorityMap(
        domain_to_node=domain_to_node,
        node_to_domains=node_to_domains,
    )


def register_graph(graph_data: dict[str, Any]) -> GraphSnapshot:
    """Validate and atomically register a new access graph."""
    global _snapshot

    if not graph_data:
        raise InvalidGraphError(
            message="Graph data is empty",
            error_code="EMPTY_GRAPH",
            details=["Graph must contain at least one node"],
        )

    # Accept Pact's "components" key as an alias for "nodes"
    if "nodes" not in graph_data and "components" in graph_data:
        graph_data["nodes"] = graph_data.pop("components")

    nodes_raw = graph_data.get("nodes")
    if not nodes_raw:
        raise InvalidGraphError(
            message="Graph contains no nodes",
            error_code="EMPTY_GRAPH",
            details=["Graph must contain at least one node"],
        )

    # Provide defaults for optional top-level fields
    if "graph_version" not in graph_data:
        graph_data["graph_version"] = "1"
    if "created_at" not in graph_data:
        graph_data["created_at"] = datetime.now(timezone.utc).isoformat()

    # Parse + structural validation (dangling edges, id/key mismatch)
    try:
        access_graph = AccessGraph(**graph_data)
    except DuplicateAuthorityError:
        raise
    except ValidationError as exc:
        raise InvalidGraphError(
            message="Graph failed schema validation",
            error_code="SCHEMA_VALIDATION_ERROR",
            details=[str(e) for e in exc.errors()],
        ) from exc
    except ValueError as exc:
        raise InvalidGraphError(
            message=str(exc),
            error_code="INVALID_STRUCTURE",
            details=[str(exc)],
        ) from exc

    # Build authority map (re-checks exclusivity outside the model_validator
    # so callers get a proper DuplicateAuthorityError)
    authority_map = build_authority_map(access_graph)

    new_snapshot = GraphSnapshot(
        access_graph=access_graph,
        authority_map=authority_map,
    )

    # Atomic swap
    _snapshot = new_snapshot
    return new_snapshot


def register_graph_from_file(file_path: str) -> GraphSnapshot:
    """Load access_graph.json from *file_path* and delegate to register_graph."""
    p = Path(file_path)
    if not p.exists():
        raise RegistryError(
            message=f"File not found: {file_path}",
            error_code="FILE_NOT_FOUND",
            context={"file_path": file_path},
        )
    try:
        raw = p.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as exc:
        raise RegistryError(
            message=f"Cannot read file: {file_path}: {exc}",
            error_code="FILE_READ_ERROR",
            context={"file_path": file_path},
        ) from exc

    return register_graph(data)


def get_authority(domain: str) -> str:
    """Return the node_id authoritative for *domain*, or empty string."""
    snap = _require_snapshot()
    return snap.authority_map.domain_to_node.get(domain, "")


def get_domains_for_node(node_id: str) -> list[str]:
    """Return domains that *node_id* is authoritative for."""
    snap = _require_snapshot()
    if node_id not in snap.access_graph.nodes:
        raise NodeNotFoundError(
            message=f"Node '{node_id}' not found in access graph",
            error_code="NODE_NOT_FOUND",
            node_id=node_id,
        )
    return list(snap.authority_map.node_to_domains.get(node_id, []))


def get_node(node_id: str) -> GraphNode:
    """Return the GraphNode for *node_id*."""
    snap = _require_snapshot()
    node = snap.access_graph.nodes.get(node_id)
    if node is None:
        raise NodeNotFoundError(
            message=f"Node '{node_id}' not found in access graph",
            error_code="NODE_NOT_FOUND",
            node_id=node_id,
        )
    return node


def get_all_node_ids() -> list[str]:
    """Return all node_ids in the current graph."""
    snap = _require_snapshot()
    return list(snap.access_graph.nodes.keys())


def get_current_snapshot() -> GraphSnapshot:
    """Return the current GraphSnapshot or raise if none registered."""
    return _require_snapshot()
