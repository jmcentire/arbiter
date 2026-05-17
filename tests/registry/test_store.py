from arbiter.registry.store import register_graph


def test_register_graph_accepts_components_alias_without_mutating_input():
    graph_data = {
        "components": {
            "api": {
                "node_id": "api",
                "authority_domains": ["orders"],
                "edges": [],
            }
        },
        "graph_version": "1",
        "created_at": "2024-01-01T00:00:00+00:00",
    }

    snapshot = register_graph(graph_data)

    assert "api" in snapshot.access_graph.nodes
    assert snapshot.authority_map.domain_to_node == {"orders": "api"}
    assert "components" in graph_data
    assert "nodes" not in graph_data


def test_register_graph_prefers_nodes_when_components_also_present():
    graph_data = {
        "components": {
            "ignored": {
                "node_id": "ignored",
                "authority_domains": ["ignored"],
                "edges": [],
            }
        },
        "nodes": {
            "api": {
                "node_id": "api",
                "authority_domains": ["orders"],
                "edges": [],
            }
        },
    }

    snapshot = register_graph(graph_data)

    assert set(snapshot.access_graph.nodes) == {"api"}
    assert snapshot.authority_map.domain_to_node == {"orders": "api"}
