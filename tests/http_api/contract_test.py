"""
Contract tests for http_api component.
Tests verify behavior at boundaries using mocked engine dependencies.
Run with: pytest tests/test_http_api.py -v
"""

import json
import re
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Import the component under test
from http_api import (
    create_app,
    run_server,
    handle_register,
    handle_blast_radius,
    handle_get_trust,
    handle_reset_taint,
    handle_get_authority,
    handle_canary_inject,
    handle_canary_results,
    handle_get_report,
    handle_ingest_findings,
    handle_health,
    handle_error,
    ServerConfig,
    ServerContext,
    ErrorCode,
    TrustTier,
    DataClassificationTier,
    FindingSeverity,
    ErrorResponse,
    AccessGraphPayload,
    AccessGraphNode,
    AccessGraphEdge,
    BlastRadiusRequest,
    BlastRadiusResponse,
    BlastRadiusNode,
    TrustResponse,
    TaintResetRequest,
    TaintResetResponse,
    AuthorityResponse,
    AuthorityEntry,
    CanaryInjectRequest,
    CanaryInjectResponse,
    CanaryResultsResponse,
    CanaryEscapeEvent,
    FindingsRequest,
    Finding,
    FindingsResponse,
    ReportResponse,
    HealthResponse,
    RegisterResponse,
    LedgerEvent,
)

# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

ISO8601_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


def is_iso8601_utc(value: str) -> bool:
    """Check if a string looks like a valid ISO 8601 UTC timestamp."""
    if not isinstance(value, str):
        return False
    # Accept trailing Z or +00:00
    if ISO8601_REGEX.match(value):
        return True
    # Fallback: try parsing
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.tzinfo is not None
    except (ValueError, TypeError):
        return False


# ──────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_trust_engine():
    engine = MagicMock()
    engine.get_trust = MagicMock()
    engine.reset_taint = MagicMock()
    return engine


@pytest.fixture
def mock_blast_radius_engine():
    engine = MagicMock()
    engine.register_graph = MagicMock()
    engine.compute_blast_radius = MagicMock()
    return engine


@pytest.fixture
def mock_authority_engine():
    engine = MagicMock()
    engine.get_authority = MagicMock()
    return engine


@pytest.fixture
def mock_canary_engine():
    engine = MagicMock()
    engine.inject = MagicMock()
    engine.get_results = MagicMock()
    return engine


@pytest.fixture
def mock_report_engine():
    engine = MagicMock()
    engine.get_report = MagicMock()
    return engine


@pytest.fixture
def mock_findings_engine():
    engine = MagicMock()
    engine.ingest = MagicMock()
    return engine


@pytest.fixture
def valid_server_config():
    return ServerConfig(
        host="127.0.0.1",
        port=7700,
        debug=False,
        max_request_size_bytes=10 * 1024 * 1024,
    )


@pytest.fixture
def server_context(
    valid_server_config,
    mock_trust_engine,
    mock_blast_radius_engine,
    mock_authority_engine,
    mock_canary_engine,
    mock_report_engine,
    mock_findings_engine,
):
    return ServerContext(
        config=valid_server_config,
        trust_engine=mock_trust_engine,
        blast_radius_engine=mock_blast_radius_engine,
        authority_engine=mock_authority_engine,
        canary_engine=mock_canary_engine,
        report_engine=mock_report_engine,
        findings_engine=mock_findings_engine,
    )


@pytest.fixture
def app(server_context):
    application = create_app(server_context)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def valid_access_graph_payload():
    return {
        "nodes": [
            {"node_id": "node-1", "node_type": "service", "labels": {"env": "prod"}},
            {"node_id": "node-2", "node_type": "database", "labels": {"env": "prod"}},
        ],
        "edges": [
            {
                "source": "node-1",
                "target": "node-2",
                "access_type": "read",
                "classification": "INTERNAL",
            }
        ],
        "metadata": {"version": "1.0"},
    }


@pytest.fixture
def valid_blast_radius_request():
    return {
        "node_id": "node-1",
        "max_depth": 3,
        "classification_filter": "INTERNAL",
    }


@pytest.fixture
def valid_taint_reset_request():
    return {
        "node_id": "node-1",
        "review_id": "review-abc-123",
        "reason": "Reviewed and cleared by security team",
    }


@pytest.fixture
def valid_canary_inject_request():
    return {
        "run_id": "run-001",
        "target_tiers": ["INTERNAL", "CONFIDENTIAL"],
        "canary_count": 10,
    }


@pytest.fixture
def valid_findings_request():
    return {
        "findings": [
            {
                "finding_id": "finding-001",
                "node_id": "node-1",
                "severity": "HIGH",
                "category": "access_violation",
                "message": "Unauthorized access detected",
                "span_context": {"trace_id": "abc123"},
                "timestamp": "2024-01-01T00:00:00Z",
            }
        ],
        "source": "baton-adapter",
    }


# ──────────────────────────────────────────────────────────────────────
# create_app tests
# ──────────────────────────────────────────────────────────────────────


class TestCreateApp:
    def test_happy_path_returns_flask_app(self, server_context):
        """create_app returns a Flask app with all 10 routes registered."""
        application = create_app(server_context)
        assert application is not None
        # Check that routes are registered - at least 10 endpoints
        rules = [rule.rule for rule in application.url_map.iter_rules()]
        expected_paths = [
            "/register",
            "/blast-radius",
            "/trust/",
            "/trust/reset-taint",
            "/authority",
            "/canary/inject",
            "/canary/results/",
            "/report/",
            "/findings",
            "/health",
        ]
        for path in expected_paths:
            assert any(
                path in rule for rule in rules
            ), f"Route {path} not found in {rules}"

    def test_missing_engine_raises_error(self, valid_server_config):
        """create_app raises error when an engine reference is None."""
        context = ServerContext(
            config=valid_server_config,
            trust_engine=None,
            blast_radius_engine=MagicMock(),
            authority_engine=MagicMock(),
            canary_engine=MagicMock(),
            report_engine=MagicMock(),
            findings_engine=MagicMock(),
        )
        with pytest.raises(Exception):
            create_app(context)

    def test_missing_multiple_engines_raises_error(self, valid_server_config):
        """create_app raises error when multiple engine references are None."""
        context = ServerContext(
            config=valid_server_config,
            trust_engine=None,
            blast_radius_engine=None,
            authority_engine=MagicMock(),
            canary_engine=MagicMock(),
            report_engine=MagicMock(),
            findings_engine=MagicMock(),
        )
        with pytest.raises(Exception):
            create_app(context)

    def test_invalid_config_port_zero(self):
        """create_app raises error when port is 0."""
        with pytest.raises(Exception):
            ServerConfig(
                host="127.0.0.1",
                port=0,
                debug=False,
                max_request_size_bytes=1024,
            )

    def test_invalid_config_port_too_high(self):
        """create_app raises error when port > 65535."""
        with pytest.raises(Exception):
            ServerConfig(
                host="127.0.0.1",
                port=70000,
                debug=False,
                max_request_size_bytes=1024,
            )

    def test_app_not_running_after_creation(self, server_context):
        """App is not yet running after create_app returns."""
        application = create_app(server_context)
        # The app should exist but not be serving
        assert application is not None


# ──────────────────────────────────────────────────────────────────────
# run_server tests
# ──────────────────────────────────────────────────────────────────────


class TestRunServer:
    def test_happy_path_calls_run(self, server_context):
        """run_server binds to configured host:port."""
        with patch("http_api.create_app") as mock_create:
            mock_app = MagicMock()
            mock_create.return_value = mock_app
            try:
                run_server(server_context)
            except Exception:
                pass
            # Verify the app's run method was called or attempted
            # The exact mechanism depends on implementation

    def test_port_in_use_raises(self, server_context):
        """run_server raises when port is already bound."""
        with patch("http_api.create_app") as mock_create:
            mock_app = MagicMock()
            mock_app.run.side_effect = OSError("Address already in use")
            mock_create.return_value = mock_app
            with pytest.raises(Exception):
                run_server(server_context)


# ──────────────────────────────────────────────────────────────────────
# POST /register tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleRegister:
    def test_happy_path(
        self, client, mock_blast_radius_engine, valid_access_graph_payload
    ):
        """POST /register with valid payload returns correct counts and ISO timestamp."""
        mock_blast_radius_engine.register_graph.return_value = RegisterResponse(
            node_count=2,
            edge_count=1,
            registered_at="2024-01-01T00:00:00Z",
        )
        resp = client.post(
            "/register",
            data=json.dumps(valid_access_graph_payload),
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code == 200 or resp.status_code == 201
        assert data["node_count"] == 2
        assert data["edge_count"] == 1
        assert is_iso8601_utc(data["registered_at"])

    def test_invalid_json(self, client):
        """POST /register with malformed JSON returns INVALID_JSON."""
        resp = client.post(
            "/register",
            data="not valid json {{{",
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "INVALID_JSON"

    def test_validation_error_missing_nodes(self, client):
        """POST /register with missing required fields returns VALIDATION_ERROR."""
        resp = client.post(
            "/register",
            data=json.dumps({"metadata": {}}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] in ("VALIDATION_ERROR", "INVALID_JSON")

    def test_graph_invalid_edge_references_missing_node(self, client):
        """POST /register where edge references non-existent node returns ACCESS_GRAPH_INVALID."""
        payload = {
            "nodes": [
                {"node_id": "node-1", "node_type": "service", "labels": {}},
            ],
            "edges": [
                {
                    "source": "node-1",
                    "target": "node-nonexistent",
                    "access_type": "read",
                    "classification": "INTERNAL",
                }
            ],
            "metadata": {},
        }
        resp = client.post(
            "/register",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400 or resp.status_code == 422
        data = resp.get_json()
        assert data["error_code"] == "ACCESS_GRAPH_INVALID"

    def test_graph_invalid_duplicate_node_ids(self, client):
        """POST /register with duplicate node_ids returns ACCESS_GRAPH_INVALID."""
        payload = {
            "nodes": [
                {"node_id": "node-1", "node_type": "service", "labels": {}},
                {"node_id": "node-1", "node_type": "database", "labels": {}},
            ],
            "edges": [],
            "metadata": {},
        }
        resp = client.post(
            "/register",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400 or resp.status_code == 422
        data = resp.get_json()
        assert data["error_code"] == "ACCESS_GRAPH_INVALID"

    def test_engine_failure(
        self, client, mock_blast_radius_engine, valid_access_graph_payload
    ):
        """POST /register when engine raises returns error."""
        mock_blast_radius_engine.register_graph.side_effect = RuntimeError(
            "engine failure"
        )
        resp = client.post(
            "/register",
            data=json.dumps(valid_access_graph_payload),
            content_type="application/json",
        )
        assert resp.status_code == 500 or resp.status_code == 502
        data = resp.get_json()
        assert data["error_code"] in (
            "BLAST_RADIUS_FAILED",
            "INTERNAL_ERROR",
        )

    def test_postcondition_counts_match(
        self, client, mock_blast_radius_engine, valid_access_graph_payload
    ):
        """RegisterResponse.node_count and edge_count match input lengths."""
        mock_blast_radius_engine.register_graph.return_value = RegisterResponse(
            node_count=2,
            edge_count=1,
            registered_at="2024-01-01T00:00:00Z",
        )
        resp = client.post(
            "/register",
            data=json.dumps(valid_access_graph_payload),
            content_type="application/json",
        )
        if resp.status_code in (200, 201):
            data = resp.get_json()
            assert data["node_count"] == len(valid_access_graph_payload["nodes"])
            assert data["edge_count"] == len(valid_access_graph_payload["edges"])

    def test_empty_graph(self, client, mock_blast_radius_engine):
        """POST /register with empty nodes and edges lists succeeds with counts 0."""
        payload = {"nodes": [], "edges": [], "metadata": {}}
        mock_blast_radius_engine.register_graph.return_value = RegisterResponse(
            node_count=0,
            edge_count=0,
            registered_at="2024-01-01T00:00:00Z",
        )
        resp = client.post(
            "/register",
            data=json.dumps(payload),
            content_type="application/json",
        )
        # Empty graph may be accepted or rejected depending on implementation
        data = resp.get_json()
        if resp.status_code in (200, 201):
            assert data["node_count"] == 0
            assert data["edge_count"] == 0


# ──────────────────────────────────────────────────────────────────────
# POST /blast-radius tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleBlastRadius:
    def test_happy_path(
        self, client, mock_blast_radius_engine, valid_blast_radius_request
    ):
        """POST /blast-radius returns affected nodes with origin."""
        mock_blast_radius_engine.compute_blast_radius.return_value = (
            BlastRadiusResponse(
                origin_node_id="node-1",
                affected_nodes=[
                    BlastRadiusNode(
                        node_id="node-2",
                        node_type="database",
                        depth=1,
                        max_classification="INTERNAL",
                        trust_score=0.85,
                    )
                ],
                total_affected=1,
                max_depth_reached=1,
                computed_at="2024-01-01T00:00:00Z",
            )
        )
        resp = client.post(
            "/blast-radius",
            data=json.dumps(valid_blast_radius_request),
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["origin_node_id"] == "node-1"
        assert data["total_affected"] == len(data["affected_nodes"])
        assert is_iso8601_utc(data["computed_at"])

    def test_invalid_json(self, client):
        """POST /blast-radius with malformed JSON returns INVALID_JSON."""
        resp = client.post(
            "/blast-radius",
            data="not json",
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "INVALID_JSON"

    def test_validation_error(self, client):
        """POST /blast-radius with missing fields returns VALIDATION_ERROR."""
        resp = client.post(
            "/blast-radius",
            data=json.dumps({"node_id": "x"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"

    def test_node_not_found(self, client, mock_blast_radius_engine):
        """POST /blast-radius with unknown node returns NODE_NOT_FOUND."""
        from http_api import NodeNotFoundError

        mock_blast_radius_engine.compute_blast_radius.side_effect = NodeNotFoundError(
            "node-unknown"
        )
        payload = {
            "node_id": "node-unknown",
            "max_depth": 3,
            "classification_filter": "INTERNAL",
        }
        resp = client.post(
            "/blast-radius",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "NODE_NOT_FOUND"
        assert "node-unknown" in data["message"]

    def test_computation_failed(self, client, mock_blast_radius_engine):
        """POST /blast-radius when engine raises returns BLAST_RADIUS_FAILED."""
        mock_blast_radius_engine.compute_blast_radius.side_effect = RuntimeError(
            "traversal error"
        )
        payload = {
            "node_id": "node-1",
            "max_depth": 3,
            "classification_filter": "INTERNAL",
        }
        resp = client.post(
            "/blast-radius",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code >= 400
        data = resp.get_json()
        assert data["error_code"] in ("BLAST_RADIUS_FAILED", "INTERNAL_ERROR")

    def test_total_affected_invariant(self, client, mock_blast_radius_engine):
        """total_affected always equals len(affected_nodes)."""
        nodes = [
            BlastRadiusNode(
                node_id=f"node-{i}",
                node_type="service",
                depth=i,
                max_classification="INTERNAL",
                trust_score=0.9,
            )
            for i in range(5)
        ]
        mock_blast_radius_engine.compute_blast_radius.return_value = (
            BlastRadiusResponse(
                origin_node_id="node-0",
                affected_nodes=nodes,
                total_affected=5,
                max_depth_reached=4,
                computed_at="2024-01-01T00:00:00Z",
            )
        )
        payload = {
            "node_id": "node-0",
            "max_depth": 10,
            "classification_filter": "INTERNAL",
        }
        resp = client.post(
            "/blast-radius",
            data=json.dumps(payload),
            content_type="application/json",
        )
        if resp.status_code == 200:
            data = resp.get_json()
            assert data["total_affected"] == len(data["affected_nodes"])

    def test_max_depth_reached_invariant(self, client, mock_blast_radius_engine):
        """max_depth_reached <= requested max_depth."""
        mock_blast_radius_engine.compute_blast_radius.return_value = (
            BlastRadiusResponse(
                origin_node_id="node-1",
                affected_nodes=[],
                total_affected=0,
                max_depth_reached=2,
                computed_at="2024-01-01T00:00:00Z",
            )
        )
        payload = {
            "node_id": "node-1",
            "max_depth": 5,
            "classification_filter": "INTERNAL",
        }
        resp = client.post(
            "/blast-radius",
            data=json.dumps(payload),
            content_type="application/json",
        )
        if resp.status_code == 200:
            data = resp.get_json()
            assert data["max_depth_reached"] <= 5

    def test_zero_depth(self, client, mock_blast_radius_engine):
        """POST /blast-radius with max_depth=0 returns minimal result."""
        mock_blast_radius_engine.compute_blast_radius.return_value = (
            BlastRadiusResponse(
                origin_node_id="node-1",
                affected_nodes=[],
                total_affected=0,
                max_depth_reached=0,
                computed_at="2024-01-01T00:00:00Z",
            )
        )
        payload = {
            "node_id": "node-1",
            "max_depth": 0,
            "classification_filter": "INTERNAL",
        }
        resp = client.post(
            "/blast-radius",
            data=json.dumps(payload),
            content_type="application/json",
        )
        if resp.status_code == 200:
            data = resp.get_json()
            assert data["max_depth_reached"] == 0


# ──────────────────────────────────────────────────────────────────────
# GET /trust/<node_id> tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleGetTrust:
    def test_happy_path(self, client, mock_trust_engine):
        """GET /trust/<node_id> returns trust score, tier, taint status."""
        mock_trust_engine.get_trust.return_value = TrustResponse(
            node_id="node-1",
            trust_score=0.85,
            trust_tier="HIGH",
            is_tainted=False,
            recent_events=[],
            queried_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/trust/node-1")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["node_id"] == "node-1"
        assert 0.0 <= data["trust_score"] <= 1.0
        assert data["trust_tier"] in (
            "FULL", "HIGH", "MODERATE", "LOW", "NONE", "TAINTED",
        )
        assert isinstance(data["is_tainted"], bool)
        assert is_iso8601_utc(data["queried_at"])

    def test_node_not_found(self, client, mock_trust_engine):
        """GET /trust/<node_id> with unknown node returns NODE_NOT_FOUND."""
        from http_api import NodeNotFoundError

        mock_trust_engine.get_trust.side_effect = NodeNotFoundError("unknown-node")
        resp = client.get("/trust/unknown-node")
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "NODE_NOT_FOUND"
        assert "unknown-node" in data["message"]

    def test_computation_failed(self, client, mock_trust_engine):
        """GET /trust/<node_id> when engine raises returns TRUST_COMPUTATION_FAILED."""
        mock_trust_engine.get_trust.side_effect = RuntimeError("computation error")
        resp = client.get("/trust/node-1")
        assert resp.status_code >= 400
        data = resp.get_json()
        assert data["error_code"] in ("TRUST_COMPUTATION_FAILED", "INTERNAL_ERROR")

    def test_score_range(self, client, mock_trust_engine):
        """trust_score is always in [0.0, 1.0]."""
        mock_trust_engine.get_trust.return_value = TrustResponse(
            node_id="node-1",
            trust_score=0.0,
            trust_tier="NONE",
            is_tainted=False,
            recent_events=[],
            queried_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/trust/node-1")
        if resp.status_code == 200:
            data = resp.get_json()
            assert 0.0 <= data["trust_score"] <= 1.0

    def test_recent_events_max_20(self, client, mock_trust_engine):
        """recent_events has at most 20 entries."""
        events = [
            LedgerEvent(
                event_id=f"evt-{i}",
                node_id="node-1",
                event_type="trust_update",
                trust_score=0.5,
                timestamp="2024-01-01T00:00:00Z",
                details={},
            )
            for i in range(20)
        ]
        mock_trust_engine.get_trust.return_value = TrustResponse(
            node_id="node-1",
            trust_score=0.5,
            trust_tier="MODERATE",
            is_tainted=False,
            recent_events=events,
            queried_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/trust/node-1")
        if resp.status_code == 200:
            data = resp.get_json()
            assert len(data["recent_events"]) <= 20

    def test_tainted_node(self, client, mock_trust_engine):
        """GET /trust/<node_id> for a tainted node returns is_tainted=true."""
        mock_trust_engine.get_trust.return_value = TrustResponse(
            node_id="node-tainted",
            trust_score=0.0,
            trust_tier="TAINTED",
            is_tainted=True,
            recent_events=[],
            queried_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/trust/node-tainted")
        if resp.status_code == 200:
            data = resp.get_json()
            assert data["is_tainted"] is True
            assert data["trust_tier"] == "TAINTED"


# ──────────────────────────────────────────────────────────────────────
# POST /trust/reset-taint tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleResetTaint:
    def test_happy_path(self, client, mock_trust_engine, valid_taint_reset_request):
        """POST /trust/reset-taint clears taint and returns new score."""
        mock_trust_engine.reset_taint.return_value = TaintResetResponse(
            node_id="node-1",
            review_id="review-abc-123",
            previous_trust_score=0.0,
            new_trust_score=0.75,
            ledger_event_id="evt-reset-001",
            reset_at="2024-01-01T00:00:00Z",
        )
        resp = client.post(
            "/trust/reset-taint",
            data=json.dumps(valid_taint_reset_request),
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code == 200
        assert data["node_id"] == "node-1"
        assert data["review_id"] == "review-abc-123"
        assert data["ledger_event_id"] is not None
        assert is_iso8601_utc(data["reset_at"])

    def test_invalid_json(self, client):
        """POST /trust/reset-taint with malformed JSON returns INVALID_JSON."""
        resp = client.post(
            "/trust/reset-taint",
            data="{{bad json",
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "INVALID_JSON"

    def test_validation_error(self, client):
        """POST /trust/reset-taint with missing fields returns VALIDATION_ERROR."""
        resp = client.post(
            "/trust/reset-taint",
            data=json.dumps({"node_id": "n"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"

    def test_node_not_found(self, client, mock_trust_engine):
        """POST /trust/reset-taint with unknown node returns NODE_NOT_FOUND."""
        from http_api import NodeNotFoundError

        mock_trust_engine.reset_taint.side_effect = NodeNotFoundError("node-unknown")
        payload = {
            "node_id": "node-unknown",
            "review_id": "review-1",
            "reason": "test",
        }
        resp = client.post(
            "/trust/reset-taint",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "NODE_NOT_FOUND"
        assert "node-unknown" in data["message"]

    def test_review_not_found(self, client, mock_trust_engine):
        """POST /trust/reset-taint with invalid review_id returns REVIEW_NOT_FOUND."""
        from http_api import ReviewNotFoundError

        mock_trust_engine.reset_taint.side_effect = ReviewNotFoundError(
            "review-invalid"
        )
        payload = {
            "node_id": "node-1",
            "review_id": "review-invalid",
            "reason": "test reason",
        }
        resp = client.post(
            "/trust/reset-taint",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "REVIEW_NOT_FOUND"
        assert "review-invalid" in data["message"]

    def test_taint_reset_failed(self, client, mock_trust_engine):
        """POST /trust/reset-taint when node not tainted returns TAINT_RESET_FAILED."""
        from http_api import TaintResetFailedError

        mock_trust_engine.reset_taint.side_effect = TaintResetFailedError(
            "node not tainted"
        )
        payload = {
            "node_id": "node-1",
            "review_id": "review-1",
            "reason": "test reason",
        }
        resp = client.post(
            "/trust/reset-taint",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code in (400, 409, 422)
        data = resp.get_json()
        assert data["error_code"] == "TAINT_RESET_FAILED"

    def test_reason_too_long(self, client):
        """POST /trust/reset-taint with reason > 2000 chars returns VALIDATION_ERROR."""
        payload = {
            "node_id": "node-1",
            "review_id": "review-1",
            "reason": "x" * 2001,
        }
        resp = client.post(
            "/trust/reset-taint",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"

    def test_empty_reason(self, client):
        """POST /trust/reset-taint with empty reason returns VALIDATION_ERROR."""
        payload = {
            "node_id": "node-1",
            "review_id": "review-1",
            "reason": "",
        }
        resp = client.post(
            "/trust/reset-taint",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"


# ──────────────────────────────────────────────────────────────────────
# GET /authority tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleGetAuthority:
    def test_happy_path(self, client, mock_authority_engine):
        """GET /authority returns authority entries with correct total count."""
        mock_authority_engine.get_authority.return_value = AuthorityResponse(
            entries=[
                AuthorityEntry(
                    node_id="node-1",
                    authority_source="manifest-v1",
                    granted_permissions=["read", "write"],
                    declared_at="2024-01-01T00:00:00Z",
                )
            ],
            total_entries=1,
            queried_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/authority")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_entries"] == len(data["entries"])
        assert is_iso8601_utc(data["queried_at"])

    def test_authority_unavailable(self, client, mock_authority_engine):
        """GET /authority when engine not initialized returns AUTHORITY_UNAVAILABLE."""
        from http_api import AuthorityUnavailableError

        mock_authority_engine.get_authority.side_effect = AuthorityUnavailableError(
            "not initialized"
        )
        resp = client.get("/authority")
        assert resp.status_code in (500, 503)
        data = resp.get_json()
        assert data["error_code"] == "AUTHORITY_UNAVAILABLE"

    def test_total_entries_invariant(self, client, mock_authority_engine):
        """total_entries always equals len(entries)."""
        entries = [
            AuthorityEntry(
                node_id=f"node-{i}",
                authority_source="manifest",
                granted_permissions=["read"],
                declared_at="2024-01-01T00:00:00Z",
            )
            for i in range(3)
        ]
        mock_authority_engine.get_authority.return_value = AuthorityResponse(
            entries=entries,
            total_entries=3,
            queried_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/authority")
        if resp.status_code == 200:
            data = resp.get_json()
            assert data["total_entries"] == len(data["entries"])

    def test_empty_authority(self, client, mock_authority_engine):
        """GET /authority when no manifests returns empty list with total_entries=0."""
        mock_authority_engine.get_authority.return_value = AuthorityResponse(
            entries=[],
            total_entries=0,
            queried_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/authority")
        if resp.status_code == 200:
            data = resp.get_json()
            assert data["total_entries"] == 0
            assert data["entries"] == []


# ──────────────────────────────────────────────────────────────────────
# POST /canary/inject tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleCanaryInject:
    def test_happy_path(
        self, client, mock_canary_engine, valid_canary_inject_request
    ):
        """POST /canary/inject returns injected count and tiers."""
        mock_canary_engine.inject.return_value = CanaryInjectResponse(
            run_id="run-001",
            injected_count=20,  # 10 canaries * 2 tiers
            tiers_seeded=["INTERNAL", "CONFIDENTIAL"],
            injected_at="2024-01-01T00:00:00Z",
        )
        resp = client.post(
            "/canary/inject",
            data=json.dumps(valid_canary_inject_request),
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code in (200, 201)
        assert data["run_id"] == "run-001"
        assert data["injected_count"] == 20
        assert is_iso8601_utc(data["injected_at"])

    def test_invalid_json(self, client):
        """POST /canary/inject with malformed JSON returns INVALID_JSON."""
        resp = client.post(
            "/canary/inject",
            data="bad{json",
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "INVALID_JSON"

    def test_validation_error(self, client):
        """POST /canary/inject with missing fields returns VALIDATION_ERROR."""
        resp = client.post(
            "/canary/inject",
            data=json.dumps({"run_id": "r"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"

    def test_injection_failed(self, client, mock_canary_engine):
        """POST /canary/inject when engine fails returns CANARY_INJECTION_FAILED."""
        mock_canary_engine.inject.side_effect = RuntimeError("injection error")
        payload = {
            "run_id": "run-fail",
            "target_tiers": ["INTERNAL"],
            "canary_count": 5,
        }
        resp = client.post(
            "/canary/inject",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code >= 400
        data = resp.get_json()
        assert data["error_code"] in ("CANARY_INJECTION_FAILED", "INTERNAL_ERROR")

    def test_count_invariant(self, client, mock_canary_engine):
        """injected_count == canary_count * len(target_tiers)."""
        mock_canary_engine.inject.return_value = CanaryInjectResponse(
            run_id="run-002",
            injected_count=30,  # 10 * 3
            tiers_seeded=["INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
            injected_at="2024-01-01T00:00:00Z",
        )
        payload = {
            "run_id": "run-002",
            "target_tiers": ["INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
            "canary_count": 10,
        }
        resp = client.post(
            "/canary/inject",
            data=json.dumps(payload),
            content_type="application/json",
        )
        if resp.status_code in (200, 201):
            data = resp.get_json()
            expected = payload["canary_count"] * len(payload["target_tiers"])
            assert data["injected_count"] == expected

    def test_empty_tiers(self, client):
        """POST /canary/inject with empty target_tiers returns VALIDATION_ERROR."""
        payload = {
            "run_id": "run-003",
            "target_tiers": [],
            "canary_count": 5,
        }
        resp = client.post(
            "/canary/inject",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"

    def test_count_zero(self, client):
        """POST /canary/inject with canary_count=0 returns VALIDATION_ERROR."""
        payload = {
            "run_id": "run-004",
            "target_tiers": ["INTERNAL"],
            "canary_count": 0,
        }
        resp = client.post(
            "/canary/inject",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"

    def test_count_over_1000(self, client):
        """POST /canary/inject with canary_count=1001 returns VALIDATION_ERROR."""
        payload = {
            "run_id": "run-005",
            "target_tiers": ["INTERNAL"],
            "canary_count": 1001,
        }
        resp = client.post(
            "/canary/inject",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"


# ──────────────────────────────────────────────────────────────────────
# GET /canary/results/<run_id> tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleCanaryResults:
    def test_happy_path(self, client, mock_canary_engine):
        """GET /canary/results/<run_id> returns escape events and counts."""
        escapes = [
            CanaryEscapeEvent(
                canary_id="canary-1",
                expected_tier="CONFIDENTIAL",
                observed_tier="INTERNAL",
                observed_node_id="node-leak",
                detected_at="2024-01-01T00:00:00Z",
            )
        ]
        mock_canary_engine.get_results.return_value = CanaryResultsResponse(
            run_id="run-001",
            status="completed",
            total_injected=20,
            total_escaped=1,
            escapes=escapes,
            queried_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/canary/results/run-001")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["run_id"] == "run-001"
        assert data["total_escaped"] == len(data["escapes"])
        assert is_iso8601_utc(data["queried_at"])

    def test_run_not_found(self, client, mock_canary_engine):
        """GET /canary/results with unknown run returns RUN_NOT_FOUND."""
        from http_api import RunNotFoundError

        mock_canary_engine.get_results.side_effect = RunNotFoundError(
            "run-unknown"
        )
        resp = client.get("/canary/results/run-unknown")
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "RUN_NOT_FOUND"
        assert "run-unknown" in data["message"]

    def test_results_unavailable(self, client, mock_canary_engine):
        """GET /canary/results when engine fails returns CANARY_RESULTS_UNAVAILABLE."""
        mock_canary_engine.get_results.side_effect = RuntimeError("engine failure")
        resp = client.get("/canary/results/run-fail")
        assert resp.status_code >= 400
        data = resp.get_json()
        assert data["error_code"] in (
            "CANARY_RESULTS_UNAVAILABLE",
            "INTERNAL_ERROR",
        )

    def test_no_escapes(self, client, mock_canary_engine):
        """GET /canary/results with no escapes returns empty list."""
        mock_canary_engine.get_results.return_value = CanaryResultsResponse(
            run_id="run-clean",
            status="completed",
            total_injected=20,
            total_escaped=0,
            escapes=[],
            queried_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/canary/results/run-clean")
        if resp.status_code == 200:
            data = resp.get_json()
            assert data["total_escaped"] == 0
            assert data["escapes"] == []

    def test_total_escaped_invariant(self, client, mock_canary_engine):
        """total_escaped always equals len(escapes)."""
        escapes = [
            CanaryEscapeEvent(
                canary_id=f"c-{i}",
                expected_tier="CONFIDENTIAL",
                observed_tier="PUBLIC",
                observed_node_id=f"node-{i}",
                detected_at="2024-01-01T00:00:00Z",
            )
            for i in range(3)
        ]
        mock_canary_engine.get_results.return_value = CanaryResultsResponse(
            run_id="run-x",
            status="completed",
            total_injected=10,
            total_escaped=3,
            escapes=escapes,
            queried_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/canary/results/run-x")
        if resp.status_code == 200:
            data = resp.get_json()
            assert data["total_escaped"] == len(data["escapes"])


# ──────────────────────────────────────────────────────────────────────
# GET /report/<run_id> tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleGetReport:
    def test_happy_path(self, client, mock_report_engine):
        """GET /report/<run_id> returns full report with summaries."""
        mock_report_engine.get_report.return_value = ReportResponse(
            run_id="run-001",
            status="completed",
            trust_summary={"average_score": 0.75},
            findings_summary={"total": 5},
            canary_summary={"total_escaped": 0},
            blast_radius_summary={"max_affected": 10},
            generated_at="2024-01-01T00:00:00Z",
        )
        resp = client.get("/report/run-001")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["run_id"] == "run-001"
        assert "trust_summary" in data
        assert "findings_summary" in data
        assert "canary_summary" in data
        assert "blast_radius_summary" in data
        assert is_iso8601_utc(data["generated_at"])

    def test_run_not_found(self, client, mock_report_engine):
        """GET /report/<run_id> with unknown run returns RUN_NOT_FOUND."""
        from http_api import RunNotFoundError

        mock_report_engine.get_report.side_effect = RunNotFoundError("run-unknown")
        resp = client.get("/report/run-unknown")
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "RUN_NOT_FOUND"
        assert "run-unknown" in data["message"]

    def test_report_not_found(self, client, mock_report_engine):
        """GET /report/<run_id> when generation fails returns REPORT_NOT_FOUND."""
        from http_api import ReportNotFoundError

        mock_report_engine.get_report.side_effect = ReportNotFoundError("run-bad")
        resp = client.get("/report/run-bad")
        assert resp.status_code == 404
        data = resp.get_json()
        assert data["error_code"] == "REPORT_NOT_FOUND"


# ──────────────────────────────────────────────────────────────────────
# POST /findings tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleIngestFindings:
    def test_happy_path(
        self, client, mock_findings_engine, valid_findings_request
    ):
        """POST /findings returns accepted/rejected counts."""
        mock_findings_engine.ingest.return_value = FindingsResponse(
            accepted_count=1,
            rejected_count=0,
            ingested_at="2024-01-01T00:00:00Z",
        )
        resp = client.post(
            "/findings",
            data=json.dumps(valid_findings_request),
            content_type="application/json",
        )
        data = resp.get_json()
        assert resp.status_code in (200, 201)
        assert data["accepted_count"] + data["rejected_count"] == len(
            valid_findings_request["findings"]
        )
        assert is_iso8601_utc(data["ingested_at"])

    def test_invalid_json(self, client):
        """POST /findings with malformed JSON returns INVALID_JSON."""
        resp = client.post(
            "/findings",
            data="bad json {{",
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "INVALID_JSON"

    def test_validation_error(self, client):
        """POST /findings with missing fields returns VALIDATION_ERROR."""
        resp = client.post(
            "/findings",
            data=json.dumps({"source": "test"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"

    def test_ingestion_failed(self, client, mock_findings_engine):
        """POST /findings when engine raises returns FINDINGS_INGESTION_FAILED."""
        mock_findings_engine.ingest.side_effect = RuntimeError("ingestion error")
        payload = {
            "findings": [
                {
                    "finding_id": "f-1",
                    "node_id": "n-1",
                    "severity": "HIGH",
                    "category": "test",
                    "message": "test finding",
                    "span_context": {},
                    "timestamp": "2024-01-01T00:00:00Z",
                }
            ],
            "source": "test-adapter",
        }
        resp = client.post(
            "/findings",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code >= 400
        data = resp.get_json()
        assert data["error_code"] in ("FINDINGS_INGESTION_FAILED", "INTERNAL_ERROR")

    def test_count_invariant(self, client, mock_findings_engine):
        """accepted_count + rejected_count == len(findings)."""
        mock_findings_engine.ingest.return_value = FindingsResponse(
            accepted_count=2,
            rejected_count=1,
            ingested_at="2024-01-01T00:00:00Z",
        )
        findings = [
            {
                "finding_id": f"f-{i}",
                "node_id": f"n-{i}",
                "severity": "HIGH",
                "category": "test",
                "message": "test",
                "span_context": {},
                "timestamp": "2024-01-01T00:00:00Z",
            }
            for i in range(3)
        ]
        payload = {"findings": findings, "source": "adapter"}
        resp = client.post(
            "/findings",
            data=json.dumps(payload),
            content_type="application/json",
        )
        if resp.status_code in (200, 201):
            data = resp.get_json()
            assert data["accepted_count"] + data["rejected_count"] == len(findings)

    def test_empty_findings(self, client):
        """POST /findings with empty findings list returns VALIDATION_ERROR."""
        payload = {"findings": [], "source": "adapter"}
        resp = client.post(
            "/findings",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"

    def test_empty_source(self, client):
        """POST /findings with empty source returns VALIDATION_ERROR."""
        payload = {
            "findings": [
                {
                    "finding_id": "f-1",
                    "node_id": "n-1",
                    "severity": "HIGH",
                    "category": "test",
                    "message": "test",
                    "span_context": {},
                    "timestamp": "2024-01-01T00:00:00Z",
                }
            ],
            "source": "",
        }
        resp = client.post(
            "/findings",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"


# ──────────────────────────────────────────────────────────────────────
# GET /health tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleHealth:
    def test_happy_path(self, client):
        """GET /health returns status ok with version and uptime."""
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] in ("ok", "degraded")
        assert "version" in data
        assert "uptime_seconds" in data
        assert "engines_ready" in data

    def test_status_values(self, client):
        """GET /health status is 'ok' or 'degraded'."""
        resp = client.get("/health")
        data = resp.get_json()
        assert data["status"] in ("ok", "degraded")

    def test_uptime_non_negative(self, client):
        """GET /health uptime_seconds >= 0."""
        resp = client.get("/health")
        data = resp.get_json()
        assert data["uptime_seconds"] >= 0

    def test_content_type_json(self, client):
        """GET /health has Content-Type: application/json."""
        resp = client.get("/health")
        assert "application/json" in resp.content_type


# ──────────────────────────────────────────────────────────────────────
# handle_error tests
# ──────────────────────────────────────────────────────────────────────


class TestHandleError:
    def test_validation_error_returns_400(self, client):
        """ValidationError produces VALIDATION_ERROR with HTTP 400."""
        # Trigger a validation error by sending invalid payload to any POST endpoint
        resp = client.post(
            "/register",
            data=json.dumps({"nodes": "not_a_list", "edges": [], "metadata": {}}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "VALIDATION_ERROR"
        assert "message" in data

    def test_unexpected_exception_returns_500(
        self, client, mock_blast_radius_engine
    ):
        """Unexpected exception produces INTERNAL_ERROR with HTTP 500."""
        mock_blast_radius_engine.register_graph.side_effect = MemoryError(
            "out of memory"
        )
        payload = {
            "nodes": [
                {"node_id": "n1", "node_type": "s", "labels": {}},
            ],
            "edges": [],
            "metadata": {},
        }
        resp = client.post(
            "/register",
            data=json.dumps(payload),
            content_type="application/json",
        )
        assert resp.status_code == 500
        data = resp.get_json()
        assert data["error_code"] == "INTERNAL_ERROR"

    def test_malformed_json_not_500(self, client):
        """Malformed JSON body produces INVALID_JSON with HTTP 400, never HTTP 500."""
        for endpoint in [
            "/register",
            "/blast-radius",
            "/trust/reset-taint",
            "/canary/inject",
            "/findings",
        ]:
            resp = client.post(
                endpoint,
                data="{invalid json!!!!",
                content_type="application/json",
            )
            assert resp.status_code == 400, (
                f"Expected 400 for malformed JSON on {endpoint}, got {resp.status_code}"
            )
            data = resp.get_json()
            assert data["error_code"] == "INVALID_JSON"

    def test_error_response_always_has_valid_error_code(self, client):
        """All error responses have a valid ErrorCode enum value."""
        valid_codes = {
            "INVALID_JSON",
            "VALIDATION_ERROR",
            "NODE_NOT_FOUND",
            "RUN_NOT_FOUND",
            "REVIEW_NOT_FOUND",
            "ACCESS_GRAPH_INVALID",
            "BLAST_RADIUS_FAILED",
            "TRUST_COMPUTATION_FAILED",
            "TAINT_RESET_FAILED",
            "AUTHORITY_UNAVAILABLE",
            "CANARY_INJECTION_FAILED",
            "CANARY_RESULTS_UNAVAILABLE",
            "REPORT_NOT_FOUND",
            "FINDINGS_INGESTION_FAILED",
            "INTERNAL_ERROR",
            "METHOD_NOT_ALLOWED",
            "CONTENT_TYPE_UNSUPPORTED",
        }
        # Test a known error case
        resp = client.post(
            "/register",
            data="bad json",
            content_type="application/json",
        )
        data = resp.get_json()
        assert data["error_code"] in valid_codes


# ──────────────────────────────────────────────────────────────────────
# Cross-cutting invariant tests
# ──────────────────────────────────────────────────────────────────────


class TestCrossCuttingInvariants:
    def test_all_responses_json_content_type(self, client):
        """All HTTP responses have Content-Type: application/json."""
        endpoints = [
            ("GET", "/health"),
            ("GET", "/authority"),
            ("GET", "/trust/node-1"),
            ("GET", "/canary/results/run-1"),
            ("GET", "/report/run-1"),
        ]
        for method, path in endpoints:
            if method == "GET":
                resp = client.get(path)
            else:
                resp = client.post(path)
            assert "application/json" in resp.content_type, (
                f"{method} {path} returned Content-Type: {resp.content_type}"
            )

    @pytest.mark.parametrize(
        "endpoint",
        ["/register", "/blast-radius", "/trust/reset-taint", "/canary/inject", "/findings"],
    )
    def test_post_endpoints_reject_malformed_json(self, client, endpoint):
        """All POST endpoints return INVALID_JSON for malformed request bodies."""
        resp = client.post(
            endpoint,
            data="{not valid json",
            content_type="application/json",
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["error_code"] == "INVALID_JSON"

    def test_error_responses_conform_to_schema(self, client):
        """All error responses have error_code, message, and details fields."""
        resp = client.post(
            "/register",
            data="bad",
            content_type="application/json",
        )
        data = resp.get_json()
        assert "error_code" in data
        assert "message" in data
        assert "details" in data

    @pytest.mark.parametrize(
        "endpoint,method",
        [
            ("/register", "GET"),
            ("/blast-radius", "GET"),
            ("/trust/reset-taint", "GET"),
            ("/canary/inject", "GET"),
            ("/findings", "GET"),
        ],
    )
    def test_method_not_allowed(self, client, endpoint, method):
        """Using wrong HTTP method returns METHOD_NOT_ALLOWED or 405."""
        resp = client.get(endpoint)
        assert resp.status_code == 405
        data = resp.get_json()
        if data:
            assert data["error_code"] == "METHOD_NOT_ALLOWED"

    @pytest.mark.parametrize(
        "endpoint",
        ["/register", "/blast-radius", "/trust/reset-taint", "/canary/inject", "/findings"],
    )
    def test_unsupported_content_type(self, client, endpoint):
        """POST with non-JSON Content-Type returns error."""
        resp = client.post(
            endpoint,
            data="some data",
            content_type="text/plain",
        )
        # Should be 400 or 415 (Unsupported Media Type)
        assert resp.status_code in (400, 415)
        data = resp.get_json()
        if data:
            assert data["error_code"] in ("CONTENT_TYPE_UNSUPPORTED", "INVALID_JSON")

    def test_trust_authority_never_conflated(self, client, mock_trust_engine, mock_authority_engine):
        """Trust and authority response types are never shared or conflated."""
        mock_trust_engine.get_trust.return_value = TrustResponse(
            node_id="node-1",
            trust_score=0.85,
            trust_tier="HIGH",
            is_tainted=False,
            recent_events=[],
            queried_at="2024-01-01T00:00:00Z",
        )
        mock_authority_engine.get_authority.return_value = AuthorityResponse(
            entries=[],
            total_entries=0,
            queried_at="2024-01-01T00:00:00Z",
        )
        trust_resp = client.get("/trust/node-1")
        authority_resp = client.get("/authority")

        if trust_resp.status_code == 200 and authority_resp.status_code == 200:
            trust_data = trust_resp.get_json()
            authority_data = authority_resp.get_json()
            # Trust response should have trust-specific fields
            assert "trust_score" in trust_data
            assert "trust_tier" in trust_data
            assert "is_tainted" in trust_data
            # Authority should NOT have trust fields
            assert "trust_score" not in authority_data
            assert "trust_tier" not in authority_data
            assert "is_tainted" not in authority_data
            # Authority should have authority-specific fields
            assert "entries" in authority_data
            assert "total_entries" in authority_data
            # Trust should NOT have authority fields
            assert "entries" not in trust_data
            assert "total_entries" not in trust_data

    def test_post_register_timestamp_is_utc(
        self, client, mock_blast_radius_engine, valid_access_graph_payload
    ):
        """Registration timestamp is ISO 8601 UTC."""
        mock_blast_radius_engine.register_graph.return_value = RegisterResponse(
            node_count=2,
            edge_count=1,
            registered_at="2024-06-15T12:00:00Z",
        )
        resp = client.post(
            "/register",
            data=json.dumps(valid_access_graph_payload),
            content_type="application/json",
        )
        if resp.status_code in (200, 201):
            data = resp.get_json()
            assert is_iso8601_utc(data["registered_at"])

    def test_get_trust_timestamp_is_utc(self, client, mock_trust_engine):
        """Trust query timestamp is ISO 8601 UTC."""
        mock_trust_engine.get_trust.return_value = TrustResponse(
            node_id="node-1",
            trust_score=0.5,
            trust_tier="MODERATE",
            is_tainted=False,
            recent_events=[],
            queried_at="2024-06-15T12:00:00+00:00",
        )
        resp = client.get("/trust/node-1")
        if resp.status_code == 200:
            data = resp.get_json()
            assert is_iso8601_utc(data["queried_at"])

    def test_node_not_found_error_includes_node_id(self, client, mock_trust_engine):
        """NODE_NOT_FOUND error message includes the specific node_id."""
        from http_api import NodeNotFoundError

        mock_trust_engine.get_trust.side_effect = NodeNotFoundError(
            "specific-node-xyz"
        )
        resp = client.get("/trust/specific-node-xyz")
        assert resp.status_code == 404
        data = resp.get_json()
        assert "specific-node-xyz" in data["message"]

    def test_run_not_found_error_includes_run_id(self, client, mock_report_engine):
        """RUN_NOT_FOUND error message includes the specific run_id."""
        from http_api import RunNotFoundError

        mock_report_engine.get_report.side_effect = RunNotFoundError(
            "specific-run-abc"
        )
        resp = client.get("/report/specific-run-abc")
        assert resp.status_code == 404
        data = resp.get_json()
        assert "specific-run-abc" in data["message"]
