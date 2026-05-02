"""
Adversarial (Goodhart) tests for HTTP API Server component.
These tests catch implementations that pass visible tests through shortcuts
(e.g., hardcoded returns, missing validation) rather than truly satisfying the contract.
"""
import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, PropertyMock
from src.http_api import *


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_mock_engine():
    """Create a generic mock engine."""
    return MagicMock()


def make_server_config(port=7700, host="127.0.0.1", debug=False, max_request_size_bytes=10_000_000):
    """Create a ServerConfig (or dict-like) for testing."""
    try:
        return ServerConfig(host=host, port=port, debug=debug, max_request_size_bytes=max_request_size_bytes)
    except Exception:
        # Fallback if ServerConfig is a dict-based or different constructor
        return {"host": host, "port": port, "debug": debug, "max_request_size_bytes": max_request_size_bytes}


def make_server_context(port=7700, **engine_overrides):
    """Create a full ServerContext with mock engines."""
    config = make_server_config(port=port)
    engines = {
        "trust_engine": make_mock_engine(),
        "blast_radius_engine": make_mock_engine(),
        "authority_engine": make_mock_engine(),
        "canary_engine": make_mock_engine(),
        "report_engine": make_mock_engine(),
        "findings_engine": make_mock_engine(),
    }
    engines.update(engine_overrides)
    try:
        return ServerContext(config=config, **engines)
    except Exception:
        # Fallback
        ctx = MagicMock()
        ctx.config = config
        for k, v in engines.items():
            setattr(ctx, k, v)
        return ctx


def parse_iso8601(s):
    """Parse an ISO 8601 timestamp string."""
    # Handle 'Z' suffix
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def assert_recent_utc(ts_str, max_age_seconds=10):
    """Assert that an ISO 8601 timestamp string is recent UTC."""
    dt = parse_iso8601(ts_str)
    now = datetime.now(timezone.utc)
    # If naive, assume UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = abs((now - dt).total_seconds())
    assert diff < max_age_seconds, f"Timestamp {ts_str} is {diff}s from now, expected < {max_age_seconds}s"


def get_json(response):
    """Extract JSON from a Flask test client response."""
    if hasattr(response, "get_json"):
        return response.get_json()
    return json.loads(response.data)


# ---------------------------------------------------------------------------
# Test: RegisterResponse counts are dynamic, not hardcoded
# ---------------------------------------------------------------------------

class TestGoodhartRegisterDynamicCounts:
    def test_goodhart_register_different_graph_sizes(self):
        """RegisterResponse node_count and edge_count must dynamically reflect the actual input size, not be hardcoded to any particular test fixture's counts"""
        ctx = make_server_context()
        ctx.blast_radius_engine.register_graph = MagicMock(return_value=None)
        try:
            ctx.blast_radius_engine.store_graph = MagicMock(return_value=None)
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        test_cases = [
            (1, 0),
            (5, 7),
            (13, 19),
        ]

        for n_nodes, n_edges in test_cases:
            nodes = [{"node_id": f"n-{i}", "node_type": "service", "labels": {}} for i in range(n_nodes)]
            node_ids = [n["node_id"] for n in nodes]
            edges = []
            for i in range(n_edges):
                src = node_ids[i % len(node_ids)]
                tgt = node_ids[(i + 1) % len(node_ids)]
                edges.append({
                    "source": src,
                    "target": tgt,
                    "access_type": "read",
                    "classification": "PUBLIC"
                })

            payload = {"nodes": nodes, "edges": edges, "metadata": {}}
            resp = client.post("/register", json=payload, content_type="application/json")
            data = get_json(resp)
            assert resp.status_code == 200, f"Expected 200 for {n_nodes} nodes, got {resp.status_code}: {data}"
            assert data["node_count"] == n_nodes, f"Expected node_count={n_nodes}, got {data['node_count']}"
            assert data["edge_count"] == n_edges, f"Expected edge_count={n_edges}, got {data['edge_count']}"


class TestGoodhartRegisterLargeGraph:
    def test_goodhart_register_large_graph_counts(self):
        """Registration correctly counts nodes and edges for a large graph that no visible test uses"""
        ctx = make_server_context()
        ctx.blast_radius_engine.register_graph = MagicMock(return_value=None)
        try:
            ctx.blast_radius_engine.store_graph = MagicMock(return_value=None)
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        n_nodes = 37
        n_edges = 73
        nodes = [{"node_id": f"node-{i}", "node_type": "service", "labels": {}} for i in range(n_nodes)]
        node_ids = [n["node_id"] for n in nodes]
        edges = []
        for i in range(n_edges):
            edges.append({
                "source": node_ids[i % n_nodes],
                "target": node_ids[(i + 3) % n_nodes],
                "access_type": "write",
                "classification": "INTERNAL"
            })

        payload = {"nodes": nodes, "edges": edges, "metadata": {"test": True}}
        resp = client.post("/register", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["node_count"] == 37
        assert data["edge_count"] == 73


class TestGoodhartRegisterTimestamp:
    def test_goodhart_register_timestamp_is_recent_utc(self):
        """Registration timestamp must be a genuinely current UTC time"""
        ctx = make_server_context()
        ctx.blast_radius_engine.register_graph = MagicMock(return_value=None)
        try:
            ctx.blast_radius_engine.store_graph = MagicMock(return_value=None)
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        nodes = [{"node_id": "ts-test-node", "node_type": "service", "labels": {}}]
        payload = {"nodes": nodes, "edges": [], "metadata": {}}
        resp = client.post("/register", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert "registered_at" in data
        assert_recent_utc(data["registered_at"])


# ---------------------------------------------------------------------------
# Test: Blast radius origin echoes input
# ---------------------------------------------------------------------------

class TestGoodhartBlastRadiusOrigin:
    def test_goodhart_blast_radius_origin_echoes_input(self):
        """BlastRadiusResponse.origin_node_id must echo back the actual requested node_id"""
        ctx = make_server_context()
        br_result = MagicMock()
        br_result.origin_node_id = "node-xyz-999"
        br_result.affected_nodes = []
        br_result.total_affected = 0
        br_result.max_depth_reached = 0
        br_result.computed_at = datetime.now(timezone.utc).isoformat()
        ctx.blast_radius_engine.compute_blast_radius = MagicMock(return_value=br_result)
        try:
            ctx.blast_radius_engine.compute = MagicMock(return_value=br_result)
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        payload = {"node_id": "node-xyz-999", "max_depth": 3, "classification_filter": "PUBLIC"}
        resp = client.post("/blast-radius", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["origin_node_id"] == "node-xyz-999"


class TestGoodhartBlastRadiusTimestamp:
    def test_goodhart_blast_radius_computed_at_is_timestamp(self):
        """BlastRadiusResponse.computed_at must be a genuine ISO 8601 UTC timestamp"""
        ctx = make_server_context()
        br_result = MagicMock()
        br_result.origin_node_id = "ts-br-node"
        br_result.affected_nodes = []
        br_result.total_affected = 0
        br_result.max_depth_reached = 0
        br_result.computed_at = datetime.now(timezone.utc).isoformat()
        ctx.blast_radius_engine.compute_blast_radius = MagicMock(return_value=br_result)
        try:
            ctx.blast_radius_engine.compute = MagicMock(return_value=br_result)
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        payload = {"node_id": "ts-br-node", "max_depth": 5, "classification_filter": "INTERNAL"}
        resp = client.post("/blast-radius", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert "computed_at" in data
        assert_recent_utc(data["computed_at"])


# ---------------------------------------------------------------------------
# Test: Trust node_id echoed for novel IDs
# ---------------------------------------------------------------------------

class TestGoodhartTrustNodeIdEchoed:
    def test_goodhart_trust_node_id_echoed_for_different_ids(self):
        """TrustResponse.node_id must dynamically match the queried node_id"""
        ctx = make_server_context()

        def mock_get_trust(node_id):
            result = MagicMock()
            result.node_id = node_id
            result.trust_score = 0.75
            result.trust_tier = "HIGH"
            result.is_tainted = False
            result.recent_events = []
            result.queried_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.trust_engine.get_trust = MagicMock(side_effect=mock_get_trust)
        try:
            ctx.trust_engine.get_trust_score = MagicMock(side_effect=mock_get_trust)
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        for nid in ["svc-alpha-7", "db-prod-42", "node-with-dashes-123"]:
            resp = client.get(f"/trust/{nid}")
            data = get_json(resp)
            assert resp.status_code == 200, f"Expected 200 for {nid}, got {resp.status_code}"
            assert data["node_id"] == nid, f"Expected node_id={nid}, got {data['node_id']}"


# ---------------------------------------------------------------------------
# Test: Trust score boundaries 0.0 and 1.0
# ---------------------------------------------------------------------------

class TestGoodhartTrustScoreBoundaries:
    def _make_trust_mock(self, score, is_tainted=False):
        def mock_get_trust(node_id):
            result = MagicMock()
            result.node_id = node_id
            result.trust_score = score
            result.trust_tier = "NONE" if score == 0.0 else "FULL"
            result.is_tainted = is_tainted
            result.recent_events = []
            result.queried_at = datetime.now(timezone.utc).isoformat()
            return result
        return mock_get_trust

    def test_goodhart_trust_score_boundary_zero(self):
        """Trust score of exactly 0.0 must be accepted and returned correctly"""
        ctx = make_server_context()
        ctx.trust_engine.get_trust = MagicMock(side_effect=self._make_trust_mock(0.0))
        try:
            ctx.trust_engine.get_trust_score = MagicMock(side_effect=self._make_trust_mock(0.0))
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/trust/zero-score-node")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["trust_score"] == 0.0

    def test_goodhart_trust_score_boundary_one(self):
        """Trust score of exactly 1.0 must be accepted and returned correctly"""
        ctx = make_server_context()
        ctx.trust_engine.get_trust = MagicMock(side_effect=self._make_trust_mock(1.0))
        try:
            ctx.trust_engine.get_trust_score = MagicMock(side_effect=self._make_trust_mock(1.0))
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/trust/full-score-node")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["trust_score"] == 1.0


# ---------------------------------------------------------------------------
# Test: Canary inject run_id echoed and count formula
# ---------------------------------------------------------------------------

class TestGoodhartCanaryInjectDynamic:
    def test_goodhart_canary_inject_run_id_echoed(self):
        """CanaryInjectResponse.run_id must echo the actual request run_id"""
        ctx = make_server_context()

        def mock_inject(run_id=None, target_tiers=None, canary_count=None, **kwargs):
            result = MagicMock()
            tiers = target_tiers or []
            result.run_id = run_id
            result.injected_count = (canary_count or 0) * len(tiers)
            result.tiers_seeded = tiers
            result.injected_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.canary_engine.inject = MagicMock(side_effect=lambda *a, **kw: mock_inject(**kw))
        try:
            ctx.canary_engine.inject_canaries = ctx.canary_engine.inject
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "run_id": "run-novel-abc-123",
            "target_tiers": ["RESTRICTED"],
            "canary_count": 5
        }
        resp = client.post("/canary/inject", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["run_id"] == "run-novel-abc-123"

    def test_goodhart_canary_inject_count_multi_tier(self):
        """Injected count must equal canary_count * number of target tiers"""
        ctx = make_server_context()

        def mock_inject(*args, **kwargs):
            result = MagicMock()
            # The handler should compute this, not the engine
            result.run_id = kwargs.get("run_id", "test-run")
            result.injected_count = 21  # 7 * 3
            result.tiers_seeded = ["PUBLIC", "INTERNAL", "CONFIDENTIAL"]
            result.injected_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.canary_engine.inject = MagicMock(side_effect=mock_inject)
        try:
            ctx.canary_engine.inject_canaries = ctx.canary_engine.inject
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "run_id": "run-multi-tier",
            "target_tiers": ["PUBLIC", "INTERNAL", "CONFIDENTIAL"],
            "canary_count": 7
        }
        resp = client.post("/canary/inject", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["injected_count"] == 21

    def test_goodhart_canary_inject_single_tier_single_count(self):
        """Injected count formula holds for the smallest valid input: 1 * 1 = 1"""
        ctx = make_server_context()

        def mock_inject(*args, **kwargs):
            result = MagicMock()
            result.run_id = kwargs.get("run_id", "test-run")
            result.injected_count = 1
            result.tiers_seeded = ["PUBLIC"]
            result.injected_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.canary_engine.inject = MagicMock(side_effect=mock_inject)
        try:
            ctx.canary_engine.inject_canaries = ctx.canary_engine.inject
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "run_id": "run-single",
            "target_tiers": ["PUBLIC"],
            "canary_count": 1
        }
        resp = client.post("/canary/inject", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["injected_count"] == 1

    def test_goodhart_canary_inject_max_count_all_tiers(self):
        """Injected count formula holds for maximum: 1000 * 4 = 4000"""
        ctx = make_server_context()

        def mock_inject(*args, **kwargs):
            result = MagicMock()
            result.run_id = kwargs.get("run_id", "test-run")
            result.injected_count = 4000
            result.tiers_seeded = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
            result.injected_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.canary_engine.inject = MagicMock(side_effect=mock_inject)
        try:
            ctx.canary_engine.inject_canaries = ctx.canary_engine.inject
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "run_id": "run-max",
            "target_tiers": ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"],
            "canary_count": 1000
        }
        resp = client.post("/canary/inject", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["injected_count"] == 4000


# ---------------------------------------------------------------------------
# Test: Canary results run_id echoed
# ---------------------------------------------------------------------------

class TestGoodhartCanaryResultsEchoed:
    def test_goodhart_canary_results_run_id_echoed(self):
        """CanaryResultsResponse.run_id must echo the queried run_id"""
        ctx = make_server_context()

        def mock_results(run_id):
            result = MagicMock()
            result.run_id = run_id
            result.status = "completed"
            result.total_injected = 10
            result.total_escaped = 0
            result.escapes = []
            result.queried_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.canary_engine.get_results = MagicMock(side_effect=mock_results)
        try:
            ctx.canary_engine.results = ctx.canary_engine.get_results
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/canary/results/run-unique-xyz-777")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["run_id"] == "run-unique-xyz-777"

    def test_goodhart_canary_results_with_multiple_escapes(self):
        """total_escaped must equal len(escapes) with multiple escape events"""
        ctx = make_server_context()

        def mock_results(run_id):
            result = MagicMock()
            result.run_id = run_id
            result.status = "completed"
            result.total_injected = 20
            result.total_escaped = 5
            result.escapes = [
                {"canary_id": f"c-{i}", "expected_tier": "CONFIDENTIAL", "observed_tier": "PUBLIC",
                 "observed_node_id": f"node-{i}", "detected_at": datetime.now(timezone.utc).isoformat()}
                for i in range(5)
            ]
            result.queried_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.canary_engine.get_results = MagicMock(side_effect=mock_results)
        try:
            ctx.canary_engine.results = ctx.canary_engine.get_results
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/canary/results/run-multi-escape")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["total_escaped"] == 5
        assert len(data["escapes"]) == 5


# ---------------------------------------------------------------------------
# Test: Report run_id echoed and all summary fields present
# ---------------------------------------------------------------------------

class TestGoodhartReportDynamic:
    def test_goodhart_report_run_id_echoed(self):
        """ReportResponse.run_id must echo the queried run_id"""
        ctx = make_server_context()

        def mock_report(run_id):
            result = MagicMock()
            result.run_id = run_id
            result.status = "completed"
            result.trust_summary = {"avg_score": 0.8}
            result.findings_summary = {"total": 5}
            result.canary_summary = {"escaped": 0}
            result.blast_radius_summary = {"max_depth": 3}
            result.generated_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.report_engine.get_report = MagicMock(side_effect=mock_report)
        try:
            ctx.report_engine.generate_report = ctx.report_engine.get_report
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/report/run-adversarial-999")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["run_id"] == "run-adversarial-999"

    def test_goodhart_report_response_has_all_summary_fields(self):
        """ReportResponse must include all four summary dicts"""
        ctx = make_server_context()

        def mock_report(run_id):
            result = MagicMock()
            result.run_id = run_id
            result.status = "completed"
            result.trust_summary = {"avg": 0.5}
            result.findings_summary = {"count": 1}
            result.canary_summary = {"injected": 10}
            result.blast_radius_summary = {"nodes": 5}
            result.generated_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.report_engine.get_report = MagicMock(side_effect=mock_report)
        try:
            ctx.report_engine.generate_report = ctx.report_engine.get_report
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/report/run-summary-check")
        data = get_json(resp)
        assert resp.status_code == 200
        assert "trust_summary" in data
        assert "findings_summary" in data
        assert "canary_summary" in data
        assert "blast_radius_summary" in data
        assert "generated_at" in data


# ---------------------------------------------------------------------------
# Test: Error messages include specific identifiers
# ---------------------------------------------------------------------------

class TestGoodhartErrorSpecificIds:
    def test_goodhart_error_response_includes_specific_node_id(self):
        """Error messages must include the specific entity identifier that caused the error"""
        ctx = make_server_context()

        # Make trust engine raise NodeNotFound for a novel node_id
        class NodeNotFoundError(Exception):
            def __init__(self, node_id):
                self.node_id = node_id
                super().__init__(f"Node not found: {node_id}")

        ctx.trust_engine.get_trust = MagicMock(
            side_effect=NodeNotFoundError("svc-unique-deadbeef")
        )
        try:
            ctx.trust_engine.get_trust_score = ctx.trust_engine.get_trust
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/trust/svc-unique-deadbeef")
        data = get_json(resp)
        assert resp.status_code in (404, 400)
        assert "svc-unique-deadbeef" in data.get("message", ""), \
            f"Expected 'svc-unique-deadbeef' in error message, got: {data.get('message')}"

    def test_goodhart_review_not_found_includes_review_id(self):
        """REVIEW_NOT_FOUND error message must include the specific review_id"""
        ctx = make_server_context()

        class ReviewNotFoundError(Exception):
            def __init__(self, review_id):
                self.review_id = review_id
                super().__init__(f"Review not found: {review_id}")

        ctx.trust_engine.reset_taint = MagicMock(
            side_effect=ReviewNotFoundError("rev-nonexistent-12345")
        )
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "node_id": "some-node",
            "review_id": "rev-nonexistent-12345",
            "reason": "Testing review not found"
        }
        resp = client.post("/trust/reset-taint", json=payload, content_type="application/json")
        data = get_json(resp)
        assert "rev-nonexistent-12345" in data.get("message", ""), \
            f"Expected 'rev-nonexistent-12345' in error message, got: {data.get('message')}"


# ---------------------------------------------------------------------------
# Test: Error responses always have details field
# ---------------------------------------------------------------------------

class TestGoodhartErrorResponseSchema:
    def test_goodhart_error_response_has_details_field(self):
        """All error responses must include 'details' field as part of ErrorResponse schema"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        # Malformed JSON
        resp = client.post("/register", data="not-json{{{", content_type="application/json")
        data = get_json(resp)
        assert "error_code" in data
        assert "message" in data
        assert "details" in data, f"Missing 'details' in error response: {data}"

    def test_goodhart_content_type_json_on_error_responses(self):
        """Error responses must also have Content-Type: application/json"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        resp = client.post("/register", data="bad json!", content_type="application/json")
        ct = resp.content_type or resp.headers.get("Content-Type", "")
        assert "application/json" in ct, f"Expected application/json Content-Type on error, got: {ct}"


# ---------------------------------------------------------------------------
# Test: Method not allowed for various methods
# ---------------------------------------------------------------------------

class TestGoodhartMethodNotAllowed:
    def test_goodhart_get_endpoints_reject_post(self):
        """GET-only endpoints must reject POST requests with METHOD_NOT_ALLOWED"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        get_only = ["/authority", "/health"]
        for path in get_only:
            resp = client.post(path, json={}, content_type="application/json")
            assert resp.status_code == 405, f"POST {path} should return 405, got {resp.status_code}"
            data = get_json(resp)
            assert data.get("error_code") == "METHOD_NOT_ALLOWED", \
                f"POST {path} should return METHOD_NOT_ALLOWED, got {data.get('error_code')}"

    def test_goodhart_post_endpoints_reject_get(self):
        """POST-only endpoints must reject GET requests with METHOD_NOT_ALLOWED"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        post_only = ["/register", "/blast-radius", "/trust/reset-taint", "/canary/inject", "/findings"]
        for path in post_only:
            resp = client.get(path)
            assert resp.status_code == 405, f"GET {path} should return 405, got {resp.status_code}"
            data = get_json(resp)
            assert data.get("error_code") == "METHOD_NOT_ALLOWED", \
                f"GET {path} should return METHOD_NOT_ALLOWED, got {data.get('error_code')}"

    def test_goodhart_no_delete_or_put_endpoints(self):
        """No endpoint should accept DELETE or PUT methods"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        all_paths = [
            "/register", "/blast-radius", "/trust/test-node",
            "/trust/reset-taint", "/authority", "/canary/inject",
            "/canary/results/run-1", "/report/run-1", "/findings", "/health"
        ]
        for path in all_paths:
            for method in [client.delete, client.put]:
                resp = method(path)
                assert resp.status_code == 405, \
                    f"{method.__name__.upper()} {path} should return 405, got {resp.status_code}"


# ---------------------------------------------------------------------------
# Test: Content type validation
# ---------------------------------------------------------------------------

class TestGoodhartContentType:
    def test_goodhart_unsupported_content_type_xml(self):
        """POST endpoints must reject Content-Type: application/xml"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        resp = client.post("/register", data="<xml/>", content_type="application/xml")
        data = get_json(resp)
        assert resp.status_code == 415, f"Expected 415 for XML content type, got {resp.status_code}"
        assert data.get("error_code") == "CONTENT_TYPE_UNSUPPORTED"

    def test_goodhart_unsupported_content_type_form(self):
        """POST endpoints must reject Content-Type: application/x-www-form-urlencoded"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        resp = client.post("/findings", data="key=value", content_type="application/x-www-form-urlencoded")
        data = get_json(resp)
        assert resp.status_code == 415, f"Expected 415 for form content type, got {resp.status_code}"
        assert data.get("error_code") == "CONTENT_TYPE_UNSUPPORTED"


# ---------------------------------------------------------------------------
# Test: Health endpoint degraded state
# ---------------------------------------------------------------------------

class TestGoodhartHealthDegraded:
    def test_goodhart_health_engines_ready_false_when_degraded(self):
        """Health endpoint must reflect actual engine readiness state"""
        ctx = make_server_context()
        # Make engines report not ready
        ctx.trust_engine.is_ready = MagicMock(return_value=False)
        ctx.blast_radius_engine.is_ready = MagicMock(return_value=False)
        ctx.authority_engine.is_ready = MagicMock(return_value=False)
        ctx.canary_engine.is_ready = MagicMock(return_value=False)
        ctx.report_engine.is_ready = MagicMock(return_value=False)
        ctx.findings_engine.is_ready = MagicMock(return_value=False)
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/health")
        data = get_json(resp)
        assert resp.status_code == 200
        # When engines aren't ready, either engines_ready should be False or status should be 'degraded'
        assert data.get("engines_ready") is False or data.get("status") == "degraded", \
            f"Expected engines_ready=False or status=degraded, got: {data}"

    def test_goodhart_health_version_is_string(self):
        """Health response must include a non-empty version string"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/health")
        data = get_json(resp)
        assert resp.status_code == 200
        assert "version" in data
        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0


# ---------------------------------------------------------------------------
# Test: Reset taint response fields and boundaries
# ---------------------------------------------------------------------------

class TestGoodhartResetTaintBoundaries:
    def _setup_taint_reset_ctx(self):
        ctx = make_server_context()

        def mock_reset(node_id=None, review_id=None, reason=None, **kwargs):
            result = MagicMock()
            result.node_id = node_id
            result.review_id = review_id
            result.previous_trust_score = 0.1
            result.new_trust_score = 0.7
            result.ledger_event_id = "evt-reset-123"
            result.reset_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.trust_engine.reset_taint = MagicMock(side_effect=lambda *a, **kw: mock_reset(**kw))
        return ctx

    def test_goodhart_reset_taint_response_has_all_fields(self):
        """TaintResetResponse must include all required fields"""
        ctx = self._setup_taint_reset_ctx()
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "node_id": "taint-node-test",
            "review_id": "review-test-456",
            "reason": "Testing reset response completeness"
        }
        resp = client.post("/trust/reset-taint", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        for field in ["node_id", "review_id", "previous_trust_score", "new_trust_score", "ledger_event_id", "reset_at"]:
            assert field in data, f"Missing field '{field}' in TaintResetResponse: {data}"
        assert 0.0 <= data["previous_trust_score"] <= 1.0
        assert 0.0 <= data["new_trust_score"] <= 1.0

    def test_goodhart_reset_taint_reason_exactly_2000_chars(self):
        """A reason string of exactly 2000 characters should be accepted"""
        ctx = self._setup_taint_reset_ctx()
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "node_id": "taint-node-boundary",
            "review_id": "review-boundary",
            "reason": "A" * 2000
        }
        resp = client.post("/trust/reset-taint", json=payload, content_type="application/json")
        assert resp.status_code == 200, \
            f"Expected 200 for 2000-char reason, got {resp.status_code}: {get_json(resp)}"

    def test_goodhart_reset_taint_reason_exactly_1_char(self):
        """A reason string of exactly 1 character should be accepted"""
        ctx = self._setup_taint_reset_ctx()
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "node_id": "taint-node-min",
            "review_id": "review-min",
            "reason": "x"
        }
        resp = client.post("/trust/reset-taint", json=payload, content_type="application/json")
        assert resp.status_code == 200, \
            f"Expected 200 for 1-char reason, got {resp.status_code}: {get_json(resp)}"

    def test_goodhart_reset_taint_reason_2001_chars(self):
        """A reason string of exactly 2001 characters must be rejected"""
        ctx = self._setup_taint_reset_ctx()
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "node_id": "taint-node-over",
            "review_id": "review-over",
            "reason": "B" * 2001
        }
        resp = client.post("/trust/reset-taint", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code in (400, 422), \
            f"Expected 400/422 for 2001-char reason, got {resp.status_code}"
        assert data.get("error_code") == "VALIDATION_ERROR"

    def test_goodhart_reset_taint_node_id_and_review_id_echoed(self):
        """TaintResetResponse must echo back the exact node_id and review_id from the request"""
        ctx = self._setup_taint_reset_ctx()
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "node_id": "node-adversarial-xyz",
            "review_id": "review-adversarial-abc",
            "reason": "Testing echo of IDs"
        }
        resp = client.post("/trust/reset-taint", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["node_id"] == "node-adversarial-xyz"
        assert data["review_id"] == "review-adversarial-abc"


# ---------------------------------------------------------------------------
# Test: Graph validation checks both source and target
# ---------------------------------------------------------------------------

class TestGoodhartGraphValidation:
    def test_goodhart_register_edge_references_target_not_in_nodes(self):
        """Graph validation must check that edge targets exist in nodes"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "nodes": [
                {"node_id": "A", "node_type": "service", "labels": {}},
                {"node_id": "B", "node_type": "service", "labels": {}},
            ],
            "edges": [
                {"source": "A", "target": "C", "access_type": "read", "classification": "PUBLIC"}
            ],
            "metadata": {}
        }
        resp = client.post("/register", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code in (400, 422)
        assert data.get("error_code") == "ACCESS_GRAPH_INVALID"

    def test_goodhart_register_edge_references_source_not_in_nodes(self):
        """Graph validation must check that edge sources exist in nodes"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "nodes": [
                {"node_id": "A", "node_type": "service", "labels": {}},
                {"node_id": "B", "node_type": "service", "labels": {}},
            ],
            "edges": [
                {"source": "C", "target": "A", "access_type": "read", "classification": "PUBLIC"}
            ],
            "metadata": {}
        }
        resp = client.post("/register", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code in (400, 422)
        assert data.get("error_code") == "ACCESS_GRAPH_INVALID"

    def test_goodhart_register_edge_invalid_classification(self):
        """An edge with an invalid classification tier value should be rejected"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "nodes": [
                {"node_id": "A", "node_type": "service", "labels": {}},
                {"node_id": "B", "node_type": "service", "labels": {}},
            ],
            "edges": [
                {"source": "A", "target": "B", "access_type": "read", "classification": "INVALID_TIER"}
            ],
            "metadata": {}
        }
        resp = client.post("/register", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code in (400, 422)
        assert data.get("error_code") == "VALIDATION_ERROR"

    def test_goodhart_register_with_unicode_node_ids(self):
        """Registration should handle node_ids with Unicode characters"""
        ctx = make_server_context()
        ctx.blast_radius_engine.register_graph = MagicMock(return_value=None)
        try:
            ctx.blast_radius_engine.store_graph = MagicMock(return_value=None)
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "nodes": [
                {"node_id": "nöde-ünïcödé", "node_type": "service", "labels": {}},
                {"node_id": "节点-alpha", "node_type": "database", "labels": {}},
            ],
            "edges": [],
            "metadata": {}
        }
        resp = client.post("/register", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["node_count"] == 2


# ---------------------------------------------------------------------------
# Test: Findings count invariant with partial rejection
# ---------------------------------------------------------------------------

class TestGoodhartFindingsCount:
    def test_goodhart_findings_count_invariant_partial_reject(self):
        """accepted_count + rejected_count must equal total findings for partial rejections"""
        ctx = make_server_context()

        def mock_ingest(*args, **kwargs):
            result = MagicMock()
            result.accepted_count = 3
            result.rejected_count = 7
            result.ingested_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.findings_engine.ingest = MagicMock(side_effect=mock_ingest)
        try:
            ctx.findings_engine.ingest_findings = ctx.findings_engine.ingest
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        findings = [
            {
                "finding_id": f"f-{i}",
                "node_id": f"node-{i}",
                "severity": "HIGH",
                "category": "access_violation",
                "message": f"Finding {i}",
                "span_context": {},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            for i in range(10)
        ]
        payload = {"findings": findings, "source": "baton-adapter"}
        resp = client.post("/findings", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["accepted_count"] + data["rejected_count"] == 10

    def test_goodhart_findings_all_rejected(self):
        """When all findings are rejected, accepted_count should be 0"""
        ctx = make_server_context()

        def mock_ingest(*args, **kwargs):
            result = MagicMock()
            result.accepted_count = 0
            result.rejected_count = 5
            result.ingested_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.findings_engine.ingest = MagicMock(side_effect=mock_ingest)
        try:
            ctx.findings_engine.ingest_findings = ctx.findings_engine.ingest
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        findings = [
            {
                "finding_id": f"f-rej-{i}",
                "node_id": f"node-rej-{i}",
                "severity": "LOW",
                "category": "test",
                "message": f"Rejected finding {i}",
                "span_context": {},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            for i in range(5)
        ]
        payload = {"findings": findings, "source": "test-adapter"}
        resp = client.post("/findings", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert data["accepted_count"] == 0
        assert data["rejected_count"] == 5

    def test_goodhart_findings_ingested_at_is_current(self):
        """FindingsResponse.ingested_at must be a genuine current timestamp"""
        ctx = make_server_context()

        def mock_ingest(*args, **kwargs):
            result = MagicMock()
            result.accepted_count = 1
            result.rejected_count = 0
            result.ingested_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.findings_engine.ingest = MagicMock(side_effect=mock_ingest)
        try:
            ctx.findings_engine.ingest_findings = ctx.findings_engine.ingest
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        findings = [
            {
                "finding_id": "f-ts-1",
                "node_id": "node-ts-1",
                "severity": "MEDIUM",
                "category": "test",
                "message": "Timestamp test",
                "span_context": {},
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        ]
        payload = {"findings": findings, "source": "ts-adapter"}
        resp = client.post("/findings", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert_recent_utc(data["ingested_at"])


# ---------------------------------------------------------------------------
# Test: Trust and authority never conflated
# ---------------------------------------------------------------------------

class TestGoodhartTrustAuthorityNeverConflated:
    def test_goodhart_trust_response_not_authority_type(self):
        """GET /trust response must never contain authority-specific fields"""
        ctx = make_server_context()

        def mock_get_trust(node_id):
            result = MagicMock()
            result.node_id = node_id
            result.trust_score = 0.85
            result.trust_tier = "HIGH"
            result.is_tainted = False
            result.recent_events = []
            result.queried_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.trust_engine.get_trust = MagicMock(side_effect=mock_get_trust)
        try:
            ctx.trust_engine.get_trust_score = ctx.trust_engine.get_trust
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/trust/conflation-test-node")
        data = get_json(resp)
        assert resp.status_code == 200
        assert "authority_source" not in data
        assert "granted_permissions" not in data
        assert "trust_score" in data
        assert "trust_tier" in data

    def test_goodhart_authority_response_not_trust_type(self):
        """GET /authority response must never contain trust-specific fields at top level"""
        ctx = make_server_context()

        def mock_authority():
            result = MagicMock()
            result.entries = [
                {
                    "node_id": "svc-1",
                    "authority_source": "manifest.yaml",
                    "granted_permissions": ["read", "write"],
                    "declared_at": datetime.now(timezone.utc).isoformat()
                }
            ]
            result.total_entries = 1
            result.queried_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.authority_engine.get_authority = MagicMock(side_effect=lambda: mock_authority())
        try:
            ctx.authority_engine.get_authority_map = ctx.authority_engine.get_authority
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/authority")
        data = get_json(resp)
        assert resp.status_code == 200
        assert "trust_score" not in data
        assert "trust_tier" not in data
        assert "entries" in data
        assert "total_entries" in data


# ---------------------------------------------------------------------------
# Test: Authority and trust timestamps
# ---------------------------------------------------------------------------

class TestGoodhartTimestamps:
    def test_goodhart_authority_queried_at_is_timestamp(self):
        """AuthorityResponse.queried_at must be a genuine current UTC ISO 8601 timestamp"""
        ctx = make_server_context()

        def mock_authority():
            result = MagicMock()
            result.entries = []
            result.total_entries = 0
            result.queried_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.authority_engine.get_authority = MagicMock(side_effect=lambda: mock_authority())
        try:
            ctx.authority_engine.get_authority_map = ctx.authority_engine.get_authority
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/authority")
        data = get_json(resp)
        assert resp.status_code == 200
        assert_recent_utc(data["queried_at"])

    def test_goodhart_trust_queried_at_timestamp(self):
        """TrustResponse.queried_at must be a genuine current UTC ISO 8601 timestamp"""
        ctx = make_server_context()

        def mock_get_trust(node_id):
            result = MagicMock()
            result.node_id = node_id
            result.trust_score = 0.5
            result.trust_tier = "MODERATE"
            result.is_tainted = False
            result.recent_events = []
            result.queried_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.trust_engine.get_trust = MagicMock(side_effect=mock_get_trust)
        try:
            ctx.trust_engine.get_trust_score = ctx.trust_engine.get_trust
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        resp = client.get("/trust/ts-check-node")
        data = get_json(resp)
        assert resp.status_code == 200
        assert_recent_utc(data["queried_at"])


# ---------------------------------------------------------------------------
# Test: create_app port boundaries
# ---------------------------------------------------------------------------

class TestGoodhartCreateAppPortBoundaries:
    def test_goodhart_create_app_port_one_valid(self):
        """Port 1 is the minimum valid port and must be accepted"""
        ctx = make_server_context(port=1)
        app = create_app(ctx)
        assert app is not None

    def test_goodhart_create_app_port_65535_valid(self):
        """Port 65535 is the maximum valid port and must be accepted"""
        ctx = make_server_context(port=65535)
        app = create_app(ctx)
        assert app is not None

    def test_goodhart_create_app_negative_port(self):
        """Negative port values must be rejected during app creation"""
        with pytest.raises(Exception):
            ctx = make_server_context(port=-1)
            create_app(ctx)

    def test_goodhart_create_app_all_ten_routes_distinct(self):
        """The Flask app must have all required route rules registered"""
        ctx = make_server_context()
        app = create_app(ctx)

        rules = [rule.rule for rule in app.url_map.iter_rules()]
        # Filter out Flask's built-in static route
        rules = [r for r in rules if r != "/static/<path:filename>"]

        expected_routes = [
            "/register",
            "/blast-radius",
            "/authority",
            "/canary/inject",
            "/findings",
            "/health",
        ]
        # Routes with parameters
        param_routes_patterns = [
            "/trust/",  # /trust/<node_id>
            "/trust/reset-taint",
            "/canary/results/",  # /canary/results/<run_id>
            "/report/",  # /report/<run_id>
        ]

        for route in expected_routes:
            assert route in rules, f"Missing route: {route}. Found: {rules}"

        # Check parameterized routes exist
        for pattern in param_routes_patterns:
            found = any(pattern in r for r in rules)
            assert found, f"Missing parameterized route matching: {pattern}. Found: {rules}"


# ---------------------------------------------------------------------------
# Test: Canary inject validation
# ---------------------------------------------------------------------------

class TestGoodhartCanaryInjectValidation:
    def test_goodhart_canary_inject_canary_count_negative(self):
        """Negative canary_count must be rejected"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "run_id": "run-negative",
            "target_tiers": ["PUBLIC"],
            "canary_count": -1
        }
        resp = client.post("/canary/inject", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code in (400, 422)
        assert data.get("error_code") == "VALIDATION_ERROR"

    def test_goodhart_canary_inject_tiers_seeded_matches_request(self):
        """CanaryInjectResponse.tiers_seeded must reflect the actual target_tiers from the request"""
        ctx = make_server_context()

        def mock_inject(*args, **kwargs):
            result = MagicMock()
            result.run_id = kwargs.get("run_id", "test-run")
            result.injected_count = 6
            result.tiers_seeded = ["CONFIDENTIAL", "RESTRICTED"]
            result.injected_at = datetime.now(timezone.utc).isoformat()
            return result

        ctx.canary_engine.inject = MagicMock(side_effect=mock_inject)
        try:
            ctx.canary_engine.inject_canaries = ctx.canary_engine.inject
        except Exception:
            pass
        app = create_app(ctx)
        client = app.test_client()

        payload = {
            "run_id": "run-tiers-check",
            "target_tiers": ["CONFIDENTIAL", "RESTRICTED"],
            "canary_count": 3
        }
        resp = client.post("/canary/inject", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code == 200
        assert "CONFIDENTIAL" in data["tiers_seeded"]
        assert "RESTRICTED" in data["tiers_seeded"]
        assert len(data["tiers_seeded"]) == 2


# ---------------------------------------------------------------------------
# Test: Blast radius negative depth
# ---------------------------------------------------------------------------

class TestGoodhartBlastRadiusValidation:
    def test_goodhart_blast_radius_negative_max_depth(self):
        """Negative max_depth values should be rejected"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        payload = {"node_id": "some-node", "max_depth": -1, "classification_filter": "PUBLIC"}
        resp = client.post("/blast-radius", json=payload, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code in (400, 422)
        assert data.get("error_code") == "VALIDATION_ERROR"


# ---------------------------------------------------------------------------
# Test: Empty JSON body for POST /register
# ---------------------------------------------------------------------------

class TestGoodhartEmptyJsonBody:
    def test_goodhart_empty_json_body_post_register(self):
        """POST /register with empty JSON object {} should return VALIDATION_ERROR"""
        ctx = make_server_context()
        app = create_app(ctx)
        client = app.test_client()

        resp = client.post("/register", json={}, content_type="application/json")
        data = get_json(resp)
        assert resp.status_code in (400, 422)
        assert data.get("error_code") == "VALIDATION_ERROR"
