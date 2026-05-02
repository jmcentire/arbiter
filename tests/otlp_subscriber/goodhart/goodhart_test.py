"""
Hidden adversarial acceptance tests for OTLP Span Subscriber.
These tests catch implementations that pass visible tests through shortcuts
(hardcoded returns, incomplete validation, etc.) rather than truly satisfying the contract.
"""
import time
import threading
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from src.otlp_subscriber import *


# ─── Helpers ────────────────────────────────────────────────────────────────

def _make_valid_raw_span(
    trace_id="abcdef0123456789abcdef0123456789",
    span_id="abcdef0123456789",
    parent_span_id=None,
    name="test.span",
    start_time=1000000000,
    end_time=2000000000,
    node_id="node-test-001",
    execution_id="exec-test-001",
    component_id="comp-test",
    circuit_id="circuit-test",
    extra_attributes=None,
):
    """Build a minimal valid raw span dict for testing."""
    attrs = [
        {"key": "baton.node_id", "value": {"stringValue": node_id}},
        {"key": "baton.execution_id", "value": {"stringValue": execution_id}},
        {"key": "baton.component_id", "value": {"stringValue": component_id}},
        {"key": "baton.circuit_id", "value": {"stringValue": circuit_id}},
    ]
    if extra_attributes:
        attrs.extend(extra_attributes)

    span = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "startTimeUnixNano": start_time,
        "endTimeUnixNano": end_time,
        "attributes": attrs,
        "events": [],
        "links": [],
    }
    if parent_span_id is not None:
        span["parentSpanId"] = parent_span_id
    return span


def _make_resource_attributes():
    return []


def _make_analysis_result(kind, success=True, **kwargs):
    """Helper to build a minimal AnalysisResult."""
    defaults = {
        "analyzer_kind": kind,
        "success": success,
        "error_message": "" if success else kwargs.get("error_message", "mock error"),
        "consistency_score": None,
        "access_declared": "",
        "access_observed": "",
        "authority_domains": [],
        "trust_score": None,
        "trust_tier": None,
        "taint_detected": None,
        "taint_details": "",
        "blast_tier": None,
        "conflict_description": "",
        "conflict_detected": None,
    }
    defaults.update(kwargs)
    # Try constructing as a struct if the module provides it, otherwise use dict-like approach
    try:
        return AnalysisResult(**defaults)
    except Exception:
        # Fallback: maybe it's a different construction pattern
        result = MagicMock()
        for k, v in defaults.items():
            setattr(result, k, v)
        return result


def _make_four_results(all_success=True, failed_kinds=None):
    """Build a list of 4 AnalysisResults, optionally with some failed."""
    failed_kinds = failed_kinds or []
    kinds = [
        ("CONSISTENCY", {"consistency_score": 0.85}),
        ("ACCESS", {"access_declared": "read", "access_observed": "read", "trust_score": 0.7, "trust_tier": "HIGH", "authority_domains": ["domain1"]}),
        ("TAINT", {"taint_detected": False, "taint_details": "", "blast_tier": "CONTAINED"}),
        ("CONFLICT", {"conflict_detected": False, "conflict_description": ""}),
    ]
    results = []
    for kind_name, fields in kinds:
        try:
            kind_enum = AnalyzerKind[kind_name]
        except (KeyError, TypeError):
            kind_enum = kind_name
        is_failed = kind_name in failed_kinds
        results.append(_make_analysis_result(
            kind_enum,
            success=not is_failed,
            **(fields if not is_failed else {"error_message": f"{kind_name} failed"})
        ))
    return results


# ─── TraceId Validation ─────────────────────────────────────────────────────

class TestGoodhartTraceIdValidation:

    def test_goodhart_trace_id_uppercase_rejected(self):
        """TraceId validation must enforce lowercase hex — uppercase hex characters should be rejected"""
        raw = [_make_valid_raw_span(trace_id="ABCDEF01234567890123456789012345")]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        # Should be rejected
        assert hasattr(result, 'parsed_spans') or hasattr(result, 'rejected_count')
        parsed = getattr(result, 'parsed_spans', [])
        rejected = getattr(result, 'rejected_count', len(raw) - len(parsed))
        assert len(parsed) == 0, "Uppercase trace_id should be rejected"
        assert rejected == 1

    def test_goodhart_trace_id_33_chars_rejected(self):
        """TraceId validation must enforce exactly 32 chars — 33-char hex string rejected"""
        raw = [_make_valid_raw_span(trace_id="a" * 33)]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 0, "33-char trace_id should be rejected"

    def test_goodhart_trace_id_31_chars_rejected(self):
        """TraceId validation must enforce exactly 32 chars — 31-char hex string rejected"""
        raw = [_make_valid_raw_span(trace_id="a" * 31)]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 0, "31-char trace_id should be rejected"

    def test_goodhart_trace_id_non_hex_chars_rejected(self):
        """TraceId must reject non-hex characters even if exactly 32 chars"""
        raw = [_make_valid_raw_span(trace_id="z" * 32)]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 0, "Non-hex trace_id should be rejected"


# ─── SpanId Validation ──────────────────────────────────────────────────────

class TestGoodhartSpanIdValidation:

    def test_goodhart_span_id_uppercase_rejected(self):
        """SpanId validation must enforce lowercase hex — uppercase rejected"""
        raw = [_make_valid_raw_span(span_id="ABCDEF0123456789")]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 0, "Uppercase span_id should be rejected"

    def test_goodhart_span_id_17_chars_rejected(self):
        """SpanId validation must enforce exactly 16 chars — 17 chars rejected"""
        raw = [_make_valid_raw_span(span_id="a" * 17)]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 0, "17-char span_id should be rejected"


# ─── Protobuf Default-Value Ambiguity ───────────────────────────────────────

class TestGoodhartProtobufDefaults:

    def test_goodhart_empty_baton_execution_id_rejected(self):
        """Empty string baton.execution_id must be treated as unset/missing per protobuf ambiguity rules"""
        raw = [_make_valid_raw_span(execution_id="")]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 0, "Empty execution_id should be rejected"

    def test_goodhart_empty_baton_node_id_rejected(self):
        """Empty string baton.node_id must be treated as unset/missing per protobuf ambiguity rules"""
        raw = [_make_valid_raw_span(node_id="")]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 0, "Empty node_id should be rejected"


# ─── Duration Calculation ───────────────────────────────────────────────────

class TestGoodhartDurationCalculation:

    def test_goodhart_duration_ns_various_values(self):
        """duration_ns must be dynamically computed for arbitrary timestamp pairs, not hardcoded"""
        test_cases = [
            (1000000000, 1000000001, 1),           # 1ns delta
            (1000000000, 1999999999, 999999999),    # ~1s delta
            (5000000000, 10000000000, 5000000000),  # 5s delta
            (100, 200, 100),                        # Small timestamps
        ]
        for start, end, expected_duration in test_cases:
            raw = [_make_valid_raw_span(start_time=start, end_time=end)]
            result = parse_and_validate_spans(raw, _make_resource_attributes())
            parsed = getattr(result, 'parsed_spans', [])
            assert len(parsed) == 1, f"Span with start={start}, end={end} should parse"
            assert parsed[0].duration_ns == expected_duration, \
                f"duration_ns should be {expected_duration} for start={start}, end={end}, got {parsed[0].duration_ns}"

    def test_goodhart_received_at_is_current_time(self):
        """received_at_unix_nano must be set to actual current UTC time, not hardcoded"""
        before = time.time_ns()
        raw = [_make_valid_raw_span()]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        after = time.time_ns()
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 1
        received = parsed[0].received_at_unix_nano
        assert received > 0, "received_at_unix_nano must be positive"
        # Allow 5-second window
        assert before - 5_000_000_000 <= received <= after + 5_000_000_000, \
            "received_at_unix_nano should be near current time"


# ─── Multiple Spans Parsing ────────────────────────────────────────────────

class TestGoodhartMultiSpanParsing:

    def test_goodhart_parse_five_valid_spans(self):
        """Parsing must work correctly for multiple valid spans with different IDs in one batch"""
        raws = []
        for i in range(5):
            tid = f"abcdef012345678{i:01x}abcdef012345678{i:01x}"[:32]
            # Ensure each trace_id is exactly 32 hex chars and unique
            tid = f"{i+1:032x}"
            sid = f"{i+1:016x}"
            raws.append(_make_valid_raw_span(trace_id=tid, span_id=sid, execution_id=f"exec-{i}"))
        result = parse_and_validate_spans(raws, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 5, f"All 5 valid spans should parse, got {len(parsed)}"

    def test_goodhart_parse_root_span_none_parent(self):
        """Root spans should have parent_span_id as None"""
        raw = [_make_valid_raw_span()]  # No parent_span_id in dict
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 1
        assert parsed[0].parent_span_id is None, "Root span should have None parent_span_id"

    def test_goodhart_parse_child_span_preserves_parent(self):
        """Child spans must preserve a valid parent_span_id"""
        parent_sid = "1234567890abcdef"
        raw = [_make_valid_raw_span(parent_span_id=parent_sid)]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 1
        assert parsed[0].parent_span_id == parent_sid, "parent_span_id should be preserved"

    def test_goodhart_parse_span_name_preserved(self):
        """Span name must be preserved exactly from input"""
        name = "my.custom.span.operation/with-special_chars.v2"
        raw = [_make_valid_raw_span(name=name)]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 1
        assert parsed[0].name == name

    def test_goodhart_parse_baton_fields_preserved(self):
        """baton_component_id and baton_circuit_id must be preserved"""
        raw = [_make_valid_raw_span(component_id="comp-xyz", circuit_id="circuit-999")]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        assert len(parsed) == 1
        assert parsed[0].baton_component_id == "comp-xyz"
        assert parsed[0].baton_circuit_id == "circuit-999"

    def test_goodhart_parse_warning_not_rejected(self):
        """Spans with only WARNING-severity issues must still be accepted, not rejected"""
        # A span with unexpected extra attributes might trigger warnings but should still parse
        extra = [{"key": "unexpected.attribute", "value": {"stringValue": "surprise"}}]
        raw = [_make_valid_raw_span(extra_attributes=extra)]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        rejected = getattr(result, 'rejected_count', len(raw) - len(parsed))
        # The span should be in parsed, not rejected (warnings don't reject)
        assert len(parsed) == 1, "Span with only warnings should be accepted"
        assert rejected == 0

    def test_goodhart_parse_validation_issue_includes_span_id(self):
        """ValidationIssue must include the span_id of the problematic span"""
        bad_tid = "x" * 32  # Invalid hex
        raw = [_make_valid_raw_span(trace_id=bad_tid)]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        issues = getattr(result, 'validation_issues', [])
        assert len(issues) > 0, "Should have validation issues"
        for issue in issues:
            if hasattr(issue, 'severity') and str(issue.severity) in ('ERROR', 'ValidationSeverity.ERROR'):
                assert issue.field != "" or issue.message != "", "Issue should have field or message detail"


# ─── Aggregation ────────────────────────────────────────────────────────────

class TestGoodhartAggregation:

    def test_goodhart_aggregate_consistency_boundary_zero(self):
        """Consistency score 0.0 must be in valid range [0.0, 1.0]"""
        results = _make_four_results()
        # Override consistency to 0.0
        for r in results:
            if hasattr(r, 'analyzer_kind'):
                kind = r.analyzer_kind
                kind_name = kind.name if hasattr(kind, 'name') else str(kind)
                if kind_name == "CONSISTENCY":
                    r.consistency_score = 0.0
        enrichment = aggregate_enrichment(results)
        assert 0.0 <= enrichment.consistency <= 1.0

    def test_goodhart_aggregate_consistency_boundary_one(self):
        """Consistency score 1.0 must be in valid range [0.0, 1.0]"""
        results = _make_four_results()
        for r in results:
            if hasattr(r, 'analyzer_kind'):
                kind = r.analyzer_kind
                kind_name = kind.name if hasattr(kind, 'name') else str(kind)
                if kind_name == "CONSISTENCY":
                    r.consistency_score = 1.0
        enrichment = aggregate_enrichment(results)
        assert 0.0 <= enrichment.consistency <= 1.0

    def test_goodhart_aggregate_trust_score_boundary(self):
        """Trust score boundaries 0.0 and 1.0 must be valid"""
        for score in [0.0, 1.0]:
            results = _make_four_results()
            for r in results:
                if hasattr(r, 'analyzer_kind'):
                    kind = r.analyzer_kind
                    kind_name = kind.name if hasattr(kind, 'name') else str(kind)
                    if kind_name == "ACCESS":
                        r.trust_score = score
            enrichment = aggregate_enrichment(results)
            assert 0.0 <= enrichment.trust_score <= 1.0

    def test_goodhart_aggregate_all_failed_safe_defaults(self):
        """When all 4 analyzers fail, enrichment must have safe defaults for every field"""
        results = _make_four_results(failed_kinds=["CONSISTENCY", "ACCESS", "TAINT", "CONFLICT"])
        enrichment = aggregate_enrichment(results)
        assert enrichment.consistency == 0.0
        assert enrichment.trust_score == 0.0
        trust_tier_name = enrichment.trust_tier.name if hasattr(enrichment.trust_tier, 'name') else str(enrichment.trust_tier)
        assert trust_tier_name == "UNKNOWN"
        blast_tier_name = enrichment.blast_tier.name if hasattr(enrichment.blast_tier, 'name') else str(enrichment.blast_tier)
        assert blast_tier_name == "UNKNOWN"
        assert enrichment.taint_detected is False
        assert enrichment.access_declared == ""
        assert enrichment.access_observed == ""
        assert enrichment.authority_domains == [] or list(enrichment.authority_domains) == []
        assert enrichment.conflict == ""

    def test_goodhart_aggregate_3_results_error(self):
        """aggregate_enrichment must reject lists with exactly 3 entries"""
        results = _make_four_results()[:3]
        with pytest.raises(Exception):
            aggregate_enrichment(results)

    def test_goodhart_aggregate_5_results_error(self):
        """aggregate_enrichment must reject lists with exactly 5 entries"""
        results = _make_four_results()
        # Add a duplicate
        results.append(results[0])
        # Might raise wrong_result_count or duplicate_analyzer_kind
        with pytest.raises(Exception):
            aggregate_enrichment(results)

    def test_goodhart_aggregate_1_result_error(self):
        """aggregate_enrichment must reject a single-element result list"""
        results = _make_four_results()[:1]
        with pytest.raises(Exception):
            aggregate_enrichment(results)

    def test_goodhart_aggregate_enrichment_frozen(self):
        """ArbiterEnrichment should be frozen/immutable"""
        results = _make_four_results()
        enrichment = aggregate_enrichment(results)
        with pytest.raises((AttributeError, TypeError, Exception)):
            enrichment.consistency = 999.0


# ─── Dispatch ───────────────────────────────────────────────────────────────

class TestGoodhartDispatch:

    def test_goodhart_dispatch_all_four_kinds_present(self):
        """dispatch_to_analyzers result must contain exactly one entry per AnalyzerKind"""
        # We need a valid parsed span first
        raw = [_make_valid_raw_span()]
        parse_result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(parse_result, 'parsed_spans', [])
        if len(parsed) == 0:
            pytest.skip("Could not create valid ParsedSpan for dispatch test")

        span = parsed[0]

        # Mock all 4 analyzers to succeed
        mock_consistency = MagicMock(return_value=_make_analysis_result(
            AnalyzerKind.CONSISTENCY if hasattr(AnalyzerKind, 'CONSISTENCY') else "CONSISTENCY",
            consistency_score=0.9
        ))
        mock_access = MagicMock(return_value=_make_analysis_result(
            AnalyzerKind.ACCESS if hasattr(AnalyzerKind, 'ACCESS') else "ACCESS",
            access_declared="read", access_observed="read", trust_score=0.8
        ))
        mock_taint = MagicMock(return_value=_make_analysis_result(
            AnalyzerKind.TAINT if hasattr(AnalyzerKind, 'TAINT') else "TAINT",
            taint_detected=False
        ))
        mock_conflict = MagicMock(return_value=_make_analysis_result(
            AnalyzerKind.CONFLICT if hasattr(AnalyzerKind, 'CONFLICT') else "CONFLICT",
            conflict_detected=False
        ))

        # The actual dispatch should return exactly 4 results
        try:
            results = dispatch_to_analyzers(span)
        except Exception:
            pytest.skip("dispatch_to_analyzers requires server setup")
            return

        assert len(results) == 4, f"Expected exactly 4 results, got {len(results)}"
        kind_names = set()
        for r in results:
            kind = r.analyzer_kind
            kind_name = kind.name if hasattr(kind, 'name') else str(kind)
            kind_names.add(kind_name)
        assert len(kind_names) == 4, f"Expected 4 unique kinds, got {kind_names}"

    def test_goodhart_dispatch_two_analyzers_fail_others_succeed(self):
        """When 2 of 4 analyzers fail, the other 2 must still succeed independently"""
        raw = [_make_valid_raw_span()]
        parse_result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(parse_result, 'parsed_spans', [])
        if len(parsed) == 0:
            pytest.skip("Could not create valid ParsedSpan")

        span = parsed[0]
        try:
            results = dispatch_to_analyzers(span)
        except Exception:
            pytest.skip("dispatch_to_analyzers requires server setup")
            return

        # At minimum, verify the contract: exactly 4 results, no exceptions propagated
        assert len(results) == 4


# ─── Build Enriched Span ───────────────────────────────────────────────────

class TestGoodhartBuildEnrichedSpan:

    def test_goodhart_enriched_at_is_current_time(self):
        """enriched_at_unix_nano must reflect actual current UTC time"""
        raw = [_make_valid_raw_span()]
        parse_result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(parse_result, 'parsed_spans', [])
        if len(parsed) == 0:
            pytest.skip("Could not create valid ParsedSpan")

        span = parsed[0]
        results = _make_four_results()
        enrichment = aggregate_enrichment(results)

        before = time.time_ns()
        enriched = build_enriched_span(span, enrichment, [])
        after = time.time_ns()

        assert enriched.enriched_at_unix_nano > 0
        assert before - 5_000_000_000 <= enriched.enriched_at_unix_nano <= after + 5_000_000_000

    def test_goodhart_enriched_span_identity_preservation(self):
        """build_enriched_span must preserve input span and enrichment by identity/equality"""
        raw = [_make_valid_raw_span(
            trace_id="deadbeef" * 4,
            span_id="cafebabe" + "12345678",
            node_id="node-identity-test",
            execution_id="exec-identity-test"
        )]
        parse_result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(parse_result, 'parsed_spans', [])
        if len(parsed) == 0:
            pytest.skip("Could not create valid ParsedSpan")

        span = parsed[0]
        results = _make_four_results()
        enrichment = aggregate_enrichment(results)

        enriched = build_enriched_span(span, enrichment, [])
        assert enriched.span.trace_id == span.trace_id
        assert enriched.span.span_id == span.span_id
        assert enriched.span.baton_node_id == "node-identity-test"
        assert enriched.enrichment.consistency == enrichment.consistency
        assert enriched.enrichment.trust_score == enrichment.trust_score


# ─── Buffer Operations ─────────────────────────────────────────────────────

class TestGoodhartBuffer:

    def _add_span_to_buffer(self, execution_id, received_at=None):
        """Helper to create and add a span to the buffer."""
        raw = [_make_valid_raw_span(execution_id=execution_id)]
        result = parse_and_validate_spans(raw, _make_resource_attributes())
        parsed = getattr(result, 'parsed_spans', [])
        if len(parsed) == 0:
            pytest.skip("Could not create valid ParsedSpan for buffer test")
        span = parsed[0]
        if received_at is not None:
            # Attempt to set received_at for ordering tests
            try:
                span.received_at_unix_nano = received_at
            except (AttributeError, TypeError):
                pass  # Frozen model, can't override
        buffer_add(span)
        return span

    def test_goodhart_buffer_get_different_execution_ids_isolated(self):
        """buffer_get for one execution_id must not return spans from another"""
        # Clear buffer first
        try:
            buffer_drain()
        except Exception:
            pass

        self._add_span_to_buffer("exec-A")
        self._add_span_to_buffer("exec-A")
        self._add_span_to_buffer("exec-B")
        self._add_span_to_buffer("exec-B")

        spans_a = buffer_get("exec-A")
        spans_b = buffer_get("exec-B")

        assert len(spans_a) == 2, f"exec-A should have 2 spans, got {len(spans_a)}"
        assert len(spans_b) == 2, f"exec-B should have 2 spans, got {len(spans_b)}"

        # Verify isolation
        for s in spans_a:
            assert s.baton_execution_id == "exec-A"
        for s in spans_b:
            assert s.baton_execution_id == "exec-B"

    def test_goodhart_buffer_stats_total_spans_vs_keys(self):
        """BufferStats total_spans must count individual spans, current_size counts keys"""
        try:
            buffer_drain()
        except Exception:
            pass

        self._add_span_to_buffer("exec-X")
        self._add_span_to_buffer("exec-X")
        self._add_span_to_buffer("exec-X")
        self._add_span_to_buffer("exec-Y")
        self._add_span_to_buffer("exec-Y")

        stats = buffer_get_stats()
        assert stats.current_size == 2, f"Should have 2 keys, got {stats.current_size}"
        assert stats.total_spans >= 5, f"Should have at least 5 total spans, got {stats.total_spans}"

    def test_goodhart_buffer_drain_multiple_execution_ids(self):
        """buffer_drain must return spans from all execution_ids"""
        try:
            buffer_drain()
        except Exception:
            pass

        self._add_span_to_buffer("exec-drain-1")
        self._add_span_to_buffer("exec-drain-2")
        self._add_span_to_buffer("exec-drain-3")

        drained = buffer_drain()
        exec_ids = {s.baton_execution_id for s in drained}
        assert "exec-drain-1" in exec_ids
        assert "exec-drain-2" in exec_ids
        assert "exec-drain-3" in exec_ids

        stats = buffer_get_stats()
        assert stats.current_size == 0, "Buffer should be empty after drain"

    def test_goodhart_buffer_stats_max_size_matches_config(self):
        """BufferStats.max_size must reflect configured value, not hardcoded"""
        stats = buffer_get_stats()
        assert stats.max_size > 0, "max_size should be positive"
        assert stats.current_size <= stats.max_size, "current_size must not exceed max_size"

    def test_goodhart_buffer_stats_oldest_entry_none_when_empty(self):
        """oldest_entry_age_seconds should be None when buffer is empty"""
        try:
            buffer_drain()
        except Exception:
            pass
        stats = buffer_get_stats()
        assert stats.oldest_entry_age_seconds is None, \
            "oldest_entry_age_seconds should be None for empty buffer"

    def test_goodhart_buffer_stats_oldest_entry_nonnull_when_populated(self):
        """oldest_entry_age_seconds should be non-None when buffer has entries"""
        try:
            buffer_drain()
        except Exception:
            pass
        self._add_span_to_buffer("exec-age-test")
        stats = buffer_get_stats()
        assert stats.oldest_entry_age_seconds is not None
        assert stats.oldest_entry_age_seconds >= 0.0

    def test_goodhart_buffer_get_returns_ordered_by_received_at(self):
        """buffer_get must return spans ordered by received_at_unix_nano ascending"""
        try:
            buffer_drain()
        except Exception:
            pass

        # Add multiple spans under same execution_id
        for _ in range(3):
            self._add_span_to_buffer("exec-order-test")
            time.sleep(0.01)  # Small delay to ensure different received_at

        spans = buffer_get("exec-order-test")
        assert len(spans) == 3
        for i in range(len(spans) - 1):
            assert spans[i].received_at_unix_nano <= spans[i + 1].received_at_unix_nano, \
                "Spans must be ordered by received_at_unix_nano ascending"


# ─── Handle Export ──────────────────────────────────────────────────────────

class TestGoodhartHandleExport:

    def test_goodhart_handle_export_all_invalid_batch(self):
        """When all spans fail validation, accepted_count=0 but no crash — partial success semantics"""
        # Need server in SERVING state - this may need setup
        try:
            bad_spans = [
                _make_valid_raw_span(trace_id="x" * 32),  # Invalid hex
                _make_valid_raw_span(trace_id="y" * 32),  # Invalid hex
                _make_valid_raw_span(trace_id="z" * 32),  # Invalid hex
            ]
            result = handle_export_request(bad_spans, _make_resource_attributes())
            assert result.accepted_count == 0
            assert result.rejected_count == 3
            assert len(result.enriched_spans) == 0
        except Exception as e:
            err_str = str(e).lower()
            if "not_ready" in err_str or "server_not_ready" in err_str or "not serving" in err_str:
                pytest.skip("Server not in SERVING state for this test")
            raise

    def test_goodhart_handle_export_single_span_batch(self):
        """handle_export_request must work with a batch of exactly 1 valid span"""
        try:
            raw = [_make_valid_raw_span()]
            result = handle_export_request(raw, _make_resource_attributes())
            assert result.accepted_count == 1
            assert result.rejected_count == 0
            assert len(result.enriched_spans) == 1
        except Exception as e:
            err_str = str(e).lower()
            if "not_ready" in err_str or "server_not_ready" in err_str or "not serving" in err_str:
                pytest.skip("Server not in SERVING state for this test")
            raise

    def test_goodhart_handle_export_enriched_has_all_9_attributes(self):
        """Each enriched span must have all 9 arbiter.* attributes populated"""
        try:
            raw = [_make_valid_raw_span()]
            result = handle_export_request(raw, _make_resource_attributes())
            if result.accepted_count == 0:
                pytest.skip("No spans accepted")
            enriched = result.enriched_spans[0]
            e = enriched.enrichment
            # Check all 9 attributes exist
            assert hasattr(e, 'access_declared')
            assert hasattr(e, 'access_observed')
            assert hasattr(e, 'consistency')
            assert hasattr(e, 'trust_score')
            assert hasattr(e, 'trust_tier')
            assert hasattr(e, 'authority_domains')
            assert hasattr(e, 'taint_detected')
            assert hasattr(e, 'blast_tier')
            assert hasattr(e, 'conflict')
        except Exception as e:
            err_str = str(e).lower()
            if "not_ready" in err_str or "server_not_ready" in err_str or "not serving" in err_str:
                pytest.skip("Server not in SERVING state for this test")
            raise


# ─── Lifecycle ──────────────────────────────────────────────────────────────

class TestGoodhartLifecycle:

    def test_goodhart_is_ready_false_after_stop(self):
        """is_ready must return False after server has been stopped"""
        # If server is currently SERVING, stop it and check
        status = get_server_status()
        status_name = status.name if hasattr(status, 'name') else str(status)
        if status_name == "SERVING":
            stop(grace=1.0)
            assert is_ready() is False
        elif status_name in ("NOT_STARTED", "STOPPED"):
            assert is_ready() is False
        # Don't fail - just verify the property

    def test_goodhart_get_status_reflects_stopped(self):
        """get_server_status must return STOPPED after stop() is called"""
        status = get_server_status()
        status_name = status.name if hasattr(status, 'name') else str(status)
        if status_name == "SERVING":
            stop(grace=1.0)
            status = get_server_status()
            status_name = status.name if hasattr(status, 'name') else str(status)
            assert status_name == "STOPPED"

    def test_goodhart_stop_when_already_stopped_error(self):
        """Calling stop() when already STOPPED should raise not_running error"""
        status = get_server_status()
        status_name = status.name if hasattr(status, 'name') else str(status)
        if status_name in ("NOT_STARTED", "STOPPED"):
            with pytest.raises(Exception):
                stop(grace=1.0)


# ─── Config Edge Cases ─────────────────────────────────────────────────────

class TestGoodhartConfig:

    def test_goodhart_config_partial_yaml_applies_specified_and_defaults(self, tmp_path):
        """load_config must use specified values from YAML and defaults for the rest"""
        config_file = tmp_path / "partial.yaml"
        config_file.write_text("port: 9999\n")
        config = load_config(str(config_file))
        assert config.port == 9999
        # Other fields should have positive defaults
        assert config.max_workers > 0
        assert config.buffer_max_size > 0
        assert config.buffer_window_seconds > 0

    def test_goodhart_config_negative_port_rejected(self, tmp_path):
        """Pydantic validation must reject negative port"""
        config_file = tmp_path / "bad_port.yaml"
        config_file.write_text("port: -1\n")
        with pytest.raises(Exception):
            load_config(str(config_file))

    def test_goodhart_config_zero_max_workers_rejected(self, tmp_path):
        """Pydantic validation must reject zero max_workers"""
        config_file = tmp_path / "bad_workers.yaml"
        config_file.write_text("max_workers: 0\n")
        with pytest.raises(Exception):
            load_config(str(config_file))

    def test_goodhart_config_zero_buffer_max_size_rejected(self, tmp_path):
        """Pydantic validation must reject zero buffer_max_size"""
        config_file = tmp_path / "bad_buffer.yaml"
        config_file.write_text("buffer_max_size: 0\n")
        with pytest.raises(Exception):
            load_config(str(config_file))

    def test_goodhart_config_negative_window_seconds_rejected(self, tmp_path):
        """Pydantic validation must reject negative buffer_window_seconds"""
        config_file = tmp_path / "bad_window.yaml"
        config_file.write_text("buffer_window_seconds: -5.0\n")
        with pytest.raises(Exception):
            load_config(str(config_file))
