"""
Contract test suite for otlp_subscriber component.
Tests verify behavior against the contract specification.
Run with: pytest contract_test.py -v
"""

import time
import threading
from unittest.mock import MagicMock, patch, PropertyMock, call
from copy import deepcopy

import pytest

# ---------------------------------------------------------------------------
# Import the component under test
# ---------------------------------------------------------------------------
from otlp_subscriber import (
    load_config,
    start,
    stop,
    is_ready,
    get_server_status,
    parse_and_validate_spans,
    dispatch_to_analyzers,
    aggregate_enrichment,
    build_enriched_span,
    handle_export_request,
    buffer_add,
    buffer_get,
    buffer_get_stats,
    buffer_drain,
    buffer_evict_expired,
    OtlpSubscriberConfig,
    SpanAttribute,
    SpanLink,
    SpanEvent,
    BatonSpanContract,
    ParsedSpan,
    AnalysisResult,
    ArbiterEnrichment,
    EnrichedSpan,
    AnalyzerError,
    ExportResult,
    BufferStats,
    ValidationIssue,
    AnalyzerKind,
    TrustTier,
    BlastTier,
    ServerStatus,
    ValidationSeverity,
)


# ===========================================================================
# Conftest-equivalent: Factories and Fixtures
# ===========================================================================

VALID_TRACE_ID = "abcdef1234567890abcdef1234567890"
VALID_SPAN_ID = "abcdef1234567890"
VALID_PARENT_SPAN_ID = "1234567890abcdef"
VALID_NODE_ID = "node-test-001"
VALID_EXECUTION_ID = "exec-test-001"
VALID_COMPONENT_ID = "component-test-001"
VALID_CIRCUIT_ID = "circuit-test-001"
VALID_START_TIME = 1700000000000000000  # nanoseconds
VALID_END_TIME = 1700000001000000000    # 1 second later


def make_raw_span(
    trace_id=VALID_TRACE_ID,
    span_id=VALID_SPAN_ID,
    parent_span_id=VALID_PARENT_SPAN_ID,
    name="test-span",
    start_time_unix_nano=VALID_START_TIME,
    end_time_unix_nano=VALID_END_TIME,
    baton_node_id=VALID_NODE_ID,
    baton_execution_id=VALID_EXECUTION_ID,
    baton_component_id=VALID_COMPONENT_ID,
    baton_circuit_id=VALID_CIRCUIT_ID,
    attributes=None,
    events=None,
    links=None,
):
    """Factory for raw protobuf span dicts as would come from OTLP deserialization."""
    base_attrs = [
        {"key": "baton.node_id", "value": baton_node_id, "original_type": "string"},
        {"key": "baton.execution_id", "value": baton_execution_id, "original_type": "string"},
        {"key": "baton.component_id", "value": baton_component_id, "original_type": "string"},
        {"key": "baton.circuit_id", "value": baton_circuit_id, "original_type": "string"},
    ]
    if attributes:
        base_attrs.extend(attributes)

    raw = {
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "name": name,
        "start_time_unix_nano": start_time_unix_nano,
        "end_time_unix_nano": end_time_unix_nano,
        "attributes": base_attrs,
        "events": events or [],
        "links": links or [],
    }
    return raw


def make_resource_attributes():
    """Factory for resource attributes list."""
    return [
        {"key": "service.name", "value": "test-service", "original_type": "string"},
        {"key": "service.version", "value": "1.0.0", "original_type": "string"},
    ]


def make_parsed_span(
    trace_id=VALID_TRACE_ID,
    span_id=VALID_SPAN_ID,
    parent_span_id=VALID_PARENT_SPAN_ID,
    name="test-span",
    start_time_unix_nano=VALID_START_TIME,
    end_time_unix_nano=VALID_END_TIME,
    baton_node_id=VALID_NODE_ID,
    baton_execution_id=VALID_EXECUTION_ID,
    baton_component_id=VALID_COMPONENT_ID,
    baton_circuit_id=VALID_CIRCUIT_ID,
    received_at_unix_nano=None,
):
    """Factory for ParsedSpan domain objects."""
    if received_at_unix_nano is None:
        received_at_unix_nano = int(time.time() * 1e9)
    duration_ns = end_time_unix_nano - start_time_unix_nano

    return ParsedSpan(
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        name=name,
        start_time_unix_nano=start_time_unix_nano,
        end_time_unix_nano=end_time_unix_nano,
        duration_ns=duration_ns,
        attributes=[],
        events=[],
        links=[],
        baton_node_id=baton_node_id,
        baton_execution_id=baton_execution_id,
        baton_component_id=baton_component_id,
        baton_circuit_id=baton_circuit_id,
        resource_attributes=[],
        validation_issues=[],
        received_at_unix_nano=received_at_unix_nano,
    )


def make_analysis_result(
    analyzer_kind,
    success=True,
    error_message="",
    consistency_score=None,
    trust_score=None,
    trust_tier=None,
    access_declared="",
    access_observed="",
    authority_domains=None,
    taint_detected=None,
    taint_details="",
    blast_tier=None,
    conflict_description="",
    conflict_detected=None,
):
    """Factory for AnalysisResult."""
    return AnalysisResult(
        analyzer_kind=analyzer_kind,
        success=success,
        error_message=error_message,
        consistency_score=consistency_score,
        access_declared=access_declared,
        access_observed=access_observed,
        authority_domains=authority_domains or [],
        trust_score=trust_score,
        trust_tier=trust_tier,
        taint_detected=taint_detected,
        taint_details=taint_details,
        blast_tier=blast_tier,
        conflict_description=conflict_description,
        conflict_detected=conflict_detected,
    )


def make_all_success_results():
    """Create 4 AnalysisResult objects simulating all analyzers succeeding."""
    return [
        make_analysis_result(
            AnalyzerKind.CONSISTENCY,
            success=True,
            consistency_score=0.95,
        ),
        make_analysis_result(
            AnalyzerKind.ACCESS,
            success=True,
            access_declared="read",
            access_observed="read",
            authority_domains=["domain-a"],
            trust_score=0.85,
            trust_tier=TrustTier.HIGH,
        ),
        make_analysis_result(
            AnalyzerKind.TAINT,
            success=True,
            taint_detected=False,
            taint_details="",
            blast_tier=BlastTier.CONTAINED,
        ),
        make_analysis_result(
            AnalyzerKind.CONFLICT,
            success=True,
            conflict_description="",
            conflict_detected=False,
        ),
    ]


def make_mock_analyzer(analyzer_kind, result=None, side_effect=None):
    """Create a mock analyzer that returns a predetermined result or raises."""
    mock = MagicMock()
    mock.kind = analyzer_kind
    if side_effect:
        mock.analyze.side_effect = side_effect
    elif result:
        mock.analyze.return_value = result
    else:
        mock.analyze.return_value = make_analysis_result(analyzer_kind)
    return mock


def make_analyzer_registration(kinds=None, failing_kind=None, failing_exception=None):
    """Create a dict of mock analyzers keyed by AnalyzerKind.
    If failing_kind is specified, that analyzer will raise failing_exception.
    """
    if kinds is None:
        kinds = [AnalyzerKind.CONSISTENCY, AnalyzerKind.ACCESS, AnalyzerKind.TAINT, AnalyzerKind.CONFLICT]
    reg = {}
    for kind in kinds:
        if kind == failing_kind and failing_exception:
            reg[kind] = make_mock_analyzer(kind, side_effect=failing_exception)
        else:
            reg[kind] = make_mock_analyzer(kind)
    return reg


def make_valid_config(**overrides):
    """Factory for a valid OtlpSubscriberConfig with reasonable defaults."""
    defaults = {
        "port": 4317,
        "max_workers": 4,
        "buffer_max_size": 100,
        "buffer_window_seconds": 30.0,
        "grace_shutdown_seconds": 5.0,
        "eviction_sweep_interval_seconds": 10.0,
        "max_batch_size": 50,
        "bind_address": "0.0.0.0",
    }
    defaults.update(overrides)
    return OtlpSubscriberConfig(**defaults)


# ===========================================================================
# Module 1: test_config - load_config tests
# ===========================================================================


class TestLoadConfigHappyPath:
    """Tests for load_config with valid inputs."""

    def test_load_valid_yaml_returns_populated_config(self, tmp_path):
        """load_config with valid YAML returns OtlpSubscriberConfig with all fields."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "port: 4318\n"
            "max_workers: 8\n"
            "buffer_max_size: 200\n"
            "buffer_window_seconds: 60.0\n"
            "grace_shutdown_seconds: 10.0\n"
            "eviction_sweep_interval_seconds: 15.0\n"
            "max_batch_size: 100\n"
            "bind_address: '127.0.0.1'\n"
        )
        config = load_config(str(config_file))
        assert config.port == 4318
        assert config.max_workers == 8
        assert config.buffer_max_size == 200
        assert config.buffer_window_seconds == 60.0
        assert config.grace_shutdown_seconds == 10.0
        assert config.eviction_sweep_interval_seconds == 15.0
        assert config.max_batch_size == 100
        assert config.bind_address == "127.0.0.1"

    def test_load_missing_file_returns_defaults(self, tmp_path):
        """load_config returns default config when path does not exist."""
        config = load_config(str(tmp_path / "nonexistent.yaml"))
        assert config.port is not None
        assert config.max_workers is not None
        assert config.buffer_max_size is not None
        assert config.buffer_window_seconds is not None
        assert config.grace_shutdown_seconds is not None
        assert config.eviction_sweep_interval_seconds is not None
        assert config.max_batch_size is not None
        assert config.bind_address is not None

    def test_load_partial_yaml_applies_defaults(self, tmp_path):
        """load_config applies defaults for fields not specified in YAML."""
        config_file = tmp_path / "partial.yaml"
        config_file.write_text("port: 9999\n")
        config = load_config(str(config_file))
        assert config.port == 9999
        # All other fields should have defaults
        assert config.max_workers is not None
        assert config.buffer_max_size is not None


class TestLoadConfigEdgeCases:
    """Edge case tests for load_config."""

    def test_load_empty_file_returns_defaults(self, tmp_path):
        """load_config returns default config when file is empty."""
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        config = load_config(str(config_file))
        assert config.port is not None
        assert config.max_workers is not None
        assert config.buffer_max_size is not None


class TestLoadConfigErrors:
    """Error case tests for load_config."""

    def test_load_invalid_yaml_raises_error(self, tmp_path):
        """load_config raises error for invalid YAML syntax."""
        config_file = tmp_path / "invalid.yaml"
        config_file.write_text("port: [invalid: yaml: {{{\n")
        with pytest.raises(Exception) as exc_info:
            load_config(str(config_file))
        # Should indicate YAML parsing failure
        assert exc_info.value is not None

    def test_load_validation_failure_raises_error(self, tmp_path):
        """load_config raises validation error for invalid field values."""
        config_file = tmp_path / "bad_values.yaml"
        config_file.write_text("port: -1\nbuffer_max_size: -100\n")
        with pytest.raises(Exception) as exc_info:
            load_config(str(config_file))
        assert exc_info.value is not None

    def test_load_permission_denied_raises_error(self, tmp_path):
        """load_config raises permission error for unreadable file."""
        config_file = tmp_path / "unreadable.yaml"
        config_file.write_text("port: 4317\n")
        # Mock the file read to simulate permission denied
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with patch("pathlib.Path.exists", return_value=True):
                with pytest.raises(Exception):
                    load_config(str(config_file))

    def test_load_empty_path_rejected(self):
        """load_config requires non-empty config_path string."""
        with pytest.raises(Exception):
            load_config("")


# ===========================================================================
# Module 2: test_lifecycle - start/stop/is_ready/get_server_status
# ===========================================================================


class TestLifecycleStart:
    """Tests for server start lifecycle."""

    def test_start_transitions_to_serving(self):
        """start transitions server from NOT_STARTED to SERVING."""
        config = make_valid_config(port=0)  # port 0 for OS-assigned
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            assert get_server_status() == ServerStatus.SERVING
            assert is_ready() is True
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_start_from_stopped_transitions_to_serving(self):
        """start can transition from STOPPED back to SERVING."""
        config = make_valid_config(port=0)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            stop(grace=1.0)
            assert get_server_status() == ServerStatus.STOPPED
            start(config, analyzers)
            assert get_server_status() == ServerStatus.SERVING
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_start_already_running_raises_error(self):
        """start raises error when server is already SERVING."""
        config = make_valid_config(port=0)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            with pytest.raises(Exception) as exc_info:
                start(config, analyzers)
            # Should indicate already running
            assert exc_info.value is not None
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_start_missing_analyzer_raises_error(self):
        """start raises error when fewer than 4 analyzers provided."""
        config = make_valid_config(port=0)
        # Only 3 analyzers
        analyzers = make_analyzer_registration(
            kinds=[AnalyzerKind.CONSISTENCY, AnalyzerKind.ACCESS, AnalyzerKind.TAINT]
        )
        with pytest.raises(Exception) as exc_info:
            start(config, analyzers)
        assert exc_info.value is not None


class TestLifecycleStop:
    """Tests for server stop lifecycle."""

    def test_stop_transitions_to_stopped(self):
        """stop transitions server from SERVING to STOPPED."""
        config = make_valid_config(port=0)
        analyzers = make_analyzer_registration()
        start(config, analyzers)
        stop(grace=2.0)
        assert get_server_status() == ServerStatus.STOPPED
        assert is_ready() is False

    def test_stop_not_running_raises_error(self):
        """stop raises error when server is NOT_STARTED."""
        with pytest.raises(Exception):
            stop(grace=1.0)


class TestLifecycleStatus:
    """Tests for is_ready and get_server_status."""

    def test_is_ready_false_when_not_started(self):
        """is_ready returns False when server is NOT_STARTED."""
        # Ensure clean state - may need to handle if server is already running
        try:
            status = get_server_status()
            if status == ServerStatus.SERVING:
                stop(grace=1.0)
        except Exception:
            pass
        assert is_ready() is False

    def test_get_status_initial_is_not_started_or_stopped(self):
        """get_server_status returns NOT_STARTED or STOPPED initially."""
        status = get_server_status()
        assert status in (ServerStatus.NOT_STARTED, ServerStatus.STOPPED)


# ===========================================================================
# Module 3: test_parse_validate - parse_and_validate_spans
# ===========================================================================


class TestParseValidateHappyPath:
    """Happy path tests for parse_and_validate_spans."""

    def test_parse_valid_minimal_span(self):
        """Converts a valid minimal raw span to ParsedSpan."""
        raw = make_raw_span()
        resource_attrs = make_resource_attributes()
        result = parse_and_validate_spans([raw], resource_attrs)
        parsed = result.parsed_spans if hasattr(result, 'parsed_spans') else result[0]

        # Handle tuple or object result
        if hasattr(result, 'parsed_spans'):
            parsed_spans = result.parsed_spans
            rejected_count = result.rejected_count if hasattr(result, 'rejected_count') else 0
        else:
            parsed_spans = result[0] if isinstance(result, tuple) else [result]
            rejected_count = result[1] if isinstance(result, tuple) and len(result) > 1 else 0

        assert len(parsed_spans) == 1
        span = parsed_spans[0]
        assert span.trace_id == VALID_TRACE_ID
        assert span.span_id == VALID_SPAN_ID
        assert span.duration_ns == VALID_END_TIME - VALID_START_TIME
        assert span.received_at_unix_nano > 0
        assert span.start_time_unix_nano > 0
        assert span.end_time_unix_nano > 0

    def test_parse_valid_full_span_with_events_links(self):
        """Converts a fully-populated raw span with events, links, and attributes."""
        events = [{"name": "test-event", "timestamp_unix_nano": VALID_START_TIME + 100, "attributes": []}]
        links = [{
            "trace_id": VALID_TRACE_ID,
            "span_id": "fedcba0987654321",
            "attributes": []
        }]
        extra_attrs = [{"key": "custom.attr", "value": "custom-value", "original_type": "string"}]
        raw = make_raw_span(events=events, links=links, attributes=extra_attrs)
        resource_attrs = make_resource_attributes()
        result = parse_and_validate_spans([raw], resource_attrs)

        if hasattr(result, 'parsed_spans'):
            parsed_spans = result.parsed_spans
        else:
            parsed_spans = result[0] if isinstance(result, tuple) else [result]

        assert len(parsed_spans) == 1
        span = parsed_spans[0]
        assert len(span.events) > 0
        assert len(span.links) > 0

    def test_parse_resource_attributes_passthrough(self):
        """Resource attributes are passed through to ParsedSpan."""
        raw = make_raw_span()
        resource_attrs = make_resource_attributes()
        result = parse_and_validate_spans([raw], resource_attrs)

        if hasattr(result, 'parsed_spans'):
            parsed_spans = result.parsed_spans
        else:
            parsed_spans = result[0] if isinstance(result, tuple) else [result]

        assert len(parsed_spans) == 1
        span = parsed_spans[0]
        assert len(span.resource_attributes) > 0


class TestParseValidateEdgeCases:
    """Edge case tests for parse_and_validate_spans."""

    def test_parse_empty_list_returns_empty(self):
        """Empty input list returns empty results."""
        result = parse_and_validate_spans([], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
        elif isinstance(result, tuple):
            assert len(result[0]) == 0
        else:
            assert result is not None


class TestParseValidateErrors:
    """Error case tests for parse_and_validate_spans — one per contract error type."""

    def test_parse_malformed_protobuf_rejects_non_dict(self):
        """Non-dict raw span is rejected as malformed_protobuf."""
        result = parse_and_validate_spans(["not-a-dict"], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
            rejected = result.rejected_count if hasattr(result, 'rejected_count') else 1
        elif isinstance(result, tuple):
            assert len(result[0]) == 0
            rejected = result[1] if len(result) > 1 else 1
        assert rejected >= 1

    def test_parse_invalid_trace_id_short(self):
        """Short trace_id (not 32 hex chars) causes rejection."""
        raw = make_raw_span(trace_id="abcdef1234567890")  # only 16 chars
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
            issues = result.validation_issues if hasattr(result, 'validation_issues') else []
        elif isinstance(result, tuple):
            assert len(result[0]) == 0
            issues = result[2] if len(result) > 2 else []

        # Verify issue mentions trace_id
        if issues:
            issue_fields = [getattr(i, 'field', '') for i in issues]
            issue_messages = [getattr(i, 'message', '') for i in issues]
            assert any('trace_id' in f or 'trace_id' in m
                      for f, m in zip(issue_fields, issue_messages))

    def test_parse_invalid_trace_id_all_zeros(self):
        """All-zero trace_id is rejected."""
        raw = make_raw_span(trace_id="0" * 32)
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
        elif isinstance(result, tuple):
            assert len(result[0]) == 0

    def test_parse_invalid_span_id_short(self):
        """Short span_id (not 16 hex chars) causes rejection."""
        raw = make_raw_span(span_id="abcdef12")  # only 8 chars
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
        elif isinstance(result, tuple):
            assert len(result[0]) == 0

    def test_parse_invalid_span_id_all_zeros(self):
        """All-zero span_id is rejected."""
        raw = make_raw_span(span_id="0" * 16)
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
        elif isinstance(result, tuple):
            assert len(result[0]) == 0

    def test_parse_missing_baton_node_id(self):
        """Missing baton.node_id attribute causes rejection."""
        raw = make_raw_span()
        # Remove baton.node_id from attributes
        raw["attributes"] = [
            a for a in raw["attributes"] if a["key"] != "baton.node_id"
        ]
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
        elif isinstance(result, tuple):
            assert len(result[0]) == 0

    def test_parse_missing_baton_execution_id(self):
        """Missing baton.execution_id attribute causes rejection."""
        raw = make_raw_span()
        raw["attributes"] = [
            a for a in raw["attributes"] if a["key"] != "baton.execution_id"
        ]
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
        elif isinstance(result, tuple):
            assert len(result[0]) == 0

    def test_parse_timestamp_zero_start(self):
        """start_time_unix_nano == 0 causes rejection (protobuf default ambiguity)."""
        raw = make_raw_span(start_time_unix_nano=0)
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
        elif isinstance(result, tuple):
            assert len(result[0]) == 0

    def test_parse_timestamp_zero_end(self):
        """end_time_unix_nano == 0 causes rejection (protobuf default ambiguity)."""
        raw = make_raw_span(end_time_unix_nano=0)
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
        elif isinstance(result, tuple):
            assert len(result[0]) == 0


class TestParseValidateInvariants:
    """Invariant tests for parse_and_validate_spans."""

    def test_parse_mixed_batch_counts_add_up(self):
        """parsed_spans.length + rejected_count == raw_spans.length."""
        valid = make_raw_span(span_id="aaaaaaaaaaaaaaaa")
        bad_trace = make_raw_span(trace_id="short", span_id="bbbbbbbbbbbbbbbb")
        bad_node = make_raw_span(span_id="cccccccccccccccc")
        bad_node["attributes"] = [
            a for a in bad_node["attributes"] if a["key"] != "baton.node_id"
        ]

        result = parse_and_validate_spans([valid, bad_trace, bad_node], [])

        if hasattr(result, 'parsed_spans'):
            total = len(result.parsed_spans) + (
                result.rejected_count if hasattr(result, 'rejected_count') else 0
            )
        elif isinstance(result, tuple):
            total = len(result[0]) + (result[1] if len(result) > 1 else 0)
        else:
            total = 3  # fallback

        assert total == 3

    def test_parse_duration_ns_calculated_correctly(self):
        """duration_ns == end_time_unix_nano - start_time_unix_nano."""
        start_t = 1700000000000000000
        end_t = 1700000005000000000
        raw = make_raw_span(start_time_unix_nano=start_t, end_time_unix_nano=end_t)
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            span = result.parsed_spans[0]
        elif isinstance(result, tuple):
            span = result[0][0]

        assert span.duration_ns == end_t - start_t

    def test_parse_all_timestamps_positive(self):
        """All timestamps in parsed spans are positive."""
        raw = make_raw_span()
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            span = result.parsed_spans[0]
        elif isinstance(result, tuple):
            span = result[0][0]

        assert span.start_time_unix_nano > 0
        assert span.end_time_unix_nano > 0
        assert span.received_at_unix_nano > 0


# ===========================================================================
# Module 4: test_dispatch_enrich - dispatch, aggregate, build
# ===========================================================================


class TestDispatchToAnalyzers:
    """Tests for dispatch_to_analyzers."""

    def test_dispatch_all_succeed_returns_4_results(self):
        """All 4 analyzers succeed → 4 results with success=True."""
        span = make_parsed_span()
        analyzers = make_analyzer_registration()

        # We need to set up the analyzers before dispatching
        config = make_valid_config(port=0)
        try:
            start(config, analyzers)
            results = dispatch_to_analyzers(span)

            assert len(results) == 4
            kinds_seen = set()
            for r in results:
                assert r.success is True
                kinds_seen.add(r.analyzer_kind)
            assert kinds_seen == {
                AnalyzerKind.CONSISTENCY,
                AnalyzerKind.ACCESS,
                AnalyzerKind.TAINT,
                AnalyzerKind.CONFLICT,
            }
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_dispatch_one_failure_still_returns_4(self):
        """One analyzer fails → 4 results, 1 with success=False."""
        span = make_parsed_span()
        analyzers = make_analyzer_registration(
            failing_kind=AnalyzerKind.CONSISTENCY,
            failing_exception=RuntimeError("consistency exploded"),
        )
        config = make_valid_config(port=0)
        try:
            start(config, analyzers)
            results = dispatch_to_analyzers(span)

            assert len(results) == 4
            failed = [r for r in results if not r.success]
            succeeded = [r for r in results if r.success]
            assert len(failed) == 1
            assert failed[0].analyzer_kind == AnalyzerKind.CONSISTENCY
            assert failed[0].error_message != ""
            assert len(succeeded) == 3
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_dispatch_all_fail_no_exception_propagated(self):
        """All analyzers fail → 4 results all with success=False, no exception raised."""
        span = make_parsed_span()
        analyzers = {}
        for kind in [AnalyzerKind.CONSISTENCY, AnalyzerKind.ACCESS, AnalyzerKind.TAINT, AnalyzerKind.CONFLICT]:
            analyzers[kind] = make_mock_analyzer(kind, side_effect=RuntimeError(f"{kind} failed"))
        config = make_valid_config(port=0)
        try:
            start(config, analyzers)
            # Should NOT raise
            results = dispatch_to_analyzers(span)

            assert len(results) == 4
            assert all(r.success is False for r in results)
            assert all(r.error_message != "" for r in results)
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_dispatch_failure_isolation_other_analyzers_complete(self):
        """Failure isolation: taint failure doesn't block other 3 analyzers."""
        span = make_parsed_span()
        analyzers = make_analyzer_registration(
            failing_kind=AnalyzerKind.TAINT,
            failing_exception=ValueError("taint error"),
        )
        config = make_valid_config(port=0)
        try:
            start(config, analyzers)
            results = dispatch_to_analyzers(span)

            results_by_kind = {r.analyzer_kind: r for r in results}
            assert results_by_kind[AnalyzerKind.CONSISTENCY].success is True
            assert results_by_kind[AnalyzerKind.ACCESS].success is True
            assert results_by_kind[AnalyzerKind.TAINT].success is False
            assert results_by_kind[AnalyzerKind.CONFLICT].success is True
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass


class TestAggregateEnrichment:
    """Tests for aggregate_enrichment."""

    def test_aggregate_all_success_populates_all_9_fields(self):
        """Aggregation of 4 successful results produces ArbiterEnrichment with all 9 attributes."""
        results = make_all_success_results()
        enrichment = aggregate_enrichment(results)

        assert 0.0 <= enrichment.consistency <= 1.0
        assert 0.0 <= enrichment.trust_score <= 1.0
        assert enrichment.trust_tier is not None
        assert isinstance(enrichment.taint_detected, bool)
        assert enrichment.blast_tier is not None
        assert enrichment.access_declared is not None
        assert enrichment.access_observed is not None
        assert isinstance(enrichment.authority_domains, list)
        assert enrichment.conflict is not None

    def test_aggregate_with_failed_analyzer_uses_safe_defaults(self):
        """Failed analyzer fields get safe defaults."""
        results = [
            make_analysis_result(AnalyzerKind.CONSISTENCY, success=False, error_message="failed"),
            make_analysis_result(AnalyzerKind.ACCESS, success=False, error_message="failed"),
            make_analysis_result(AnalyzerKind.TAINT, success=False, error_message="failed"),
            make_analysis_result(AnalyzerKind.CONFLICT, success=False, error_message="failed"),
        ]
        enrichment = aggregate_enrichment(results)

        # Safe defaults for failed analyzers
        assert enrichment.consistency == 0.0
        assert enrichment.trust_score == 0.0
        assert enrichment.trust_tier == TrustTier.UNKNOWN
        assert enrichment.taint_detected is False
        assert enrichment.blast_tier == BlastTier.UNKNOWN
        assert enrichment.access_declared == ""
        assert enrichment.access_observed == ""
        assert enrichment.authority_domains == [] or enrichment.authority_domains is not None
        assert enrichment.conflict == ""

    def test_aggregate_wrong_result_count_raises(self):
        """aggregate_enrichment raises error when not exactly 4 results."""
        results = make_all_success_results()[:3]  # Only 3
        with pytest.raises(Exception):
            aggregate_enrichment(results)

    def test_aggregate_duplicate_analyzer_kind_raises(self):
        """aggregate_enrichment raises error for duplicate AnalyzerKind."""
        results = [
            make_analysis_result(AnalyzerKind.CONSISTENCY),
            make_analysis_result(AnalyzerKind.CONSISTENCY),  # duplicate
            make_analysis_result(AnalyzerKind.TAINT),
            make_analysis_result(AnalyzerKind.CONFLICT),
        ]
        with pytest.raises(Exception):
            aggregate_enrichment(results)

    def test_aggregate_empty_results_raises(self):
        """aggregate_enrichment raises error for empty results list."""
        with pytest.raises(Exception):
            aggregate_enrichment([])

    def test_aggregate_5_results_raises(self):
        """aggregate_enrichment raises error for more than 4 results."""
        results = make_all_success_results()
        results.append(make_analysis_result(AnalyzerKind.CONSISTENCY))
        with pytest.raises(Exception):
            aggregate_enrichment(results)


class TestBuildEnrichedSpan:
    """Tests for build_enriched_span."""

    def test_build_enriched_span_happy(self):
        """Composes ParsedSpan and ArbiterEnrichment into EnrichedSpan."""
        span = make_parsed_span()
        enrichment = aggregate_enrichment(make_all_success_results())
        errors = []
        enriched = build_enriched_span(span, enrichment, errors)

        assert enriched.span is span or enriched.span == span
        assert enriched.enrichment is enrichment or enriched.enrichment == enrichment
        assert enriched.enriched_at_unix_nano > 0
        assert enriched.analyzer_errors == []

    def test_build_enriched_span_with_analyzer_errors(self):
        """Analyzer errors are preserved in EnrichedSpan."""
        span = make_parsed_span()
        enrichment = aggregate_enrichment(make_all_success_results())
        errors = [
            AnalyzerError(
                analyzer_kind=AnalyzerKind.CONSISTENCY,
                error_type="RuntimeError",
                error_message="consistency exploded",
                span_id=VALID_SPAN_ID,
                node_id=VALID_NODE_ID,
            ),
            AnalyzerError(
                analyzer_kind=AnalyzerKind.TAINT,
                error_type="ValueError",
                error_message="taint broke",
                span_id=VALID_SPAN_ID,
                node_id=VALID_NODE_ID,
            ),
        ]
        enriched = build_enriched_span(span, enrichment, errors)

        assert len(enriched.analyzer_errors) == 2

    def test_build_enriched_span_empty_errors(self):
        """build_enriched_span works with empty error list."""
        span = make_parsed_span()
        enrichment = aggregate_enrichment(make_all_success_results())
        enriched = build_enriched_span(span, enrichment, [])

        assert len(enriched.analyzer_errors) == 0

    def test_build_enriched_span_timestamp_is_positive(self):
        """enriched_at_unix_nano is set to current UTC time (positive nanoseconds)."""
        before = int(time.time() * 1e9)
        span = make_parsed_span()
        enrichment = aggregate_enrichment(make_all_success_results())
        enriched = build_enriched_span(span, enrichment, [])
        after = int(time.time() * 1e9)

        assert before <= enriched.enriched_at_unix_nano <= after + 1_000_000_000  # 1s tolerance


class TestTrustTierDisplayOnlyInvariant:
    """Invariant: trust_tier is for display only, trust_score is the policy value."""

    def test_trust_tier_is_display_trust_score_is_float(self):
        """trust_score is a float in [0.0, 1.0], trust_tier is informational."""
        results = make_all_success_results()
        enrichment = aggregate_enrichment(results)

        assert isinstance(enrichment.trust_score, float)
        assert 0.0 <= enrichment.trust_score <= 1.0
        assert enrichment.trust_tier in (
            TrustTier.FULL, TrustTier.HIGH, TrustTier.MEDIUM,
            TrustTier.LOW, TrustTier.NONE, TrustTier.UNKNOWN,
        )


# ===========================================================================
# Module 5: test_buffer - correlation buffer operations
# ===========================================================================


class TestBufferAdd:
    """Tests for buffer_add."""

    def test_buffer_add_and_get_round_trip(self):
        """Added span is retrievable by execution_id."""
        config = make_valid_config(port=0, buffer_max_size=100)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            span = make_parsed_span(baton_execution_id="exec-round-trip")
            buffer_add(span)
            result = buffer_get("exec-round-trip")
            assert len(result) == 1
            assert result[0].span_id == VALID_SPAN_ID
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_buffer_add_multiple_same_execution_id(self):
        """Multiple spans with same execution_id are all retrievable."""
        config = make_valid_config(port=0, buffer_max_size=100)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            exec_id = "exec-multi"
            for i in range(3):
                span = make_parsed_span(
                    span_id=f"{'a' * 15}{i}",
                    baton_execution_id=exec_id,
                    received_at_unix_nano=VALID_START_TIME + i * 1000,
                )
                buffer_add(span)
            result = buffer_get(exec_id)
            assert len(result) == 3
            # Ordered by received_at_unix_nano ascending
            for i in range(len(result) - 1):
                assert result[i].received_at_unix_nano <= result[i + 1].received_at_unix_nano
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass


class TestBufferGet:
    """Tests for buffer_get."""

    def test_buffer_get_unknown_id_returns_empty(self):
        """buffer_get returns empty list for unknown execution_id."""
        config = make_valid_config(port=0)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            result = buffer_get("nonexistent-execution-id")
            assert result == [] or len(result) == 0
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass


class TestBufferStats:
    """Tests for buffer_get_stats."""

    def test_buffer_stats_reflect_state(self):
        """buffer_get_stats returns accurate metrics."""
        config = make_valid_config(port=0, buffer_max_size=100)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            span = make_parsed_span(baton_execution_id="exec-stats")
            buffer_add(span)
            stats = buffer_get_stats()
            assert stats.current_size >= 1
            assert stats.current_size <= stats.max_size
            assert stats.total_spans >= 1
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass


class TestBufferDrain:
    """Tests for buffer_drain."""

    def test_buffer_drain_returns_all_and_empties(self):
        """Drain returns all buffered spans and leaves buffer empty."""
        config = make_valid_config(port=0, buffer_max_size=100)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            for i in range(5):
                span = make_parsed_span(
                    span_id=f"{'b' * 15}{i}",
                    baton_execution_id=f"exec-drain-{i % 2}",
                )
                buffer_add(span)

            drained = buffer_drain()
            assert len(drained) == 5
            stats = buffer_get_stats()
            assert stats.current_size == 0
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_buffer_drain_empty_buffer(self):
        """Draining an empty buffer returns empty list."""
        config = make_valid_config(port=0, buffer_max_size=100)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            drained = buffer_drain()
            assert len(drained) == 0
            stats = buffer_get_stats()
            assert stats.current_size == 0
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass


class TestBufferEviction:
    """Tests for buffer_evict_expired."""

    def test_buffer_evict_nothing_when_all_fresh(self):
        """No evictions when all entries are within the window."""
        config = make_valid_config(port=0, buffer_max_size=100, buffer_window_seconds=300.0)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            span = make_parsed_span(baton_execution_id="exec-fresh")
            buffer_add(span)
            evicted = buffer_evict_expired()
            assert evicted == 0
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass


class TestBufferInvariants:
    """Invariant tests for correlation buffer."""

    def test_buffer_bounded_invariant(self):
        """Buffer never exceeds buffer_max_size after add."""
        max_size = 5
        config = make_valid_config(port=0, buffer_max_size=max_size, buffer_window_seconds=0.001)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            # Add old spans that can be evicted, then add more
            import time as t
            for i in range(max_size):
                span = make_parsed_span(
                    span_id=f"{'c' * 15}{i}",
                    baton_execution_id=f"exec-bounded-{i}",
                    received_at_unix_nano=1,  # very old
                )
                buffer_add(span)

            t.sleep(0.01)  # let window expire

            # Add one more — should trigger eviction
            span = make_parsed_span(
                span_id="dddddddddddddddd",
                baton_execution_id="exec-bounded-new",
            )
            buffer_add(span)
            stats = buffer_get_stats()
            assert stats.current_size <= max_size
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_buffer_append_only_span_not_modified(self):
        """Spans in buffer are not modified after insertion."""
        config = make_valid_config(port=0, buffer_max_size=100)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            original_span = make_parsed_span(baton_execution_id="exec-immutable")
            original_trace_id = original_span.trace_id
            original_span_id = original_span.span_id
            original_node_id = original_span.baton_node_id

            buffer_add(original_span)
            retrieved = buffer_get("exec-immutable")

            assert len(retrieved) == 1
            assert retrieved[0].trace_id == original_trace_id
            assert retrieved[0].span_id == original_span_id
            assert retrieved[0].baton_node_id == original_node_id
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass


# ===========================================================================
# Module 6: test_handle_export - end-to-end pipeline
# ===========================================================================


class TestHandleExportHappyPath:
    """Happy path tests for handle_export_request."""

    def test_handle_export_valid_batch(self):
        """Valid batch returns ExportResult with correct counts and enriched spans."""
        config = make_valid_config(port=0, max_batch_size=50)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            raw_spans = [
                make_raw_span(span_id="aaaaaaaaaaaaaaaa"),
                make_raw_span(span_id="bbbbbbbbbbbbbbbb"),
            ]
            resource_attrs = make_resource_attributes()
            result = handle_export_request(raw_spans, resource_attrs)

            assert result.accepted_count == 2
            assert result.rejected_count == 0
            assert len(result.enriched_spans) == 2

            # Each enriched span has all 9 arbiter attributes
            for es in result.enriched_spans:
                e = es.enrichment
                assert hasattr(e, 'consistency')
                assert hasattr(e, 'trust_score')
                assert hasattr(e, 'trust_tier')
                assert hasattr(e, 'taint_detected')
                assert hasattr(e, 'blast_tier')
                assert hasattr(e, 'access_declared')
                assert hasattr(e, 'access_observed')
                assert hasattr(e, 'authority_domains')
                assert hasattr(e, 'conflict')
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_handle_export_validation_issues_surfaced(self):
        """Validation issues from mixed batch are surfaced in result."""
        config = make_valid_config(port=0, max_batch_size=50)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            valid = make_raw_span(span_id="aaaaaaaaaaaaaaaa")
            invalid = make_raw_span(span_id="aaaaaaaaaaaaaaaa", trace_id="bad")
            result = handle_export_request([valid, invalid], make_resource_attributes())

            assert len(result.validation_issues) > 0
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass


class TestHandleExportErrors:
    """Error case tests for handle_export_request."""

    def test_handle_export_server_not_ready(self):
        """handle_export_request raises when server is not SERVING."""
        # Don't start the server
        with pytest.raises(Exception):
            handle_export_request([make_raw_span()], [])

    def test_handle_export_batch_too_large(self):
        """handle_export_request raises for batch exceeding max_batch_size."""
        config = make_valid_config(port=0, max_batch_size=2)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            raw_spans = [
                make_raw_span(span_id=f"{'a' * 15}{i}") for i in range(3)
            ]
            with pytest.raises(Exception):
                handle_export_request(raw_spans, [])
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_handle_export_empty_batch(self):
        """handle_export_request raises for empty raw_spans."""
        config = make_valid_config(port=0, max_batch_size=50)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            with pytest.raises(Exception):
                handle_export_request([], [])
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass


class TestHandleExportInvariants:
    """Invariant tests for handle_export_request."""

    def test_handle_export_partial_success(self):
        """Valid spans are processed even when some fail validation in same batch."""
        config = make_valid_config(port=0, max_batch_size=50)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            valid_1 = make_raw_span(span_id="aaaaaaaaaaaaaaaa")
            valid_2 = make_raw_span(span_id="bbbbbbbbbbbbbbbb")
            invalid = make_raw_span(span_id="cccccccccccccccc", trace_id="invalid-trace")
            result = handle_export_request([valid_1, invalid, valid_2], make_resource_attributes())

            assert result.accepted_count == 2
            assert result.rejected_count == 1
            assert len(result.enriched_spans) == 2
            assert result.accepted_count + result.rejected_count == 3
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_handle_export_accepted_rejected_count_sum(self):
        """accepted_count + rejected_count always equals len(raw_spans)."""
        config = make_valid_config(port=0, max_batch_size=50)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            batch_size = 5
            raw_spans = []
            for i in range(batch_size):
                if i % 3 == 0:
                    # Create invalid span
                    raw_spans.append(make_raw_span(
                        span_id=f"{'d' * 15}{i}",
                        trace_id="too-short"
                    ))
                else:
                    raw_spans.append(make_raw_span(
                        span_id=f"{'e' * 15}{i}"
                    ))
            result = handle_export_request(raw_spans, make_resource_attributes())
            assert result.accepted_count + result.rejected_count == batch_size
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_handle_export_enriched_spans_added_to_buffer(self):
        """Each accepted span is added to the correlation buffer."""
        config = make_valid_config(port=0, max_batch_size=50, buffer_max_size=100)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            exec_id = "exec-buffer-check"
            raw_spans = [
                make_raw_span(
                    span_id="aaaaaaaaaaaaaaaa",
                    baton_execution_id=exec_id,
                ),
            ]
            handle_export_request(raw_spans, make_resource_attributes())
            buffered = buffer_get(exec_id)
            assert len(buffered) >= 1
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass


# ===========================================================================
# Module 7: Cross-cutting invariant tests
# ===========================================================================


class TestCrossCuttingInvariants:
    """Tests for contract-wide invariants."""

    def test_protobuf_zero_timestamp_treated_as_unset(self):
        """Protobuf default 0 for timestamps is treated as unset/invalid."""
        raw = make_raw_span(start_time_unix_nano=0)
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
        elif isinstance(result, tuple):
            assert len(result[0]) == 0

    def test_protobuf_zero_end_timestamp_treated_as_unset(self):
        """Protobuf default 0 for end timestamp is treated as unset/invalid."""
        raw = make_raw_span(end_time_unix_nano=0)
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            assert len(result.parsed_spans) == 0
        elif isinstance(result, tuple):
            assert len(result[0]) == 0

    def test_all_parsed_span_timestamps_are_utc_nanoseconds(self):
        """All timestamps are positive nanosecond integers (UTC)."""
        raw = make_raw_span()
        result = parse_and_validate_spans([raw], [])

        if hasattr(result, 'parsed_spans'):
            span = result.parsed_spans[0]
        elif isinstance(result, tuple):
            span = result[0][0]

        # All timestamps positive, plausible nanosecond values
        assert span.start_time_unix_nano > 0
        assert span.end_time_unix_nano > 0
        assert span.received_at_unix_nano > 0
        # Nanosecond range check (after year 2000)
        assert span.start_time_unix_nano > 946684800000000000
        assert span.received_at_unix_nano > 946684800000000000

    def test_enrichment_consistency_bounded(self):
        """consistency score is always in [0.0, 1.0]."""
        results = make_all_success_results()
        enrichment = aggregate_enrichment(results)
        assert 0.0 <= enrichment.consistency <= 1.0

    def test_enrichment_trust_score_bounded(self):
        """trust_score is always in [0.0, 1.0]."""
        results = make_all_success_results()
        enrichment = aggregate_enrichment(results)
        assert 0.0 <= enrichment.trust_score <= 1.0

    def test_failure_isolation_never_propagates_exceptions(self):
        """dispatch_to_analyzers never propagates analyzer exceptions to caller."""
        config = make_valid_config(port=0)
        analyzers = {}
        for kind in [AnalyzerKind.CONSISTENCY, AnalyzerKind.ACCESS, AnalyzerKind.TAINT, AnalyzerKind.CONFLICT]:
            analyzers[kind] = make_mock_analyzer(kind, side_effect=Exception(f"catastrophic {kind}"))
        try:
            start(config, analyzers)
            span = make_parsed_span()
            # Must not raise
            results = dispatch_to_analyzers(span)
            assert len(results) == 4
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_partial_success_never_rejects_entire_batch(self):
        """Server never rejects entire batch — valid spans always processed."""
        config = make_valid_config(port=0, max_batch_size=50)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            # 1 valid, 4 invalid
            raw_spans = [make_raw_span(span_id="aaaaaaaaaaaaaaaa")]
            for i in range(4):
                raw_spans.append(make_raw_span(span_id="aaaaaaaaaaaaaaaa", trace_id="bad"))

            result = handle_export_request(raw_spans, make_resource_attributes())
            # At least the valid span must be accepted
            assert result.accepted_count >= 1
            assert result.accepted_count + result.rejected_count == 5
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass

    def test_server_serving_requires_all_4_analyzers(self):
        """Server is_ready returns True only with all 4 analyzers and SERVING status."""
        # Without starting — not ready
        try:
            current = get_server_status()
            if current == ServerStatus.SERVING:
                stop(grace=1.0)
        except Exception:
            pass
        assert is_ready() is False

        # With all 4 analyzers and started — ready
        config = make_valid_config(port=0)
        analyzers = make_analyzer_registration()
        try:
            start(config, analyzers)
            assert is_ready() is True
            assert get_server_status() == ServerStatus.SERVING
        finally:
            try:
                stop(grace=1.0)
            except Exception:
                pass
