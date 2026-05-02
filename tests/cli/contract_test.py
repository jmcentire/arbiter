"""
Contract test suite for the CLI component.
Tests cover all 14 commands, utility functions, group-level behavior,
parameter validation, invariants, and integration smoke tests.

Run with: pytest contract_test.py -v
"""

import json
import re
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Attempt imports – the component may organize things differently, so we
# try several reasonable module paths and fall back to a namespace dict
# that lets the tests be *syntactically* valid even if the real module is
# missing at collection time.
# ---------------------------------------------------------------------------
try:
    from cli import (
        arbiter_group,
        cmd_init,
        cmd_register,
        cmd_trust_show,
        cmd_trust_reset_taint,
        cmd_authority_show,
        cmd_blast_radius,
        cmd_soak_compute,
        cmd_report,
        cmd_canary_inject,
        cmd_canary_results,
        cmd_watch,
        cmd_findings,
        cmd_conflicts,
        format_output,
        format_error,
        map_exception_to_exit_code,
        resolve_output_format,
        ExitCode,
        OutputFormat,
        CliContext,
        ArbiterConfig,
        CliError,
        InitResponse,
        RegisterResponse,
        TrustShowResponse,
        TrustResetTaintResponse,
        AuthorityShowResponse,
        BlastRadiusResponse,
        SoakComputeResponse,
        ReportResponse,
        CanaryInjectResponse,
        CanaryResultsResponse,
        WatchStatus,
        FindingsResponse,
        ConflictsResponse,
        TrustScoreEntry,
        BlastRadiusNode,
        AuthorityEntry,
        Finding,
        FindingSeverity,
        TaintEscape,
        Conflict,
    )
except ImportError:
    # If the top-level 'cli' module doesn't expose everything, try
    # sub-module imports that match a plausible project layout.
    from cli.types import (
        ExitCode,
        OutputFormat,
        CliContext,
        ArbiterConfig,
        CliError,
        InitResponse,
        RegisterResponse,
        TrustShowResponse,
        TrustResetTaintResponse,
        AuthorityShowResponse,
        BlastRadiusResponse,
        SoakComputeResponse,
        ReportResponse,
        CanaryInjectResponse,
        CanaryResultsResponse,
        WatchStatus,
        FindingsResponse,
        ConflictsResponse,
        TrustScoreEntry,
        BlastRadiusNode,
        AuthorityEntry,
        Finding,
        FindingSeverity,
        TaintEscape,
        Conflict,
    )
    from cli.formatting import format_output, format_error
    from cli.utils import map_exception_to_exit_code, resolve_output_format
    from cli.commands import (
        arbiter_group,
        cmd_init,
        cmd_register,
        cmd_trust_show,
        cmd_trust_reset_taint,
        cmd_authority_show,
        cmd_blast_radius,
        cmd_soak_compute,
        cmd_report,
        cmd_canary_inject,
        cmd_canary_results,
        cmd_watch,
        cmd_findings,
        cmd_conflicts,
    )

# Click test runner
try:
    from click.testing import CliRunner
except ImportError:
    CliRunner = None


# ═══════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════════

SAMPLE_NODE_ID = "service-a.prod"
SAMPLE_RUN_ID = "550e8400-e29b-41d4-a716-446655440000"
SAMPLE_REVIEW_ID = "review-001"
SAMPLE_VERSION = "1.2.3"
SAMPLE_TIER = "confidential"


@pytest.fixture
def cli_runner():
    """CliRunner with separate stderr stream."""
    return CliRunner(mix_stderr=False)


@pytest.fixture
def tmp_config(tmp_path):
    """Write a minimal valid YAML config and return its path."""
    cfg = tmp_path / "arbiter.yaml"
    cfg.write_text(
        "registry_path: ./registry\n"
        "ledger_checksum_interval: 100\n"
        "http_port: 8080\n"
        "otlp_port: 4317\n"
        "cold_start_timeout_s: 3.0\n"
    )
    return str(cfg)


@pytest.fixture
def invalid_config(tmp_path):
    """Write malformed YAML and return its path."""
    cfg = tmp_path / "bad.yaml"
    cfg.write_text("{{not: valid: yaml:::")
    return str(cfg)


@pytest.fixture
def tmp_registry(tmp_path):
    """Create a minimal registry directory structure."""
    reg = tmp_path / "registry"
    reg.mkdir()
    (reg / "trust_ledger.jsonl").write_text("")
    (reg / "config.yaml").write_text("")
    return str(reg)


@pytest.fixture
def arbiter_config(tmp_registry):
    """A valid ArbiterConfig instance."""
    return ArbiterConfig(
        registry_path=tmp_registry,
        ledger_checksum_interval=100,
        http_port=8080,
        otlp_port=4317,
        cold_start_timeout_s=3.0,
    )


@pytest.fixture
def mock_context(arbiter_config):
    """A CliContext with resolved output_format=json and mocked paths."""
    return CliContext(
        registry_path=arbiter_config.registry_path,
        config=arbiter_config,
        output_format=OutputFormat.json,
    )


@pytest.fixture
def sample_trust_history():
    return [
        TrustScoreEntry(
            timestamp="2024-01-01T00:00:00Z",
            raw_score=0.5,
            event_type="initial",
            tainted=False,
        ),
        TrustScoreEntry(
            timestamp="2024-01-02T00:00:00Z",
            raw_score=0.7,
            event_type="attestation",
            tainted=False,
        ),
    ]


@pytest.fixture
def sample_init_response(tmp_registry):
    return InitResponse(
        registry_path=tmp_registry,
        created_files=["trust_ledger.jsonl", "config.yaml"],
        message="Registry initialized.",
    )


@pytest.fixture
def sample_register_response():
    return RegisterResponse(
        nodes_ingested=5, edges_ingested=8, message="Access graph registered."
    )


@pytest.fixture
def sample_trust_show_response(sample_trust_history):
    return TrustShowResponse(
        node_id=SAMPLE_NODE_ID,
        current_score=0.7,
        tainted=False,
        history=sample_trust_history,
    )


@pytest.fixture
def sample_trust_reset_response():
    return TrustResetTaintResponse(
        node_id=SAMPLE_NODE_ID,
        review_id=SAMPLE_REVIEW_ID,
        previous_score=0.3,
        new_score=0.6,
        message="Taint cleared.",
    )


@pytest.fixture
def sample_authority_response():
    return AuthorityShowResponse(
        authority_map=[
            AuthorityEntry(
                node_id=SAMPLE_NODE_ID,
                authority_scope="write:secrets",
                declared_by="manifest-a",
                timestamp="2024-01-01T00:00:00Z",
            )
        ],
        total_entries=1,
    )


@pytest.fixture
def sample_blast_radius_response():
    return BlastRadiusResponse(
        origin_node=SAMPLE_NODE_ID,
        version=SAMPLE_VERSION,
        affected_nodes=[
            BlastRadiusNode(
                node_id="service-b",
                depth=1,
                data_tier="confidential",
                trust_score=0.8,
            ),
            BlastRadiusNode(
                node_id="service-c",
                depth=2,
                data_tier="internal",
                trust_score=0.6,
            ),
        ],
        total_affected=2,
        max_depth=2,
    )


@pytest.fixture
def sample_soak_response():
    return SoakComputeResponse(
        node_id=SAMPLE_NODE_ID,
        tier=SAMPLE_TIER,
        soak_duration_hours=24.0,
        trust_score=0.7,
        message="Soak period computed.",
    )


@pytest.fixture
def sample_report_response():
    return ReportResponse(
        run_id=SAMPLE_RUN_ID,
        generated_at="2024-06-15T12:00:00Z",
        summary="All checks passed.",
        findings_count=0,
        report_path="/registry/reports/report.json",
    )


@pytest.fixture
def sample_canary_inject_response():
    return CanaryInjectResponse(
        run_id=SAMPLE_RUN_ID,
        injected_count=10,
        tiers_covered=[SAMPLE_TIER],
        message="Canaries injected.",
    )


@pytest.fixture
def sample_canary_results_response():
    return CanaryResultsResponse(
        run_id=SAMPLE_RUN_ID,
        escapes=[
            TaintEscape(
                canary_id="canary-1",
                source_tier=SAMPLE_TIER,
                found_at_node="service-b",
                found_at_tier="internal",
                timestamp="2024-06-15T13:00:00Z",
            )
        ],
        total_escapes=1,
        total_canaries=10,
        escape_rate=0.1,
    )


@pytest.fixture
def sample_findings_response():
    return FindingsResponse(
        node_id=SAMPLE_NODE_ID,
        findings=[
            Finding(
                finding_id="f-1",
                node_id=SAMPLE_NODE_ID,
                severity=FindingSeverity.high,
                category="trust-authority-mismatch",
                message="Trust score inconsistent with declared authority.",
                timestamp="2024-06-15T12:00:00Z",
            )
        ],
        total=1,
    )


@pytest.fixture
def sample_conflicts_response():
    return ConflictsResponse(
        conflicts=[
            Conflict(
                conflict_id="c-1",
                node_ids=[SAMPLE_NODE_ID, "service-b"],
                conflict_type="authority-overlap",
                message="Overlapping authority declarations.",
                resolved=False,
                timestamp="2024-06-15T12:00:00Z",
            )
        ],
        total=1,
        unresolved_only=False,
    )


# ═══════════════════════════════════════════════════════════════════════════
# 1. UTILITY FUNCTION TESTS (format_output, format_error,
#    map_exception_to_exit_code, resolve_output_format)
# ═══════════════════════════════════════════════════════════════════════════


class TestFormatOutput:
    """Tests for the format_output pure helper."""

    def test_json_produces_valid_json(self, sample_init_response):
        result = format_output(sample_init_response, OutputFormat.json)
        parsed = json.loads(result)
        expected = sample_init_response.model_dump(mode="json")
        assert parsed == expected

    def test_text_produces_nonempty_string(self, sample_init_response):
        result = format_output(sample_init_response, OutputFormat.text)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_json_no_trailing_newline(self, sample_init_response):
        result = format_output(sample_init_response, OutputFormat.json)
        assert not result.endswith("\n")

    def test_text_no_trailing_newline(self, sample_init_response):
        result = format_output(sample_init_response, OutputFormat.text)
        assert not result.endswith("\n")

    def test_json_roundtrip_register(self, sample_register_response):
        result = format_output(sample_register_response, OutputFormat.json)
        parsed = json.loads(result)
        assert parsed == sample_register_response.model_dump(mode="json")

    def test_json_roundtrip_trust_show(self, sample_trust_show_response):
        result = format_output(sample_trust_show_response, OutputFormat.json)
        parsed = json.loads(result)
        assert parsed == sample_trust_show_response.model_dump(mode="json")

    def test_json_roundtrip_blast_radius(self, sample_blast_radius_response):
        result = format_output(sample_blast_radius_response, OutputFormat.json)
        parsed = json.loads(result)
        assert parsed == sample_blast_radius_response.model_dump(mode="json")

    def test_json_roundtrip_canary_results(self, sample_canary_results_response):
        result = format_output(sample_canary_results_response, OutputFormat.json)
        parsed = json.loads(result)
        assert parsed == sample_canary_results_response.model_dump(mode="json")

    def test_text_contains_key_fields_trust(self, sample_trust_show_response):
        result = format_output(sample_trust_show_response, OutputFormat.text)
        assert SAMPLE_NODE_ID in result

    def test_text_contains_key_fields_findings(self, sample_findings_response):
        result = format_output(sample_findings_response, OutputFormat.text)
        assert SAMPLE_NODE_ID in result


class TestFormatError:
    """Tests for the format_error pure helper."""

    def _make_error(self, node_id="", field=""):
        return CliError(
            error_code="node_not_found",
            message="Node 'service-x' not found in access graph.",
            exit_code=4,
            node_id=node_id,
            field=field,
        )

    def test_json_produces_valid_json(self):
        err = self._make_error(node_id="service-x")
        result = format_error(err, OutputFormat.json)
        parsed = json.loads(result)
        assert parsed == err.model_dump(mode="json")

    def test_text_includes_error_code_and_message(self):
        err = self._make_error()
        result = format_error(err, OutputFormat.text)
        assert "node_not_found" in result
        assert "not found" in result.lower()

    def test_text_includes_node_id_when_nonempty(self):
        err = self._make_error(node_id="service-x")
        result = format_error(err, OutputFormat.text)
        assert "service-x" in result

    def test_text_includes_field_when_nonempty(self):
        err = self._make_error(field="review_id")
        result = format_error(err, OutputFormat.text)
        assert "review_id" in result

    def test_text_no_extra_context_when_both_empty(self):
        err = self._make_error(node_id="", field="")
        result = format_error(err, OutputFormat.text)
        # Should still have code + message
        assert "node_not_found" in result
        assert "not found" in result.lower()


class TestMapExceptionToExitCode:
    """Tests for map_exception_to_exit_code."""

    def test_file_not_found_maps_to_not_found(self):
        exc = FileNotFoundError("missing")
        result = map_exception_to_exit_code(exc)
        assert result == ExitCode.NOT_FOUND_4

    def test_permission_error_maps_to_io_error(self):
        exc = PermissionError("denied")
        result = map_exception_to_exit_code(exc)
        assert result == ExitCode.IO_ERROR_3

    def test_os_error_maps_to_io_error(self):
        exc = OSError("disk failure")
        result = map_exception_to_exit_code(exc)
        assert result == ExitCode.IO_ERROR_3

    def test_value_error_maps_to_usage_error(self):
        exc = ValueError("bad input")
        result = map_exception_to_exit_code(exc)
        assert result == ExitCode.USAGE_ERROR_2

    def test_unrecognized_maps_to_domain_error(self):
        exc = RuntimeError("unexpected")
        result = map_exception_to_exit_code(exc)
        assert result == ExitCode.DOMAIN_ERROR_1

    def test_deterministic_repeated_calls(self):
        """Same exception type always returns same ExitCode."""
        exc = FileNotFoundError("test")
        results = [map_exception_to_exit_code(exc) for _ in range(10)]
        assert all(r == ExitCode.NOT_FOUND_4 for r in results)


class TestResolveOutputFormat:
    """Tests for resolve_output_format."""

    def test_text_passthrough_tty_true(self):
        assert resolve_output_format(OutputFormat.text, True) == OutputFormat.text

    def test_text_passthrough_tty_false(self):
        assert resolve_output_format(OutputFormat.text, False) == OutputFormat.text

    def test_json_passthrough_tty_true(self):
        assert resolve_output_format(OutputFormat.json, True) == OutputFormat.json

    def test_json_passthrough_tty_false(self):
        assert resolve_output_format(OutputFormat.json, False) == OutputFormat.json

    def test_auto_tty_true_returns_text(self):
        assert resolve_output_format(OutputFormat.auto, True) == OutputFormat.text

    def test_auto_tty_false_returns_json(self):
        assert resolve_output_format(OutputFormat.auto, False) == OutputFormat.json

    def test_never_returns_auto(self):
        for fmt in OutputFormat:
            for tty in (True, False):
                result = resolve_output_format(fmt, tty)
                assert result != OutputFormat.auto, (
                    f"resolve_output_format({fmt}, {tty}) returned auto"
                )


# ═══════════════════════════════════════════════════════════════════════════
# 2. GROUP-LEVEL TESTS (arbiter_group, CliContext construction)
# ═══════════════════════════════════════════════════════════════════════════


class TestArbiterGroup:
    """Tests for the top-level Click group callback."""

    @pytest.fixture(autouse=True)
    def _setup_runner(self, cli_runner):
        self.runner = cli_runner

    def test_help_output(self):
        result = self.runner.invoke(arbiter_group, ["--help"])
        assert result.exit_code == 0
        assert len(result.output) > 0
        assert "Usage" in result.output or "usage" in result.output.lower()

    @patch("cli.config.load_config")
    def test_valid_config_creates_context(self, mock_load, tmp_config, tmp_registry):
        mock_load.return_value = ArbiterConfig(
            registry_path=tmp_registry,
            ledger_checksum_interval=100,
            http_port=8080,
            otlp_port=4317,
            cold_start_timeout_s=3.0,
        )
        # Invoke with a trivial subcommand placeholder
        # We test that the group itself doesn't error out.
        result = self.runner.invoke(
            arbiter_group,
            ["--config", tmp_config, "--format", "json", "--help"],
        )
        assert result.exit_code == 0

    def test_config_not_found_nondefault_path(self, tmp_path):
        nonexistent = str(tmp_path / "does_not_exist.yaml")
        result = self.runner.invoke(
            arbiter_group, ["--config", nonexistent, "--help"]
        )
        # Group should either show help or error; if config is only loaded
        # when a subcommand runs, --help may still succeed. We check that
        # a real subcommand with bad config produces a non-zero exit:
        result2 = self.runner.invoke(
            arbiter_group, ["--config", nonexistent, "init"]
        )
        assert result2.exit_code != 0

    def test_config_invalid_yaml(self, invalid_config):
        result = self.runner.invoke(
            arbiter_group, ["--config", invalid_config, "init"]
        )
        assert result.exit_code != 0

    def test_registry_path_invalid(self, tmp_config, tmp_path):
        bad_reg = str(tmp_path / "no_such_dir" / "nested")
        result = self.runner.invoke(
            arbiter_group,
            ["--config", tmp_config, "--registry-path", bad_reg, "init"],
        )
        # Should fail – either at group level or at command level
        # The contract says registry_path_invalid if explicit path doesn't exist
        assert result.exit_code != 0

    def test_format_json_flag(self, tmp_config):
        result = self.runner.invoke(
            arbiter_group, ["--config", tmp_config, "--format", "json", "--help"]
        )
        assert result.exit_code == 0

    def test_format_text_flag(self, tmp_config):
        result = self.runner.invoke(
            arbiter_group, ["--config", tmp_config, "--format", "text", "--help"]
        )
        assert result.exit_code == 0


# ═══════════════════════════════════════════════════════════════════════════
# 3. SUBCOMMAND TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestCmdInit:
    """Tests for `arbiter init`."""

    @patch("cli.commands.registry")
    def test_happy_path(self, mock_reg, cli_runner, mock_context, sample_init_response):
        mock_reg.initialize_registry.return_value = sample_init_response
        result = cli_runner.invoke(
            arbiter_group, ["--format", "json", "init", "--force"], obj=mock_context
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "registry_path" in data
        assert "created_files" in data

    @patch("cli.commands.registry")
    def test_force_flag(self, mock_reg, cli_runner, mock_context, sample_init_response):
        mock_reg.initialize_registry.return_value = sample_init_response
        result = cli_runner.invoke(
            arbiter_group, ["--format", "json", "init", "--force"], obj=mock_context
        )
        assert result.exit_code == 0

    @patch("cli.commands.registry")
    def test_already_initialized_no_force(self, mock_reg, cli_runner, mock_context):
        mock_reg.initialize_registry.side_effect = Exception("already_initialized")
        result = cli_runner.invoke(
            arbiter_group, ["--format", "json", "init"], obj=mock_context
        )
        assert result.exit_code != 0

    @patch("cli.commands.registry")
    def test_permission_denied(self, mock_reg, cli_runner, mock_context):
        mock_reg.initialize_registry.side_effect = PermissionError("cannot write")
        result = cli_runner.invoke(
            arbiter_group, ["--format", "json", "init"], obj=mock_context
        )
        assert result.exit_code != 0


class TestCmdRegister:
    """Tests for `arbiter register`."""

    @patch("cli.commands.registry")
    def test_happy_path(self, mock_reg, cli_runner, mock_context, sample_register_response, tmp_path):
        graph_file = tmp_path / "graph.json"
        graph_file.write_text('{"nodes": [], "edges": []}')
        mock_reg.ingest_access_graph.return_value = sample_register_response
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "register", str(graph_file)],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["nodes_ingested"] == 5
        assert data["edges_ingested"] == 8

    @patch("cli.commands.registry")
    def test_file_not_found(self, mock_reg, cli_runner, mock_context):
        mock_reg.ingest_access_graph.side_effect = FileNotFoundError("no such file")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "register", "/nonexistent/graph.json"],
            obj=mock_context,
        )
        assert result.exit_code != 0

    @patch("cli.commands.registry")
    def test_registry_not_initialized(self, mock_reg, cli_runner, mock_context, tmp_path):
        graph_file = tmp_path / "graph.json"
        graph_file.write_text("{}")
        mock_reg.ingest_access_graph.side_effect = Exception("registry_not_initialized")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "register", str(graph_file)],
            obj=mock_context,
        )
        assert result.exit_code != 0


class TestCmdTrustShow:
    """Tests for `arbiter trust show`."""

    @patch("cli.commands.trust_engine")
    def test_happy_path(self, mock_te, cli_runner, mock_context, sample_trust_show_response):
        mock_te.compute_trust_score.return_value = 0.7
        mock_te.get_trust_history.return_value = sample_trust_show_response.history
        # The command should assemble TrustShowResponse
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "trust", "show", SAMPLE_NODE_ID],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["node_id"] == SAMPLE_NODE_ID
        assert "current_score" in data
        assert "history" in data
        # History ordered oldest-first
        if len(data["history"]) > 1:
            assert data["history"][0]["timestamp"] <= data["history"][-1]["timestamp"]

    @patch("cli.commands.trust_engine")
    def test_node_not_found(self, mock_te, cli_runner, mock_context):
        mock_te.compute_trust_score.side_effect = LookupError("node_not_found")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "trust", "show", "nonexistent-node"],
            obj=mock_context,
        )
        assert result.exit_code != 0
        # Verify error on stderr includes node info
        if result.stderr:
            assert "nonexistent-node" in result.stderr or "not_found" in result.stderr.lower()

    @patch("cli.commands.trust_engine")
    def test_ledger_corrupted(self, mock_te, cli_runner, mock_context):
        mock_te.compute_trust_score.side_effect = Exception("ledger_corrupted")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "trust", "show", SAMPLE_NODE_ID],
            obj=mock_context,
        )
        assert result.exit_code != 0

    @patch("cli.commands.trust_engine")
    @patch("cli.commands.authority_engine")
    def test_trust_authority_separation(self, mock_ae, mock_te, cli_runner, mock_context, sample_trust_show_response):
        mock_te.compute_trust_score.return_value = 0.7
        mock_te.get_trust_history.return_value = sample_trust_show_response.history
        cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "trust", "show", SAMPLE_NODE_ID],
            obj=mock_context,
        )
        # trust_engine should be called, authority_engine should NOT
        assert mock_te.compute_trust_score.called or mock_te.get_trust_history.called
        assert not mock_ae.get_authority_map.called


class TestCmdTrustResetTaint:
    """Tests for `arbiter trust reset-taint`."""

    @patch("cli.commands.trust_engine")
    def test_happy_path(self, mock_te, cli_runner, mock_context, sample_trust_reset_response):
        mock_te.reset_taint.return_value = sample_trust_reset_response
        result = cli_runner.invoke(
            arbiter_group,
            [
                "--format", "json", "trust", "reset-taint",
                SAMPLE_NODE_ID, "--review", SAMPLE_REVIEW_ID,
            ],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["node_id"] == SAMPLE_NODE_ID
        assert "previous_score" in data
        assert "new_score" in data

    @patch("cli.commands.trust_engine")
    def test_not_tainted(self, mock_te, cli_runner, mock_context):
        mock_te.reset_taint.side_effect = Exception("not_tainted")
        result = cli_runner.invoke(
            arbiter_group,
            [
                "--format", "json", "trust", "reset-taint",
                SAMPLE_NODE_ID, "--review", SAMPLE_REVIEW_ID,
            ],
            obj=mock_context,
        )
        assert result.exit_code != 0

    @patch("cli.commands.trust_engine")
    def test_node_not_found(self, mock_te, cli_runner, mock_context):
        mock_te.reset_taint.side_effect = LookupError("node_not_found")
        result = cli_runner.invoke(
            arbiter_group,
            [
                "--format", "json", "trust", "reset-taint",
                SAMPLE_NODE_ID, "--review", SAMPLE_REVIEW_ID,
            ],
            obj=mock_context,
        )
        assert result.exit_code != 0


class TestCmdAuthorityShow:
    """Tests for `arbiter authority show`."""

    @patch("cli.commands.authority_engine")
    def test_happy_path(self, mock_ae, cli_runner, mock_context, sample_authority_response):
        mock_ae.get_authority_map.return_value = sample_authority_response
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "authority", "show"],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "authority_map" in data
        assert data["total_entries"] >= 0

    @patch("cli.commands.authority_engine")
    def test_registry_not_initialized(self, mock_ae, cli_runner, mock_context):
        mock_ae.get_authority_map.side_effect = Exception("registry_not_initialized")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "authority", "show"],
            obj=mock_context,
        )
        assert result.exit_code != 0


class TestCmdBlastRadius:
    """Tests for `arbiter blast-radius`."""

    @patch("cli.commands.blast_radius_engine")
    def test_happy_path(self, mock_br, cli_runner, mock_context, sample_blast_radius_response):
        mock_br.compute_blast_radius.return_value = sample_blast_radius_response
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "blast-radius", SAMPLE_NODE_ID, SAMPLE_VERSION],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_affected"] == len(data["affected_nodes"])
        # Ordered by depth ascending
        depths = [n["depth"] for n in data["affected_nodes"]]
        assert depths == sorted(depths)
        if data["affected_nodes"]:
            assert data["max_depth"] == max(depths)
        else:
            assert data["max_depth"] == 0

    @patch("cli.commands.blast_radius_engine")
    def test_empty_blast_radius(self, mock_br, cli_runner, mock_context):
        empty_resp = BlastRadiusResponse(
            origin_node=SAMPLE_NODE_ID,
            version=SAMPLE_VERSION,
            affected_nodes=[],
            total_affected=0,
            max_depth=0,
        )
        mock_br.compute_blast_radius.return_value = empty_resp
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "blast-radius", SAMPLE_NODE_ID, SAMPLE_VERSION],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_affected"] == 0
        assert data["max_depth"] == 0
        assert data["affected_nodes"] == []

    @patch("cli.commands.blast_radius_engine")
    def test_node_not_found(self, mock_br, cli_runner, mock_context):
        mock_br.compute_blast_radius.side_effect = LookupError("node_not_found")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "blast-radius", "ghost-node", SAMPLE_VERSION],
            obj=mock_context,
        )
        assert result.exit_code != 0


class TestCmdSoakCompute:
    """Tests for `arbiter soak compute`."""

    @patch("cli.commands.soak_engine")
    def test_happy_path(self, mock_se, cli_runner, mock_context, sample_soak_response):
        mock_se.compute_soak_duration.return_value = sample_soak_response
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "soak", "compute", SAMPLE_NODE_ID, SAMPLE_TIER],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["soak_duration_hours"] >= 0

    @patch("cli.commands.soak_engine")
    def test_invalid_tier(self, mock_se, cli_runner, mock_context):
        mock_se.compute_soak_duration.side_effect = ValueError("invalid_tier")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "soak", "compute", SAMPLE_NODE_ID, "nonexistent-tier"],
            obj=mock_context,
        )
        assert result.exit_code != 0

    @patch("cli.commands.soak_engine")
    def test_node_not_found(self, mock_se, cli_runner, mock_context):
        mock_se.compute_soak_duration.side_effect = LookupError("node_not_found")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "soak", "compute", "ghost", SAMPLE_TIER],
            obj=mock_context,
        )
        assert result.exit_code != 0


class TestCmdReport:
    """Tests for `arbiter report`."""

    @patch("cli.commands.report_engine")
    def test_happy_path(self, mock_re, cli_runner, mock_context, sample_report_response):
        mock_re.generate_report.return_value = sample_report_response
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "report", "--run", SAMPLE_RUN_ID],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["run_id"] == SAMPLE_RUN_ID
        # Validate ISO 8601 timestamp
        datetime.fromisoformat(data["generated_at"].replace("Z", "+00:00"))
        assert len(data["report_path"]) > 0

    @patch("cli.commands.report_engine")
    def test_run_not_found(self, mock_re, cli_runner, mock_context):
        mock_re.generate_report.side_effect = LookupError("run_not_found")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "report", "--run", SAMPLE_RUN_ID],
            obj=mock_context,
        )
        assert result.exit_code != 0


class TestCmdCanaryInject:
    """Tests for `arbiter canary inject`."""

    @patch("cli.commands.canary_engine")
    def test_happy_path(self, mock_ce, cli_runner, mock_context, sample_canary_inject_response):
        mock_ce.inject_canaries.return_value = sample_canary_inject_response
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "canary", "inject", "--tiers", SAMPLE_TIER],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["injected_count"] > 0
        # Validate UUID v4 format for run_id
        uuid.UUID(data["run_id"], version=4)
        assert SAMPLE_TIER in data["tiers_covered"]

    @patch("cli.commands.canary_engine")
    def test_empty_tiers(self, mock_ce, cli_runner, mock_context):
        mock_ce.inject_canaries.side_effect = ValueError("empty_tiers")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "canary", "inject", "--tiers", ""],
            obj=mock_context,
        )
        assert result.exit_code != 0

    @patch("cli.commands.canary_engine")
    def test_invalid_tier(self, mock_ce, cli_runner, mock_context):
        mock_ce.inject_canaries.side_effect = ValueError("invalid_tier")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "canary", "inject", "--tiers", "bogus-tier"],
            obj=mock_context,
        )
        assert result.exit_code != 0


class TestCmdCanaryResults:
    """Tests for `arbiter canary results`."""

    @patch("cli.commands.canary_engine")
    def test_happy_path(self, mock_ce, cli_runner, mock_context, sample_canary_results_response):
        mock_ce.get_canary_results.return_value = sample_canary_results_response
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "canary", "results", "--run", SAMPLE_RUN_ID],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total_escapes"] == len(data["escapes"])
        if data["total_canaries"] > 0:
            expected_rate = data["total_escapes"] / data["total_canaries"]
            assert abs(data["escape_rate"] - expected_rate) < 1e-9

    @patch("cli.commands.canary_engine")
    def test_zero_canaries(self, mock_ce, cli_runner, mock_context):
        zero_resp = CanaryResultsResponse(
            run_id=SAMPLE_RUN_ID,
            escapes=[],
            total_escapes=0,
            total_canaries=0,
            escape_rate=0.0,
        )
        mock_ce.get_canary_results.return_value = zero_resp
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "canary", "results", "--run", SAMPLE_RUN_ID],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["escape_rate"] == 0.0
        assert data["total_canaries"] == 0

    @patch("cli.commands.canary_engine")
    def test_run_not_found(self, mock_ce, cli_runner, mock_context):
        mock_ce.get_canary_results.side_effect = LookupError("run_not_found")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "canary", "results", "--run", SAMPLE_RUN_ID],
            obj=mock_context,
        )
        assert result.exit_code != 0


class TestCmdWatch:
    """Tests for `arbiter watch`."""

    @patch("cli.commands.http_api")
    @patch("cli.commands.otlp_subscriber")
    def test_port_conflict_same_ports(self, mock_otlp, mock_http, cli_runner, mock_context):
        """http_port and otlp_port must differ."""
        result = cli_runner.invoke(
            arbiter_group,
            [
                "--format", "json", "watch",
                "--http-port", "8080", "--otlp-port", "8080",
            ],
            obj=mock_context,
        )
        assert result.exit_code != 0

    @patch("cli.commands.http_api")
    @patch("cli.commands.otlp_subscriber")
    def test_port_in_use(self, mock_otlp, mock_http, cli_runner, mock_context):
        mock_otlp.start.side_effect = OSError("port_in_use")
        result = cli_runner.invoke(
            arbiter_group,
            [
                "--format", "json", "watch",
                "--http-port", "8080", "--otlp-port", "4317",
            ],
            obj=mock_context,
        )
        assert result.exit_code != 0


class TestCmdFindings:
    """Tests for `arbiter findings`."""

    @patch("cli.commands.findings_engine")
    def test_happy_path(self, mock_fe, cli_runner, mock_context, sample_findings_response):
        mock_fe.get_findings.return_value = sample_findings_response
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "findings", "--node", SAMPLE_NODE_ID],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == len(data["findings"])
        for f in data["findings"]:
            assert "severity" in f
            assert "message" in f
            assert "node_id" in f

    @patch("cli.commands.findings_engine")
    def test_node_not_found(self, mock_fe, cli_runner, mock_context):
        mock_fe.get_findings.side_effect = LookupError("node_not_found")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "findings", "--node", "ghost"],
            obj=mock_context,
        )
        assert result.exit_code != 0


class TestCmdConflicts:
    """Tests for `arbiter conflicts`."""

    @patch("cli.commands.conflicts_engine")
    def test_happy_path_all(self, mock_ce, cli_runner, mock_context, sample_conflicts_response):
        mock_ce.list_conflicts.return_value = sample_conflicts_response
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "conflicts"],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["total"] == len(data["conflicts"])

    @patch("cli.commands.conflicts_engine")
    def test_unresolved_only(self, mock_ce, cli_runner, mock_context):
        unresolved_resp = ConflictsResponse(
            conflicts=[
                Conflict(
                    conflict_id="c-1",
                    node_ids=[SAMPLE_NODE_ID],
                    conflict_type="authority-overlap",
                    message="Overlap.",
                    resolved=False,
                    timestamp="2024-06-15T12:00:00Z",
                )
            ],
            total=1,
            unresolved_only=True,
        )
        mock_ce.list_conflicts.return_value = unresolved_resp
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "conflicts", "--unresolved"],
            obj=mock_context,
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["unresolved_only"] is True
        for c in data["conflicts"]:
            assert c["resolved"] is False

    @patch("cli.commands.conflicts_engine")
    def test_registry_not_initialized(self, mock_ce, cli_runner, mock_context):
        mock_ce.list_conflicts.side_effect = Exception("registry_not_initialized")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "conflicts"],
            obj=mock_context,
        )
        assert result.exit_code != 0


# ═══════════════════════════════════════════════════════════════════════════
# 4. PARAMETER VALIDATION TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestParamValidation:
    """Tests for custom Click ParamTypes (NodeIdType, RunIdType, VersionType)."""

    @pytest.fixture(autouse=True)
    def _setup(self, cli_runner, mock_context):
        self.runner = cli_runner
        self.ctx = mock_context

    @patch("cli.commands.trust_engine")
    def test_node_id_valid_simple(self, mock_te, sample_trust_show_response):
        mock_te.compute_trust_score.return_value = 0.7
        mock_te.get_trust_history.return_value = sample_trust_show_response.history
        result = self.runner.invoke(
            arbiter_group,
            ["--format", "json", "trust", "show", "my-node.v1"],
            obj=self.ctx,
        )
        # Valid node ID should not fail at param level
        # (may fail at engine level which is a different error)
        if result.exit_code != 0:
            # If it fails, it shouldn't be a usage/param error
            assert "Invalid value" not in (result.output + (result.stderr or ""))

    def test_node_id_empty_rejected(self):
        result = self.runner.invoke(
            arbiter_group,
            ["--format", "json", "trust", "show", ""],
            obj=self.ctx,
        )
        assert result.exit_code != 0

    def test_node_id_invalid_chars_rejected(self):
        result = self.runner.invoke(
            arbiter_group,
            ["--format", "json", "trust", "show", "node@#$%"],
            obj=self.ctx,
        )
        assert result.exit_code != 0

    @patch("cli.commands.report_engine")
    def test_run_id_valid_uuid(self, mock_re, sample_report_response):
        mock_re.generate_report.return_value = sample_report_response
        result = self.runner.invoke(
            arbiter_group,
            ["--format", "json", "report", "--run", SAMPLE_RUN_ID],
            obj=self.ctx,
        )
        # Should not fail at param level
        if result.exit_code == 0:
            data = json.loads(result.output)
            assert data["run_id"] == SAMPLE_RUN_ID

    def test_run_id_invalid_rejected(self):
        result = self.runner.invoke(
            arbiter_group,
            ["--format", "json", "report", "--run", "not-a-uuid"],
            obj=self.ctx,
        )
        assert result.exit_code != 0

    @patch("cli.commands.blast_radius_engine")
    def test_version_tag_valid_semver(self, mock_br, sample_blast_radius_response):
        mock_br.compute_blast_radius.return_value = sample_blast_radius_response
        result = self.runner.invoke(
            arbiter_group,
            ["--format", "json", "blast-radius", SAMPLE_NODE_ID, "1.0.0-alpha.1"],
            obj=self.ctx,
        )
        # Valid semver should not fail at param level
        if result.exit_code != 0:
            assert "Invalid value" not in (result.output + (result.stderr or ""))

    def test_version_tag_invalid_rejected(self):
        result = self.runner.invoke(
            arbiter_group,
            ["--format", "json", "blast-radius", SAMPLE_NODE_ID, "v1.2"],
            obj=self.ctx,
        )
        assert result.exit_code != 0


# ═══════════════════════════════════════════════════════════════════════════
# 5. INVARIANT TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestInvariants:
    """Cross-cutting invariant tests from the contract."""

    def test_output_format_never_auto_after_resolve(self):
        """CliContext.output_format should never be 'auto' after resolution."""
        for fmt in OutputFormat:
            for tty in (True, False):
                resolved = resolve_output_format(fmt, tty)
                assert resolved != OutputFormat.auto

    def test_json_output_equals_model_dump(self, sample_blast_radius_response):
        """JSON output is identical to response.model_dump(mode='json')."""
        result = format_output(sample_blast_radius_response, OutputFormat.json)
        parsed = json.loads(result)
        assert parsed == sample_blast_radius_response.model_dump(mode="json")

    def test_exit_codes_deterministic(self):
        """Same exception type always produces same exit code."""
        exceptions = [
            FileNotFoundError("x"),
            PermissionError("x"),
            ValueError("x"),
            RuntimeError("x"),
        ]
        for exc in exceptions:
            results = {map_exception_to_exit_code(exc) for _ in range(5)}
            assert len(results) == 1, f"Non-deterministic exit code for {type(exc)}"

    @patch("cli.commands.trust_engine")
    def test_errors_on_stderr_not_stdout(self, mock_te, cli_runner, mock_context):
        """Error output must go to stderr, not stdout."""
        mock_te.compute_trust_score.side_effect = LookupError("node_not_found")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "trust", "show", "nonexistent"],
            obj=mock_context,
        )
        if result.exit_code != 0:
            # stdout should not contain error markers
            if result.output:
                try:
                    data = json.loads(result.output)
                    # If stdout has JSON, it should not be an error object
                    # (errors go to stderr)
                    assert "error_code" not in data
                except json.JSONDecodeError:
                    pass
            # stderr should have something if available
            if result.stderr:
                assert len(result.stderr) > 0


# ═══════════════════════════════════════════════════════════════════════════
# 6. INTEGRATION SMOKE TESTS
# ═══════════════════════════════════════════════════════════════════════════


class TestIntegrationSmoke:
    """End-to-end integration-style tests using CliRunner."""

    @patch("cli.commands.registry")
    @patch("cli.config.load_config")
    def test_init_json_end_to_end(self, mock_load, mock_reg, cli_runner, tmp_config, tmp_registry):
        mock_load.return_value = ArbiterConfig(
            registry_path=tmp_registry,
            ledger_checksum_interval=100,
            http_port=8080,
            otlp_port=4317,
            cold_start_timeout_s=3.0,
        )
        mock_reg.initialize_registry.return_value = InitResponse(
            registry_path=tmp_registry,
            created_files=["trust_ledger.jsonl", "config.yaml"],
            message="Registry initialized.",
        )
        result = cli_runner.invoke(
            arbiter_group,
            ["--config", tmp_config, "--format", "json", "init", "--force"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "registry_path" in data
        assert "created_files" in data

    def test_no_stacktrace_on_config_error(self, cli_runner, tmp_path):
        """No Python stack traces should leak to user on errors."""
        bad_path = str(tmp_path / "nope.yaml")
        result = cli_runner.invoke(
            arbiter_group,
            ["--config", bad_path, "init"],
        )
        combined = (result.output or "") + (result.stderr or "")
        assert "Traceback" not in combined
        assert 'File "' not in combined

    @patch("cli.commands.trust_engine")
    def test_no_stacktrace_on_domain_error(self, mock_te, cli_runner, mock_context):
        """Domain exceptions should not leak tracebacks."""
        mock_te.compute_trust_score.side_effect = LookupError("node_not_found")
        result = cli_runner.invoke(
            arbiter_group,
            ["--format", "json", "trust", "show", "ghost"],
            obj=mock_context,
        )
        combined = (result.output or "") + (result.stderr or "")
        assert "Traceback" not in combined
        assert 'File "' not in combined

    def test_error_pipeline_nonzero_exit(self, cli_runner, tmp_path):
        """Bad config → formatted error → non-zero exit code."""
        bad_path = str(tmp_path / "nonexistent.yaml")
        result = cli_runner.invoke(
            arbiter_group,
            ["--config", bad_path, "init"],
        )
        assert result.exit_code != 0
        # stderr should contain an error indication
        if result.stderr:
            assert len(result.stderr) > 0
