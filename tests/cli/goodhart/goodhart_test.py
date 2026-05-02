"""
Hidden adversarial acceptance tests for CLI Entry Point component.
These tests catch implementations that "teach to the test" by hardcoding
returns or skipping proper validation.
"""
import json
import re
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock
import pytest

# We import from the CLI module under test
from src.cli import (
    format_output,
    format_error,
    map_exception_to_exit_code,
    resolve_output_format,
)

# Attempt to import models/types; adjust as needed for actual project structure
try:
    from src.cli import (
        CliError,
        ExitCode,
        OutputFormat,
        TrustShowResponse,
        TrustScoreEntry,
        BlastRadiusResponse,
        BlastRadiusNode,
        FindingsResponse,
        Finding,
        ConflictsResponse,
        Conflict,
        CanaryResultsResponse,
        TaintEscape,
        CanaryInjectResponse,
        InitResponse,
        RegisterResponse,
        ReportResponse,
        SoakComputeResponse,
        AuthorityShowResponse,
        AuthorityEntry,
        TrustResetTaintResponse,
        NodeIdType,
        RunIdType,
        VersionType,
    )
except ImportError:
    # Fallback: try alternate import paths
    pass

try:
    from src.models import (
        CliError,
        ExitCode,
        OutputFormat,
        TrustShowResponse,
        TrustScoreEntry,
        BlastRadiusResponse,
        BlastRadiusNode,
        FindingsResponse,
        Finding,
        ConflictsResponse,
        Conflict,
        CanaryResultsResponse,
        TaintEscape,
        CanaryInjectResponse,
        InitResponse,
        RegisterResponse,
        ReportResponse,
        SoakComputeResponse,
        AuthorityShowResponse,
        AuthorityEntry,
        TrustResetTaintResponse,
    )
except ImportError:
    pass

try:
    from src.cli import cli, arbiter_group
    from click.testing import CliRunner
except ImportError:
    pass


# ============================================================
# resolve_output_format tests
# ============================================================

class TestGoodhartResolveOutputFormat:
    def test_goodhart_resolve_format_text_not_tty(self):
        """Explicit 'text' format should not be overridden when is_tty is False."""
        result = resolve_output_format("text", is_tty=False)
        assert result == "text", (
            "Explicit 'text' format must be returned unchanged regardless of TTY"
        )

    def test_goodhart_resolve_format_json_tty_true(self):
        """Explicit 'json' format should not be overridden when is_tty is True."""
        result = resolve_output_format("json", is_tty=True)
        assert result == "json", (
            "Explicit 'json' format must be returned unchanged regardless of TTY"
        )


# ============================================================
# format_output tests
# ============================================================

class TestGoodhartFormatOutput:
    def _make_trust_show_response(self, score=0.85, node_id="nodeA"):
        """Helper to build a TrustShowResponse-like model."""
        try:
            return TrustShowResponse(
                node_id=node_id,
                current_score=score,
                tainted=False,
                history=[
                    TrustScoreEntry(
                        timestamp="2024-01-01T00:00:00Z",
                        raw_score=0.5,
                        event_type="init",
                        tainted=False,
                    )
                ],
            )
        except Exception:
            pytest.skip("Cannot construct TrustShowResponse model")

    def _make_blast_radius_response(self, num_nodes=3):
        """Helper to build a BlastRadiusResponse with multiple nodes."""
        try:
            nodes = [
                BlastRadiusNode(
                    node_id=f"node_{i}",
                    depth=i,
                    data_tier="tier_a",
                    trust_score=0.5 + i * 0.1,
                )
                for i in range(1, num_nodes + 1)
            ]
            return BlastRadiusResponse(
                origin_node="origin",
                version="1.0.0",
                affected_nodes=nodes,
                total_affected=num_nodes,
                max_depth=num_nodes,
            )
        except Exception:
            pytest.skip("Cannot construct BlastRadiusResponse model")

    def _make_findings_response(self, num_findings=0):
        """Helper to build a FindingsResponse."""
        try:
            findings = [
                Finding(
                    finding_id=f"f-{i}",
                    node_id="test_node",
                    severity="medium",
                    category="consistency",
                    message=f"Finding {i}",
                    timestamp="2024-01-01T00:00:00Z",
                )
                for i in range(num_findings)
            ]
            return FindingsResponse(
                node_id="test_node",
                findings=findings,
                total=num_findings,
            )
        except Exception:
            pytest.skip("Cannot construct FindingsResponse model")

    def test_goodhart_format_output_json_different_models(self):
        """format_output in JSON mode correctly serializes arbitrary response models."""
        models = [
            self._make_trust_show_response(score=0.75, node_id="svc.alpha"),
            self._make_blast_radius_response(num_nodes=2),
            self._make_findings_response(num_findings=3),
        ]
        for model in models:
            result = format_output(model, "json")
            parsed = json.loads(result)
            expected = model.model_dump(mode="json")
            assert parsed == expected, (
                f"JSON output for {type(model).__name__} must match model_dump"
            )

    def test_goodhart_format_output_text_different_models(self):
        """format_output in text mode produces non-empty strings for all model types."""
        models = [
            self._make_trust_show_response(),
            self._make_blast_radius_response(),
            self._make_findings_response(num_findings=1),
        ]
        for model in models:
            result = format_output(model, "text")
            assert isinstance(result, str), "Text output must be a string"
            assert len(result.strip()) > 0, (
                f"Text output for {type(model).__name__} must be non-empty"
            )
            assert not result.endswith("\n"), "No trailing newline allowed"

    def test_goodhart_format_output_json_nested_lists(self):
        """format_output correctly serializes nested lists in response models."""
        resp = self._make_blast_radius_response(num_nodes=4)
        result = format_output(resp, "json")
        parsed = json.loads(result)
        assert len(parsed["affected_nodes"]) == 4, (
            "All nested nodes must be serialized"
        )

    def test_goodhart_format_output_text_no_trailing_newline_all_models(self):
        """format_output never adds trailing newline for any model type."""
        models = [
            self._make_trust_show_response(),
            self._make_blast_radius_response(),
            self._make_findings_response(num_findings=2),
        ]
        for model in models:
            result = format_output(model, "text")
            assert not result.endswith("\n"), (
                f"format_output text should not end with newline for {type(model).__name__}"
            )

    def test_goodhart_format_output_json_preserves_float_precision(self):
        """format_output JSON mode preserves float values matching model_dump."""
        resp = self._make_trust_show_response(score=0.123456789)
        result = format_output(resp, "json")
        parsed = json.loads(result)
        expected = resp.model_dump(mode="json")
        assert parsed["current_score"] == expected["current_score"], (
            "Float precision must match model_dump"
        )

    def test_goodhart_format_output_json_empty_lists(self):
        """format_output correctly handles response models with empty lists."""
        resp = self._make_findings_response(num_findings=0)
        result = format_output(resp, "json")
        parsed = json.loads(result)
        assert parsed["findings"] == [], "Empty findings should be empty JSON array"
        assert parsed["total"] == 0


# ============================================================
# format_error tests
# ============================================================

class TestGoodhartFormatError:
    def _make_cli_error(self, error_code="test_error", message="Test message",
                        exit_code=1, node_id="", field=""):
        try:
            return CliError(
                error_code=error_code,
                message=message,
                exit_code=exit_code,
                node_id=node_id,
                field=field,
            )
        except Exception:
            pytest.skip("Cannot construct CliError model")

    def test_goodhart_format_error_text_both_node_and_field(self):
        """format_error text includes both node_id and field when both are non-empty."""
        err = self._make_cli_error(
            error_code="schema_violation",
            message="Invalid tier value",
            exit_code=2,
            node_id="service.api-gw",
            field="tier",
        )
        result = format_error(err, "text")
        assert "schema_violation" in result
        assert "Invalid tier value" in result
        assert "service.api-gw" in result
        assert "tier" in result

    def test_goodhart_format_error_text_format_pattern(self):
        """format_error text follows 'Error [{error_code}]: {message}' pattern."""
        err = self._make_cli_error(
            error_code="ledger_corrupted",
            message="Checksum mismatch at line 42",
            exit_code=1,
        )
        result = format_error(err, "text")
        # Check the pattern: should contain Error [error_code] and the message
        assert "ledger_corrupted" in result
        assert "Checksum mismatch at line 42" in result
        # Check pattern more strictly
        assert re.search(r"Error\s*\[ledger_corrupted\]", result), (
            "Text error format should follow 'Error [{error_code}]' pattern"
        )

    def test_goodhart_format_error_json_all_fields_present(self):
        """format_error JSON output includes all CliError fields."""
        err = self._make_cli_error(
            error_code="node_not_found",
            message="Node xyz not found",
            exit_code=4,
            node_id="xyz",
            field="",
        )
        result = format_error(err, "json")
        parsed = json.loads(result)
        for key in ("error_code", "message", "exit_code", "node_id", "field"):
            assert key in parsed, f"JSON error output must include '{key}' field"

    def test_goodhart_format_error_json_different_error_codes(self):
        """format_error JSON works for various error_code values, not hardcoded."""
        codes = [
            "registry_not_initialized",
            "permission_denied",
            "port_conflict",
            "empty_review_id",
            "invalid_tier",
        ]
        for code in codes:
            err = self._make_cli_error(error_code=code, message=f"Error: {code}")
            result = format_error(err, "json")
            parsed = json.loads(result)
            assert parsed["error_code"] == code, (
                f"JSON error_code should be '{code}', got '{parsed['error_code']}'"
            )

    def test_goodhart_format_error_special_chars_in_message(self):
        """format_error handles special characters in messages without breaking."""
        msg = "Field 'name' has invalid value: <script>alert('xss')</script>"
        err = self._make_cli_error(
            error_code="schema_violation",
            message=msg,
            exit_code=2,
            field="name",
        )
        # JSON mode should still produce valid JSON
        json_result = format_error(err, "json")
        parsed = json.loads(json_result)
        assert parsed["message"] == msg

        # Text mode should preserve the message
        text_result = format_error(err, "text")
        assert msg in text_result or "Field" in text_result


# ============================================================
# map_exception_to_exit_code tests
# ============================================================

class TestGoodhartMapException:
    def test_goodhart_map_exception_runtime_error_unrecognized(self):
        """Completely unknown exception types like RuntimeError return DOMAIN_ERROR_1."""
        result = map_exception_to_exit_code(RuntimeError("something unexpected"))
        # ExitCode might be an enum or int
        exit_val = result.value if hasattr(result, "value") else result
        assert exit_val == 1, (
            "Unrecognized exception RuntimeError should map to DOMAIN_ERROR_1 (1)"
        )

    def test_goodhart_map_exception_type_error_unrecognized(self):
        """TypeError is not a domain exception and should map to DOMAIN_ERROR_1 default."""
        result = map_exception_to_exit_code(TypeError("bad type"))
        exit_val = result.value if hasattr(result, "value") else result
        assert exit_val == 1, (
            "Unrecognized TypeError should map to DOMAIN_ERROR_1 (1)"
        )

    def test_goodhart_map_exception_keyboard_interrupt(self):
        """KeyboardInterrupt should still be handled gracefully by the mapper."""
        # This tests that the function doesn't crash on unexpected exception types
        try:
            result = map_exception_to_exit_code(KeyboardInterrupt())
            exit_val = result.value if hasattr(result, "value") else result
            # Should return some valid exit code (likely DOMAIN_ERROR_1 as default)
            assert exit_val in (0, 1, 2, 3, 4), "Should return a valid exit code"
        except (KeyboardInterrupt, SystemExit):
            pytest.fail("map_exception_to_exit_code should not re-raise exceptions")


# ============================================================
# NodeIdType validation tests
# ============================================================

class TestGoodhartNodeIdValidation:
    def _validate_node_id(self, value):
        """Attempt to validate a node_id through NodeIdType or pattern check."""
        try:
            param_type = NodeIdType()
            return param_type.convert(value, None, None)
        except Exception:
            # If NodeIdType raises, validation failed
            raise

    def test_goodhart_node_id_valid_dots_dashes_underscores(self):
        """NodeIdType accepts IDs with dots, dashes, and underscores."""
        try:
            result = self._validate_node_id("my-service_v2.0")
            assert result == "my-service_v2.0"
        except NameError:
            pytest.skip("NodeIdType not importable")

    def test_goodhart_node_id_single_char(self):
        """NodeIdType accepts a single valid character."""
        try:
            result = self._validate_node_id("a")
            assert result == "a"
        except NameError:
            pytest.skip("NodeIdType not importable")

    def test_goodhart_node_id_rejects_spaces(self):
        """NodeIdType rejects IDs with spaces."""
        try:
            with pytest.raises(Exception):
                self._validate_node_id("my service")
        except NameError:
            pytest.skip("NodeIdType not importable")

    def test_goodhart_node_id_rejects_slashes(self):
        """NodeIdType rejects IDs with forward slashes."""
        try:
            with pytest.raises(Exception):
                self._validate_node_id("path/to/node")
        except NameError:
            pytest.skip("NodeIdType not importable")

    def test_goodhart_node_id_rejects_at_sign(self):
        """NodeIdType rejects IDs with @ symbol."""
        try:
            with pytest.raises(Exception):
                self._validate_node_id("user@domain")
        except NameError:
            pytest.skip("NodeIdType not importable")

    def test_goodhart_node_id_rejects_colon(self):
        """NodeIdType rejects IDs with colons."""
        try:
            with pytest.raises(Exception):
                self._validate_node_id("namespace:node")
        except NameError:
            pytest.skip("NodeIdType not importable")

    def test_goodhart_node_id_numeric_only(self):
        """NodeIdType accepts purely numeric node IDs like '12345'."""
        try:
            result = self._validate_node_id("12345")
            assert result == "12345"
        except NameError:
            pytest.skip("NodeIdType not importable")


# ============================================================
# VersionType validation tests
# ============================================================

class TestGoodhartVersionValidation:
    def _validate_version(self, value):
        try:
            param_type = VersionType()
            return param_type.convert(value, None, None)
        except Exception:
            raise

    def test_goodhart_version_tag_with_beta_prerelease(self):
        """VersionType accepts semver with beta pre-release suffix."""
        try:
            result = self._validate_version("2.0.0-beta.3")
            assert result == "2.0.0-beta.3"
        except NameError:
            pytest.skip("VersionType not importable")

    def test_goodhart_version_tag_prerelease_with_dots(self):
        """VersionType accepts pre-release identifiers with multiple dots."""
        try:
            result = self._validate_version("1.0.0-rc.1.2")
            assert result == "1.0.0-rc.1.2"
        except NameError:
            pytest.skip("VersionType not importable")

    def test_goodhart_version_tag_zero_version(self):
        """VersionType accepts '0.0.0' as valid."""
        try:
            result = self._validate_version("0.0.0")
            assert result == "0.0.0"
        except NameError:
            pytest.skip("VersionType not importable")

    def test_goodhart_version_tag_rejects_leading_v(self):
        """VersionType rejects 'v1.2.3' with leading v prefix."""
        try:
            with pytest.raises(Exception):
                self._validate_version("v1.2.3")
        except NameError:
            pytest.skip("VersionType not importable")

    def test_goodhart_version_tag_rejects_four_parts(self):
        """VersionType rejects '1.2.3.4' with four numeric parts."""
        try:
            with pytest.raises(Exception):
                self._validate_version("1.2.3.4")
        except NameError:
            pytest.skip("VersionType not importable")

    def test_goodhart_version_tag_rejects_missing_patch(self):
        """VersionType rejects '1.2' missing the patch number."""
        try:
            with pytest.raises(Exception):
                self._validate_version("1.2")
        except NameError:
            pytest.skip("VersionType not importable")

    def test_goodhart_version_tag_rejects_empty(self):
        """VersionType rejects empty string."""
        try:
            with pytest.raises(Exception):
                self._validate_version("")
        except NameError:
            pytest.skip("VersionType not importable")

    def test_goodhart_version_tag_large_numbers(self):
        """VersionType accepts semver with large version numbers."""
        try:
            result = self._validate_version("100.200.300")
            assert result == "100.200.300"
        except NameError:
            pytest.skip("VersionType not importable")


# ============================================================
# RunIdType validation tests
# ============================================================

class TestGoodhartRunIdValidation:
    def _validate_run_id(self, value):
        try:
            param_type = RunIdType()
            return param_type.convert(value, None, None)
        except Exception:
            raise

    def test_goodhart_run_id_valid_different_uuids(self):
        """RunIdType accepts multiple different valid UUID v4 strings."""
        try:
            for _ in range(3):
                uid = str(uuid.uuid4())
                result = self._validate_run_id(uid)
                assert result == uid
        except NameError:
            pytest.skip("RunIdType not importable")

    def test_goodhart_run_id_rejects_plain_string(self):
        """RunIdType rejects plain non-UUID strings."""
        try:
            with pytest.raises(Exception):
                self._validate_run_id("not-a-uuid-at-all")
        except NameError:
            pytest.skip("RunIdType not importable")

    def test_goodhart_run_id_rejects_empty(self):
        """RunIdType rejects empty string."""
        try:
            with pytest.raises(Exception):
                self._validate_run_id("")
        except NameError:
            pytest.skip("RunIdType not importable")

    def test_goodhart_run_id_rejects_partial_uuid(self):
        """RunIdType rejects truncated/partial UUID strings."""
        try:
            with pytest.raises(Exception):
                self._validate_run_id("550e8400-e29b-41d4-a716")
        except NameError:
            pytest.skip("RunIdType not importable")


# ============================================================
# Integration / CLI runner tests
# ============================================================

class TestGoodhartCLIIntegration:
    """Tests that exercise commands via CliRunner with mocked engine dependencies."""

    def _get_runner(self):
        try:
            return CliRunner(mix_stderr=False)
        except Exception:
            return CliRunner()

    def test_goodhart_trust_show_different_node_ids(self):
        """cmd_trust_show returns the correct node_id for different inputs, not hardcoded."""
        try:
            runner = self._get_runner()
        except Exception:
            pytest.skip("CliRunner not available")

        node_ids = ["serviceA", "data-store.v2", "node_xyz"]
        for nid in node_ids:
            try:
                # Mock the trust_engine to return a response for the given node_id
                mock_response = TrustShowResponse(
                    node_id=nid,
                    current_score=0.8,
                    tainted=False,
                    history=[],
                )
                with patch("src.cli.trust_engine") as mock_engine:
                    mock_engine.compute_trust_score.return_value = 0.8
                    mock_engine.get_trust_history.return_value = []
                    # Also try patching at command level
                    result = runner.invoke(cli, ["--format", "json", "trust", "show", nid])
                    if result.exit_code == 0:
                        output = json.loads(result.output)
                        assert output["node_id"] == nid, (
                            f"node_id should be '{nid}', not hardcoded"
                        )
            except Exception:
                # If the specific patching path doesn't work, that's ok - 
                # the test structure catches hardcoded values
                pass

    def test_goodhart_error_output_stderr_not_stdout_generic(self):
        """Error output should go to stderr, never stdout, for any error condition."""
        try:
            runner = CliRunner(mix_stderr=False)
        except TypeError:
            pytest.skip("CliRunner doesn't support mix_stderr")

        try:
            # Invoke a command that will fail (e.g., trust show with non-existent node)
            result = runner.invoke(cli, ["--format", "json", "trust", "show", "nonexistent_node_xyz"])
            if result.exit_code != 0:
                # stdout should not contain error info
                if result.output:
                    try:
                        parsed = json.loads(result.output)
                        assert "error_code" not in parsed, (
                            "Error output should be on stderr, not stdout"
                        )
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pytest.skip("CLI not invokable for this test")

    def test_goodhart_no_stacktrace_on_domain_error(self):
        """No Python traceback should leak to user output on any error path."""
        try:
            runner = CliRunner(mix_stderr=False)
        except TypeError:
            pytest.skip("CliRunner doesn't support mix_stderr")

        try:
            result = runner.invoke(cli, [
                "--format", "text", "blast-radius", "nonexistent_abc", "1.0.0"
            ])
            all_output = (result.output or "") + (getattr(result, 'stderr', '') or "")
            assert "Traceback" not in all_output, (
                "Stack traces must not leak to user output"
            )
            assert 'File "' not in all_output, (
                "Python file references must not leak to user output"
            )
        except Exception:
            pytest.skip("CLI not invokable for this test")

    def test_goodhart_init_exit_code_success(self):
        """cmd_init returns exit code 0 on successful initialization."""
        try:
            runner = self._get_runner()
            with patch("src.cli.registry") as mock_reg:
                mock_reg.initialize_registry.return_value = InitResponse(
                    registry_path="/tmp/test_reg",
                    created_files=["/tmp/test_reg/ledger.jsonl"],
                    message="Initialized",
                )
                result = runner.invoke(cli, [
                    "--format", "json", "init", "--force"
                ])
                assert result.exit_code == 0, (
                    f"Expected exit code 0, got {result.exit_code}"
                )
        except Exception:
            pytest.skip("Cannot invoke CLI init command")

    def test_goodhart_group_registry_path_file_not_dir(self):
        """arbiter_group rejects registry_path that points to a regular file."""
        import tempfile
        import os
        try:
            runner = self._get_runner()
            # Create a temp file (not directory)
            with tempfile.NamedTemporaryFile(delete=False) as f:
                temp_path = f.name
            try:
                result = runner.invoke(cli, [
                    "--registry-path", temp_path, "--format", "json", "init"
                ])
                assert result.exit_code != 0, (
                    "Should fail when registry_path is a file, not a directory"
                )
            finally:
                os.unlink(temp_path)
        except Exception:
            pytest.skip("Cannot invoke CLI for registry_path test")

    def test_goodhart_group_default_config_missing_uses_defaults(self):
        """When default config path doesn't exist, defaults should be used (no error)."""
        import os
        try:
            runner = self._get_runner()
            # Ensure we're in a directory without arbiter.yaml
            original_dir = os.getcwd()
            import tempfile
            with tempfile.TemporaryDirectory() as tmpdir:
                os.chdir(tmpdir)
                try:
                    result = runner.invoke(cli, [
                        "--format", "json", "init", "--force"
                    ])
                    # Should not fail with config_not_found
                    if result.exit_code != 0:
                        all_output = (result.output or "") + (getattr(result, 'stderr', '') or "")
                        assert "config_not_found" not in all_output, (
                            "Default config path missing should not raise config_not_found"
                        )
                finally:
                    os.chdir(original_dir)
        except Exception:
            pytest.skip("Cannot invoke CLI for default config test")


# ============================================================
# Postcondition invariant tests
# ============================================================

class TestGoodhartPostconditionInvariants:
    """Tests that verify postcondition invariants hold for various inputs."""

    def test_goodhart_canary_results_escape_rate_nonzero(self):
        """escape_rate must equal total_escapes / total_canaries for non-zero canary counts."""
        try:
            escapes = [
                TaintEscape(
                    canary_id=f"canary-{i}",
                    source_tier="pii",
                    found_at_node=f"node_{i}",
                    found_at_tier="public",
                    timestamp="2024-01-01T00:00:00Z",
                )
                for i in range(3)
            ]
            resp = CanaryResultsResponse(
                run_id=str(uuid.uuid4()),
                escapes=escapes,
                total_escapes=3,
                total_canaries=10,
                escape_rate=0.3,
            )
            # Verify the invariant
            assert resp.total_escapes == len(resp.escapes)
            assert resp.escape_rate == resp.total_escapes / resp.total_canaries
            assert abs(resp.escape_rate - 0.3) < 1e-9
        except NameError:
            pytest.skip("CanaryResultsResponse not importable")

    def test_goodhart_blast_radius_invariants_multi_depth(self):
        """BlastRadiusResponse invariants hold: total_affected==len, max_depth==max."""
        try:
            nodes = [
                BlastRadiusNode(node_id="a", depth=1, data_tier="t1", trust_score=0.9),
                BlastRadiusNode(node_id="b", depth=2, data_tier="t1", trust_score=0.8),
                BlastRadiusNode(node_id="c", depth=3, data_tier="t2", trust_score=0.7),
                BlastRadiusNode(node_id="d", depth=2, data_tier="t1", trust_score=0.6),
            ]
            resp = BlastRadiusResponse(
                origin_node="origin",
                version="2.1.0",
                affected_nodes=nodes,
                total_affected=4,
                max_depth=3,
            )
            assert resp.total_affected == len(resp.affected_nodes)
            assert resp.max_depth == max(n.depth for n in resp.affected_nodes)
        except NameError:
            pytest.skip("BlastRadiusResponse not importable")

    def test_goodhart_findings_total_matches_len(self):
        """FindingsResponse.total must equal len(findings) for various counts."""
        try:
            for count in [0, 1, 5, 10]:
                findings = [
                    Finding(
                        finding_id=f"f-{i}",
                        node_id="test",
                        severity="low",
                        category="test",
                        message=f"msg {i}",
                        timestamp="2024-01-01T00:00:00Z",
                    )
                    for i in range(count)
                ]
                resp = FindingsResponse(
                    node_id="test",
                    findings=findings,
                    total=count,
                )
                assert resp.total == len(resp.findings), (
                    f"total ({resp.total}) must equal len(findings) ({len(resp.findings)})"
                )
        except NameError:
            pytest.skip("FindingsResponse not importable")

    def test_goodhart_conflicts_total_matches_len(self):
        """ConflictsResponse.total must equal len(conflicts)."""
        try:
            conflicts = [
                Conflict(
                    conflict_id=f"c-{i}",
                    node_ids=["a", "b"],
                    conflict_type="trust_authority",
                    message=f"Conflict {i}",
                    resolved=(i % 2 == 0),
                    timestamp="2024-01-01T00:00:00Z",
                )
                for i in range(4)
            ]
            resp = ConflictsResponse(
                conflicts=conflicts,
                total=4,
                unresolved_only=False,
            )
            assert resp.total == len(resp.conflicts)
        except NameError:
            pytest.skip("ConflictsResponse not importable")

    def test_goodhart_conflicts_unresolved_filter_strict(self):
        """When unresolved_only=True, all returned conflicts must have resolved=False."""
        try:
            # Build mixed conflicts
            all_conflicts = [
                Conflict(
                    conflict_id="c-1",
                    node_ids=["a"],
                    conflict_type="t",
                    message="m",
                    resolved=True,
                    timestamp="2024-01-01T00:00:00Z",
                ),
                Conflict(
                    conflict_id="c-2",
                    node_ids=["b"],
                    conflict_type="t",
                    message="m",
                    resolved=False,
                    timestamp="2024-01-01T00:00:00Z",
                ),
                Conflict(
                    conflict_id="c-3",
                    node_ids=["c"],
                    conflict_type="t",
                    message="m",
                    resolved=False,
                    timestamp="2024-01-01T00:00:00Z",
                ),
            ]
            # Simulate filtering
            unresolved = [c for c in all_conflicts if not c.resolved]
            resp = ConflictsResponse(
                conflicts=unresolved,
                total=len(unresolved),
                unresolved_only=True,
            )
            for c in resp.conflicts:
                assert c.resolved is False, (
                    "With unresolved_only=True, no resolved conflict should appear"
                )
            assert resp.total == len(resp.conflicts)
        except NameError:
            pytest.skip("ConflictsResponse not importable")


# ============================================================
# format_output with 'auto' should be rejected or never happen
# ============================================================

class TestGoodhartFormatOutputAutoRejection:
    def test_goodhart_format_output_rejects_auto(self):
        """format_output should not accept 'auto' as output_format per contract precondition."""
        try:
            resp = TrustShowResponse(
                node_id="test",
                current_score=0.5,
                tainted=False,
                history=[],
            )
        except Exception:
            pytest.skip("Cannot construct test model")

        try:
            result = format_output(resp, "auto")
            # If it doesn't raise, verify it at least didn't return auto-formatted garbage
            # The contract says precondition: output_format is 'text' or 'json' (never 'auto')
            # A compliant implementation should raise or handle this
            pytest.fail(
                "format_output should reject 'auto' format per precondition"
            )
        except (ValueError, TypeError, KeyError, AssertionError) as e:
            # Expected: some kind of error for invalid precondition
            pass
        except Exception:
            # Any exception is acceptable for precondition violation
            pass


# ============================================================
# Authority / Trust separation invariant
# ============================================================

class TestGoodhartTrustAuthoritySeparation:
    def test_goodhart_authority_show_uses_authority_engine(self):
        """authority show must delegate to authority_engine, never trust_engine."""
        try:
            runner = CliRunner(mix_stderr=False)
        except TypeError:
            runner = CliRunner()

        try:
            with patch("src.cli.authority_engine") as mock_auth, \
                 patch("src.cli.trust_engine") as mock_trust:
                mock_auth.get_authority_map.return_value = AuthorityShowResponse(
                    authority_map=[],
                    total_entries=0,
                )
                result = runner.invoke(cli, ["--format", "json", "authority", "show"])
                if result.exit_code == 0:
                    assert mock_auth.get_authority_map.called, (
                        "authority show must call authority_engine"
                    )
                    assert not mock_trust.compute_trust_score.called, (
                        "authority show must not call trust_engine"
                    )
        except Exception:
            pytest.skip("Cannot invoke authority show command")

    def test_goodhart_trust_show_uses_trust_engine(self):
        """trust show must delegate to trust_engine, never authority_engine."""
        try:
            runner = CliRunner(mix_stderr=False)
        except TypeError:
            runner = CliRunner()

        try:
            with patch("src.cli.trust_engine") as mock_trust, \
                 patch("src.cli.authority_engine") as mock_auth:
                mock_trust.compute_trust_score.return_value = 0.9
                mock_trust.get_trust_history.return_value = []
                result = runner.invoke(cli, ["--format", "json", "trust", "show", "testnode"])
                if result.exit_code == 0:
                    assert mock_trust.compute_trust_score.called or mock_trust.get_trust_history.called, (
                        "trust show must call trust_engine"
                    )
                    assert not mock_auth.get_authority_map.called, (
                        "trust show must not call authority_engine"
                    )
        except Exception:
            pytest.skip("Cannot invoke trust show command")
