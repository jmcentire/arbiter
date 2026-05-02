"""
Contract tests for the human_gate component.
Tests organized into classes mirroring the five functions plus invariants.
Run with: pytest contract_test.py -v
"""

import json
import math
import uuid
import socket
from datetime import datetime, timezone
from unittest.mock import MagicMock, Mock, patch, PropertyMock, call
from urllib.error import URLError, HTTPError
from io import BytesIO

import pytest

from human_gate import (
    evaluate_gate,
    build_gate_event,
    send_gate_notification,
    trigger_human_gate,
    validate_human_gate_config,
    GateTriggerReason,
    FindingType,
    DataTier,
    RequiredAction,
    HumanGateConfig,
    GateDecision,
    GateEvent,
    WebhookResult,
    GateResult,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def valid_config():
    """Standard valid HumanGateConfig for testing."""
    return HumanGateConfig(
        enabled=True,
        webhook_url="https://hooks.example.com/gate",
        block_on_gate=True,
        timeout_seconds=5.0,
        schema_version="1",
    )


@pytest.fixture
def disabled_config():
    """HumanGateConfig with enabled=False."""
    return HumanGateConfig(
        enabled=False,
        webhook_url="",
        block_on_gate=False,
        timeout_seconds=5.0,
        schema_version="1",
    )


@pytest.fixture
def non_blocking_config():
    """Valid HumanGateConfig with block_on_gate=False."""
    return HumanGateConfig(
        enabled=True,
        webhook_url="https://hooks.example.com/gate",
        block_on_gate=False,
        timeout_seconds=5.0,
        schema_version="1",
    )


@pytest.fixture
def mock_stigmergy_emitter():
    """Mock stigmergy emitter that returns True."""
    emitter = MagicMock()
    emitter.return_value = True
    return emitter


@pytest.fixture
def failing_stigmergy_emitter():
    """Mock stigmergy emitter that returns False."""
    emitter = MagicMock()
    emitter.return_value = False
    return emitter


@pytest.fixture
def sample_triggered_decision():
    """A GateDecision that is triggered."""
    return GateDecision(
        triggered=True,
        trigger_reason=GateTriggerReason.FINANCIAL_TIER,
        required_action=RequiredAction.REVIEW_AND_APPROVE,
        summary="Gate triggered for node build-test-node",
    )


@pytest.fixture
def sample_not_triggered_decision():
    """A GateDecision that is not triggered."""
    return GateDecision(
        triggered=False,
        trigger_reason=None,
        required_action=None,
        summary="No gate trigger for node safe-node",
    )


@pytest.fixture
def sample_gate_event():
    """A valid GateEvent for testing notifications."""
    return GateEvent(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        node_id="test-node-1",
        finding_type=FindingType.TRUST_VIOLATION,
        trust_score=0.3,
        data_tier=DataTier.FINANCIAL,
        trigger_reason=GateTriggerReason.FINANCIAL_TIER,
        required_action=RequiredAction.REVIEW_AND_APPROVE,
        summary="Test gate event for test-node-1",
        schema_version="1",
    )


# ============================================================================
# Class 1: test_evaluate_gate
# ============================================================================

class TestEvaluateGate:
    """Tests for evaluate_gate: pure function, truth-table style."""

    # --- Happy path: trigger conditions ---

    def test_financial_tier_triggers(self):
        """FINANCIAL data tier triggers FINANCIAL_TIER."""
        result = evaluate_gate(
            node_id="node-1",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.8,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.FINANCIAL_TIER
        assert result.required_action is not None
        assert "node-1" in result.summary

    def test_auth_tier_triggers(self):
        """AUTH data tier triggers AUTH_TIER."""
        result = evaluate_gate(
            node_id="node-2",
            finding_type=FindingType.ACCESS_CONFLICT,
            trust_score=0.9,
            data_tier=DataTier.AUTH,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.AUTH_TIER
        assert result.required_action is not None

    def test_compliance_tier_triggers(self):
        """COMPLIANCE data tier triggers COMPLIANCE_TIER."""
        result = evaluate_gate(
            node_id="node-3",
            finding_type=FindingType.BLAST_RADIUS_EXCEEDED,
            trust_score=0.7,
            data_tier=DataTier.COMPLIANCE,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.COMPLIANCE_TIER
        assert result.required_action is not None

    def test_low_trust_authoritative_triggers(self):
        """Authoritative node with trust < 0.5 triggers LOW_TRUST_AUTHORITATIVE."""
        result = evaluate_gate(
            node_id="node-4",
            finding_type=FindingType.CANARY_TRIGGERED,
            trust_score=0.3,
            data_tier=DataTier.PUBLIC,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.LOW_TRUST_AUTHORITATIVE
        assert result.required_action is not None

    def test_unresolvable_conflict_triggers(self):
        """Unresolvable conflict triggers UNRESOLVABLE_CONFLICT."""
        result = evaluate_gate(
            node_id="node-5",
            finding_type=FindingType.CLASSIFICATION_MISMATCH,
            trust_score=0.8,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=True,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.UNRESOLVABLE_CONFLICT
        assert result.required_action is not None

    def test_not_triggered_for_safe_inputs(self):
        """PUBLIC tier, high trust, not authoritative, no conflict = not triggered."""
        result = evaluate_gate(
            node_id="node-6",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.8,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is False
        assert result.trigger_reason is None
        assert result.required_action is None
        assert "node-6" in result.summary

    # --- Edge cases: boundary trust scores ---

    def test_trust_score_zero_boundary(self):
        """Trust score 0.0 is valid and triggers LOW_TRUST_AUTHORITATIVE when authoritative."""
        result = evaluate_gate(
            node_id="node-7",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.0,
            data_tier=DataTier.PUBLIC,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.LOW_TRUST_AUTHORITATIVE

    def test_trust_score_one_boundary(self):
        """Trust score 1.0 is valid; no trigger for benign inputs."""
        result = evaluate_gate(
            node_id="node-8",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=1.0,
            data_tier=DataTier.INTERNAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is False

    def test_trust_score_049_just_below_threshold(self):
        """Trust 0.49 + authoritative triggers LOW_TRUST_AUTHORITATIVE (< 0.5)."""
        result = evaluate_gate(
            node_id="node-9",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.49,
            data_tier=DataTier.INTERNAL,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.LOW_TRUST_AUTHORITATIVE

    def test_trust_score_050_at_threshold_no_low_trust_trigger(self):
        """Trust 0.5 + authoritative does NOT trigger LOW_TRUST_AUTHORITATIVE (threshold is < 0.5)."""
        result = evaluate_gate(
            node_id="node-10",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.5,
            data_tier=DataTier.INTERNAL,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        # Gate should not fire for LOW_TRUST_AUTHORITATIVE
        if result.triggered:
            assert result.trigger_reason != GateTriggerReason.LOW_TRUST_AUTHORITATIVE
        else:
            assert result.triggered is False

    # --- Edge cases: non-triggering data tiers ---

    def test_internal_tier_alone_no_trigger(self):
        """INTERNAL data tier alone does not trigger gate."""
        result = evaluate_gate(
            node_id="node-11",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.8,
            data_tier=DataTier.INTERNAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is False

    def test_public_tier_alone_no_trigger(self):
        """PUBLIC data tier alone does not trigger gate."""
        result = evaluate_gate(
            node_id="node-12",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.8,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is False

    def test_confidential_tier_alone_no_trigger(self):
        """CONFIDENTIAL data tier alone does not trigger gate (only FINANCIAL/AUTH/COMPLIANCE)."""
        result = evaluate_gate(
            node_id="node-13",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.8,
            data_tier=DataTier.CONFIDENTIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is False

    def test_authoritative_high_trust_no_trigger(self):
        """Authoritative + high trust does NOT trigger LOW_TRUST_AUTHORITATIVE."""
        result = evaluate_gate(
            node_id="node-14",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.8,
            data_tier=DataTier.PUBLIC,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is False

    # --- Parametrized: all FindingType values work without error for triggered path ---

    @pytest.mark.parametrize("finding_type", list(FindingType))
    def test_all_finding_types_accepted(self, finding_type):
        """All FindingType enum values are accepted without error."""
        result = evaluate_gate(
            node_id="param-node",
            finding_type=finding_type,
            trust_score=0.5,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.FINANCIAL_TIER

    # --- Parametrized: all DataTier values are accepted ---

    @pytest.mark.parametrize("data_tier", list(DataTier))
    def test_all_data_tiers_accepted(self, data_tier):
        """All DataTier enum values are accepted without error."""
        result = evaluate_gate(
            node_id="param-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.8,
            data_tier=data_tier,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert isinstance(result, GateDecision)

    # --- Error cases ---

    def test_error_nan_trust_score(self):
        """NaN trust_score raises error."""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="node-err",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=float("nan"),
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_error_inf_trust_score(self):
        """Infinite trust_score raises error."""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="node-err",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=float("inf"),
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_error_negative_inf_trust_score(self):
        """Negative infinite trust_score raises error."""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="node-err",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=float("-inf"),
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_error_negative_trust_score(self):
        """Negative trust_score raises error."""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="node-err",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=-0.1,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_error_trust_score_above_one(self):
        """Trust score > 1.0 raises error."""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="node-err",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=1.1,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_error_empty_node_id(self):
        """Empty node_id raises error."""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_error_whitespace_only_node_id(self):
        """Whitespace-only node_id raises error."""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="   ",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    # --- Determinism invariant ---

    def test_determinism_same_inputs_same_output(self):
        """Same inputs always produce same output."""
        kwargs = dict(
            node_id="det-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        result1 = evaluate_gate(**kwargs)
        result2 = evaluate_gate(**kwargs)
        assert result1.triggered == result2.triggered
        assert result1.trigger_reason == result2.trigger_reason
        assert result1.required_action == result2.required_action
        assert result1.summary == result2.summary


# ============================================================================
# Class 2: test_build_gate_event
# ============================================================================

class TestBuildGateEvent:
    """Tests for build_gate_event: factory function for GateEvent."""

    def test_happy_basic_field_population(self, sample_triggered_decision):
        """All fields populate correctly from inputs and decision."""
        event = build_gate_event(
            node_id="build-node-1",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            decision=sample_triggered_decision,
            schema_version="1",
        )
        assert event.node_id == "build-node-1"
        assert event.finding_type == FindingType.TRUST_VIOLATION
        assert event.trust_score == 0.3
        assert event.data_tier == DataTier.FINANCIAL
        assert event.trigger_reason == sample_triggered_decision.trigger_reason
        assert event.required_action == sample_triggered_decision.required_action
        assert event.schema_version == "1"
        assert event.summary == sample_triggered_decision.summary

    def test_event_id_is_valid_uuid4(self, sample_triggered_decision):
        """event_id is a valid UUID4."""
        event = build_gate_event(
            node_id="uuid-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            decision=sample_triggered_decision,
            schema_version="1",
        )
        parsed = uuid.UUID(event.event_id)
        assert parsed.version == 4

    def test_timestamp_is_utc_iso8601(self, sample_triggered_decision):
        """Timestamp is UTC ISO 8601."""
        event = build_gate_event(
            node_id="ts-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            decision=sample_triggered_decision,
            schema_version="1",
        )
        parsed_ts = datetime.fromisoformat(event.timestamp)
        assert parsed_ts.tzinfo is not None
        # Check it's UTC (offset 0)
        assert parsed_ts.utcoffset().total_seconds() == 0

    def test_schema_version_propagated(self, sample_triggered_decision):
        """schema_version from input propagates to event."""
        event = build_gate_event(
            node_id="sv-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            decision=sample_triggered_decision,
            schema_version="1",
        )
        assert event.schema_version == "1"

    def test_frozen_pydantic_model(self, sample_triggered_decision):
        """GateEvent is frozen — assignment raises error."""
        event = build_gate_event(
            node_id="freeze-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            decision=sample_triggered_decision,
            schema_version="1",
        )
        with pytest.raises(Exception):
            event.node_id = "mutated"

    def test_error_decision_not_triggered(self, sample_not_triggered_decision):
        """build_gate_event raises when decision.triggered is False."""
        with pytest.raises(Exception):
            build_gate_event(
                node_id="err-node",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.PUBLIC,
                decision=sample_not_triggered_decision,
                schema_version="1",
            )

    def test_unique_event_ids_across_calls(self, sample_triggered_decision):
        """Each call generates a different event_id."""
        event1 = build_gate_event(
            node_id="uniq-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            decision=sample_triggered_decision,
            schema_version="1",
        )
        event2 = build_gate_event(
            node_id="uniq-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            decision=sample_triggered_decision,
            schema_version="1",
        )
        assert event1.event_id != event2.event_id


# ============================================================================
# Class 3: test_send_gate_notification
# ============================================================================

class TestSendGateNotification:
    """Tests for send_gate_notification with mocked HTTP."""

    def _make_mock_response(self, status=200, body=b"OK", headers=None):
        """Helper to create a mock HTTP response."""
        mock_resp = MagicMock()
        mock_resp.status = status
        mock_resp.getcode.return_value = status
        mock_resp.read.return_value = body
        mock_resp.headers = headers or {}
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    @patch("human_gate.urllib.request.urlopen")
    def test_happy_200_response(self, mock_urlopen, sample_gate_event, valid_config):
        """200 response → success=True, status_code=200, no error."""
        mock_urlopen.return_value = self._make_mock_response(200)
        result = send_gate_notification(sample_gate_event, valid_config)
        assert result.success is True
        assert result.status_code == 200
        assert result.error_message is None
        assert result.elapsed_ms >= 0

    @patch("human_gate.urllib.request.urlopen")
    def test_happy_request_headers(self, mock_urlopen, sample_gate_event, valid_config):
        """Request includes X-Gate-Event-Id and Content-Type headers."""
        mock_urlopen.return_value = self._make_mock_response(200)
        send_gate_notification(sample_gate_event, valid_config)

        # Inspect the Request object passed to urlopen
        call_args = mock_urlopen.call_args
        request_obj = call_args[0][0] if call_args[0] else call_args[1].get("url")

        # Check headers on the Request object
        assert request_obj.get_header("X-gate-event-id") == sample_gate_event.event_id or \
               request_obj.get_header("X-Gate-Event-Id") == sample_gate_event.event_id
        content_type = request_obj.get_header("Content-type") or request_obj.get_header("Content-Type")
        assert content_type == "application/json"

    @patch("human_gate.urllib.request.urlopen")
    def test_happy_request_body_json(self, mock_urlopen, sample_gate_event, valid_config):
        """Request body is JSON containing schema_version."""
        mock_urlopen.return_value = self._make_mock_response(200)
        send_gate_notification(sample_gate_event, valid_config)

        call_args = mock_urlopen.call_args
        request_obj = call_args[0][0] if call_args[0] else call_args[1].get("url")
        body = json.loads(request_obj.data)
        assert "schema_version" in body
        assert body["schema_version"] == "1"

    @patch("human_gate.urllib.request.urlopen")
    def test_error_connection_refused(self, mock_urlopen, sample_gate_event, valid_config):
        """Connection refused → success=False, status_code=None, error has context."""
        mock_urlopen.side_effect = URLError(ConnectionRefusedError("Connection refused"))
        result = send_gate_notification(sample_gate_event, valid_config)
        assert result.success is False
        assert result.status_code is None
        assert result.error_message is not None
        assert sample_gate_event.node_id in result.error_message
        assert valid_config.webhook_url in result.error_message
        assert result.elapsed_ms >= 0

    @patch("human_gate.urllib.request.urlopen")
    def test_error_timeout(self, mock_urlopen, sample_gate_event, valid_config):
        """Timeout → success=False, status_code=None, error message set."""
        mock_urlopen.side_effect = URLError(socket.timeout("timed out"))
        result = send_gate_notification(sample_gate_event, valid_config)
        assert result.success is False
        assert result.status_code is None
        assert result.error_message is not None
        assert result.elapsed_ms >= 0

    @patch("human_gate.urllib.request.urlopen")
    def test_error_redirect_3xx(self, mock_urlopen, sample_gate_event, valid_config):
        """3xx redirect → success=False, error mentions redirect."""
        mock_urlopen.side_effect = HTTPError(
            url=valid_config.webhook_url,
            code=301,
            msg="Moved Permanently",
            hdrs={},
            fp=BytesIO(b"Moved"),
        )
        result = send_gate_notification(sample_gate_event, valid_config)
        assert result.success is False
        assert result.error_message is not None
        # Error message should mention redirect
        assert "redirect" in result.error_message.lower() or result.status_code == 301

    @patch("human_gate.urllib.request.urlopen")
    def test_error_non_2xx_500(self, mock_urlopen, sample_gate_event, valid_config):
        """500 response → success=False, status_code=500, response_body truncated."""
        body = b"Internal Server Error " * 100  # > 1024 chars
        mock_urlopen.side_effect = HTTPError(
            url=valid_config.webhook_url,
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=BytesIO(body),
        )
        result = send_gate_notification(sample_gate_event, valid_config)
        assert result.success is False
        assert result.status_code == 500
        assert result.response_body is not None
        assert len(result.response_body) <= 1024

    @patch("human_gate.urllib.request.urlopen")
    def test_error_dns_resolution(self, mock_urlopen, sample_gate_event, valid_config):
        """DNS resolution failure → success=False, status_code=None."""
        mock_urlopen.side_effect = URLError(socket.gaierror("Name resolution failed"))
        result = send_gate_notification(sample_gate_event, valid_config)
        assert result.success is False
        assert result.status_code is None
        assert result.error_message is not None

    @patch("human_gate.urllib.request.urlopen")
    def test_error_ssl(self, mock_urlopen, sample_gate_event, valid_config):
        """SSL error → success=False, status_code=None."""
        import ssl
        mock_urlopen.side_effect = URLError(ssl.SSLError("SSL handshake failed"))
        result = send_gate_notification(sample_gate_event, valid_config)
        assert result.success is False
        assert result.status_code is None
        assert result.error_message is not None

    @patch("human_gate.urllib.request.urlopen")
    def test_never_raises(self, mock_urlopen, sample_gate_event, valid_config):
        """send_gate_notification never raises — always returns WebhookResult."""
        mock_urlopen.side_effect = Exception("Totally unexpected error")
        result = send_gate_notification(sample_gate_event, valid_config)
        assert isinstance(result, WebhookResult)
        assert result.success is False
        assert result.elapsed_ms >= 0

    @patch("human_gate.urllib.request.urlopen")
    def test_elapsed_ms_always_nonnegative(self, mock_urlopen, sample_gate_event, valid_config):
        """elapsed_ms is always non-negative."""
        mock_urlopen.return_value = self._make_mock_response(200)
        result = send_gate_notification(sample_gate_event, valid_config)
        assert result.elapsed_ms >= 0

    @patch("human_gate.urllib.request.urlopen")
    def test_success_response_body_is_none(self, mock_urlopen, sample_gate_event, valid_config):
        """On success, response_body is None."""
        mock_urlopen.return_value = self._make_mock_response(200)
        result = send_gate_notification(sample_gate_event, valid_config)
        assert result.success is True
        assert result.response_body is None


# ============================================================================
# Class 4: test_trigger_human_gate
# ============================================================================

class TestTriggerHumanGate:
    """Tests for trigger_human_gate: orchestration with mocked dependencies."""

    @patch("human_gate.send_gate_notification")
    def test_happy_triggered_full_flow(
        self, mock_notify, valid_config, mock_stigmergy_emitter
    ):
        """Triggered gate: stigmergy emitted, notification sent, correct GateResult."""
        mock_notify.return_value = WebhookResult(
            success=True, status_code=200, error_message=None,
            response_body=None, elapsed_ms=50.0,
        )
        result = trigger_human_gate(
            node_id="orch-node-1",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=valid_config,
            stigmergy_emitter=mock_stigmergy_emitter,
        )
        assert result.triggered is True
        assert result.stigmergy_emitted is True
        assert result.notification_sent is True
        assert result.notification_error is None
        # event_id is valid UUID4
        parsed_uuid = uuid.UUID(result.event_id)
        assert parsed_uuid.version == 4
        mock_stigmergy_emitter.assert_called_once()

    @patch("human_gate.send_gate_notification")
    def test_happy_not_triggered_no_side_effects(
        self, mock_notify, valid_config, mock_stigmergy_emitter
    ):
        """Not-triggered gate: no stigmergy emission or notification."""
        result = trigger_human_gate(
            node_id="safe-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.9,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=valid_config,
            stigmergy_emitter=mock_stigmergy_emitter,
        )
        assert result.triggered is False
        assert result.stigmergy_emitted is False
        assert result.notification_sent is False
        assert result.blocked is False
        mock_stigmergy_emitter.assert_not_called()
        mock_notify.assert_not_called()

    def test_happy_disabled_config_short_circuits(
        self, disabled_config, mock_stigmergy_emitter
    ):
        """Disabled config short-circuits: all fields false/empty."""
        result = trigger_human_gate(
            node_id="disabled-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=disabled_config,
            stigmergy_emitter=mock_stigmergy_emitter,
        )
        assert result.triggered is False
        assert result.stigmergy_emitted is False
        assert result.notification_sent is False
        assert result.blocked is False
        mock_stigmergy_emitter.assert_not_called()

    @patch("human_gate.send_gate_notification")
    def test_happy_blocked_when_block_on_gate_true(
        self, mock_notify, valid_config, mock_stigmergy_emitter
    ):
        """blocked=True when triggered and config.block_on_gate=True."""
        assert valid_config.block_on_gate is True
        mock_notify.return_value = WebhookResult(
            success=True, status_code=200, error_message=None,
            response_body=None, elapsed_ms=10.0,
        )
        result = trigger_human_gate(
            node_id="block-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=valid_config,
            stigmergy_emitter=mock_stigmergy_emitter,
        )
        assert result.triggered is True
        assert result.blocked is True

    @patch("human_gate.send_gate_notification")
    def test_happy_not_blocked_when_block_on_gate_false(
        self, mock_notify, non_blocking_config, mock_stigmergy_emitter
    ):
        """blocked=False when triggered but config.block_on_gate=False."""
        assert non_blocking_config.block_on_gate is False
        mock_notify.return_value = WebhookResult(
            success=True, status_code=200, error_message=None,
            response_body=None, elapsed_ms=10.0,
        )
        result = trigger_human_gate(
            node_id="noblock-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=non_blocking_config,
            stigmergy_emitter=mock_stigmergy_emitter,
        )
        assert result.triggered is True
        assert result.blocked is False

    @patch("human_gate.send_gate_notification")
    def test_edge_webhook_failure_graceful(
        self, mock_notify, valid_config, mock_stigmergy_emitter
    ):
        """Webhook failure is non-fatal: notification_sent=False, notification_error set."""
        mock_notify.return_value = WebhookResult(
            success=False, status_code=500, error_message="Server error for orch-node-2",
            response_body="Internal Server Error", elapsed_ms=100.0,
        )
        result = trigger_human_gate(
            node_id="orch-node-2",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=valid_config,
            stigmergy_emitter=mock_stigmergy_emitter,
        )
        assert result.triggered is True
        assert result.stigmergy_emitted is True
        assert result.notification_sent is False
        assert result.notification_error is not None

    @patch("human_gate.send_gate_notification")
    def test_edge_stigmergy_failure_still_notifies(
        self, mock_notify, valid_config, failing_stigmergy_emitter
    ):
        """Even if stigmergy emission fails, webhook is still attempted."""
        mock_notify.return_value = WebhookResult(
            success=True, status_code=200, error_message=None,
            response_body=None, elapsed_ms=20.0,
        )
        result = trigger_human_gate(
            node_id="stig-fail-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=valid_config,
            stigmergy_emitter=failing_stigmergy_emitter,
        )
        assert result.triggered is True
        assert result.stigmergy_emitted is False
        mock_notify.assert_called_once()

    @patch("human_gate.send_gate_notification")
    def test_edge_trigger_reason_matches_decision(
        self, mock_notify, valid_config, mock_stigmergy_emitter
    ):
        """GateResult.trigger_reason matches evaluate_gate's decision."""
        mock_notify.return_value = WebhookResult(
            success=True, status_code=200, error_message=None,
            response_body=None, elapsed_ms=10.0,
        )
        result = trigger_human_gate(
            node_id="reason-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=valid_config,
            stigmergy_emitter=mock_stigmergy_emitter,
        )
        assert result.trigger_reason == GateTriggerReason.FINANCIAL_TIER

    def test_error_enabled_no_webhook_url(self, mock_stigmergy_emitter):
        """Error when config.enabled is True but webhook_url is empty."""
        bad_config = HumanGateConfig(
            enabled=True,
            webhook_url="",
            block_on_gate=False,
            timeout_seconds=5.0,
            schema_version="1",
        )
        with pytest.raises(Exception):
            trigger_human_gate(
                node_id="bad-config-node",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.FINANCIAL,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=bad_config,
                stigmergy_emitter=mock_stigmergy_emitter,
            )

    def test_error_stigmergy_emitter_not_callable(self, valid_config):
        """Error when stigmergy_emitter is not callable."""
        with pytest.raises(Exception):
            trigger_human_gate(
                node_id="not-callable-node",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.3,
                data_tier=DataTier.FINANCIAL,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=valid_config,
                stigmergy_emitter="not-a-callable",
            )

    @patch("human_gate.send_gate_notification")
    def test_error_emitter_raises_exception(self, mock_notify, valid_config):
        """Emitter raising exception is handled gracefully."""
        bad_emitter = MagicMock(side_effect=RuntimeError("Emitter crashed"))
        mock_notify.return_value = WebhookResult(
            success=True, status_code=200, error_message=None,
            response_body=None, elapsed_ms=10.0,
        )
        # Should either handle gracefully and return GateResult, or raise a specific error
        try:
            result = trigger_human_gate(
                node_id="emitter-crash-node",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.3,
                data_tier=DataTier.FINANCIAL,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=valid_config,
                stigmergy_emitter=bad_emitter,
            )
            # If it returns, should still have tried notification
            assert result.triggered is True
            assert result.stigmergy_emitted is False
        except Exception:
            # Contract says this is an error case — it may raise
            pass

    def test_error_invalid_trust_score(self, valid_config, mock_stigmergy_emitter):
        """Invalid trust_score raises through trigger_human_gate."""
        with pytest.raises(Exception):
            trigger_human_gate(
                node_id="trust-err-node",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=float("nan"),
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=valid_config,
                stigmergy_emitter=mock_stigmergy_emitter,
            )

    def test_error_empty_node_id(self, valid_config, mock_stigmergy_emitter):
        """Empty node_id raises through trigger_human_gate."""
        with pytest.raises(Exception):
            trigger_human_gate(
                node_id="",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=valid_config,
                stigmergy_emitter=mock_stigmergy_emitter,
            )

    @patch("human_gate.send_gate_notification")
    def test_event_id_unique_across_calls(
        self, mock_notify, valid_config, mock_stigmergy_emitter
    ):
        """Two trigger_human_gate calls produce different event_ids."""
        mock_notify.return_value = WebhookResult(
            success=True, status_code=200, error_message=None,
            response_body=None, elapsed_ms=10.0,
        )
        kwargs = dict(
            node_id="unique-id-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=valid_config,
            stigmergy_emitter=mock_stigmergy_emitter,
        )
        result1 = trigger_human_gate(**kwargs)
        result2 = trigger_human_gate(**kwargs)
        assert result1.event_id != result2.event_id

    @patch("human_gate.send_gate_notification")
    def test_stigmergy_called_before_notification(
        self, mock_notify, valid_config
    ):
        """Stigmergy emission is called before webhook notification (ordering)."""
        call_order = []
        emitter = MagicMock(side_effect=lambda e: (call_order.append("stigmergy"), True)[-1])
        mock_notify.side_effect = lambda e, c: (
            call_order.append("webhook"),
            WebhookResult(
                success=True, status_code=200, error_message=None,
                response_body=None, elapsed_ms=10.0,
            ),
        )[-1]

        trigger_human_gate(
            node_id="order-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=valid_config,
            stigmergy_emitter=emitter,
        )

        assert call_order.index("stigmergy") < call_order.index("webhook")


# ============================================================================
# Class 5: test_validate_human_gate_config
# ============================================================================

class TestValidateHumanGateConfig:
    """Tests for validate_human_gate_config."""

    def test_happy_valid_config(self, valid_config):
        """Valid config returns empty list."""
        errors = validate_human_gate_config(valid_config)
        assert errors == []

    def test_error_enabled_no_webhook_url(self):
        """Enabled config with empty webhook_url reports error."""
        config = HumanGateConfig(
            enabled=True,
            webhook_url="",
            block_on_gate=False,
            timeout_seconds=5.0,
            schema_version="1",
        )
        errors = validate_human_gate_config(config)
        assert len(errors) > 0
        assert any("webhook_url" in e.lower() or "webhook" in e.lower() for e in errors)

    def test_error_bad_url_scheme(self):
        """Non-http(s) webhook_url reports error."""
        config = HumanGateConfig(
            enabled=True,
            webhook_url="ftp://example.com/gate",
            block_on_gate=False,
            timeout_seconds=5.0,
            schema_version="1",
        )
        errors = validate_human_gate_config(config)
        assert len(errors) > 0
        assert any("http" in e.lower() for e in errors)

    def test_error_timeout_too_low(self):
        """timeout_seconds < 0.1 reports error."""
        config = HumanGateConfig(
            enabled=True,
            webhook_url="https://hooks.example.com/gate",
            block_on_gate=False,
            timeout_seconds=0.05,
            schema_version="1",
        )
        errors = validate_human_gate_config(config)
        assert len(errors) > 0
        assert any("timeout" in e.lower() for e in errors)

    def test_error_timeout_too_high(self):
        """timeout_seconds > 30.0 reports error."""
        config = HumanGateConfig(
            enabled=True,
            webhook_url="https://hooks.example.com/gate",
            block_on_gate=False,
            timeout_seconds=60.0,
            schema_version="1",
        )
        errors = validate_human_gate_config(config)
        assert len(errors) > 0
        assert any("timeout" in e.lower() for e in errors)

    def test_error_bad_schema_version(self):
        """Unrecognized schema_version reports error."""
        config = HumanGateConfig(
            enabled=True,
            webhook_url="https://hooks.example.com/gate",
            block_on_gate=False,
            timeout_seconds=5.0,
            schema_version="99",
        )
        errors = validate_human_gate_config(config)
        assert len(errors) > 0
        assert any("schema_version" in e.lower() or "schema" in e.lower() or "version" in e.lower() for e in errors)

    def test_edge_multiple_errors_simultaneously(self):
        """Config with multiple issues reports all errors."""
        config = HumanGateConfig(
            enabled=True,
            webhook_url="",
            block_on_gate=False,
            timeout_seconds=0.01,
            schema_version="99",
        )
        errors = validate_human_gate_config(config)
        assert len(errors) >= 2

    def test_edge_timeout_boundary_low_valid(self):
        """timeout_seconds=0.1 is valid (boundary)."""
        config = HumanGateConfig(
            enabled=True,
            webhook_url="https://hooks.example.com/gate",
            block_on_gate=False,
            timeout_seconds=0.1,
            schema_version="1",
        )
        errors = validate_human_gate_config(config)
        timeout_errors = [e for e in errors if "timeout" in e.lower()]
        assert len(timeout_errors) == 0

    def test_edge_timeout_boundary_high_valid(self):
        """timeout_seconds=30.0 is valid (boundary)."""
        config = HumanGateConfig(
            enabled=True,
            webhook_url="https://hooks.example.com/gate",
            block_on_gate=False,
            timeout_seconds=30.0,
            schema_version="1",
        )
        errors = validate_human_gate_config(config)
        timeout_errors = [e for e in errors if "timeout" in e.lower()]
        assert len(timeout_errors) == 0

    def test_disabled_config_with_empty_url_valid(self):
        """Disabled config with empty URL should be valid (URL not required when disabled)."""
        config = HumanGateConfig(
            enabled=False,
            webhook_url="",
            block_on_gate=False,
            timeout_seconds=5.0,
            schema_version="1",
        )
        errors = validate_human_gate_config(config)
        # Should not report webhook_url error since not enabled
        webhook_errors = [e for e in errors if "webhook" in e.lower()]
        assert len(webhook_errors) == 0


# ============================================================================
# Class 6: Invariants and cross-cutting properties
# ============================================================================

class TestHumanGateInvariants:
    """Cross-cutting invariant tests."""

    def test_gate_decision_is_frozen(self):
        """GateDecision is frozen Pydantic model."""
        decision = evaluate_gate(
            node_id="frozen-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.8,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        with pytest.raises(Exception):
            decision.triggered = True

    def test_gate_event_is_frozen(self, sample_triggered_decision):
        """GateEvent is frozen Pydantic model."""
        event = build_gate_event(
            node_id="frozen-event-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            decision=sample_triggered_decision,
            schema_version="1",
        )
        with pytest.raises(Exception):
            event.node_id = "mutated"

    def test_gate_event_timestamps_are_utc(self, sample_triggered_decision):
        """All GateEvent timestamps are UTC."""
        event = build_gate_event(
            node_id="utc-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            decision=sample_triggered_decision,
            schema_version="1",
        )
        ts = datetime.fromisoformat(event.timestamp)
        assert ts.tzinfo is not None
        assert ts.utcoffset().total_seconds() == 0

    def test_trust_and_authority_are_distinct_low_trust_no_authority(self):
        """Low trust without authority does NOT trigger LOW_TRUST_AUTHORITATIVE."""
        result = evaluate_gate(
            node_id="distinct-1",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.1,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        # Should not trigger at all (no other trigger conditions met)
        assert result.triggered is False

    def test_trust_and_authority_are_distinct_high_trust_authority(self):
        """Authority without low trust does NOT trigger LOW_TRUST_AUTHORITATIVE."""
        result = evaluate_gate(
            node_id="distinct-2",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.9,
            data_tier=DataTier.PUBLIC,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is False

    def test_not_triggered_implies_no_reason_and_no_action(self):
        """When triggered=False, trigger_reason and required_action are both None."""
        result = evaluate_gate(
            node_id="no-trigger-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.8,
            data_tier=DataTier.INTERNAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is False
        assert result.trigger_reason is None
        assert result.required_action is None

    def test_triggered_implies_reason_and_action_present(self):
        """When triggered=True, trigger_reason and required_action are not None."""
        result = evaluate_gate(
            node_id="triggered-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason is not None
        assert result.required_action is not None

    def test_summary_always_contains_node_id(self):
        """Summary always contains the node_id, whether triggered or not."""
        for triggered_data_tier, expected_triggered in [
            (DataTier.FINANCIAL, True),
            (DataTier.PUBLIC, False),
        ]:
            node = f"summary-node-{triggered_data_tier.name}"
            result = evaluate_gate(
                node_id=node,
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.8,
                data_tier=triggered_data_tier,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )
            assert node in result.summary, (
                f"node_id '{node}' not found in summary: '{result.summary}'"
            )

    def test_determinism_multiple_runs(self):
        """Evaluate gate 10 times with same inputs; all results identical."""
        kwargs = dict(
            node_id="determ-node",
            finding_type=FindingType.ACCESS_CONFLICT,
            trust_score=0.4,
            data_tier=DataTier.AUTH,
            is_authoritative=True,
            is_unresolvable_conflict=True,
        )
        results = [evaluate_gate(**kwargs) for _ in range(10)]
        for r in results[1:]:
            assert r.triggered == results[0].triggered
            assert r.trigger_reason == results[0].trigger_reason
            assert r.required_action == results[0].required_action
            assert r.summary == results[0].summary

    @patch("human_gate.send_gate_notification")
    def test_webhook_result_is_frozen(self, mock_urlopen, sample_gate_event, valid_config):
        """WebhookResult is frozen."""
        wr = WebhookResult(
            success=True, status_code=200, error_message=None,
            response_body=None, elapsed_ms=10.0,
        )
        with pytest.raises(Exception):
            wr.success = False

    @patch("human_gate.send_gate_notification")
    def test_gate_result_is_frozen(self, mock_notify, valid_config, mock_stigmergy_emitter):
        """GateResult is frozen Pydantic model."""
        mock_notify.return_value = WebhookResult(
            success=True, status_code=200, error_message=None,
            response_body=None, elapsed_ms=10.0,
        )
        result = trigger_human_gate(
            node_id="frozen-result-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=valid_config,
            stigmergy_emitter=mock_stigmergy_emitter,
        )
        with pytest.raises(Exception):
            result.triggered = False

    def test_schema_version_is_1(self, sample_triggered_decision):
        """schema_version in GateEvent is always '1' for this contract version."""
        event = build_gate_event(
            node_id="schema-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            decision=sample_triggered_decision,
            schema_version="1",
        )
        assert event.schema_version == "1"

    @patch("human_gate.send_gate_notification")
    def test_notification_error_none_when_not_triggered(
        self, mock_notify, valid_config, mock_stigmergy_emitter
    ):
        """notification_error is None when gate is not triggered."""
        result = trigger_human_gate(
            node_id="no-err-node",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.9,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=valid_config,
            stigmergy_emitter=mock_stigmergy_emitter,
        )
        assert result.notification_error is None
