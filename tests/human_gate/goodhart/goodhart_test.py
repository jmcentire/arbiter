"""
Adversarial hidden acceptance tests for the Human Gate component.
These tests target gaps in visible test coverage to catch implementations
that hardcode returns or take shortcuts based on visible test inputs.
"""
import math
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call
from urllib.error import URLError, HTTPError
from io import BytesIO

import pytest

from src.human_gate import (
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


# ─── Helper factories ────────────────────────────────────────────────

def _make_config(**overrides):
    defaults = dict(
        enabled=True,
        webhook_url="https://hooks.example.com/gate",
        block_on_gate=False,
        timeout_seconds=5.0,
        schema_version="1",
    )
    defaults.update(overrides)
    return HumanGateConfig(**defaults)


def _make_triggered_decision(**overrides):
    defaults = dict(
        triggered=True,
        trigger_reason=GateTriggerReason.FINANCIAL_TIER,
        required_action=RequiredAction.REVIEW_AND_APPROVE,
        summary="Gate triggered for node-abc",
    )
    defaults.update(overrides)
    return GateDecision(**defaults)


def _make_gate_event(**overrides):
    defaults = dict(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        node_id="node-test-123",
        finding_type=FindingType.TRUST_VIOLATION,
        trust_score=0.3,
        data_tier=DataTier.FINANCIAL,
        trigger_reason=GateTriggerReason.FINANCIAL_TIER,
        required_action=RequiredAction.REVIEW_AND_APPROVE,
        summary="Test gate event",
        schema_version="1",
    )
    defaults.update(overrides)
    return GateEvent(**defaults)


# ─── evaluate_gate tests ─────────────────────────────────────────────

class TestGoodhartEvaluateGate:

    def test_goodhart_financial_with_all_finding_types(self):
        """FINANCIAL data tier should trigger FINANCIAL_TIER regardless of finding_type"""
        for ft in FindingType:
            result = evaluate_gate(
                node_id="node-fin-ft",
                finding_type=ft,
                trust_score=0.8,
                data_tier=DataTier.FINANCIAL,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )
            assert result.triggered is True, f"Should trigger for FINANCIAL with {ft}"
            assert result.trigger_reason == GateTriggerReason.FINANCIAL_TIER, f"Reason should be FINANCIAL_TIER with {ft}"

    def test_goodhart_summary_contains_various_node_ids(self):
        """summary field must contain the node_id for arbitrary node_id strings"""
        node_ids = [
            "node-with-dashes",
            "node/with/slashes",
            "node.with.dots",
            "a" * 200,
            "nöde-ünïcödé",
            "node_123_abc",
            "x",
        ]
        for nid in node_ids:
            result = evaluate_gate(
                node_id=nid,
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.8,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )
            assert nid in result.summary, f"summary should contain node_id '{nid}'"

    def test_goodhart_summary_contains_node_id_when_triggered(self):
        """summary must contain node_id even when gate is triggered"""
        nid = "unique-node-xyz-789"
        result = evaluate_gate(
            node_id=nid,
            finding_type=FindingType.ACCESS_CONFLICT,
            trust_score=0.3,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert nid in result.summary

    def test_goodhart_low_trust_authoritative_near_zero(self):
        """LOW_TRUST_AUTHORITATIVE triggers for very small trust like 0.001 when authoritative"""
        result = evaluate_gate(
            node_id="node-lt-001",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.001,
            data_tier=DataTier.INTERNAL,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.LOW_TRUST_AUTHORITATIVE

    def test_goodhart_unresolvable_conflict_all_non_triggering_tiers(self):
        """UNRESOLVABLE_CONFLICT fires for any data tier, including non-triggering ones"""
        for tier in [DataTier.PUBLIC, DataTier.INTERNAL, DataTier.CONFIDENTIAL]:
            result = evaluate_gate(
                node_id="node-unres",
                finding_type=FindingType.ACCESS_CONFLICT,
                trust_score=0.9,
                data_tier=tier,
                is_authoritative=False,
                is_unresolvable_conflict=True,
            )
            assert result.triggered is True, f"Should trigger UNRESOLVABLE for {tier}"
            assert result.trigger_reason == GateTriggerReason.UNRESOLVABLE_CONFLICT

    def test_goodhart_financial_and_low_trust_auth_overlap(self):
        """When FINANCIAL tier AND low trust authoritative both apply, gate must trigger"""
        result = evaluate_gate(
            node_id="node-overlap",
            finding_type=FindingType.BLAST_RADIUS_EXCEEDED,
            trust_score=0.1,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason is not None
        assert result.required_action is not None

    def test_goodhart_non_authoritative_low_trust_no_trigger(self):
        """Low trust without is_authoritative=true must NOT trigger on non-triggering tier"""
        result = evaluate_gate(
            node_id="node-nonauth",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.1,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is False
        assert result.trigger_reason is None
        assert result.required_action is None

    def test_goodhart_trust_slightly_above_zero(self):
        """trust_score=0.0001 is valid and triggers LOW_TRUST_AUTHORITATIVE when authoritative"""
        result = evaluate_gate(
            node_id="node-tiny-trust",
            finding_type=FindingType.CANARY_TRIGGERED,
            trust_score=0.0001,
            data_tier=DataTier.INTERNAL,
            is_authoritative=True,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.LOW_TRUST_AUTHORITATIVE

    def test_goodhart_error_trust_slightly_over_one(self):
        """trust_score just barely above 1.0 must be rejected"""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="node-err",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=1.0000001,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_goodhart_error_trust_slightly_below_zero(self):
        """trust_score just barely below 0.0 must be rejected"""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="node-err2",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=-0.0000001,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_goodhart_error_negative_infinity(self):
        """Negative infinity trust_score must be rejected"""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="node-neginf",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=float("-inf"),
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_goodhart_error_tab_only_node_id(self):
        """Tab-only node_id is whitespace-only and must be rejected"""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="\t\t",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_goodhart_error_newline_only_node_id(self):
        """Newline-only node_id is whitespace-only and must be rejected"""
        with pytest.raises(Exception):
            evaluate_gate(
                node_id="\n\n",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )

    def test_goodhart_auth_tier_triggers_across_trust_levels(self):
        """AUTH tier triggers AUTH_TIER regardless of trust_score"""
        for ts in [0.0, 0.25, 0.5, 0.75, 1.0]:
            result = evaluate_gate(
                node_id="node-auth-ts",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=ts,
                data_tier=DataTier.AUTH,
                is_authoritative=False,
                is_unresolvable_conflict=False,
            )
            assert result.triggered is True, f"AUTH should trigger at trust={ts}"
            assert result.trigger_reason == GateTriggerReason.AUTH_TIER

    def test_goodhart_compliance_non_authoritative(self):
        """COMPLIANCE tier triggers COMPLIANCE_TIER even when is_authoritative=false"""
        result = evaluate_gate(
            node_id="node-comp-noauth",
            finding_type=FindingType.CLASSIFICATION_MISMATCH,
            trust_score=0.9,
            data_tier=DataTier.COMPLIANCE,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True
        assert result.trigger_reason == GateTriggerReason.COMPLIANCE_TIER

    def test_goodhart_required_action_for_unresolvable(self):
        """UNRESOLVABLE_CONFLICT should map to RESOLVE_CONFLICT required action"""
        result = evaluate_gate(
            node_id="node-unres-action",
            finding_type=FindingType.ACCESS_CONFLICT,
            trust_score=0.8,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=True,
        )
        assert result.triggered is True
        assert result.required_action == RequiredAction.RESOLVE_CONFLICT

    def test_goodhart_canary_finding_type_accepted(self):
        """CANARY_TRIGGERED finding type should be accepted"""
        result = evaluate_gate(
            node_id="node-canary",
            finding_type=FindingType.CANARY_TRIGGERED,
            trust_score=0.8,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is True

    def test_goodhart_classification_mismatch_no_trigger_on_public(self):
        """CLASSIFICATION_MISMATCH finding type is valid, gate depends on tier not finding type"""
        result = evaluate_gate(
            node_id="node-classmis",
            finding_type=FindingType.CLASSIFICATION_MISMATCH,
            trust_score=0.8,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
        )
        assert result.triggered is False

    def test_goodhart_unresolvable_with_financial_tier(self):
        """Both FINANCIAL tier and unresolvable_conflict true: must trigger"""
        result = evaluate_gate(
            node_id="node-both",
            finding_type=FindingType.ACCESS_CONFLICT,
            trust_score=0.8,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=True,
        )
        assert result.triggered is True
        assert result.trigger_reason is not None


# ─── build_gate_event tests ──────────────────────────────────────────

class TestGoodhartBuildGateEvent:

    def test_goodhart_different_finding_types(self):
        """build_gate_event propagates any FindingType, not just the one in visible tests"""
        for ft in FindingType:
            decision = _make_triggered_decision()
            event = build_gate_event(
                node_id="node-ft-test",
                finding_type=ft,
                trust_score=0.5,
                data_tier=DataTier.FINANCIAL,
                decision=decision,
                schema_version="1",
            )
            assert event.finding_type == ft

    def test_goodhart_different_data_tiers(self):
        """build_gate_event propagates AUTH and COMPLIANCE data tiers correctly"""
        for tier, reason in [
            (DataTier.AUTH, GateTriggerReason.AUTH_TIER),
            (DataTier.COMPLIANCE, GateTriggerReason.COMPLIANCE_TIER),
        ]:
            decision = _make_triggered_decision(trigger_reason=reason)
            event = build_gate_event(
                node_id="node-tier-test",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=tier,
                decision=decision,
                schema_version="1",
            )
            assert event.data_tier == tier
            assert event.trigger_reason == reason

    def test_goodhart_preserves_trust_score_exactly(self):
        """build_gate_event preserves exact trust_score float value"""
        ts = 0.123456789
        decision = _make_triggered_decision()
        event = build_gate_event(
            node_id="node-trust-exact",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=ts,
            data_tier=DataTier.FINANCIAL,
            decision=decision,
            schema_version="1",
        )
        assert event.trust_score == ts

    def test_goodhart_preserves_summary_from_decision(self):
        """build_gate_event propagates summary from decision"""
        summary = "Custom summary for node-xyz-999"
        decision = _make_triggered_decision(summary=summary)
        event = build_gate_event(
            node_id="node-xyz-999",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.5,
            data_tier=DataTier.FINANCIAL,
            decision=decision,
            schema_version="1",
        )
        assert event.summary == summary

    def test_goodhart_unique_event_ids_across_calls(self):
        """Multiple calls produce distinct UUID4 event_ids"""
        decision = _make_triggered_decision()
        event_ids = set()
        for _ in range(10):
            event = build_gate_event(
                node_id="node-uniq",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.FINANCIAL,
                decision=decision,
                schema_version="1",
            )
            event_ids.add(event.event_id)
        assert len(event_ids) == 10

    def test_goodhart_timestamp_is_timezone_aware_utc(self):
        """Timestamp must be timezone-aware with UTC"""
        decision = _make_triggered_decision()
        event = build_gate_event(
            node_id="node-tz",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.5,
            data_tier=DataTier.FINANCIAL,
            decision=decision,
            schema_version="1",
        )
        ts = datetime.fromisoformat(event.timestamp)
        assert ts.tzinfo is not None, "Timestamp must be timezone-aware"
        assert ts.utcoffset().total_seconds() == 0, "Timestamp must be UTC"

    def test_goodhart_schema_version_propagated(self):
        """schema_version is propagated exactly to GateEvent"""
        decision = _make_triggered_decision()
        event = build_gate_event(
            node_id="node-sv",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.5,
            data_tier=DataTier.FINANCIAL,
            decision=decision,
            schema_version="1",
        )
        assert event.schema_version == "1"

    def test_goodhart_node_id_propagated(self):
        """node_id is propagated exactly to GateEvent"""
        nid = "very-specific-node-id-12345"
        decision = _make_triggered_decision()
        event = build_gate_event(
            node_id=nid,
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.5,
            data_tier=DataTier.FINANCIAL,
            decision=decision,
            schema_version="1",
        )
        assert event.node_id == nid

    def test_goodhart_required_action_propagated(self):
        """required_action from decision is propagated to GateEvent"""
        for action in RequiredAction:
            decision = _make_triggered_decision(required_action=action)
            event = build_gate_event(
                node_id="node-act",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.FINANCIAL,
                decision=decision,
                schema_version="1",
            )
            assert event.required_action == action


# ─── validate_human_gate_config tests ────────────────────────────────

class TestGoodhartValidateConfig:

    def test_goodhart_disabled_with_empty_url_valid(self):
        """When enabled=false, empty webhook_url should not trigger the 'enabled requires url' error"""
        config = _make_config(enabled=False, webhook_url="")
        errors = validate_human_gate_config(config)
        # Should not have an error about enabled requiring webhook_url
        # May have other errors (e.g., about URL scheme) but the enabled+url check shouldn't fire
        enabled_url_errors = [e for e in errors if "enabled" in e.lower() and "url" in e.lower()]
        assert len(enabled_url_errors) == 0

    def test_goodhart_ftp_url_rejected(self):
        """ftp:// URL scheme must be rejected"""
        config = _make_config(webhook_url="ftp://example.com/hook")
        errors = validate_human_gate_config(config)
        assert len(errors) > 0

    def test_goodhart_timeout_zero_rejected(self):
        """timeout_seconds=0.0 is below minimum"""
        config = _make_config(timeout_seconds=0.0)
        errors = validate_human_gate_config(config)
        assert len(errors) > 0

    def test_goodhart_timeout_negative_rejected(self):
        """Negative timeout is invalid"""
        config = _make_config(timeout_seconds=-1.0)
        errors = validate_human_gate_config(config)
        assert len(errors) > 0

    def test_goodhart_schema_version_2_rejected(self):
        """schema_version='2' is not recognized"""
        config = _make_config(schema_version="2")
        errors = validate_human_gate_config(config)
        assert len(errors) > 0

    def test_goodhart_schema_version_empty_rejected(self):
        """Empty schema_version is invalid"""
        config = _make_config(schema_version="")
        errors = validate_human_gate_config(config)
        assert len(errors) > 0

    def test_goodhart_url_no_scheme_rejected(self):
        """URL without scheme must be rejected"""
        config = _make_config(webhook_url="example.com/hook")
        errors = validate_human_gate_config(config)
        assert len(errors) > 0

    def test_goodhart_returns_list_type_always(self):
        """Return type is always list"""
        valid_config = _make_config()
        result = validate_human_gate_config(valid_config)
        assert isinstance(result, list)
        assert len(result) == 0

        invalid_config = _make_config(timeout_seconds=-1.0, schema_version="9")
        result = validate_human_gate_config(invalid_config)
        assert isinstance(result, list)
        assert len(result) > 0

    def test_goodhart_timeout_just_below_minimum(self):
        """timeout_seconds=0.09 is just below 0.1 minimum"""
        config = _make_config(timeout_seconds=0.09)
        errors = validate_human_gate_config(config)
        assert len(errors) > 0

    def test_goodhart_timeout_just_above_maximum(self):
        """timeout_seconds=30.01 is just above 30.0 maximum"""
        config = _make_config(timeout_seconds=30.01)
        errors = validate_human_gate_config(config)
        assert len(errors) > 0

    def test_goodhart_ws_url_rejected(self):
        """ws:// and wss:// URL schemes must be rejected"""
        config = _make_config(webhook_url="ws://example.com/hook")
        errors = validate_human_gate_config(config)
        assert len(errors) > 0

    def test_goodhart_valid_http_url_accepted(self):
        """http:// URL should be accepted (not just https://)"""
        config = _make_config(webhook_url="http://internal.example.com/hook")
        errors = validate_human_gate_config(config)
        assert len(errors) == 0


# ─── send_gate_notification tests ────────────────────────────────────

class TestGoodhartSendNotification:

    def test_goodhart_response_body_truncated_to_1024(self):
        """Non-2xx response body must be truncated to max 1024 chars"""
        event = _make_gate_event()
        config = _make_config()
        large_body = "X" * 2000

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 500
            mock_resp.getcode.return_value = 500
            mock_resp.read.return_value = large_body.encode("utf-8")
            mock_resp.headers = {}
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)

            error = HTTPError(
                url=config.webhook_url,
                code=500,
                msg="Internal Server Error",
                hdrs={},
                fp=BytesIO(large_body.encode("utf-8")),
            )
            mock_urlopen.side_effect = error

            result = send_gate_notification(event, config)
            assert result.success is False
            if result.response_body is not None:
                assert len(result.response_body) <= 1024

    def test_goodhart_success_response_body_is_none(self):
        """On 2xx success, response_body must be None"""
        event = _make_gate_event()
        config = _make_config()

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.getcode.return_value = 200
            mock_resp.read.return_value = b'{"ok": true}'
            mock_resp.headers = {}
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = send_gate_notification(event, config)
            assert result.success is True
            assert result.response_body is None

    def test_goodhart_success_error_message_is_none(self):
        """On 2xx success, error_message must be None"""
        event = _make_gate_event()
        config = _make_config()

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.getcode.return_value = 200
            mock_resp.read.return_value = b""
            mock_resp.headers = {}
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = send_gate_notification(event, config)
            assert result.success is True
            assert result.error_message is None

    def test_goodhart_error_message_contains_node_id(self):
        """Error messages must contain the event's node_id"""
        unique_nid = "distinctive-node-id-for-error-check-42"
        event = _make_gate_event(node_id=unique_nid)
        config = _make_config()

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = URLError("Connection refused")
            result = send_gate_notification(event, config)
            assert result.success is False
            assert unique_nid in result.error_message

    def test_goodhart_error_message_contains_webhook_url(self):
        """Error messages must contain the webhook_url"""
        unique_url = "https://unique-webhook-host-999.example.com/gate-hook"
        event = _make_gate_event()
        config = _make_config(webhook_url=unique_url)

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = URLError("Connection refused")
            result = send_gate_notification(event, config)
            assert result.success is False
            assert unique_url in result.error_message

    def test_goodhart_request_body_contains_schema_version(self):
        """JSON request body must include schema_version"""
        event = _make_gate_event(schema_version="1")
        config = _make_config()
        captured_request = {}

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            def capture_request(req, **kwargs):
                captured_request["data"] = req.data
                mock_resp = MagicMock()
                mock_resp.status = 200
                mock_resp.getcode.return_value = 200
                mock_resp.read.return_value = b""
                mock_resp.headers = {}
                mock_resp.__enter__ = MagicMock(return_value=mock_resp)
                mock_resp.__exit__ = MagicMock(return_value=False)
                return mock_resp

            mock_urlopen.side_effect = capture_request
            result = send_gate_notification(event, config)

            if "data" in captured_request and captured_request["data"]:
                body = json.loads(captured_request["data"])
                assert "schema_version" in body
                assert body["schema_version"] == "1"

    def test_goodhart_201_is_success(self):
        """HTTP 201 should be treated as success"""
        event = _make_gate_event()
        config = _make_config()

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 201
            mock_resp.getcode.return_value = 201
            mock_resp.read.return_value = b""
            mock_resp.headers = {}
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = send_gate_notification(event, config)
            assert result.success is True
            assert result.status_code == 201

    def test_goodhart_204_is_success(self):
        """HTTP 204 should be treated as success"""
        event = _make_gate_event()
        config = _make_config()

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 204
            mock_resp.getcode.return_value = 204
            mock_resp.read.return_value = b""
            mock_resp.headers = {}
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = send_gate_notification(event, config)
            assert result.success is True
            assert result.status_code == 204

    def test_goodhart_301_is_redirect_failure(self):
        """HTTP 301 redirect must be treated as failure"""
        event = _make_gate_event()
        config = _make_config()

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            error = HTTPError(
                url=config.webhook_url,
                code=301,
                msg="Moved Permanently",
                hdrs={},
                fp=BytesIO(b""),
            )
            mock_urlopen.side_effect = error

            result = send_gate_notification(event, config)
            assert result.success is False
            assert result.error_message is not None
            assert "redirect" in result.error_message.lower()

    def test_goodhart_302_is_redirect_failure(self):
        """HTTP 302 redirect must be treated as failure"""
        event = _make_gate_event()
        config = _make_config()

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            error = HTTPError(
                url=config.webhook_url,
                code=302,
                msg="Found",
                hdrs={},
                fp=BytesIO(b""),
            )
            mock_urlopen.side_effect = error

            result = send_gate_notification(event, config)
            assert result.success is False
            assert result.error_message is not None
            assert "redirect" in result.error_message.lower()

    def test_goodhart_non_2xx_has_status_code_set(self):
        """On non-2xx response, status_code must not be None"""
        event = _make_gate_event()
        config = _make_config()

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            error = HTTPError(
                url=config.webhook_url,
                code=500,
                msg="Internal Server Error",
                hdrs={},
                fp=BytesIO(b"server error"),
            )
            mock_urlopen.side_effect = error

            result = send_gate_notification(event, config)
            assert result.success is False
            assert result.status_code is not None
            assert result.status_code == 500

    def test_goodhart_frozen_webhook_result(self):
        """WebhookResult must be frozen"""
        event = _make_gate_event()
        config = _make_config()

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.getcode.return_value = 200
            mock_resp.read.return_value = b""
            mock_resp.headers = {}
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = send_gate_notification(event, config)
            with pytest.raises(Exception):
                result.success = False

    def test_goodhart_connection_error_status_code_is_none(self):
        """On connection error, status_code must be None"""
        event = _make_gate_event()
        config = _make_config()

        with patch("src.human_gate.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = URLError("Connection refused")
            result = send_gate_notification(event, config)
            assert result.success is False
            assert result.status_code is None


# ─── trigger_human_gate tests ────────────────────────────────────────

class TestGoodhartTriggerHumanGate:

    def test_goodhart_disabled_does_not_call_emitter(self):
        """When disabled, stigmergy emitter must never be invoked"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config(enabled=False)
        result = trigger_human_gate(
            node_id="node-disabled",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.5,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=config,
            stigmergy_emitter=mock_emitter,
        )
        assert result.triggered is False
        mock_emitter.assert_not_called()

    def test_goodhart_not_triggered_does_not_call_emitter(self):
        """When gate doesn't trigger, emitter must not be called"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config()
        result = trigger_human_gate(
            node_id="node-no-trigger",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.9,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=config,
            stigmergy_emitter=mock_emitter,
        )
        assert result.triggered is False
        assert result.stigmergy_emitted is False
        assert result.notification_sent is False
        mock_emitter.assert_not_called()

    def test_goodhart_event_id_is_valid_uuid4_when_triggered(self):
        """event_id must be valid UUID4 when triggered"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config()

        with patch("src.human_gate.send_gate_notification") as mock_notify:
            mock_notify.return_value = WebhookResult(
                success=True, status_code=200, error_message=None,
                response_body=None, elapsed_ms=10.0
            )
            result = trigger_human_gate(
                node_id="node-uuid-check",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.FINANCIAL,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=config,
                stigmergy_emitter=mock_emitter,
            )
            assert result.triggered is True
            parsed = uuid.UUID(result.event_id, version=4)
            assert str(parsed) == result.event_id

    def test_goodhart_emitter_receives_gate_event_with_correct_fields(self):
        """Stigmergy emitter must receive GateEvent with fields matching inputs"""
        captured = {}

        def capture_emitter(event):
            captured["event"] = event
            return True

        config = _make_config()

        with patch("src.human_gate.send_gate_notification") as mock_notify:
            mock_notify.return_value = WebhookResult(
                success=True, status_code=200, error_message=None,
                response_body=None, elapsed_ms=10.0
            )
            trigger_human_gate(
                node_id="node-emitter-check",
                finding_type=FindingType.BLAST_RADIUS_EXCEEDED,
                trust_score=0.3,
                data_tier=DataTier.FINANCIAL,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=config,
                stigmergy_emitter=capture_emitter,
            )

        assert "event" in captured
        event = captured["event"]
        assert isinstance(event, GateEvent)
        assert event.node_id == "node-emitter-check"
        assert event.finding_type == FindingType.BLAST_RADIUS_EXCEEDED
        assert event.data_tier == DataTier.FINANCIAL
        assert event.trigger_reason == GateTriggerReason.FINANCIAL_TIER

    def test_goodhart_notification_error_none_when_sent(self):
        """notification_error must be None when notification_sent is true"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config()

        with patch("src.human_gate.send_gate_notification") as mock_notify:
            mock_notify.return_value = WebhookResult(
                success=True, status_code=200, error_message=None,
                response_body=None, elapsed_ms=5.0
            )
            result = trigger_human_gate(
                node_id="node-notif-ok",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.FINANCIAL,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=config,
                stigmergy_emitter=mock_emitter,
            )
            assert result.notification_sent is True
            assert result.notification_error is None

    def test_goodhart_notification_error_none_when_not_triggered(self):
        """notification_error must be None when gate not triggered"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config()
        result = trigger_human_gate(
            node_id="node-no-notif",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.9,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=config,
            stigmergy_emitter=mock_emitter,
        )
        assert result.triggered is False
        assert result.notification_error is None

    def test_goodhart_blocked_false_when_not_triggered_despite_block_on_gate(self):
        """blocked is false when not triggered, even if block_on_gate=true"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config(block_on_gate=True)
        result = trigger_human_gate(
            node_id="node-block-no-trig",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.9,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=config,
            stigmergy_emitter=mock_emitter,
        )
        assert result.triggered is False
        assert result.blocked is False

    def test_goodhart_blocked_false_when_disabled_despite_block_on_gate(self):
        """blocked is false when disabled, even if block_on_gate=true"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config(enabled=False, block_on_gate=True)
        result = trigger_human_gate(
            node_id="node-block-disabled",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.5,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=config,
            stigmergy_emitter=mock_emitter,
        )
        assert result.triggered is False
        assert result.blocked is False

    def test_goodhart_auth_tier_orchestration(self):
        """Full orchestration works for AUTH tier"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config()

        with patch("src.human_gate.send_gate_notification") as mock_notify:
            mock_notify.return_value = WebhookResult(
                success=True, status_code=200, error_message=None,
                response_body=None, elapsed_ms=5.0
            )
            result = trigger_human_gate(
                node_id="node-auth-orch",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.8,
                data_tier=DataTier.AUTH,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=config,
                stigmergy_emitter=mock_emitter,
            )
            assert result.triggered is True
            assert result.trigger_reason == GateTriggerReason.AUTH_TIER
            assert result.stigmergy_emitted is True

    def test_goodhart_compliance_tier_orchestration(self):
        """Full orchestration works for COMPLIANCE tier"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config()

        with patch("src.human_gate.send_gate_notification") as mock_notify:
            mock_notify.return_value = WebhookResult(
                success=True, status_code=200, error_message=None,
                response_body=None, elapsed_ms=5.0
            )
            result = trigger_human_gate(
                node_id="node-comp-orch",
                finding_type=FindingType.CLASSIFICATION_MISMATCH,
                trust_score=0.7,
                data_tier=DataTier.COMPLIANCE,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=config,
                stigmergy_emitter=mock_emitter,
            )
            assert result.triggered is True
            assert result.trigger_reason == GateTriggerReason.COMPLIANCE_TIER

    def test_goodhart_unresolvable_conflict_orchestration(self):
        """Full orchestration works for UNRESOLVABLE_CONFLICT"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config()

        with patch("src.human_gate.send_gate_notification") as mock_notify:
            mock_notify.return_value = WebhookResult(
                success=True, status_code=200, error_message=None,
                response_body=None, elapsed_ms=5.0
            )
            result = trigger_human_gate(
                node_id="node-unres-orch",
                finding_type=FindingType.ACCESS_CONFLICT,
                trust_score=0.9,
                data_tier=DataTier.PUBLIC,
                is_authoritative=False,
                is_unresolvable_conflict=True,
                config=config,
                stigmergy_emitter=mock_emitter,
            )
            assert result.triggered is True
            assert result.trigger_reason == GateTriggerReason.UNRESOLVABLE_CONFLICT

    def test_goodhart_low_trust_authoritative_orchestration(self):
        """Full orchestration works for LOW_TRUST_AUTHORITATIVE"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config()

        with patch("src.human_gate.send_gate_notification") as mock_notify:
            mock_notify.return_value = WebhookResult(
                success=True, status_code=200, error_message=None,
                response_body=None, elapsed_ms=5.0
            )
            result = trigger_human_gate(
                node_id="node-lta-orch",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.2,
                data_tier=DataTier.INTERNAL,
                is_authoritative=True,
                is_unresolvable_conflict=False,
                config=config,
                stigmergy_emitter=mock_emitter,
            )
            assert result.triggered is True
            assert result.trigger_reason == GateTriggerReason.LOW_TRUST_AUTHORITATIVE

    def test_goodhart_stigmergy_false_reports_emitted_false(self):
        """When emitter returns False, stigmergy_emitted must be False"""
        mock_emitter = MagicMock(return_value=False)
        config = _make_config()

        with patch("src.human_gate.send_gate_notification") as mock_notify:
            mock_notify.return_value = WebhookResult(
                success=True, status_code=200, error_message=None,
                response_body=None, elapsed_ms=5.0
            )
            result = trigger_human_gate(
                node_id="node-stig-false",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.FINANCIAL,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=config,
                stigmergy_emitter=mock_emitter,
            )
            assert result.triggered is True
            assert result.stigmergy_emitted is False

    def test_goodhart_frozen_gate_result(self):
        """GateResult must be frozen"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config()

        with patch("src.human_gate.send_gate_notification") as mock_notify:
            mock_notify.return_value = WebhookResult(
                success=True, status_code=200, error_message=None,
                response_body=None, elapsed_ms=5.0
            )
            result = trigger_human_gate(
                node_id="node-frozen",
                finding_type=FindingType.TRUST_VIOLATION,
                trust_score=0.5,
                data_tier=DataTier.FINANCIAL,
                is_authoritative=False,
                is_unresolvable_conflict=False,
                config=config,
                stigmergy_emitter=mock_emitter,
            )
            with pytest.raises(Exception):
                result.triggered = False

    def test_goodhart_disabled_with_financial_tier(self):
        """When disabled, even FINANCIAL tier must not trigger"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config(enabled=False)
        result = trigger_human_gate(
            node_id="node-dis-fin",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.5,
            data_tier=DataTier.FINANCIAL,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=config,
            stigmergy_emitter=mock_emitter,
        )
        assert result.triggered is False
        assert result.stigmergy_emitted is False
        assert result.notification_sent is False
        assert result.blocked is False

    def test_goodhart_trigger_reason_none_when_not_triggered(self):
        """trigger_reason must be None when not triggered"""
        mock_emitter = MagicMock(return_value=True)
        config = _make_config()
        result = trigger_human_gate(
            node_id="node-reason-none",
            finding_type=FindingType.TRUST_VIOLATION,
            trust_score=0.9,
            data_tier=DataTier.PUBLIC,
            is_authoritative=False,
            is_unresolvable_conflict=False,
            config=config,
            stigmergy_emitter=mock_emitter,
        )
        assert result.triggered is False
        assert result.trigger_reason is None
