# === Human Gate (human_gate) v1 ===
#  Dependencies: stigmergy
# Handles human-in-the-loop gating for trust enforcement. Sends fire-and-forget webhook POST notifications (AS008) to configured human_gate.webhook_url when gate triggers (FINANCIAL/AUTH/COMPLIANCE tier, LOW_TRUST_AUTHORITATIVE, unresolvable conflict). Request body includes node, finding type, trust score, data tier, required action. Webhook failure is non-fatal. block_on_gate config controls whether deploy is blocked pending approval. Actual approval flows back through reset-taint CLI/API — this component only handles the notification side. Also emits gate events to Stigmergy. Implemented as three composable layers: pure gate evaluation, isolated webhook notification, and orchestration.

# Module invariants:
#   - All GateEvent timestamps are UTC (timezone-aware, tzinfo=timezone.utc)
#   - GateEvent and GateDecision and GateResult and WebhookResult are frozen Pydantic models — never mutated after construction
#   - Trust score is raw float, never mapped to display tiers for policy decisions
#   - Stigmergy emission always precedes webhook notification in orchestration — Stigmergy is system of record
#   - Webhook failure is always non-fatal — never raises, never blocks orchestration
#   - All error messages include the specific node_id and, where applicable, webhook_url that caused the error
#   - The trust ledger is never written to or read from by this component — gate decisions are based on supplied trust_score
#   - Trust and authority are distinct: LOW_TRUST_AUTHORITATIVE trigger fires only when trust is low AND authority is declared (never conflated)
#   - schema_version in webhook payload is always '1' for this contract version
#   - HTTP redirects are never followed on webhook POST — a redirect is treated as a webhook failure
#   - event_id is globally unique per gate evaluation (UUID4)
#   - send_gate_notification uses stdlib urllib.request only — no third-party HTTP clients
#   - block_on_gate controls the 'blocked' field in GateResult but does not actually block execution — downstream consumers enforce blocking

class GateTriggerReason(Enum):
    """Reason a human gate was triggered. Maps to data classification tiers and trust/authority conditions."""
    FINANCIAL_TIER = "FINANCIAL_TIER"
    AUTH_TIER = "AUTH_TIER"
    COMPLIANCE_TIER = "COMPLIANCE_TIER"
    LOW_TRUST_AUTHORITATIVE = "LOW_TRUST_AUTHORITATIVE"
    UNRESOLVABLE_CONFLICT = "UNRESOLVABLE_CONFLICT"

class FindingType(Enum):
    """Type of finding that may trigger a gate. Subset of arbiter finding types relevant to gating."""
    TRUST_VIOLATION = "TRUST_VIOLATION"
    ACCESS_CONFLICT = "ACCESS_CONFLICT"
    BLAST_RADIUS_EXCEEDED = "BLAST_RADIUS_EXCEEDED"
    CLASSIFICATION_MISMATCH = "CLASSIFICATION_MISMATCH"
    CANARY_TRIGGERED = "CANARY_TRIGGERED"

class DataTier(Enum):
    """Data classification tier. Used in gate evaluation to determine if human review is required."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    FINANCIAL = "FINANCIAL"
    AUTH = "AUTH"
    COMPLIANCE = "COMPLIANCE"

class RequiredAction(Enum):
    """Action required from the human reviewer before the gate can be cleared."""
    REVIEW_AND_APPROVE = "REVIEW_AND_APPROVE"
    REVIEW_AND_RESET_TAINT = "REVIEW_AND_RESET_TAINT"
    RESOLVE_CONFLICT = "RESOLVE_CONFLICT"
    ESCALATE = "ESCALATE"

class HumanGateConfig:
    """Configuration for the human gate component. Loaded from arbiter config YAML under human_gate key."""
    enabled: bool                            # required, Whether the human gate is active. When false, evaluate_gate still runs but trigger_human_gate short-circuits.
    webhook_url: str                         # required, regex(^(https?://.+)?$), URL to POST gate notifications to. Must be a valid http:// or https:// URL when enabled is true. Empty string permitted only when enabled is false.
    block_on_gate: bool                      # required, Whether deployments should be blocked pending human approval when a gate fires. This component sets the 'blocked' flag; enforcement is downstream.
    timeout_seconds: float                   # required, range(0.1 <= value <= 30.0), HTTP timeout in seconds for webhook POST. Must be positive. Default matches cold-start target of 3 seconds.
    schema_version: str                      # required, Schema version string included in webhook payload for consumer compatibility. Fixed to '1' for this contract version.

class GateDecision:
    """Pure result of gate evaluation. Frozen Pydantic model. Produced by evaluate_gate before any side effects."""
    triggered: bool                          # required, Whether the gate condition was met and human review is required.
    trigger_reason: OptionalGateTriggerReason # required, Reason the gate fired. None if triggered is false.
    required_action: OptionalRequiredAction  # required, Action required from reviewer. None if triggered is false.
    summary: str                             # required, Human-readable summary of the gate decision. Always includes node_id.

OptionalGateTriggerReason = Any | None

OptionalRequiredAction = Any | None

class GateEvent:
    """Frozen Pydantic model representing a gate event. Emitted to Stigmergy and sent via webhook. Serves as the canonical record of a gate firing."""
    event_id: str                            # required, regex(^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$), Globally unique event identifier. UUID4 string.
    timestamp: str                           # required, regex(.*([Zz]|\+00:00)$), ISO 8601 UTC timestamp of gate event creation. Must end with +00:00 or Z.
    node_id: str                             # required, length(1 <= len <= 512), Identifier of the node that triggered the gate.
    finding_type: FindingType                # required, Type of finding that caused the gate to fire.
    trust_score: float                       # required, range(0.0 <= value <= 1.0), Raw trust score of the node at time of gate evaluation.
    data_tier: DataTier                      # required, Data classification tier of the data involved in the finding.
    trigger_reason: GateTriggerReason        # required, Why the gate was triggered.
    required_action: RequiredAction          # required, What the human reviewer must do.
    summary: str                             # required, Human-readable summary of the gate event. Includes node_id and trigger context.
    schema_version: str                      # required, Schema version for webhook consumer compatibility. Matches HumanGateConfig.schema_version.

class WebhookResult:
    """Frozen Pydantic model capturing the outcome of a webhook POST attempt. Never raises — all outcomes are captured in this model."""
    success: bool                            # required, True if webhook POST returned a 2xx status code with no redirect.
    status_code: OptionalInt                 # required, HTTP status code returned, or None if the request failed before receiving a response.
    error_message: OptionalStr               # required, Human-readable error description. None on success. Includes node_id and webhook_url context.
    response_body: OptionalStr               # required, Response body on non-2xx responses for diagnostic logging. None on success or connection failure. Truncated to 1024 characters.
    elapsed_ms: float                        # required, range(0.0 <= value), Time elapsed for the webhook request in milliseconds.

OptionalInt = Any | None

OptionalStr = Any | None

class GateResult:
    """Frozen Pydantic model capturing the full outcome of a human gate orchestration. Returned by trigger_human_gate."""
    event_id: str                            # required, regex(^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$), UUID4 event identifier. Matches the GateEvent.event_id if gate was triggered, or a unique tracking ID if not.
    triggered: bool                          # required, Whether the gate was triggered and notifications were attempted.
    trigger_reason: OptionalGateTriggerReason # required, Reason the gate fired. None if not triggered.
    stigmergy_emitted: bool                  # required, Whether the gate event was successfully emitted to Stigmergy.
    notification_sent: bool                  # required, Whether the webhook notification was successfully delivered (2xx, no redirect).
    notification_error: OptionalStr          # required, Error message from webhook attempt. None on success or if gate was not triggered.
    blocked: bool                            # required, Whether the deployment should be blocked pending human approval. True only when triggered=true AND config.block_on_gate=true.

class StigmeryEmitter:
    """Callable dependency for emitting events to Stigmergy. Injected into trigger_human_gate for testability. In production, wraps stigmergy.emit_event. Accepts a GateEvent and returns bool indicating delivery success."""
    emit: str                                # required, Callable signature: (event: GateEvent) -> bool. Represented as a string type reference for contract purposes. Implementation is a callable.

def evaluate_gate(
    node_id: str,              # length(1 <= len <= 512)
    finding_type: FindingType,
    trust_score: float,        # range(0.0 <= value <= 1.0)
    data_tier: DataTier,
    is_authoritative: bool,
    is_unresolvable_conflict: bool,
) -> GateDecision:
    """
    Pure function: evaluates whether a human gate should be triggered based on node findings, trust score, and data tier. Deterministic given the same inputs. No side effects. Returns a GateDecision with trigger_reason and required_action if triggered, or triggered=false with None fields otherwise. Gate fires for FINANCIAL/AUTH/COMPLIANCE data tiers, LOW_TRUST_AUTHORITATIVE conditions, or unresolvable conflicts.

    Preconditions:
      - trust_score is a raw computed value from the trust ledger, not a display tier mapping
      - is_authoritative reflects declared authority from manifests, not earned trust

    Postconditions:
      - If triggered is true, trigger_reason is not None
      - If triggered is true, required_action is not None
      - If triggered is false, trigger_reason is None and required_action is None
      - summary always contains node_id
      - Result is deterministic: same inputs always produce same output
      - FINANCIAL_TIER triggers when data_tier is FINANCIAL
      - AUTH_TIER triggers when data_tier is AUTH
      - COMPLIANCE_TIER triggers when data_tier is COMPLIANCE
      - LOW_TRUST_AUTHORITATIVE triggers when is_authoritative is true AND trust_score < 0.5
      - UNRESOLVABLE_CONFLICT triggers when is_unresolvable_conflict is true

    Errors:
      - invalid_trust_score (ValueError): trust_score is NaN, infinite, or outside [0.0, 1.0]
          detail: trust_score must be a finite float between 0.0 and 1.0, got {value} for node {node_id}
      - empty_node_id (ValueError): node_id is empty string or only whitespace
          detail: node_id must be non-empty for gate evaluation

    Side effects: none
    Idempotent: yes
    """
    ...

def send_gate_notification(
    event: GateEvent,
    config: HumanGateConfig,
) -> WebhookResult:
    """
    Sends a webhook POST notification for a gate event. Uses stdlib urllib.request with configurable timeout. Never raises exceptions — all outcomes captured in WebhookResult. Includes X-Gate-Event-Id header and Content-Type: application/json. Does not follow HTTP redirects (3xx treated as failure). Logs non-2xx response bodies for diagnostics. Error messages always include node_id and webhook_url context.

    Preconditions:
      - config.webhook_url is a non-empty valid http:// or https:// URL
      - config.timeout_seconds is positive
      - event is a valid frozen GateEvent with all required fields

    Postconditions:
      - Function never raises — all error conditions produce a WebhookResult with success=false
      - On success (2xx, no redirect): success=true, status_code is set, error_message is None, response_body is None
      - On non-2xx response: success=false, status_code is set, response_body contains truncated body (max 1024 chars)
      - On redirect (3xx): success=false, error_message mentions redirect prohibition
      - On connection/timeout error: success=false, status_code is None, error_message describes the failure
      - error_message always includes event.node_id and config.webhook_url when present
      - elapsed_ms is always set and non-negative
      - Request includes X-Gate-Event-Id header with event.event_id
      - Request includes Content-Type: application/json header
      - Request body is JSON-serialized GateEvent including schema_version

    Errors:
      - connection_refused (WebhookResult): Target host refuses connection
          success: false
          detail: Connection refused to {webhook_url} for node {node_id}
      - timeout (WebhookResult): Request exceeds config.timeout_seconds
          success: false
          detail: Webhook POST timed out after {timeout}s to {webhook_url} for node {node_id}
      - dns_resolution_failure (WebhookResult): Webhook URL hostname cannot be resolved
          success: false
          detail: DNS resolution failed for {webhook_url} for node {node_id}
      - ssl_error (WebhookResult): TLS handshake fails for https:// URL
          success: false
          detail: SSL error connecting to {webhook_url} for node {node_id}
      - redirect_received (WebhookResult): Server responds with 3xx redirect
          success: false
          detail: Redirect received from {webhook_url} for node {node_id}, redirects are prohibited
      - non_2xx_response (WebhookResult): Server responds with non-2xx, non-3xx status
          success: false
          detail: Webhook POST to {webhook_url} returned {status_code} for node {node_id}
      - serialization_error (WebhookResult): GateEvent cannot be serialized to JSON (should not occur with valid Pydantic model)
          success: false
          detail: Failed to serialize gate event for node {node_id}

    Side effects: none
    Idempotent: no
    """
    ...

def trigger_human_gate(
    node_id: str,              # length(1 <= len <= 512)
    finding_type: FindingType,
    trust_score: float,        # range(0.0 <= value <= 1.0)
    data_tier: DataTier,
    is_authoritative: bool,
    is_unresolvable_conflict: bool,
    config: HumanGateConfig,
    stigmergy_emitter: str,
) -> GateResult:
    """
    Orchestrates the full human gate flow: evaluates gate condition, emits GateEvent to Stigmergy (system of record, first), then sends webhook notification (best-effort, second). Returns GateResult summarizing the entire operation. If config.enabled is false, short-circuits with triggered=false. If gate evaluates to not-triggered, short-circuits without Stigmergy emission or webhook. Stigmergy emitter is an injectable callable for testability. OpenTelemetry span wraps the full orchestration.

    Preconditions:
      - config is a valid HumanGateConfig (if enabled, webhook_url is non-empty)
      - stigmergy_emitter is a callable accepting GateEvent and returning bool
      - trust_score is a raw computed value, not a display tier

    Postconditions:
      - If config.enabled is false: triggered=false, stigmergy_emitted=false, notification_sent=false, blocked=false
      - If evaluate_gate returns triggered=false: triggered=false, stigmergy_emitted=false, notification_sent=false, blocked=false
      - If triggered: Stigmergy emission is attempted before webhook notification
      - If triggered and Stigmergy emission fails: webhook is still attempted (best-effort both)
      - blocked is true only when triggered=true AND config.block_on_gate=true
      - event_id is always a valid UUID4
      - GateResult.trigger_reason matches GateDecision.trigger_reason when triggered
      - notification_error is None when notification_sent is true or when not triggered

    Errors:
      - invalid_trust_score (ValueError): trust_score is NaN, infinite, or outside [0.0, 1.0]
          detail: trust_score must be a finite float between 0.0 and 1.0, got {value} for node {node_id}
      - empty_node_id (ValueError): node_id is empty string or only whitespace
          detail: node_id must be non-empty for gate evaluation
      - config_enabled_no_webhook_url (ValueError): config.enabled is true but config.webhook_url is empty
          detail: HumanGateConfig.webhook_url must be set when enabled is true for node {node_id}
      - stigmergy_emitter_not_callable (TypeError): stigmergy_emitter is not a callable
          detail: stigmergy_emitter must be callable, got {type}
      - stigmergy_emitter_exception (GateResult): stigmergy_emitter raises an unexpected exception
          detail: Stigmergy emission failed for node {node_id}, continuing with webhook. Error: {error}

    Side effects: none
    Idempotent: no
    """
    ...

def build_gate_event(
    node_id: str,              # length(1 <= len <= 512)
    finding_type: FindingType,
    trust_score: float,        # range(0.0 <= value <= 1.0)
    data_tier: DataTier,
    decision: GateDecision,
    schema_version: str,
) -> GateEvent:
    """
    Constructs a frozen GateEvent Pydantic model from a GateDecision and input context. Generates a UUID4 event_id and UTC timestamp. Pure factory function except for UUID generation and clock read.

    Preconditions:
      - decision.triggered is true
      - decision.trigger_reason is not None
      - decision.required_action is not None

    Postconditions:
      - Returned GateEvent.event_id is a valid UUID4
      - Returned GateEvent.timestamp is UTC ISO 8601
      - Returned GateEvent.node_id matches input node_id
      - Returned GateEvent.trigger_reason matches decision.trigger_reason
      - Returned GateEvent.required_action matches decision.required_action
      - Returned GateEvent.schema_version matches input schema_version
      - Returned GateEvent is a frozen Pydantic model

    Errors:
      - decision_not_triggered (ValueError): decision.triggered is false
          detail: Cannot build GateEvent from non-triggered decision for node {node_id}

    Side effects: none
    Idempotent: no
    """
    ...

def validate_human_gate_config(
    config: HumanGateConfig,
) -> list:
    """
    Validates a HumanGateConfig for internal consistency. Checks that webhook_url is set when enabled, timeout_seconds is within bounds, and schema_version is recognized. Returns list of validation error strings (empty list means valid).

    Postconditions:
      - Returns empty list if config is valid
      - Returns list of human-readable error strings if config is invalid
      - Checks: enabled=true requires non-empty webhook_url
      - Checks: webhook_url must match http:// or https:// pattern when non-empty
      - Checks: timeout_seconds must be in [0.1, 30.0]
      - Checks: schema_version must be '1' for this contract version

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['GateTriggerReason', 'FindingType', 'DataTier', 'RequiredAction', 'HumanGateConfig', 'GateDecision', 'OptionalGateTriggerReason', 'OptionalRequiredAction', 'GateEvent', 'WebhookResult', 'OptionalInt', 'OptionalStr', 'GateResult', 'StigmeryEmitter', 'evaluate_gate', 'send_gate_notification', 'trigger_human_gate', 'build_gate_event', 'validate_human_gate_config']
