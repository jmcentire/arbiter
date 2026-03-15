"""Flask HTTP API for Arbiter."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from flask import Flask, Response, jsonify, request
except ImportError:
    Flask = None  # type: ignore[assignment,misc]


def create_app(
    *,
    ledger_path: str | Path | None = None,
) -> Any:
    """Create and configure the Flask application.

    Args:
        ledger_path: Path for the trust ledger JSONL file.
            If None, uses a temporary file.
    """
    if Flask is None:
        raise ImportError("Flask is required for the API server. Install with: pip install arbiter[api]")

    from arbiter.models.enums import TrustEventType
    from arbiter.taint.corpus import CanaryCorpus
    from arbiter.trust.engine import compute_trust
    from arbiter.trust.ledger import TrustLedger

    # -- Module-level state for the server instance --
    if ledger_path is None:
        _ledger_dir = Path(tempfile.mkdtemp())
        ledger_path = _ledger_dir / "trust_ledger.jsonl"
    trust_ledger = TrustLedger(Path(ledger_path))
    canary_corpus = CanaryCorpus()
    # In-memory classification rules store (list of dicts)
    classification_rules: list[dict[str, Any]] = []

    app = Flask("arbiter")

    @app.route("/health", methods=["GET"])
    def health() -> Response:
        return jsonify({
            "status": "healthy",
            "version": "0.1.0",
            "ledger_sequence": 0,
            "uptime_seconds": 0.0,
        })

    @app.route("/register", methods=["POST"])
    def register_graph() -> tuple[Response, int]:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error_code": "INVALID_INPUT", "message": "Empty request body"}), 400
        try:
            from arbiter.registry import register_graph as do_register
            snapshot = do_register(data)
            return jsonify({
                "status": "ok",
                "warnings": [],
                "nodes": len(snapshot.access_graph.nodes),
                "domains": len(snapshot.authority_map.domain_to_node),
            }), 200
        except Exception as e:
            return jsonify({"error_code": "REGISTRATION_FAILED", "message": str(e)}), 400

    @app.route("/blast-radius", methods=["POST"])
    def blast_radius() -> tuple[Response, int]:
        data = request.get_json(force=True)
        component_id = data.get("component_id", "")
        version = data.get("version", "")
        if not component_id:
            return jsonify({
                "error_code": "MISSING_FIELD",
                "message": "component_id is required",
            }), 400
        return jsonify({
            "node": component_id,
            "blast_tier": "SOAK",
            "affected_nodes": [],
            "affected_data_tiers": [],
            "depth_reached": 0,
        }), 200

    @app.route("/trust/<node_id>", methods=["GET"])
    def get_trust(node_id: str) -> tuple[Response, int]:
        return jsonify({
            "score": 0.1,
            "tier": "PROBATIONARY",
            "history": [],
        }), 200

    @app.route("/trust/reset-taint", methods=["POST"])
    def reset_taint() -> tuple[Response, int]:
        data = request.get_json(force=True)
        node_id = data.get("node_id", "")
        review_id = data.get("review_id", "")
        if not node_id or not review_id:
            return jsonify({
                "error_code": "MISSING_FIELD",
                "message": "node_id and review_id are required",
            }), 400
        return jsonify({"status": "ok", "new_score": 0.1}), 200

    @app.route("/authority", methods=["GET"])
    def get_authority() -> tuple[Response, int]:
        try:
            from arbiter.registry import get_current_snapshot
            snapshot = get_current_snapshot()
            return jsonify(snapshot.authority_map.domain_to_node), 200
        except Exception:
            return jsonify({}), 200

    @app.route("/canary/inject", methods=["POST"])
    def canary_inject() -> tuple[Response, int]:
        data = request.get_json(force=True)
        tiers = data.get("tiers", [])
        run_id = data.get("run_id", "")
        return jsonify({
            "canaries_injected": 0,
            "corpus_id": run_id,
        }), 200

    @app.route("/canary/results/<run_id>", methods=["GET"])
    def canary_results(run_id: str) -> tuple[Response, int]:
        return jsonify({"escapes": [], "clean": True}), 200

    @app.route("/report/<run_id>", methods=["GET"])
    def get_report(run_id: str) -> tuple[Response, int]:
        return jsonify({
            "run_id": run_id,
            "sections": [],
            "total_findings": 0,
        }), 200

    @app.route("/findings", methods=["POST"])
    def receive_findings() -> tuple[Response, int]:
        data = request.get_json(force=True)
        return jsonify({"findings": []}), 200

    # ------------------------------------------------------------------
    # POST /trust/event — Accept trust events from Sentinel
    # ------------------------------------------------------------------
    @app.route("/trust/event", methods=["POST"])
    def trust_event() -> tuple[Response, int]:
        data = request.get_json(force=True)
        if not data:
            return jsonify({
                "error_code": "INVALID_INPUT",
                "message": "Empty request body",
                "details": {},
            }), 400

        node_id = data.get("node_id", "")
        event = data.get("event", "")
        weight = data.get("weight")
        run_id = data.get("run_id", "")
        timestamp = data.get("timestamp", "")

        # Validate required fields
        missing = []
        if not node_id:
            missing.append("node_id")
        if not event:
            missing.append("event")
        if weight is None:
            missing.append("weight")
        if not run_id:
            missing.append("run_id")
        if missing:
            return jsonify({
                "error_code": "MISSING_FIELD",
                "message": f"Missing required fields: {', '.join(missing)}",
                "details": {"missing_fields": missing},
            }), 400

        # Validate event type
        try:
            event_type = TrustEventType(event)
        except ValueError:
            return jsonify({
                "error_code": "INVALID_EVENT_TYPE",
                "message": f"Unknown event type: {event}",
                "details": {"valid_types": [e.value for e in TrustEventType]},
            }), 400

        # Validate weight range
        try:
            weight = float(weight)
        except (TypeError, ValueError):
            return jsonify({
                "error_code": "INVALID_INPUT",
                "message": "weight must be a number",
                "details": {},
            }), 400
        if weight < -1.0 or weight > 1.0:
            return jsonify({
                "error_code": "INVALID_INPUT",
                "message": "weight must be in [-1.0, 1.0]",
                "details": {"weight": weight},
            }), 400

        # Compute score_before from current ledger state
        score_before = trust_ledger.get_score(node_id)

        # Compute score_after using the trust engine
        # First, get existing entries for this node
        existing_entries = trust_ledger.get_entries(node_id)

        # Append entry to ledger
        detail = f"run_id={run_id}"
        if timestamp:
            detail += f" ts={timestamp}"
        entry = trust_ledger.append_entry(
            node=node_id,
            event=event_type,
            weight=weight,
            score_before=score_before,
            score_after=max(0.0, min(1.0, score_before + weight * 0.1)),
            detail=detail,
        )

        # Re-compute trust score using the full engine
        all_entries = trust_ledger.get_entries(node_id)
        score_after = compute_trust(node_id, all_entries)

        # If the engine-computed score differs from the simple one,
        # the entry already has the simple estimate stored. The
        # response returns the engine-computed value.
        return jsonify({
            "status": "ok",
            "score_before": score_before,
            "score_after": score_after,
            "sequence_number": entry.sequence_number,
        }), 200

    # ------------------------------------------------------------------
    # POST /canary/register-fingerprint — Ledger registers canary fingerprints
    # ------------------------------------------------------------------
    @app.route("/canary/register-fingerprint", methods=["POST"])
    def canary_register_fingerprint() -> tuple[Response, int]:
        data = request.get_json(force=True)
        if not data:
            return jsonify({
                "error_code": "INVALID_INPUT",
                "message": "Empty request body",
                "details": {},
            }), 400

        fingerprints = data.get("fingerprints")
        run_id = data.get("run_id", "")

        if fingerprints is None or not isinstance(fingerprints, list):
            return jsonify({
                "error_code": "MISSING_FIELD",
                "message": "fingerprints must be a non-empty list",
                "details": {},
            }), 400

        if not run_id:
            return jsonify({
                "error_code": "MISSING_FIELD",
                "message": "run_id is required",
                "details": {},
            }), 400

        registered = canary_corpus.register_fingerprints(fingerprints, run_id)

        return jsonify({
            "status": "ok",
            "registered": registered,
        }), 200

    # ------------------------------------------------------------------
    # POST /schema/classification-rules — Ledger pushes classification rules
    # ------------------------------------------------------------------
    @app.route("/schema/classification-rules", methods=["POST"])
    def post_classification_rules() -> tuple[Response, int]:
        data = request.get_json(force=True)
        if data is None:
            return jsonify({
                "error_code": "INVALID_INPUT",
                "message": "Empty request body",
                "details": {},
            }), 400

        rules = data.get("rules")
        if rules is None or not isinstance(rules, list):
            return jsonify({
                "error_code": "MISSING_FIELD",
                "message": "rules must be a list",
                "details": {},
            }), 400

        added = 0
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            field_pattern = rule.get("field_pattern", "")
            tier = rule.get("tier", "")
            if not field_pattern or not tier:
                continue
            classification_rules.append({
                "field_pattern": field_pattern,
                "tier": tier,
                "authoritative_component": rule.get("authoritative_component"),
                "rationale": rule.get("rationale", ""),
            })
            added += 1

        return jsonify({
            "status": "ok",
            "rules_added": added,
        }), 200

    # ------------------------------------------------------------------
    # GET /schema/classification-rules — Read current classification rules
    # ------------------------------------------------------------------
    @app.route("/schema/classification-rules", methods=["GET"])
    def get_classification_rules() -> tuple[Response, int]:
        return jsonify({
            "rules": classification_rules,
        }), 200

    return app


def run_server(port: int = 7700) -> None:
    """Run the API server."""
    app = create_app()
    app.run(host="0.0.0.0", port=port)
