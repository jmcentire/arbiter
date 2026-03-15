"""Canary corpus management.

Manages injection of synthetic canary data and retrieval of active canaries.
Canary fingerprints use UUIDs embedded in domain-shaped strings to ensure
they are structurally valid, globally unique, and impossible in real data.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from .models import CanaryEntry

__all__ = [
    "CanaryCorpus",
]

# Default canary patterns by tier. {uuid} is replaced with a unique value.
_DEFAULT_PATTERNS: dict[str, str] = {
    "PII": "arbiter-{uuid}@canary.invalid",
    "FINANCIAL": "4000-0000-0000-{uuid4}",
    "AUTH": "arbiter-auth-canary-{uuid}",
    "COMPLIANCE": "arbiter-compliance-canary-{uuid}",
    "PUBLIC": "arbiter-canary-public-{uuid}",
}


class CanaryCorpus:
    """Manages a corpus of canary entries for taint detection.

    Canaries are synthetic data injected into test runs. If a canary
    fingerprint appears in a node's output and that node is not authorized
    for the canary's data tier, it constitutes a taint escape.
    """

    def __init__(self) -> None:
        self._canaries: list[CanaryEntry] = []

    def inject_canaries(
        self,
        tiers: list[str],
        run_id: str,
        *,
        count_per_tier: int = 1,
        patterns: dict[str, str] | None = None,
    ) -> list[CanaryEntry]:
        """Inject canary entries for the specified data tiers.

        Creates one or more canaries per tier with unique fingerprints.
        Each fingerprint contains an embedded UUID for uniqueness.

        Args:
            tiers: List of data tier names to create canaries for.
            run_id: The injection run identifier.
            count_per_tier: Number of canaries per tier (default 1).
            patterns: Optional custom patterns by tier. Uses defaults if not provided.

        Returns:
            List of newly created CanaryEntry instances.
        """
        effective_patterns = {**_DEFAULT_PATTERNS, **(patterns or {})}
        injected: list[CanaryEntry] = []
        now = datetime.now(timezone.utc).isoformat()

        for tier in tiers:
            pattern = effective_patterns.get(tier, f"arbiter-canary-{tier.lower()}-{{uuid}}")
            for _ in range(count_per_tier):
                canary_uuid = str(uuid.uuid4())
                canary_id = f"canary-{tier.lower()}-{canary_uuid[:8]}"
                fingerprint = pattern.replace("{uuid}", canary_uuid).replace(
                    "{uuid4}", canary_uuid[:4]
                )

                entry = CanaryEntry(
                    id=canary_id,
                    fingerprint=fingerprint,
                    classification=tier,
                    run_id=run_id,
                    injected_at=now,
                    active=True,
                )
                self._canaries.append(entry)
                injected.append(entry)

        return injected

    def register_fingerprints(
        self,
        fingerprints: list[dict[str, str]],
        run_id: str,
    ) -> int:
        """Register externally-provided canary fingerprints.

        Used by Ledger to push pre-generated fingerprints into the corpus
        without going through Arbiter's own injection pipeline.

        Args:
            fingerprints: List of dicts with keys: fingerprint, category, tier.
            run_id: The run identifier for these fingerprints.

        Returns:
            Number of fingerprints successfully registered.
        """
        now = datetime.now(timezone.utc).isoformat()
        registered = 0
        for fp in fingerprints:
            fingerprint = fp.get("fingerprint", "")
            category = fp.get("category", "")
            tier = fp.get("tier", category)
            if not fingerprint:
                continue
            canary_id = f"ext-{tier.lower()}-{uuid.uuid4().hex[:8]}"
            entry = CanaryEntry(
                id=canary_id,
                fingerprint=fingerprint,
                classification=tier or category,
                run_id=run_id,
                injected_at=now,
                active=True,
            )
            self._canaries.append(entry)
            registered += 1
        return registered

    def get_active_canaries(self) -> list[CanaryEntry]:
        """Return all currently active canaries.

        Returns:
            List of active CanaryEntry instances.
        """
        return [c for c in self._canaries if c.active]

    def deactivate(self, canary_id: str) -> bool:
        """Deactivate a canary by ID.

        Args:
            canary_id: The canary to deactivate.

        Returns:
            True if the canary was found and deactivated, False otherwise.
        """
        for i, canary in enumerate(self._canaries):
            if canary.id == canary_id:
                # CanaryEntry is frozen, so replace it
                self._canaries[i] = CanaryEntry(
                    id=canary.id,
                    fingerprint=canary.fingerprint,
                    classification=canary.classification,
                    run_id=canary.run_id,
                    injected_at=canary.injected_at,
                    active=False,
                )
                return True
        return False

    def get_canaries_by_run(self, run_id: str) -> list[CanaryEntry]:
        """Get all canaries for a specific run.

        Args:
            run_id: The injection run identifier.

        Returns:
            List of CanaryEntry instances for that run.
        """
        return [c for c in self._canaries if c.run_id == run_id]

    @property
    def all_canaries(self) -> list[CanaryEntry]:
        """All canaries in the corpus, active and inactive."""
        return list(self._canaries)
