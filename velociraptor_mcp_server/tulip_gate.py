"""Optional per-call admission gate for RunVQLQueryTool, powered by tulip-agents.

**Off by default, fully optional.** If `tulip-agents` isn't installed, or
`VELOCIRAPTOR_TULIP_GATE_ENABLED` isn't set, nothing in this file changes
RunVQLQueryTool's behavior at all — every call runs exactly as it does today.

Today, RunVQLQueryTool's only defense is the server-startup
`VELOCIRAPTOR_DISABLED_TOOLS` / `VELOCIRAPTOR_DISABLED_CATEGORIES` switch:
the whole tool is on or off for every caller, with no distinction between a
read-only query and one that runs a remediation artifact (quarantine, kill,
delete) against a live endpoint. This adds an optional second layer: a
per-call decision (allow / require a human / deny) based on what the query
actually does, plus a tamper-evident audit record of every decision.

**Validated against Velociraptor's real built-in artifact catalog** (324
artifacts pulled from a live server, see this PR's description for the full
methodology) rather than asserted to work. Two real misses were found and
fixed here (`cleanup`, `rekey`). Two false positives are known and left
unresolved on purpose, not hidden: `MacOS.Detection.InstallHistory` and
`MacOS.System.QuarantineEvents` are read-only artifacts whose names happen
to contain "install"/"quarantine" — they'll currently get flagged even
though they don't mutate anything. This is a keyword heuristic, not a claim
of a complete or production-grade risk classifier — see the PR description
for why that gap is real and matters, and what a better answer looks like.

Also not built: a live human-approval-and-resume loop. A held query is
blocked, full stop — there's no queue or UI yet for a human to review and
release it. `tulip-agents` has the primitives for that (an interrupt/resume
mechanism plus checkpoint backends), but wiring an actual approval workflow
is separate work, not included here.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)

try:
    from tulip.control import Action, AdmissionError, AuditTrail, ControlPolicy, admit

    _TULIP_AVAILABLE = True
except ImportError:  # tulip-agents is an optional extra, not a hard dependency
    _TULIP_AVAILABLE = False


class GateBlocked(Exception):
    """Raised when the admission gate holds or denies a call. Always
    defined — whether or not tulip-agents is installed — so callers never
    need to import from tulip.control directly."""

    def __init__(self, outcome: str, reason: str) -> None:
        self.outcome = outcome
        self.reason = reason
        super().__init__(f"{outcome}: {reason}")


_DANGEROUS_MARKERS = (
    "remediation", "quarantine", "kill", "delete", "remove", "uninstall",
    "disable", "reset", "wipe", "format", "upgrade", "install",
    "cleanup", "rekey",
)

_state: dict[str, Any] = {}


def _policies_and_trail():
    if not _state:
        _state["read_policy"] = ControlPolicy(
            require_verification_score=0.0,
            require_human_for=frozenset(),
            max_blast_radius=10,
        )
        _state["default_policy"] = ControlPolicy()  # production -> human, blast<=1
        _state["trail"] = AuditTrail()
    return _state["read_policy"], _state["default_policy"], _state["trail"]


def gate_enabled() -> bool:
    """Whether the gate is actually active for this process. False (i.e. no
    behavior change) unless BOTH tulip-agents is installed AND the operator
    explicitly opted in via env var."""
    if not _TULIP_AVAILABLE:
        return False
    return os.getenv("VELOCIRAPTOR_TULIP_GATE_ENABLED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
    )


def _classify(vql: str) -> "Action":
    is_dangerous = any(marker in vql.lower() for marker in _DANGEROUS_MARKERS)
    return Action(
        name="RunVQLQueryTool",
        asset="velociraptor-fleet",
        blast_radius=50 if is_dangerous else 1,
        environment=os.getenv("VELOCIRAPTOR_TULIP_ENVIRONMENT", "production"),
        kind="dfir-remediation" if is_dangerous else "dfir-query",
        tags=frozenset({"dangerous"}) if is_dangerous else frozenset(),
    )


async def gated_run_vql_query(vql: str, run: Callable[[], Awaitable[Any]]) -> Any:
    """Run `run()` (the real client call) through the admission gate.

    Raises GateBlocked if the call is held for a human or denied outright —
    `run` is never invoked in that case. Callers should catch GateBlocked
    the same way they'd catch any other tool failure and surface the
    decision's reason to the caller.
    """
    read_policy, default_policy, trail = _policies_and_trail()
    action = _classify(vql)
    policy = default_policy if "dangerous" in action.tags else read_policy
    try:
        return await admit(action, run, policy=policy, trail=trail)
    except AdmissionError as e:
        raise GateBlocked(e.decision.outcome, e.decision.reason) from e


def audit_trail():
    """The tamper-evident record of every gated decision made this process
    (JSONL-exportable via `.export_jsonl()`, verifiable via `.verify()`)."""
    _, _, trail = _policies_and_trail()
    return trail
