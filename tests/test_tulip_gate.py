"""
Tests for the optional tulip-agents admission gate.

These deliberately don't require a live Velociraptor server or a live
tulip-agents install for the "disabled by default" assertions — those are
the ones that matter most, since the whole point is that nothing changes
for anyone who doesn't opt in.
"""

import os
from unittest.mock import patch

from velociraptor_mcp_server import tulip_gate


class TestGateEnabled:
    """gate_enabled() must default to False, and only flip on explicit
    opt-in — this is the "off by default" contract the README promises."""

    def test_disabled_with_no_env_var(self):
        with patch.dict(os.environ, {}, clear=True):
            assert tulip_gate.gate_enabled() is False

    def test_disabled_when_env_var_false(self):
        with patch.dict(os.environ, {"VELOCIRAPTOR_TULIP_GATE_ENABLED": "false"}):
            assert tulip_gate.gate_enabled() is False

    def test_enabled_only_if_tulip_agents_is_actually_installed(self):
        """Setting the env var alone can't turn the gate on if tulip-agents
        isn't installed — this must never raise, just stay off."""
        with patch.object(tulip_gate, "_TULIP_AVAILABLE", False):
            with patch.dict(os.environ, {"VELOCIRAPTOR_TULIP_GATE_ENABLED": "true"}):
                assert tulip_gate.gate_enabled() is False


class TestClassify:
    """Validated against Velociraptor's real 324-artifact built-in catalog
    (see this feature's PR description for the full methodology). These
    cases are the ones that validation actually found — including the two
    documented, unresolved false positives, asserted here as known current
    behavior rather than silently left undocumented."""

    def test_benign_read_query_is_not_dangerous(self):
        action = tulip_gate._classify("SELECT * FROM clients() LIMIT 10")
        assert "dangerous" not in action.tags
        assert action.blast_radius == 1

    def test_remediation_query_is_dangerous(self):
        action = tulip_gate._classify(
            "SELECT * FROM Artifact.Windows.Remediation.Quarantine(ClientId='C.123')"
        )
        assert "dangerous" in action.tags
        assert action.blast_radius == 50

    def test_cleanup_and_rekey_are_caught(self):
        """These were real misses found during validation against the real
        artifact catalog — fixed here, asserted so they can't regress."""
        assert "dangerous" in tulip_gate._classify("SELECT * FROM Generic.Client.CleanupTemp()").tags
        assert "dangerous" in tulip_gate._classify("SELECT * FROM Generic.Client.Rekey()").tags

    def test_known_false_positives_are_documented_not_hidden(self):
        """These two are read-only artifacts that get flagged anyway because
        their names contain "install"/"quarantine". This is a known,
        disclosed limitation of the keyword heuristic, not a regression —
        see tulip_gate.py's module docstring and the PR description."""
        assert "dangerous" in tulip_gate._classify(
            "SELECT * FROM Artifact.MacOS.Detection.InstallHistory()"
        ).tags
        assert "dangerous" in tulip_gate._classify(
            "SELECT * FROM Artifact.MacOS.System.QuarantineEvents()"
        ).tags


class TestDynamicArtifactNameEvasion:
    """Found by adversarial probing, confirmed live end-to-end against a real
    server (ALLOWED AND EXECUTED before this fix) — see tulip_gate.py's
    module docstring. Fragmenting a dangerous artifact name across
    concatenated VQL variables defeats plain marker matching entirely,
    since no complete marker word survives in the literal submitted text."""

    def test_fragmented_concatenation_is_now_caught(self):
        vql = (
            'LET p1 = "Windows.Reme" LET p2 = "diation.Quaran" LET p3 = "tine" '
            "SELECT * FROM Artifact.call(name=p1 + p2 + p3, ClientId='C.1')"
        )
        action = tulip_gate._classify(vql)
        assert "dangerous" in action.tags
        assert "dynamic-artifact-name" in action.tags

    def test_literal_artifact_call_with_a_real_marker_is_caught_as_before(self):
        vql = 'SELECT * FROM Artifact.call(name="Windows.Remediation.Quarantine", ClientId=\'C.1\')'
        assert "dangerous" in tulip_gate._classify(vql).tags

    def test_benign_literal_artifact_call_is_not_flagged(self):
        """The mitigation targets *dynamic* name resolution, not
        Artifact.call() itself — a literal, benign artifact name must not
        get swept up as collateral damage."""
        vql = 'SELECT * FROM Artifact.call(name="Generic.Client.Info", ClientId=\'C.1\')'
        assert "dangerous" not in tulip_gate._classify(vql).tags
