#!/usr/bin/env python3
"""Measure `tulip_gate`'s markers against Velociraptor's real artifact catalog.

The gate's markers are a keyword heuristic, so the only honest way to
talk about them is to run them over every artifact name that actually
exists and report both halves: what a marker catches, and what it
collides with. This does that offline and reproducibly against the
upstream definitions, so the numbers in the PR description can be
re-derived without a live Velociraptor server.

    git clone --depth 1 --filter=blob:none --sparse \\
        https://github.com/Velocidex/velociraptor.git /tmp/velo
    cd /tmp/velo && git sparse-checkout set artifacts/definitions
    python scripts/validate_markers.py /tmp/velo/artifacts/definitions

Measured at Velocidex/velociraptor@7f8dc75 (421 definitions):

  - `execve`, `http_client`, `copy(` collide with ZERO artifact names.
    They appear in a query only because a caller wrote them, which is
    also why the 41 artifacts that shell out internally for read-only
    collection are correctly untouched -- their `execve` is in the
    artifact body, never in the submitted VQL.
  - `cmdshell`, `bashshell`, `vbscript`, `fetchbinary` match exactly one
    artifact name each, and in every case it is the executing one.
  - bare `powershell` would match 8 names, 5 of them read-only forensic
    artifacts -- which is why the marker is the fully-qualified
    `windows.system.powershell` instead, cutting that to 3 names and 2
    remaining (disclosed) false positives.
  - `upload` matches 15 names; 4 are server-side SIEM forwarders, kept
    as documented over-caution so that
    `Artifact.Windows.Search.FileFinder(Upload="Y")` cannot slip past.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

# Loaded by path rather than as `velociraptor_mcp_server.tulip_gate`:
# the package's __init__ imports the gRPC client, and this script has no
# business needing a gRPC stack (or a server) to count strings.
_GATE_PATH = (
    pathlib.Path(__file__).resolve().parent.parent
    / "velociraptor_mcp_server"
    / "tulip_gate.py"
)
_spec = importlib.util.spec_from_file_location("tulip_gate", _GATE_PATH)
_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gate)

_DESTRUCTIVE_MARKERS = _gate._DESTRUCTIVE_MARKERS
_EXECUTION_MARKERS = _gate._EXECUTION_MARKERS
_EGRESS_MARKERS = _gate._EGRESS_MARKERS

_NAME = re.compile(r"^name:\s*(\S+)", re.M)


def artifact_names(definitions: pathlib.Path) -> list[str]:
    names = []
    for path in sorted(definitions.rglob("*.yaml")):
        match = _NAME.search(path.read_text(errors="replace"))
        if match:
            names.append(match.group(1))
    return names


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    definitions = pathlib.Path(sys.argv[1])
    if not definitions.is_dir():
        print(f"not a directory: {definitions}")
        return 2

    names = artifact_names(definitions)
    print(f"{len(names)} real artifact definitions in {definitions}\n")

    families = (
        ("destructive", _DESTRUCTIVE_MARKERS),
        ("execution", _EXECUTION_MARKERS),
        ("egress", _EGRESS_MARKERS),
    )
    for family, markers in families:
        print(f"[{family}]")
        for marker in markers:
            hits = [n for n in names if marker in n.lower()]
            shown = ", ".join(hits[:5]) + (" ..." if len(hits) > 5 else "")
            print(f"  {marker:28} {len(hits):3} artifact names  {shown}")
        print()

    all_markers = _DESTRUCTIVE_MARKERS + _EXECUTION_MARKERS + _EGRESS_MARKERS
    flagged = [n for n in names if any(m in n.lower() for m in all_markers)]
    print(
        f"{len(flagged)}/{len(names)} artifact names would be held if named "
        f"directly in a query ({100 * len(flagged) // len(names)}%)."
    )
    print(
        "A gate is judged on what it lets through, not on what it stops: "
        "over-caution here costs a confirmation prompt, a miss costs an "
        "endpoint."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
