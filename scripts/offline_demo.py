#!/usr/bin/env python3
"""The whole offline measurement. Executes every escape for real; no network.

    python scripts/offline_demo.py
    python scripts/offline_demo.py --json audit/offline.json

What this is. Eight escapes a tool-using agent could attempt, run against five
isolation tiers: the tiers an agent framework actually ships, all available to
an unprivileged process with no root, no namespaces and no container runtime.
Each cell is what HAPPENED on this machine, not what a threat model predicts.

What this is not. It is not a claim about gVisor, Firecracker or a real
container. The claim is narrower and more useful: the thing people deploy when
they say "sandboxed" is usually a subprocess with a working directory, an
environment filter, some resource limits and a timeout, and this measures which
escapes those flags stop. The answer is the shape of the matrix.

Host safety is enforced, not assumed. Wall-clock caps, per-process rlimits, a
memory precheck, one probe at a time, and loopback-only network. The only probe
that detaches a process is self-limiting. See sandbox/runner.py.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sandbox.matrix import build, format_matrix                 # noqa: E402
from sandbox.probes import PROBES                               # noqa: E402
from sandbox.runner import TIERS, host_is_healthy               # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    ok, msg = host_is_healthy()
    print("agent-sandbox-escape -- offline measurement")
    print(f"every escape below was executed for real. host: {msg}")
    if not ok:
        print("REFUSING TO RUN: not enough free memory.")
        return 2
    print()

    print("THE TIERS (all available to an unprivileged process):")
    for tier in TIERS:
        print(f"  {tier.key:<12} {tier.note()}")
    print()

    root = Path(tempfile.mkdtemp(prefix="agb-demo-"))
    cells = build(root)

    print("THE MATRIX -- ESCAPED means the escape reached outside the sandbox")
    print(format_matrix(cells))
    print()

    maximal = TIERS[-1].key
    open_at_max = [p for p in PROBES if cells[p.key][maximal]["escaped"]]
    closed_by_compute = [p for p in PROBES
                         if cells[p.key]["t0_naked"]["escaped"]
                         and not cells[p.key][maximal]["escaped"]]
    kernel_only = [p for p in PROBES if not cells[p.key]["t0_naked"]["escaped"]]

    print(f"AT THE MAXIMAL COMPUTE TIER ({maximal}):")
    print(f"  {len(open_at_max)} of {len(PROBES)} escapes are STILL OPEN, and "
          f"every one needs capability")
    print("  or namespace isolation this stack does not have:")
    for p in open_at_max:
        print(f"    {p.key:<22} {p.note}")
    print(f"  {len(closed_by_compute)} were closed by a compute flag, each at "
          f"the tier that adds it:")
    for p in closed_by_compute:
        first = next(t.key for t in TIERS
                     if not cells[p.key][t.key]["escaped"])
        print(f"    {p.key:<22} closed at {first}")
    if kernel_only:
        print(f"  {len(kernel_only)} was never the sandbox's doing at all:")
        for p in kernel_only:
            print(f"    {p.key:<22} {cells[p.key]['t0_naked']['detail']}")
    print()
    print("  A working directory, an env scrub, rlimits and a fresh session")
    print("  are COMPUTE isolation. Reading a host file, traversing out,")
    print("  opening a socket and detaching a process are CAPABILITY escapes,")
    print("  and no compute flag touches them. That gap is the whole finding.")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({
            "note": "Every cell executed for real on the host. Tiers are what "
                    "an unprivileged agent framework ships, not a container.",
            "tiers": [{"key": t.key, "provides": t.note()} for t in TIERS],
            "probes": [{"key": p.key, "what": p.what, "family": p.family,
                        "note": p.note} for p in PROBES],
            "matrix": {p.key: {t.key: cells[p.key][t.key] for t in TIERS}
                       for p in PROBES},
            "summary": {
                "open_at_maximal_tier": [p.key for p in open_at_max],
                "closed_by_compute": [p.key for p in closed_by_compute],
                "kernel_only": [p.key for p in kernel_only]},
        }, indent=2) + "\n")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
