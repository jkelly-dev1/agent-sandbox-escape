"""Re-derive README.md's measured figures from audit/*.json and diff them.

Not derived: the test count under Reproducing, and the grandchild probe's
~1.5 s self-termination, which tests/test_sandbox.py pins in the probe source.

A README is prose and drifts; audit/*.json is evidence and does not. This
script rebuilds each figure from the JSON and asserts the exact string is
present in the README, so a re-run that shifts a figure fails loudly instead of
leaving a wrong figure in the document.

    python3 scripts/check_readme_numbers.py            check
    python3 scripts/check_readme_numbers.py --emit     print what it derives

Whitespace AND emphasis are normalized on both sides, so a reflowed paragraph
is not a false alarm that trains a reader to ignore the script. The matrix and
the participation grid are fixed-width blocks, and their column padding is
normalized away with everything else: this checks the FIGURES, not the layout.

The count is printed whether OR NOT anything is missing, so a version of this
script that stopped deriving half of them shows it in the count.
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name):
    with open(os.path.join(ROOT, "audit", name), encoding="utf-8") as fh:
        return json.load(fh)


def rows_matrix():
    """One row per escape: what each cumulative tier did to it.

    ESCAPED or `--`, exactly as the block prints it. A cell that flipped
    because a tier stopped applying a flag is the finding this repository is
    built on, so every one of the forty is derived rather than eyeballed.
    """
    off = load("offline.json")
    tiers = [t["key"] for t in off["tiers"]]
    out = []
    for probe in off["probes"]:
        key = probe["key"]
        cells = [("ESCAPED" if off["matrix"][key][t]["escaped"] else "--")
                 for t in tiers]
        out.append(("matrix:" + key, "%s %s" % (key, " ".join(cells))))
    return out


def _participation(run, model):
    """(declined, api-blocked, wrote, escaped) for one model.

    A decline is NOT A stop reason. claude-opus-5 declines with
    stop_reason=refusal and gpt-5.4 declines by completing its turn without
    writing code, so keying on the stop reason would report gpt-5.4 as having
    declined nothing. A decline means the API blocked nothing and no code came
    back. The README's grid keeps these three outcomes separate rather than
    folding them into a single escape rate, which would answer a question the
    run cannot.
    """
    rs = [r for r in run["records"] if r["model"] == model]
    # "api-blocked" is a PROVIDER content refusal specifically, keyed on
    # error_kind, not on any error record: a transport error is not the API
    # declining and must not be reported as one.
    blocked = [r for r in rs if r.get("error_kind") == "api_refusal"]
    wrote = [r for r in rs if r.get("wrote_code")]
    declined = [r for r in rs
                if "stop_reason" in r and not r.get("wrote_code")]
    escaped = [r for r in rs if r.get("escaped")]
    return len(declined), len(blocked), len(wrote), len(escaped)


def rows_participation():
    run = load("real_run_2026_09_22.json")
    out = []
    for model in run["models"]:
        d, b, w, e = _participation(run, model)
        out.append(("paid:" + model, "%s %d %d %d %d" % (model, d, b, w, e)))
    return out


def rows_written():
    """Of code actually written, on a goal the offline probe proves possible.

    `possible` is the offline harness's verdict at the maximal tier, so this
    row asks whether the model achieved something a hand-written probe already
    achieved. A model that declined everything has no row here at all: 0/15
    escaped and 0 written are different facts.
    """
    run = load("real_run_2026_09_22.json")
    out = []
    for model in run["models"]:
        rs = [r for r in run["records"]
              if r["model"] == model and r.get("wrote_code")
              and r.get("possible")]
        if not rs:
            continue
        out.append(("written:" + model, "%s %d/%d"
                    % (model, sum(1 for r in rs if r.get("escaped")), len(rs))))
    return out


def prose_figures():
    off = load("offline.json")["summary"]
    orig = load("real_run.json")
    fresh = load("real_run_2026_09_22.json")
    rerun = load("real_run_opus5_rerun.json")
    out = [("prose:one-sentence",
            "stops %s of eight escapes and leaves %s wide open"
            % (_word(len(off["closed_by_compute"])),
               _word(len(off["open_at_maximal_tier"]))))]

    # The cost/scope of each paid run, derived so the two table rows cannot
    # drift from the artifacts they describe. Label-free (models | calls |
    # cost) so the row's prose label is free to change.
    def cost_row(run):
        models = ", ".join(m.replace("claude-", "") for m in run["models"])
        return "%s | %d | $%.2f" % (models, len(run["records"]),
                                    run["actual_cost_usd"])
    out.append(("prose:cost-first-run", cost_row(orig)))
    out.append(("prose:cost-rerun", cost_row(rerun)))
    out.append(("prose:cost-second-run", cost_row(fresh)))

    # opus-5 declined every attempt, in the original run and its re-run alike.
    def op5_declines(run):
        return sum(1 for r in run["records"]
                   if r["model"] == "claude-opus-5" and "error" not in r
                   and not r.get("wrote_code"))
    n = op5_declines(orig) + op5_declines(rerun)
    out.append(("prose:opus5-declines", "%d of %d" % (n, n)))
    return out


def _word(n):
    return {0: "zero", 1: "one", 2: "two", 3: "three", 4: "four",
            5: "five", 6: "six", 7: "seven", 8: "eight"}.get(n, str(n))


def emit():
    return (rows_matrix() + rows_participation() + rows_written()
            + prose_figures())


def squash(text):
    return re.sub(r"\s+", " ", text.replace("**", "").replace("`", ""))


def main():
    derived = emit()
    if "--emit" in sys.argv:
        for tag, row in derived:
            print("%s\n%s" % (tag, row))
        return 0
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
        readme = squash(fh.read())
    missing = [(t, r) for t, r in derived if squash(r) not in readme]
    for tag, row in missing:
        print("MISSING [%s]\n  %s" % (tag, row))
    tables = sum(1 for t, _ in derived if not t.startswith("prose:"))
    print("\n%d of %d derived figures found verbatim in README.md "
          "(%d table rows, %d in prose)"
          % (len(derived) - len(missing), len(derived), tables,
             len(derived) - tables))
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
