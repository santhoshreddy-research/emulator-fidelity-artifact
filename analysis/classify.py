"""Classifies every emulator check against the reference (real AWS) and prints rates.

  python analysis/classify.py                       # all results under results/raw
  python analysis/classify.py --dates 2026-11-22    # one batch day
  python analysis/classify.py --reference ministack # dry-run the logic before real data exists

Writes results/classified.csv and prints, per environment and workload: the class counts,
the match rate (RQ1) and the false-success rate (RQ2). Rules are in codebook.md.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Observed facts that legitimately vary between runs or tools and are not compared.
VOLATILE = {"seconds", "role_retries", "events", "receive_count", "initial_state", "raw_payload", "payload",
            "arn_suffix", "body_len", "role_probes", "role_restarts"}


def load(base: Path, dates: list[str] | None) -> list[dict]:
    rows = []
    for f in base.glob("*/*/*/run-*.jsonl"):
        if f.name.endswith(".latency.jsonl"):
            continue
        if dates and f.parts[-4] not in dates:
            continue
        rows += [json.loads(line) for line in f.open() if line.strip()]
    return rows


def signature(row: dict, ignore: frozenset = frozenset()) -> tuple:
    obs = {k: v for k, v in (row.get("observed") or {}).items() if k not in VOLATILE and k not in ignore}
    return (row["outcome"], row.get("error_code"), json.dumps(obs, sort_keys=True, default=str))


def reference_table(rows: list[dict]) -> dict:
    """check_id -> {'outcome', 'sig', 'flaky'} from the reference environment's runs."""
    by_check = defaultdict(list)
    for r in rows:
        by_check[r["check_id"]].append(r)
    ref = {}
    for cid, runs in by_check.items():
        outcomes = Counter(r["outcome"] for r in runs)
        top, _ = outcomes.most_common(1)[0]
        top_runs = [r for r in runs if r["outcome"] == top]
        # A fact that varies between the reference's own runs (eventual consistency, timing)
        # can't be held against an emulator: ignore it for this check.
        seen = defaultdict(set)
        for r in top_runs:
            for k, v in (r.get("observed") or {}).items():
                seen[k].add(json.dumps(v, sort_keys=True, default=str))
        ignore = frozenset(k for k, vals in seen.items() if len(vals) > 1)
        sigs = Counter(signature(r, ignore) for r in top_runs)
        ref[cid] = {"outcome": top, "sig": sigs.most_common(1)[0][0], "flaky": len(outcomes) > 1, "ignore": ignore}
    return ref


def classify_run(run_rows: list[dict], ref: dict) -> dict[str, str]:
    by_id = {r["check_id"]: r for r in run_rows}
    cls = {}
    for cid, r in by_id.items():
        ref_c = ref.get(cid)
        out = r["outcome"]
        if out == "blocked":
            cls[cid] = "blocked"
        elif ref_c is None:
            cls[cid] = "no_reference"
        elif ref_c["flaky"]:
            cls[cid] = "flaky"
        elif out == "not_implemented":
            cls[cid] = "not_implemented"
        elif out == "pass" and ref_c["outcome"] == "pass":
            cls[cid] = "match" if signature(r, ref_c["ignore"]) == ref_c["sig"] else "mismatch"
        elif out == "pass":
            cls[cid] = "false_success_a"
        elif r.get("expects") == "error" and (r.get("observed") or {}).get("accepted") and ref_c["outcome"] == "pass":
            # Negative check: real AWS rejects the request, the emulator accepted it.
            cls[cid] = "false_success_a"
        elif ref_c["outcome"] == "pass":
            cls[cid] = "false_failure"
        else:
            same = (out, r.get("error_code")) == ref_c["sig"][:2]
            cls[cid] = "match" if same else "mismatch"

    # Type B: a functional check fails here but passes on real AWS -> each control check it
    # depends on directly, that passed and matched, was a hollow success. Direct dependencies
    # only, so a broken Lambda doesn't also blame the queue it reads from.
    for cid, r in by_id.items():
        if r["kind"] == "functional" and cls.get(cid) == "false_failure":
            for d in r.get("depends_on") or []:
                if by_id.get(d, {}).get("kind") == "control" and cls.get(d) == "match":
                    cls[d] = "false_success_b"
    return cls


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default=os.environ.get("STUDY_RESULTS_DIR", ROOT / "results" / "raw"))
    ap.add_argument("--dates", nargs="*")
    ap.add_argument("--reference", default="real")
    ap.add_argument("--out", default=ROOT / "results" / "classified.csv")
    args = ap.parse_args(argv)

    rows = load(Path(args.results), args.dates)
    if not rows:
        print("No results found.")
        return 1
    by_env_wl = defaultdict(list)
    for r in rows:
        by_env_wl[(r["env"], r["workload"])].append(r)

    out_rows, summary = [], {}
    for (env, wl), wl_rows in sorted(by_env_wl.items()):
        if env == args.reference:
            continue
        ref_rows = by_env_wl.get((args.reference, wl))
        if not ref_rows:
            print(f"{env}/{wl}: no {args.reference} results to compare with; skipped")
            continue
        ref = reference_table(ref_rows)
        runs = defaultdict(list)
        for r in wl_rows:
            runs[r["run_id"]].append(r)
        counts = Counter()
        for run_id, run_rows in runs.items():
            cls = classify_run(run_rows, ref)
            for r in run_rows:
                c = cls[r["check_id"]]
                counts[c] += 1
                out_rows.append({"env": env, "workload": wl, "run_id": run_id, "tool_version": r.get("tool_version"),
                                 "check_id": r["check_id"], "kind": r["kind"], "outcome": r["outcome"],
                                 "reference_outcome": ref.get(r["check_id"], {}).get("outcome"), "class": c})
        summary[(env, wl)] = (counts, len(runs))

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out_rows[0]) if out_rows else ["env"])
        w.writeheader()
        w.writerows(out_rows)

    print(f"Reference: {args.reference}.  Rates exclude blocked, flaky and no_reference checks.\n")
    print(f"{'env':14} {'workload':8} {'runs':>4} {'checks':>6} {'match':>9} {'false succ':>10}  classes")
    for (env, wl), (counts, nruns) in summary.items():
        scored = sum(v for k, v in counts.items() if k not in {"blocked", "flaky", "no_reference"})
        match = counts["match"]
        fs = counts["false_success_a"] + counts["false_success_b"]
        rate = f"{match / scored:.0%}" if scored else "-"
        fsr = f"{fs / scored:.0%}" if scored else "-"
        print(f"{env:14} {wl:8} {nruns:>4} {scored:>6} {rate:>9} {fsr:>10}  {dict(counts)}")
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
