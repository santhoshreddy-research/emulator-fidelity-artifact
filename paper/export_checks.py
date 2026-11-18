"""Writes results/public/checks.csv: one row per check with its definition, the AWS reference and the class
each emulator received. Contains no IDs, URLs or raw observations, so it can go behind an anonymous link.

Run from the repo root:  python paper/export_checks.py
Reads the workload test files (CHECKS, NEGATIVE), results/raw (real runs) and results/classified.csv.
"""
import ast
import collections as C
import csv
import glob
import json
import os
import re
import sys

ENVS = ["aws-emulator", "floci", "ministack"]

# 1. check definitions from the test files
defs, negative = {}, set()
for f in glob.glob("**/test_w*.py", recursive=True):
    if "/discarded/" in f or "/.venv/" in f:
        continue
    for node in ast.parse(open(f).read()).body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name == "CHECKS":
                defs.update(ast.literal_eval(node.value))
            elif name == "NEGATIVE":
                negative |= set(ast.literal_eval(node.value))
print("check definitions:", len(defs), "negative:", len(negative))

# 2. AWS reference from the real runs (outcome per run, rejection code for negative checks)
real = C.defaultdict(list)
deps = {}
for f in glob.glob("results/raw/*/real/*/run-*.jsonl"):
    if f.endswith(".latency.jsonl"):
        continue
    for line in open(f):
        if line.strip():
            r = json.loads(line)
            real[r["check_id"]].append(r)
            deps.setdefault(r["check_id"], r.get("depends_on") or [])


def reference(cid):
    runs = real.get(cid, [])
    outcomes = C.Counter(r["outcome"] for r in runs)
    codes = C.Counter((r.get("observed") or {}).get("error_code") or r.get("error_code") for r in runs)
    code = codes.most_common(1)[0][0] if codes else None
    return "/".join(f"{k}x{v}" for k, v in sorted(outcomes.items())), code or ""


# 3. classes per emulator
cls = C.defaultdict(set)
for r in csv.DictReader(open("results/classified.csv")):
    cls[(r["env"], r["check_id"])].add(r["class"])

os.makedirs("results/public", exist_ok=True)
out = "results/public/checks.csv"
with open(out, "w", newline="") as fh:
    w = csv.writer(fh)
    w.writerow(["workload", "check_id", "kind", "path", "description", "prerequisites",
                "aws_outcomes_5_runs", "aws_error_code"] + [f"class_{e}" for e in ENVS])
    for cid in sorted(defs, key=lambda c: (int(c.split("-")[0][1:]), int(c.split("-C")[1]))):
        kind, desc = defs[cid]
        outcomes, code = reference(cid)
        w.writerow([cid.split("-")[0], cid, kind, "negative" if cid in negative else "normal", desc,
                    " ".join(deps.get(cid, [])), outcomes, code]
                   + ["+".join(sorted(cls.get((e, cid), {"-"}))) for e in ENVS])
print("wrote", out)

# 4. safety scan: nothing account-specific may appear
text = open(out).read()
bad = [p for p in (r"\b\d{12}\b", r"arn:aws", r"X-Amz-", r"amazonaws\.com", r"AKIA[0-9A-Z]{12}") if re.search(p, text)]
print("safety scan:", "CLEAN" if not bad else f"FOUND {bad} -- do not publish")

# 5. totals, to compare with Table III
for e in ENVS:
    print(e, dict(C.Counter("+".join(sorted(v)) for (env, _), v in cls.items() if env == e)))
sys.exit(1 if bad else 0)

