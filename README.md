# Review artifact: local AWS emulators vs. real AWS

- `workloads/` - the six workloads (W1-W6): each test file defines its checks (`CHECKS`), negative checks (`NEGATIVE`) and the observations each check records; W6 includes its CloudFormation template.
- `analysis/classify.py` - classifies each emulator execution against the AWS reference.
- `results/classified.csv` - the class of every check execution (3 emulators x 5 runs).
- `results/public/checks.csv` - one row per check: definition, kind, path, prerequisites, AWS outcomes over 5 runs, AWS error code, class per emulator.
- `paper/make_tables.py` - regenerates the paper's agreement and outcome tables: `python paper/make_tables.py results/classified.csv`
- `paper/paired_w6.py`, `paper/paired_w6_real.py` - the diagnostic W6 template-variant deployments (not scored).

Emulator versions: AWS Emulator 1.0.385, Floci 2.5.0, MiniStack 1.5.41. Python 3.14, boto3 1.44.3, pytest 9.2.0.
The test harness and raw per-run observations will be released upon publication.
