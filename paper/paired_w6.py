"""Paired W6 deployment: does each emulator deploy the ORIGINAL template, and which accommodation matters?

Variants, all derived from the current workloads/w6_full_stack/template.json:
  original    - no HTTPSPort on the CloudFront origin; DesiredCount as a Number parameter (Default 1)
  port_only   - HTTPSPort 443 explicit; DesiredCount still a Number parameter
  count_only  - no HTTPSPort; DesiredCount literal 1
  adjusted    - the template used in the measured runs

Local emulators only: endpoints are fixed to 127.0.0.1/localhost, so this cannot reach real AWS. Floci and
MiniStack get dummy keys; AWS Emulator needs its own credentials, taken from the normal boto3 chain
(set AWS_PROFILE, or the env vars, the same way the harness does for aws-emulator runs). Start the emulator first (scripts/emulators.sh start <env> && ... wait <env>).

  python paper/paired_w6.py aws-emulator        # or floci / ministack
"""
import collections
import copy
import glob
import json
import os
import sys
import time
import uuid

import boto3
import requests
from botocore.config import Config

ENDPOINTS = {
    "aws-emulator": ("https://127.0.0.1:9297", os.path.expanduser("~/.aws/emulator/9297/ca.pem")),
    "floci": ("http://localhost:4566", None),
    "ministack": ("http://localhost:4567", None),
}
env = sys.argv[1]
url, ca = ENDPOINTS[env]

path = glob.glob("**/w6_full_stack/template.json", recursive=True)[0]
adjusted = json.load(open(path))


def variant(port: bool, literal: bool) -> dict:
    t = copy.deepcopy(adjusted)
    origin = t["Resources"]["Distribution"]["Properties"]["DistributionConfig"]["Origins"][0]["CustomOriginConfig"]
    if not port:
        origin.pop("HTTPSPort", None)
    if not literal:
        t["Parameters"]["DesiredCount"] = {"Type": "Number", "Default": 1}
        t["Resources"]["Service"]["Properties"]["DesiredCount"] = {"Ref": "DesiredCount"}
    return t


VARIANTS = {"original": variant(False, False), "port_only": variant(True, False),
            "count_only": variant(False, True), "adjusted": variant(True, True)}
assert VARIANTS["adjusted"] == adjusted, "adjusted variant must equal the measured template"

if env == "aws-emulator":
    if os.environ.get("AWS_PROFILE", "") == "study-real":
        sys.exit("refusing to run with the real-AWS profile")
    # AWS Emulator writes its own credentials next to its CA (~/.aws/emulator/9297/emulator_credentials).
    import configparser
    d = os.path.dirname(ca)
    cred_file = os.path.join(d, "emulator_credentials")
    if os.path.exists(cred_file):
        os.environ["AWS_SHARED_CREDENTIALS_FILE"] = cred_file
        if os.path.exists(os.path.join(d, "config")):
            os.environ["AWS_CONFIG_FILE"] = os.path.join(d, "config")
        cp = configparser.ConfigParser()
        cp.read(cred_file)
        profiles = cp.sections()
        prof = os.environ.get("AE_PROFILE") or ("default" if "default" in profiles else (profiles or [None])[0])
        print(f"emulator credential profiles: {profiles}; using {prof}")
        os.environ.pop("AWS_PROFILE", None)
        for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
            os.environ.pop(k, None)
        session = boto3.Session(profile_name=prof, region_name="us-west-1")
    else:
        session = boto3.Session(region_name="us-west-1")
else:
    session = boto3.Session(region_name="us-west-1", aws_access_key_id="test", aws_secret_access_key="test")
creds = session.get_credentials()
print(f"credentials source: {creds.method if creds else 'NONE'}")
cfn = session.client("cloudformation", endpoint_url=url, verify=ca or True,
                     config=Config(retries={"max_attempts": 3}))
TERMINAL_WAIT = 600
ALB_WAIT = 600  # the HTTP budget real AWS gets in W6-C09

print(f"env={env} template={path}")
for name, body in VARIANTS.items():
    tag = uuid.uuid4().hex[:6]
    stack = f"pw6-{name.replace('_', '')}-{tag}"
    try:
        cfn.create_stack(StackName=stack, TemplateBody=json.dumps(body),
                         Parameters=[{"ParameterKey": "AlbName", "ParameterValue": f"pw6-{tag}"}])
    except Exception as exc:  # rejected at submission
        print(f"{name:10} REJECTED at CreateStack: {exc}")
        continue
    status, t0 = "?", time.time()
    while time.time() - t0 < TERMINAL_WAIT:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if not status.endswith("IN_PROGRESS"):
            break
        time.sleep(5)
    reasons = [f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')[:160]}"
               for e in cfn.describe_stack_events(StackName=stack)["StackEvents"]
               if e["ResourceStatus"].endswith("FAILED")][:3]
    print(f"{name:10} {status}  {' | '.join(reasons)}")
    if name == "adjusted" and status == "CREATE_COMPLETE":
        # Same request as W6-C09, but with the 10-minute budget AWS gets instead of 60 s.
        outs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
        alb = f"http://{outs.get('AlbDns')}/"
        seen, t0 = collections.Counter(), time.time()
        first_ok = None
        while time.time() - t0 < ALB_WAIT:
            try:
                code = str(requests.get(alb, timeout=10, allow_redirects=False).status_code)
            except Exception as exc:
                code = type(exc).__name__
            seen[code] += 1
            if code == "200" and first_ok is None:
                first_ok = round(time.time() - t0)
                break
            time.sleep(10)
        print(f"           ALB poll {ALB_WAIT}s: responses {dict(seen)}; first 200 after "
              f"{first_ok if first_ok is not None else 'never'} s")
    try:
        cfn.delete_stack(StackName=stack)
    except Exception as exc:
        print(f"           delete failed: {exc}")

