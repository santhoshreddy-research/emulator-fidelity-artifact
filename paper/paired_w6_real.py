"""One diagnostic deployment of the ORIGINAL W6 template on real AWS (not scored).

Original = the measured template without HTTPSPort on the CloudFront origin and with DesiredCount as a
Number parameter (Default 1), exactly the 'original' variant of paper/paired_w6.py.

Safety:
  - profile study-real only, region must be us-west-1 (refuses anything else, never us-east-1);
  - stack name and ALB name start with the study prefix, stack tagged Project=emulator-study;
  - everything is created by this one CloudFormation stack, and the stack is deleted at the end,
    also on failure or Ctrl-C (CloudFront makes the delete take 10-20 min);
  - without --go it only prints what it would do (dry run).

Run from the repo root on EC2:
  source .env.real
  python paper/paired_w6_real.py          # dry run
  python paper/paired_w6_real.py --go     # deploy, observe, delete
"""
import collections
import copy
import glob
import json
import sys
import time
import uuid

import boto3
import requests

PREFIX = "study-prefix"
REGION = "us-west-1"
PROFILE = "study-real"
GO = "--go" in sys.argv

path = glob.glob("**/w6_full_stack/template.json", recursive=True)[0]
adjusted = json.load(open(path))
t = copy.deepcopy(adjusted)
t["Resources"]["Distribution"]["Properties"]["DistributionConfig"]["Origins"][0]["CustomOriginConfig"].pop("HTTPSPort", None)
t["Parameters"]["DesiredCount"] = {"Type": "Number", "Default": 1}
t["Resources"]["Service"]["Properties"]["DesiredCount"] = {"Ref": "DesiredCount"}

tag = uuid.uuid4().hex[:4]
stack = f"{PREFIX}-pw6orig-{tag}"
alb_name = f"{PREFIX}-po{tag}"
assert len(alb_name) <= 32

session = boto3.Session(profile_name=PROFILE, region_name=REGION)
assert session.region_name == REGION, "region must be us-west-1"
role = session.client("sts").get_caller_identity()["Arn"].split("/")[1]  # role name only, no account id
cfn = session.client("cloudformation")

print(f"template      {path} (original variant: no HTTPSPort, DesiredCount Number parameter)")
print(f"profile/role  {PROFILE} / {role}   region {REGION}")
print(f"stack         {stack}   AlbName {alb_name}   tag Project=emulator-study")
print("resources     " + ", ".join(f"{k} ({v['Type'].split('::', 1)[1]})" for k, v in t["Resources"].items()))
cfn.validate_template(TemplateBody=json.dumps(t))
print("ValidateTemplate: OK")
if not GO:
    print("\nDry run only. Re-run with --go to deploy, observe and delete.")
    sys.exit(0)


def status():
    return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]


created = False
try:
    cfn.create_stack(StackName=stack, TemplateBody=json.dumps(t),
                     Parameters=[{"ParameterKey": "AlbName", "ParameterValue": alb_name}],
                     Tags=[{"Key": "Project", "Value": "emulator-study"}, {"Key": "Purpose", "Value": "paired-w6"}])
    created = True
    t0 = time.time()
    while time.time() - t0 < 3600:
        st = status()
        if not st.endswith("IN_PROGRESS"):
            break
        time.sleep(20)
    print(f"\nRESULT original template on AWS: {st} after {round(time.time() - t0)} s")
    for e in cfn.describe_stack_events(StackName=stack)["StackEvents"]:
        if e["ResourceStatus"].endswith("FAILED"):
            print(f"  FAILED {e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')[:200]}")
    if st == "CREATE_COMPLETE":
        outs = {o["OutputKey"]: o["OutputValue"] for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
        svc = cfn.describe_stack_resource(StackName=stack, LogicalResourceId="Service")
        print(f"  Service: {svc['StackResourceDetail']['ResourceStatus']}")
        seen, t1, ok = collections.Counter(), time.time(), None
        while time.time() - t1 < 600:
            try:
                code = str(requests.get(f"http://{outs.get('AlbDns')}/", timeout=10, allow_redirects=False).status_code)
            except Exception as exc:
                code = type(exc).__name__
            seen[code] += 1
            if code == "200":
                ok = round(time.time() - t1)
                break
            time.sleep(10)
        print(f"  ALB: responses {dict(seen)}; first 200 after {ok if ok is not None else 'never'} s")
except KeyboardInterrupt:
    print("\ninterrupted; deleting the stack")
finally:
    if created:
        print(f"\ndeleting {stack} (CloudFront: 10-20 min) ...")
        cfn.delete_stack(StackName=stack)
        try:
            cfn.get_waiter("stack_delete_complete").wait(StackName=stack, WaiterConfig={"Delay": 30, "MaxAttempts": 120})
            print(f"deleted {stack}")
        except Exception as exc:
            print(f"DELETE NOT CONFIRMED ({exc}). Run:\n  aws cloudformation delete-stack --profile {PROFILE} "
                  f"--region {REGION} --stack-name {stack}")

