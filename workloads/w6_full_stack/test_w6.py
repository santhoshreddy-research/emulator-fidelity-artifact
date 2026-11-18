"""W6 Full stack: one CloudFormation (JSON) template, template.json next to this file, with a VPC
and two public subnets, an internet-facing ALB, an ECS Fargate service running nginx, a regional
WAF web ACL on the ALB and a CloudFront distribution with the ALB as origin.

Unlike W1-W5, everything is created by CloudFormation. The checks then look at each service
directly and send real HTTP requests through the ALB and through CloudFront.

The WAF is REGIONAL and attached to the ALB, so the whole study stays in the study region
(a WAF on CloudFront itself would have to live in us-east-1). Requests through CloudFront still
pass the WAF, because CloudFront forwards them to the ALB.

Real AWS is slow here: CloudFront takes several minutes to deploy and to delete, so one real
run takes 30 to 60 minutes. Emulators get much shorter timeouts, since they either answer at
once or not at all.

Checks run in file order and share state. A check whose prerequisite failed is recorded as
'blocked' and skipped. Recorded observations never contain run-specific values (names, ids,
DNS names), so they can be compared across runs and environments.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse
import os
import time
from pathlib import Path

import pytest
import requests
from botocore.exceptions import ClientError

from harness.aws_helpers import quietly
from harness.record import poll

WORKLOAD = "W6"

TEMPLATE = (Path(__file__).with_name("template.json")).read_text()
# C16/C17 scale the service by updating the template (DesiredCount 1 -> 2). DesiredCount is a literal, not a
# Number parameter, because AWS Emulator passes Number parameters to ECS as strings and rejects the stack.
_t2 = json.loads(TEMPLATE)
_t2["Resources"]["Service"]["Properties"]["DesiredCount"] = 2
TEMPLATE_TWO = json.dumps(_t2)

CHECKS = {
    "W6-C01": ("control", "ValidateTemplate accepts the template and lists its two parameters"),
    "W6-C02": ("control", "CreateStack reaches CREATE_COMPLETE"),
    "W6-C03": ("control", "Every resource in the stack is CREATE_COMPLETE"),
    "W6-C04": ("data", "The stack returns all ten outputs"),
    "W6-C05": ("control", "The VPC has two public subnets in different AZs and a default route to the internet gateway"),
    "W6-C06": ("control", "The ALB is an active internet-facing application load balancer with an HTTP:80 listener and an IP target group"),
    "W6-C07": ("functional", "The ECS service is ACTIVE on FARGATE with one running task"),
    "W6-C08": ("functional", "The task registers as a healthy target in the target group"),
    "W6-C09": ("data", "HTTP GET through the ALB returns 200 and the nginx page"),
    "W6-C10": ("control", "The regional web ACL with two rules is associated with the ALB"),
    "W6-C11": ("functional", "The WAF blocks a request for /admin through the ALB with 403"),
    "W6-C12": ("functional", "The WAF blocks the study header with 403 while a normal request still gets 200"),
    "W6-C13": ("control", "The CloudFront distribution is Deployed and enabled with the ALB as its origin"),
    "W6-C14": ("data", "HTTP GET through CloudFront returns 200 and the nginx page, served by CloudFront"),
    "W6-C15": ("functional", "A request for /admin through CloudFront is blocked by the ALB's WAF with 403"),
    "W6-C16": ("control", "A change set setting DesiredCount to 2 in the template shows only an in-place Modify of the service"),
    "W6-C17": ("functional", "UpdateStack setting DesiredCount to 2 in the template completes and the service runs two tasks"),
    # negative checks: real AWS rejects these
    "W6-C18": ("data", "ValidateTemplate with a template that is not valid JSON is rejected"),
    "W6-C19": ("data", "ValidateTemplate with an unknown resource type is rejected"),
    "W6-C20": ("data", "ValidateTemplate with a Ref to an undefined resource is rejected"),
    "W6-C21": ("control", "CreateStack without a required parameter is rejected"),
    "W6-C22": ("control", "CreateStack with the name of an existing stack is rejected"),
    "W6-C23": ("control", "UpdateStack with no changes is rejected"),
    "W6-C24": ("functional", "A stack with an out-of-range SQS VisibilityTimeout fails and rolls back"),
    "W6-C25": ("data", "CreateStack with an invalid stack name is rejected"),
    # teardown
    "W6-C26": ("control", "DeleteStack removes every study stack (DELETE_COMPLETE)"),
    "W6-C27": ("control", "After deletion the stack, the ALB and the distribution are gone"),
}

# Negative checks: real AWS rejects the request (C24: the stack rolls back). They pass when that happens.
NEGATIVE = {"W6-C18", "W6-C19", "W6-C20", "W6-C21", "W6-C22", "W6-C23", "W6-C24", "W6-C25"}

OUTPUT_KEYS = sorted(["VpcId", "SubnetIds", "AlbArn", "AlbDns", "TargetGroupArn", "ClusterName", "ServiceName",
                      "WebAclArn", "DistributionId", "DistributionDomain"])


def chk(rec, cid: str, *deps: str):
    kind, desc = CHECKS[cid]
    if deps:
        rec.require(*deps, check_id=cid, kind=kind, description=desc)
    return rec.check(cid, kind, desc, depends_on=deps, negative=cid in NEGATIVE)


def code_of(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def expect_error(c, fn):
    """Runs fn(); records the error code if it is rejected, or accepted=True if it goes through."""
    try:
        result = fn()
    except ClientError as exc:
        c.observe(error_code=code_of(exc), http_status=exc.response["ResponseMetadata"].get("HTTPStatusCode"))
        return None
    c.observe(accepted=True)
    c.accepted_result = result
    raise AssertionError("request was accepted; real AWS rejects it")


def limits(env) -> dict:
    """Seconds to wait. Real AWS is slow (CloudFront); emulators answer at once or never."""
    if env.is_real:
        return {"stack": 60 * 60, "service": 15 * 60, "http": 10 * 60, "cdn": 20 * 60, "waf": 10 * 60}
    return {"stack": 10 * 60, "service": 3 * 60, "http": 60, "cdn": 60, "waf": 60}


HTTP_ERROR: dict = {}  # last connection error per URL, for failure messages

# Where an emulator serves a distribution locally. Floci returns the real-looking {id}.cloudfront.net, which
# resolves to nothing local; its docs serve the same distribution as {id}.cloudfront.localhost.floci.io on the
# API port (https://floci.io/floci/services/cloudfront/). Real AWS and other emulators use the domain as returned.
LOCAL_CDN = {"floci": "http://{id}.cloudfront.localhost.floci.io:{port}"}


def cdn_url(study_env, S, path: str = "/") -> str:
    domain = S["out"]["DistributionDomain"]
    tpl = None if study_env.is_real else LOCAL_CDN.get(study_env.name)
    if tpl:
        port = urlparse(study_env.endpoint_url).port or 80
        return tpl.format(id=domain.split(".")[0], port=port) + path
    return f"http://{domain}{path}"


def http_get(url: str, headers: dict | None = None) -> requests.Response | None:
    try:
        return requests.get(url, headers=headers or {}, timeout=10, allow_redirects=False)
    except requests.RequestException as exc:
        HTTP_ERROR[url] = f"{type(exc).__name__}: {str(exc)[:200]}"
        return None


def get_until(url: str, want: int, timeout: float, headers: dict | None = None) -> tuple[int | None, requests.Response | None]:
    """GETs url until it answers with status `want`; returns the last status and response."""
    last: list = [None]

    def attempt():
        r = http_get(url, headers)
        last[0] = r
        return r is not None and r.status_code == want

    poll(attempt, timeout, interval=5)
    r = last[0]
    return (r.status_code if r is not None else None), r


# --- shared state -------------------------------------------------------------------------

def confirm_mode(env) -> bool:
    """STUDY_CONFIRM_GLOBAL=1 on real AWS: before deleting, show the global resources (CloudFront)
    and ask on the terminal. Without a yes (or without a terminal, e.g. under nohup) nothing is
    deleted and the generated delete script is left for you to run."""
    return env.is_real and os.environ.get("STUDY_CONFIRM_GLOBAL") == "1"


def ask_terminal(question: str) -> bool:
    """Asks on the controlling terminal (pytest captures stdin); no terminal means no."""
    try:
        with open("/dev/tty", "r+") as tty:
            tty.write(question + " [y/N] ")
            tty.flush()
            return tty.readline().strip().lower() == "y"
    except OSError:
        return False


@pytest.fixture(scope="module")
def S(study_env, prefix, run_id):
    """Shared state; deletes every stack it started when the module ends, pass or fail (not in keep mode)."""
    state = {
        "stack": f"{prefix}-stack",
        "alb_name": prefix[:32].strip("-"),  # starts with the study prefix (IAM scopes listener deletes on it)
        "stacks": [],
        "lim": limits(study_env),
        "run_id": run_id,
    }
    yield state
    if study_env.is_real:
        try:
            write_inventory(study_env, state)
        except Exception as exc:  # noqa: BLE001 - listing must never stop the cleanup below
            print(f"could not write the W6 resource list: {exc}")
    if state.get("kept"):
        return
    cfn = study_env.client("cloudformation")
    for name in state["stacks"]:
        quietly(cfn.delete_stack, StackName=name)


def write_inventory(study_env, S) -> Path | None:
    """Writes logs/w6-resources-<run>.txt (every resource each study stack holds) and
    logs/w6-delete-<run>.sh (deletes those stacks, which deletes their resources in the right order).
    Called before anything is deleted, so you can always see what a run created."""
    cfn = study_env.client("cloudformation")
    region = study_env.region
    lines, cmds = [], []
    for name in dict.fromkeys(S["stacks"]):
        status = stack_status(cfn, name)
        if status is None or status == "DELETE_COMPLETE":
            continue
        lines.append(f"stack {name}  ({status})")
        try:
            for r in cfn.describe_stack_resources(StackName=name)["StackResources"]:
                lines.append(f"    {r['ResourceType']:45} {r['LogicalResourceId']:22} {r.get('PhysicalResourceId', '')}")
        except ClientError as exc:
            lines.append(f"    (could not list resources: {code_of(exc)})")
        cmds.append(f"aws cloudformation delete-stack --region {region} --stack-name {name}")
        cmds.append(f"aws cloudformation wait stack-delete-complete --region {region} --stack-name {name} "
                    f"&& echo 'deleted {name}'")
    if not lines:
        return None
    logs = Path("logs")
    logs.mkdir(exist_ok=True)
    listing = logs / f"w6-resources-{S['run_id']}.txt"
    listing.write_text("\n".join(lines) + "\n")
    script = logs / f"w6-delete-{S['run_id']}.sh"
    script.write_text(
        "#!/usr/bin/env bash\n"
        f"# Deletes the CloudFormation stacks of W6 run {S['run_id']}. Deleting a stack deletes every\n"
        "# resource it created (listed in the matching w6-resources file), in dependency order.\n"
        "# CloudFront takes 10-20 minutes to delete. Safe to re-run.\n"
        "set -uo pipefail\n"
        + "".join(f"# {line}\n" for line in lines)
        + "\n".join(cmds) + "\n")
    print(f"\nW6 resources listed in {listing}; delete script: {script}")
    return script


def stack_tags(tags: dict) -> list[dict]:
    return [{"Key": k, "Value": v} for k, v in tags.items()]


def stack_status(cfn, name: str) -> str | None:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        # "does not exist", or a name CloudFormation would never accept (the C25 negative check)
        if code_of(exc) == "ValidationError":
            return None
        raise


def wait_stack(cfn, name: str, timeout: float, gone_ok: bool = False) -> str | None:
    """Waits until the stack leaves *_IN_PROGRESS; returns the final status (None when it is gone)."""
    deadline = time.monotonic() + timeout
    status = stack_status(cfn, name)
    while status and status.endswith("_IN_PROGRESS") and time.monotonic() < deadline:
        time.sleep(15)
        status = stack_status(cfn, name)
    return status


def first_failure(cfn, name: str) -> str:
    """Type and status of the first resource that failed, for the failure message (no ids)."""
    try:
        events = cfn.describe_stack_events(StackName=name)["StackEvents"]
    except ClientError:
        return ""
    failed = [e for e in reversed(events) if e.get("ResourceStatus", "").endswith("_FAILED")]
    if failed:
        e = failed[0]
        return f"{e.get('ResourceType')} {e.get('ResourceStatus')}: {(e.get('ResourceStatusReason') or '')[:300]}"
    # no *_FAILED event (some emulators only roll back): show the events that carry a reason, oldest first
    why = [f"{e.get('ResourceType')} {e.get('ResourceStatus')}: {(e.get('ResourceStatusReason') or '')[:200]}"
           for e in reversed(events) if e.get("ResourceStatusReason")]
    return "no *_FAILED event; " + (" || ".join(why[:4]) if why else f"{len(events)} events, none with a reason")


def service(study_env, S) -> dict:
    return study_env.client("ecs").describe_services(
        cluster=S["out"]["ClusterName"], services=[S["out"]["ServiceName"]])["services"][0]


# --- create -------------------------------------------------------------------------------

def test_c01_validate(study_env, rec, S):
    with chk(rec, "W6-C01") as c:
        r = study_env.client("cloudformation").validate_template(TemplateBody=TEMPLATE)
        keys = sorted(p["ParameterKey"] for p in r.get("Parameters", []))
        c.observe(parameters=keys, capabilities=r.get("Capabilities", []))
        assert keys == ["AlbName", "Image"]


def test_c02_create_stack(study_env, rec, S, tags):
    with chk(rec, "W6-C02") as c:
        cfn = study_env.client("cloudformation")
        S["stacks"].append(S["stack"])
        cfn.create_stack(StackName=S["stack"], TemplateBody=TEMPLATE, Tags=stack_tags(tags),
                         Parameters=[{"ParameterKey": "AlbName", "ParameterValue": S["alb_name"]}])
        status = wait_stack(cfn, S["stack"], S["lim"]["stack"])
        c.observe(status=status)
        assert status == "CREATE_COMPLETE", f"stack ended {status}; {first_failure(cfn, S['stack'])}"


def test_c03_resources(study_env, rec, S):
    with chk(rec, "W6-C03", "W6-C02") as c:
        res = study_env.client("cloudformation").describe_stack_resources(StackName=S["stack"])["StackResources"]
        types = sorted(r["ResourceType"] for r in res)
        not_complete = sorted(r["LogicalResourceId"] for r in res if r["ResourceStatus"] != "CREATE_COMPLETE")
        c.observe(resources=len(res), types=sorted(set(types)), not_complete=not_complete)
        assert len(res) == 20 and not not_complete


def test_c04_outputs(study_env, rec, S):
    with chk(rec, "W6-C04", "W6-C02") as c:
        st = study_env.client("cloudformation").describe_stacks(StackName=S["stack"])["Stacks"][0]
        S["out"] = {o["OutputKey"]: o["OutputValue"] for o in st.get("Outputs", [])}
        c.observe(keys=sorted(S["out"]))
        assert sorted(S["out"]) == OUTPUT_KEYS


# --- the services, checked directly -------------------------------------------------------

def test_c05_network(study_env, rec, S):
    with chk(rec, "W6-C05", "W6-C04") as c:
        ec2 = study_env.client("ec2")
        subnets = ec2.describe_subnets(SubnetIds=S["out"]["SubnetIds"].split(","))["Subnets"]
        azs = {s["AvailabilityZone"] for s in subnets}
        public = [s.get("MapPublicIpOnLaunch") for s in subnets]
        tables = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [S["out"]["VpcId"]]}])["RouteTables"]
        default = any(r.get("DestinationCidrBlock") == "0.0.0.0/0" and str(r.get("GatewayId", "")).startswith("igw-")
                      for t in tables for r in t.get("Routes", []))
        c.observe(subnets=len(subnets), distinct_azs=len(azs), map_public_ip=public, default_route_to_igw=default)
        assert len(subnets) == 2 and len(azs) == 2 and all(public) and default


def test_c06_load_balancer(study_env, rec, S):
    with chk(rec, "W6-C06", "W6-C04") as c:
        elb = study_env.client("elbv2")

        def lb():
            return elb.describe_load_balancers(LoadBalancerArns=[S["out"]["AlbArn"]])["LoadBalancers"][0]

        b = poll(lambda: (lambda x: x if x.get("State", {}).get("Code") == "active" else None)(lb()),
                 S["lim"]["service"], interval=10) or lb()
        listeners = elb.describe_listeners(LoadBalancerArn=S["out"]["AlbArn"])["Listeners"]
        tg = elb.describe_target_groups(TargetGroupArns=[S["out"]["TargetGroupArn"]])["TargetGroups"][0]
        c.observe(scheme=b.get("Scheme"), type=b.get("Type"), state=b.get("State", {}).get("Code"),
                  azs=len(b.get("AvailabilityZones", [])),
                  listeners=sorted([lst.get("Port"), lst.get("Protocol")] for lst in listeners),
                  target_type=tg.get("TargetType"), target_protocol=tg.get("Protocol"), target_port=tg.get("Port"))
        assert b.get("Scheme") == "internet-facing" and b.get("Type") == "application"
        assert b.get("State", {}).get("Code") == "active"
        assert [[lst.get("Port"), lst.get("Protocol")] for lst in listeners] == [[80, "HTTP"]]
        assert tg.get("TargetType") == "ip"


def test_c07_service(study_env, rec, S):
    with chk(rec, "W6-C07", "W6-C04") as c:
        s = poll(lambda: (lambda x: x if x.get("runningCount") == 1 else None)(service(study_env, S)),
                 S["lim"]["service"], interval=10) or service(study_env, S)
        c.observe(status=s.get("status"), launch_type=s.get("launchType"), desired=s.get("desiredCount"),
                  running=s.get("runningCount"))
        assert s.get("status") == "ACTIVE" and s.get("launchType") == "FARGATE" and s.get("runningCount") == 1


def test_c08_target_health(study_env, rec, S):
    with chk(rec, "W6-C08", "W6-C06", "W6-C07") as c:
        elb = study_env.client("elbv2")

        def states():
            d = elb.describe_target_health(TargetGroupArn=S["out"]["TargetGroupArn"])["TargetHealthDescriptions"]
            return sorted(t.get("TargetHealth", {}).get("State") for t in d)

        got = poll(lambda: (lambda s: s if s == ["healthy"] else None)(states()), S["lim"]["service"],
                   interval=10) or states()
        c.observe(states=got)
        assert got == ["healthy"]


def test_c09_http_alb(study_env, rec, S):
    with chk(rec, "W6-C09", "W6-C08") as c:
        url = f"http://{S['out']['AlbDns']}/"
        status, r = get_until(url, 200, S["lim"]["http"])
        nginx = r is not None and "nginx" in r.text.lower()
        c.observe(status=status, nginx_page=nginx)
        assert status == 200 and nginx, f"GET {url} -> {status}; {HTTP_ERROR.get(url, '')}"


def test_c10_waf(study_env, rec, S):
    with chk(rec, "W6-C10", "W6-C04") as c:
        waf = study_env.client("wafv2")
        acl = waf.get_web_acl_for_resource(ResourceArn=S["out"]["AlbArn"]).get("WebACL") or {}
        rules = sorted(r.get("Name") for r in acl.get("Rules", []))
        same = acl.get("ARN") == S["out"]["WebAclArn"]
        c.observe(associated=bool(acl), same_acl=same, rules=rules,
                  default_action=sorted(acl.get("DefaultAction", {})))
        assert same and rules == ["block-admin-path", "block-study-header"]


def test_c11_waf_blocks_path(study_env, rec, S):
    with chk(rec, "W6-C11", "W6-C09") as c:  # tests enforcement; C10 only checks the API view
        # a new association can take a few minutes to start filtering on real AWS
        status, _ = get_until(f"http://{S['out']['AlbDns']}/admin", 403, S["lim"]["waf"])
        c.observe(status=status)
        assert status == 403, f"/admin returned {status}"


def test_c12_waf_blocks_header(study_env, rec, S):
    with chk(rec, "W6-C12", "W6-C09") as c:  # header rule is independent of the /admin rule (C11)
        url = f"http://{S['out']['AlbDns']}/"
        blocked, _ = get_until(url, 403, S["lim"]["waf"], headers={"x-study-block": "1"})
        normal = http_get(url)
        c.observe(with_header=blocked, without_header=normal.status_code if normal is not None else None)
        assert blocked == 403 and normal is not None and normal.status_code == 200


def test_c13_distribution(study_env, rec, S):
    with chk(rec, "W6-C13", "W6-C04") as c:
        cf = study_env.client("cloudfront")

        def dist():
            return cf.get_distribution(Id=S["out"]["DistributionId"])["Distribution"]

        d = poll(lambda: (lambda x: x if x.get("Status") == "Deployed" else None)(dist()), S["lim"]["cdn"],
                 interval=15) or dist()
        cfg = d.get("DistributionConfig", {})
        origins = [o.get("DomainName") for o in cfg.get("Origins", {}).get("Items", [])]
        c.observe(status=d.get("Status"), enabled=cfg.get("Enabled"), origin_is_alb=origins == [S["out"]["AlbDns"]],
                  domain_ok=d.get("DomainName") == S["out"]["DistributionDomain"])
        assert d.get("Status") == "Deployed" and cfg.get("Enabled") is True and origins == [S["out"]["AlbDns"]]


def test_c14_http_cloudfront(study_env, rec, S):
    with chk(rec, "W6-C14", "W6-C09", "W6-C13") as c:
        url = cdn_url(study_env, S, "/")
        status, r = get_until(url, 200, S["lim"]["cdn"])
        nginx = r is not None and "nginx" in r.text.lower()
        via = r is not None and ("cloudfront" in r.headers.get("Via", "").lower() or "X-Cache" in r.headers)
        c.observe(status=status, nginx_page=nginx, served_by_cloudfront=via)
        body = "" if r is None else " ".join(r.text.split())[:250]
        hdrs = {} if r is None else {k: v for k, v in r.headers.items() if k.lower() in ("server", "via", "x-cache", "content-type")}
        assert status == 200 and nginx and via, f"GET {url} -> {status}, via={via}; {HTTP_ERROR.get(url, '')} headers={hdrs} body={body!r}"


def test_c15_cloudfront_waf(study_env, rec, S):
    with chk(rec, "W6-C15", "W6-C11", "W6-C14") as c:
        url = cdn_url(study_env, S, "/admin")
        status, _ = get_until(url, 403, S["lim"]["waf"])
        c.observe(status=status)
        assert status == 403, f"GET {url} returned {status}; {HTTP_ERROR.get(url, '')}"


# --- change ------------------------------------------------------------------------------

def test_c16_change_set(study_env, rec, S):
    with chk(rec, "W6-C16", "W6-C02") as c:
        cfn = study_env.client("cloudformation")
        name = "desired-two"
        cfn.create_change_set(StackName=S["stack"], ChangeSetName=name, TemplateBody=TEMPLATE_TWO, Parameters=[
            {"ParameterKey": "AlbName", "UsePreviousValue": True},
            {"ParameterKey": "Image", "UsePreviousValue": True}])

        def described():
            d = cfn.describe_change_set(StackName=S["stack"], ChangeSetName=name)
            return d if not d.get("Status", "").endswith("_PENDING") and d.get("Status") != "CREATE_IN_PROGRESS" else None

        d = poll(described, 120, interval=5) or cfn.describe_change_set(StackName=S["stack"], ChangeSetName=name)
        changes = sorted([ch["ResourceChange"].get("LogicalResourceId"), ch["ResourceChange"].get("Action"),
                          ch["ResourceChange"].get("Replacement")] for ch in d.get("Changes", []))
        quietly(cfn.delete_change_set, StackName=S["stack"], ChangeSetName=name)
        c.observe(status=d.get("Status"), changes=changes)
        assert d.get("Status") == "CREATE_COMPLETE" and changes == [["Service", "Modify", "False"]]


def test_c17_update_stack(study_env, rec, S):
    with chk(rec, "W6-C17", "W6-C07") as c:
        cfn = study_env.client("cloudformation")
        cfn.update_stack(StackName=S["stack"], TemplateBody=TEMPLATE_TWO, Parameters=[
            {"ParameterKey": "AlbName", "UsePreviousValue": True},
            {"ParameterKey": "Image", "UsePreviousValue": True}])
        status = wait_stack(cfn, S["stack"], S["lim"]["stack"])
        s = poll(lambda: (lambda x: x if x.get("runningCount") == 2 else None)(service(study_env, S)),
                 S["lim"]["service"], interval=10) or service(study_env, S)
        c.observe(status=status, desired=s.get("desiredCount"), running=s.get("runningCount"))
        assert status == "UPDATE_COMPLETE", f"update ended {status}; {first_failure(cfn, S['stack'])}"
        assert s.get("desiredCount") == 2 and s.get("runningCount") == 2


# --- negative checks ----------------------------------------------------------------------

def test_c18_not_json(study_env, rec, S):
    with chk(rec, "W6-C18") as c:
        expect_error(c, lambda: study_env.client("cloudformation").validate_template(
            TemplateBody='{"Resources": {"Q": {"Type": "AWS::SQS::Queue"}'))


def test_c19_unknown_type(study_env, rec, S):
    with chk(rec, "W6-C19") as c:
        body = json.dumps({"Resources": {"Thing": {"Type": "AWS::Study::DoesNotExist", "Properties": {}}}})
        expect_error(c, lambda: study_env.client("cloudformation").validate_template(TemplateBody=body))


def test_c20_undefined_ref(study_env, rec, S):
    with chk(rec, "W6-C20") as c:
        body = json.dumps({"Resources": {"Q": {"Type": "AWS::SQS::Queue",
                                               "Properties": {"DelaySeconds": {"Ref": "Missing"}}}}})
        expect_error(c, lambda: study_env.client("cloudformation").validate_template(TemplateBody=body))


def create_extra(study_env, S, tags, suffix: str, body: str, params=None):
    name = f"{S['stack']}-{suffix}"
    if suffix.replace("-", "").isalnum():  # an invalid name (C25) can never become a stack
        S["stacks"].append(name)
    return study_env.client("cloudformation").create_stack(
        StackName=name, TemplateBody=body, Tags=stack_tags(tags), Parameters=params or [])


def test_c21_missing_parameter(study_env, rec, S, tags):
    with chk(rec, "W6-C21") as c:
        expect_error(c, lambda: create_extra(study_env, S, tags, "noparam", TEMPLATE))


def test_c22_duplicate_name(study_env, rec, S, tags):
    with chk(rec, "W6-C22", "W6-C02") as c:
        expect_error(c, lambda: study_env.client("cloudformation").create_stack(
            StackName=S["stack"], TemplateBody=TEMPLATE, Tags=stack_tags(tags),
            Parameters=[{"ParameterKey": "AlbName", "ParameterValue": S["alb_name"]}]))


def test_c23_no_changes(study_env, rec, S):
    with chk(rec, "W6-C23", "W6-C17") as c:
        expect_error(c, lambda: study_env.client("cloudformation").update_stack(
            StackName=S["stack"], UsePreviousTemplate=True,
            Parameters=[{"ParameterKey": k, "UsePreviousValue": True} for k in ("AlbName", "Image")]))


def test_c24_rollback(study_env, rec, S, tags):
    with chk(rec, "W6-C24") as c:
        body = json.dumps({"Resources": {"Queue": {"Type": "AWS::SQS::Queue",
                                                   "Properties": {"VisibilityTimeout": 99999}}}})
        cfn = study_env.client("cloudformation")
        name = f"{S['stack']}-rollback"
        try:
            create_extra(study_env, S, tags, "rollback", body)
        except ClientError as exc:  # rejected up front also counts as rejected
            c.observe(error_code=code_of(exc), http_status=exc.response["ResponseMetadata"].get("HTTPStatusCode"))
            return
        status = wait_stack(cfn, name, S["lim"]["stack"])
        quietly(cfn.delete_stack, StackName=name)
        if status in ("ROLLBACK_COMPLETE", "CREATE_FAILED", "ROLLBACK_FAILED"):
            c.observe(error_code=status)
            return
        c.observe(accepted=True, status=status)
        raise AssertionError(f"the invalid stack ended {status}; real AWS rolls it back")


def test_c25_bad_stack_name(study_env, rec, S, tags):
    with chk(rec, "W6-C25") as c:
        expect_error(c, lambda: create_extra(study_env, S, tags, "bad_name!", TEMPLATE, params=[
            {"ParameterKey": "AlbName", "ParameterValue": S["alb_name"]}]))


# --- teardown -----------------------------------------------------------------------------

def global_resources(study_env, S) -> list[dict]:
    """CloudFront distributions held by this run's stacks (the only global resources in W6)."""
    cfn, cf = study_env.client("cloudformation"), study_env.client("cloudfront")
    found = []
    for name in dict.fromkeys(S["stacks"]):
        if stack_status(cfn, name) in (None, "DELETE_COMPLETE"):
            continue
        try:
            res = cfn.describe_stack_resources(StackName=name)["StackResources"]
        except ClientError:
            continue
        for r in res:
            if r["ResourceType"] == "AWS::CloudFront::Distribution" and r.get("PhysicalResourceId"):
                d = cf.get_distribution(Id=r["PhysicalResourceId"])["Distribution"]
                tags = {t["Key"]: t["Value"] for t in
                        cf.list_tags_for_resource(Resource=d["ARN"])["Tags"].get("Items", [])}
                found.append({"stack": name, "id": d["Id"], "domain": d.get("DomainName"),
                              "comment": d["DistributionConfig"].get("Comment"), "tags": tags})
    return found


def test_c26_delete(study_env, rec, S):
    if study_env.is_real:
        script = write_inventory(study_env, S)  # always list what is about to be deleted
        dists = global_resources(study_env, S)
        # Only ever delete this run's own distribution: its comment is this run's ALB name and it
        # carries the study tag. Anything else stops the delete outright.
        foreign = [d for d in dists if d["comment"] != S["alb_name"] or d["tags"].get("Project") != "emulator-study"]
        if foreign:
            S["kept"] = True
            pytest.fail(f"delete stopped: {foreign} is not this run's study distribution; nothing deleted")
        if confirm_mode(study_env):
            shown = "\n".join(f"  CloudFront {d['id']} ({d['domain']}) in stack {d['stack']}" for d in dists)
            if not ask_terminal(f"\nW6 will now delete its stacks, including these global resources:\n{shown}\n"
                                f"(full list: logs/w6-resources-{S['run_id']}.txt) Delete?"):
                S["kept"] = True
                pytest.skip(f"not confirmed: nothing deleted; review and run {script}")
    with chk(rec, "W6-C26") as c:  # runs even if creation failed, to remove what exists
        cfn = study_env.client("cloudformation")
        names = list(dict.fromkeys(S["stacks"]))
        for name in names:
            quietly(cfn.delete_stack, StackName=name)
        final = {}
        for name in names:
            status = wait_stack(cfn, name, S["lim"]["stack"])
            final[name] = status or "DELETE_COMPLETE"
        main = final.get(S["stack"])
        others_ok = all(v == "DELETE_COMPLETE" for v in final.values())
        c.observe(main=main, all_deleted=others_ok)
        assert main == "DELETE_COMPLETE", f"stack ended {main}; {first_failure(cfn, S['stack'])}"
        assert others_ok, f"stacks not deleted: {[k for k, v in final.items() if v != 'DELETE_COMPLETE']}"


def test_c27_gone(study_env, rec, S):
    with chk(rec, "W6-C27", "W6-C26", "W6-C04") as c:  # nothing to check if the stack never existed
        def code(fn, **kw):
            try:
                fn(**kw)
                return "exists"
            except ClientError as exc:
                return code_of(exc)

        out = S.get("out", {})
        stack = code(study_env.client("cloudformation").describe_stacks, StackName=S["stack"])
        alb = code(study_env.client("elbv2").describe_load_balancers, LoadBalancerArns=[out["AlbArn"]]) \
            if out.get("AlbArn") else None
        dist = code(study_env.client("cloudfront").get_distribution, Id=out["DistributionId"]) \
            if out.get("DistributionId") else None
        c.observe(stack=stack, alb=alb, distribution=dist)
        assert "exists" not in (stack, alb, dist)
        S["stacks"].clear()
