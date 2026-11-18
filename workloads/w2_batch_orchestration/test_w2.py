"""W2 Batch orchestration: a Step Functions state machine (Choice, Wait, Retry, Catch, Assign)
calling a Lambda function through the optimized integration (arn:aws:states:::lambda:invoke).

Resources are created through the service APIs (not CloudFormation), like W1.
Checks run in file order and share state. A check whose prerequisite failed is recorded
as 'blocked' and skipped.

State machine (JSONPath):
  Init (Pass, Assign batchId) -> Route (Choice on $.mode)
    "skip" -> Skipped (Succeed)
    "hold" -> LongPause (Wait, SecondsPath $.wait_seconds) -> Process
    default -> Pause (Wait 2 s) -> Process
  Process (Task, lambda:invoke, Retry TransientError x3, Catch PermanentError -> Failed)
    -> Record (Pass, Assign processed/attempt) -> Summarize (Pass, reads the variables) -> end
  Failed (Fail, Error BatchFailed)
"""
from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from harness.aws_helpers import create_function_retrying, create_workload_role, quietly, zip_dir
from harness.record import poll

WORKLOAD = "W2"
LAMBDA_DIR = Path(__file__).parent / "lambda"

T_ACTIVE = 120     # function / state machine becoming ready
T_EXEC = 180       # an execution reaching a terminal status
T_ROLE = 90        # a brand-new IAM role becoming assumable by states.amazonaws.com (real AWS lag)
WAIT_SECONDS = 2   # the Pause state
MAX_ATTEMPTS = 3   # Retry on TransientError
TERMINAL = {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"}

CHECKS = {
    "W2-C01": ("control", "Create the Lambda execution role"),
    "W2-C02": ("control", "Create the Python 3.12 worker function and wait for State Active"),
    "W2-C03": ("control", "Create the Step Functions role allowed to invoke the worker"),
    "W2-C04": ("control", "ValidateStateMachineDefinition returns OK for the W2 definition"),
    "W2-C05": ("control", "CreateStateMachine (STANDARD) returns a state machine ARN"),
    "W2-C06": ("control", "DescribeStateMachine reports ACTIVE, STANDARD and the same definition"),
    "W2-C07": ("control", "ListStateMachines includes the new state machine"),
    "W2-C08": ("data", "StartExecution returns an execution ARN and a start date"),
    "W2-C09": ("functional", "The happy-path execution reaches SUCCEEDED"),
    "W2-C10": ("functional", "Its output carries batch_id and value 42 read back from Assign variables"),
    "W2-C11": ("functional", "Its history shows the Wait state lasting at least 2 s and one Lambda attempt"),
    "W2-C12": ("functional", "An execution whose Lambda fails twice with TransientError reaches SUCCEEDED"),
    "W2-C13": ("functional", "Retry fired exactly twice: 3 Lambda attempts in history and attempt 2 in the output"),
    "W2-C14": ("functional", "A caught PermanentError ends FAILED with the Fail state's error and cause"),
    "W2-C15": ("functional", "PermanentError is not retried: one Lambda attempt in history"),
    "W2-C16": ("functional", "When retries run out the execution ends FAILED with error TransientError after 4 attempts"),
    "W2-C17": ("functional", "Choice routes mode skip to the Succeed state without calling Lambda"),
    "W2-C18": ("data", "StopExecution on a waiting execution ends it ABORTED"),
    "W2-C19": ("control", "CreateStateMachine whose StartAt names a missing state is rejected"),
    "W2-C20": ("control", "ValidateStateMachineDefinition returns FAIL for a Choice state with no Choices"),
    "W2-C21": ("control", "CreateStateMachine with States.ALL not last in a Retry list is rejected"),
    "W2-C22": ("control", "CreateStateMachine with a Fail state that has Next is rejected"),
    "W2-C23": ("control", "CreateStateMachine with a Wait state that sets both Seconds and Timestamp is rejected"),
    "W2-C24": ("control", "CreateStateMachine reusing the name with a different definition is rejected"),
    "W2-C25": ("data", "StartExecution with a name containing a space is rejected"),
    "W2-C26": ("data", "StartExecution with input that is not JSON is rejected"),
    "W2-C27": ("data", "StartExecution reusing a closed execution's name with different input is rejected"),
    "W2-C28": ("control", "Delete the state machine, function and roles without errors"),
    "W2-C29": ("control", "After deletion, the state machine and function report not found"),
}

# Negative checks: real AWS rejects the request. The check passes when the error occurs.
NEGATIVE = {"W2-C19", "W2-C20", "W2-C21", "W2-C22", "W2-C23", "W2-C24", "W2-C25", "W2-C26", "W2-C27"}


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


# --- definitions --------------------------------------------------------------------

def definition(function_arn: str) -> dict:
    return {
        "Comment": "W2 batch orchestration",
        "StartAt": "Init",
        "States": {
            "Init": {"Type": "Pass", "Assign": {"batchId.$": "$.batch_id"}, "Next": "Route"},
            "Route": {
                "Type": "Choice",
                "Choices": [
                    {"Variable": "$.mode", "StringEquals": "skip", "Next": "Skipped"},
                    {"Variable": "$.mode", "StringEquals": "hold", "Next": "LongPause"},
                ],
                "Default": "Pause",
            },
            "Pause": {"Type": "Wait", "Seconds": WAIT_SECONDS, "Next": "Process"},
            "LongPause": {"Type": "Wait", "SecondsPath": "$.wait_seconds", "Next": "Process"},
            "Process": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {
                    "FunctionName": function_arn,
                    "Payload": {
                        "mode.$": "$.mode",
                        "n.$": "$.n",
                        "fail_times.$": "$.fail_times",
                        "retry.$": "$$.State.RetryCount",
                    },
                },
                "ResultSelector": {"result.$": "$.Payload"},
                "Retry": [{"ErrorEquals": ["TransientError"], "IntervalSeconds": 1,
                           "MaxAttempts": MAX_ATTEMPTS, "BackoffRate": 1.0}],
                "Catch": [{"ErrorEquals": ["PermanentError"], "ResultPath": "$.error", "Next": "Failed"}],
                "Next": "Record",
            },
            "Record": {"Type": "Pass",
                       "Assign": {"processed.$": "$.result.value", "attempt.$": "$.result.attempt"},
                       "Next": "Summarize"},
            "Summarize": {"Type": "Pass",
                          "Parameters": {"batch_id.$": "$batchId", "value.$": "$processed",
                                         "attempt.$": "$attempt", "status": "done"},
                          "End": True},
            "Failed": {"Type": "Fail", "Error": "BatchFailed", "Cause": "PermanentError caught"},
            "Skipped": {"Type": "Succeed"},
        },
    }


def tiny(**extra_state) -> dict:
    """A one-state machine, for the definition negative checks."""
    return {"StartAt": "Only", "States": {"Only": {"Type": "Pass", "End": True, **extra_state}}}


def job(batch_id: str, mode: str = "work", n: int = 21, fail_times: int = 0, **extra) -> str:
    return json.dumps({"batch_id": batch_id, "mode": mode, "n": n, "fail_times": fail_times, **extra})


# --- helpers ----------------------------------------------------------------------------

def create_state_machine_retrying(env, timeout: float = T_ROLE, **kwargs) -> dict:
    """create_state_machine, retrying while a brand-new role is not yet assumable (real AWS lag)."""
    sfn = env.client("stepfunctions")
    deadline, retries = time.monotonic() + timeout, 0
    while True:
        try:
            resp = sfn.create_state_machine(**kwargs)
            resp["emst_role_retries"] = retries
            return resp
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "").lower()
            if code_of(exc) in ("AccessDeniedException", "InvalidArn") and "role" in msg \
                    and time.monotonic() < deadline:
                retries += 1
                time.sleep(5)
                continue
            raise


def wait_role_usable(env, S, prefix: str, timeout: float = T_ROLE) -> tuple[int, bool]:
    """CreateStateMachine can succeed before states.amazonaws.com can assume a brand-new role
    (IAM propagation lag on real AWS). Run cheap probe executions (mode "fail", caught -> BatchFailed)
    until one gets past that, so the measured executions never see the lag."""
    deadline, n, ok = time.monotonic() + timeout, 0, 0
    while True:
        n += 1
        arn = start(env, S, f"probe{n}", f"{prefix}-probe{n}", job(f"{prefix}-probe{n}", mode="fail"))
        d = wait_done(env, arn, timeout=60)
        if "not authorized to assume" not in (d.get("cause") or ""):
            ok += 1
            if ok >= 3:  # IAM propagates host by host: one good probe is not enough
                return n, True
            continue
        ok = 0
        if time.monotonic() >= deadline:
            return n, False
        time.sleep(5)


def start(env, S, key: str, name: str, payload: str) -> str:
    arn = env.client("stepfunctions").start_execution(
        stateMachineArn=S["sm_arn"], name=name, input=payload)["executionArn"]
    S["executions"][key] = arn
    if not key.startswith("probe"):
        _STARTED[arn] = (env, S, key, name, payload)
    return arn


_STARTED: dict = {}
ROLE_LAG = "not authorized to assume"
MAX_ROLE_RESTARTS = 4


def wait_done(env, arn: str, timeout: float = T_EXEC) -> dict:
    """Wait for an execution to finish. On real AWS a new role can still fail to be assumed on some
    hosts minutes after the first good probe (IAM propagates unevenly). An execution that failed only
    for that reason never ran the workflow, so it is started again under a new name (counted in
    S["role_restarts"]). Emulators never hit this."""
    sfn = env.client("stepfunctions")
    for attempt in range(MAX_ROLE_RESTARTS + 1):
        poll(lambda: sfn.describe_execution(executionArn=arn)["status"] in TERMINAL, timeout, interval=1)
        d = sfn.describe_execution(executionArn=arn)
        if ROLE_LAG not in (d.get("cause") or "") or arn not in _STARTED or attempt == MAX_ROLE_RESTARTS:
            return d
        e, S, key, name, payload = _STARTED[arn]
        S["role_restarts"] = S.get("role_restarts", 0) + 1
        time.sleep(15)
        arn = start(e, S, key, f"{name}-r{attempt + 1}", payload)
    return d


def history(env, arn: str) -> list[dict]:
    pages = env.client("stepfunctions").get_paginator("get_execution_history").paginate(executionArn=arn)
    return [e for p in pages for e in p["events"]]


def lambda_attempts(events: list[dict]) -> int:
    """Lambda calls in a history: TaskScheduled (optimized integration) or LambdaFunctionScheduled."""
    return sum(1 for e in events if e["type"] in ("TaskScheduled", "LambdaFunctionScheduled"))


def task_event_style(events: list[dict]) -> str | None:
    if any(e["type"].startswith("Task") for e in events):
        return "Task"
    if any(e["type"].startswith("LambdaFunction") for e in events):
        return "LambdaFunction"
    return None


def as_dt(value) -> datetime:
    return value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def output_of(desc: dict):
    try:
        return json.loads(desc.get("output") or "null")
    except ValueError:
        return desc.get("output")


@pytest.fixture(scope="module")
def S(study_env, prefix):
    """Shared state; cleans up whatever exists when the module ends, pass or fail."""
    state = {"names": {
        "fn_role": f"{prefix}-fn-role", "sm_role": f"{prefix}-sm-role",
        "function": f"{prefix}-worker", "sm": f"{prefix}-batch",
    }, "executions": {}, "extra_sms": []}
    yield state
    sfn, lam, iam = (study_env.client(s) for s in ("stepfunctions", "lambda", "iam"))
    for arn in state["executions"].values():
        quietly(sfn.stop_execution, executionArn=arn, error="StudyCleanup", cause="W2 teardown")
    for arn in [state.get("sm_arn"), *state["extra_sms"]]:
        if arn:
            quietly(sfn.delete_state_machine, stateMachineArn=arn)
    quietly(lam.delete_function, FunctionName=state["names"]["function"])
    for role in (state["names"]["fn_role"], state["names"]["sm_role"]):
        quietly(iam.delete_role_policy, RoleName=role, PolicyName="workload")
        quietly(iam.delete_role, RoleName=role)
    quietly(study_env.client("logs").delete_log_group, logGroupName=f"/aws/lambda/{state['names']['function']}")
    if study_env.kind == "real":  # late log delivery recreates the group; delete it once more
        time.sleep(20)
        quietly(study_env.client("logs").delete_log_group, logGroupName=f"/aws/lambda/{state['names']['function']}")


# --- provisioning ----------------------------------------------------------------------

def test_c01_create_fn_role(study_env, rec, S, tags):
    with chk(rec, "W2-C01"):
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
             "Resource": "*"}]}
        S["fn_role_arn"] = create_workload_role(study_env, S["names"]["fn_role"], "lambda.amazonaws.com",
                                                policy, tags)["Arn"]


def test_c02_create_function(study_env, rec, S, tags):
    with chk(rec, "W2-C02", "W2-C01") as c:
        resp = create_function_retrying(
            study_env,
            FunctionName=S["names"]["function"],
            Runtime="python3.12",
            Handler="handler.handler",
            Role=S["fn_role_arn"],
            Code={"ZipFile": zip_dir(LAMBDA_DIR)},
            Timeout=10,
            MemorySize=128,
            Tags=tags,
        )
        S["fn_arn"] = resp["FunctionArn"]
        lam = study_env.client("lambda")
        active = poll(lambda: lam.get_function_configuration(FunctionName=S["names"]["function"]).get("State")
                      == "Active", T_ACTIVE)
        last = lam.get_function_configuration(FunctionName=S["names"]["function"]).get("State")
        c.observe(role_retries=resp["emst_role_retries"], final_state=last)
        assert active, f"function State is {last!r}, expected 'Active'"


def test_c03_create_sm_role(study_env, rec, S, tags):
    with chk(rec, "W2-C03", "W2-C02"):
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "lambda:InvokeFunction",
             "Resource": [S["fn_arn"], f"{S['fn_arn']}:*"]}]}
        S["sm_role_arn"] = create_workload_role(study_env, S["names"]["sm_role"], "states.amazonaws.com",
                                                policy, tags)["Arn"]


def test_c04_validate(study_env, rec, S):
    with chk(rec, "W2-C04", "W2-C02") as c:
        resp = study_env.client("stepfunctions").validate_state_machine_definition(
            definition=json.dumps(definition(S["fn_arn"])), type="STANDARD")
        c.observe(result=resp.get("result"))
        assert resp.get("result") == "OK", resp.get("diagnostics")


def test_c05_create_state_machine(study_env, rec, S, tags, prefix):
    with chk(rec, "W2-C05", "W2-C03") as c:
        S["definition"] = definition(S["fn_arn"])
        resp = create_state_machine_retrying(
            study_env, name=S["names"]["sm"], definition=json.dumps(S["definition"]),
            roleArn=S["sm_role_arn"], type="STANDARD",
            tags=[{"key": k, "value": v} for k, v in tags.items()],
        )
        S["sm_arn"] = resp["stateMachineArn"]
        probes, ready = wait_role_usable(study_env, S, prefix)
        c.observe(role_retries=resp["emst_role_retries"], role_probes=probes, role_ready=ready,
                  arn_suffix=S["sm_arn"].endswith(f":{S['names']['sm']}"))
        assert S["sm_arn"].startswith("arn:aws:states:")
        assert ready, f"states.amazonaws.com still could not assume the role after {probes} probe executions"


def test_c06_describe_state_machine(study_env, rec, S):
    with chk(rec, "W2-C06", "W2-C05") as c:
        d = study_env.client("stepfunctions").describe_state_machine(stateMachineArn=S["sm_arn"])
        same = json.loads(d.get("definition", "{}")) == S["definition"]
        c.observe(status=d.get("status"), type=d.get("type"), same_definition=same)
        assert d.get("status") == "ACTIVE" and d.get("type") == "STANDARD"
        assert same, "definition differs from what was created"


def test_c07_list_state_machines(study_env, rec, S):
    with chk(rec, "W2-C07", "W2-C05") as c:
        pages = study_env.client("stepfunctions").get_paginator("list_state_machines").paginate()
        found = [m for p in pages for m in p["stateMachines"] if m["stateMachineArn"] == S["sm_arn"]]
        c.observe(found=len(found), type=found[0].get("type") if found else None)
        assert len(found) == 1 and found[0]["name"] == S["names"]["sm"]


# --- executions ------------------------------------------------------------------------

def test_c08_start_execution(study_env, rec, S, prefix):
    with chk(rec, "W2-C08", "W2-C05") as c:
        S["happy_name"] = f"{prefix}-happy"
        S["happy_input"] = job(f"{prefix}-b1")
        arn = start(study_env, S, "happy", S["happy_name"], S["happy_input"])
        resp_start = study_env.client("stepfunctions").describe_execution(executionArn=arn).get("startDate")
        c.observe(has_arn=arn.startswith("arn:aws:states:"), has_start=resp_start is not None)
        assert arn.startswith("arn:aws:states:") and resp_start is not None


def test_c09_happy_succeeds(study_env, rec, S):
    with chk(rec, "W2-C09", "W2-C08") as c:
        d = wait_done(study_env, S["executions"]["happy"])
        S["happy_desc"] = d
        c.observe(status=d["status"], error=d.get("error"))
        assert d["status"] == "SUCCEEDED", f"status {d['status']}: {d.get('error')} {d.get('cause')}"


def test_c10_happy_output(study_env, rec, S, prefix):
    with chk(rec, "W2-C10", "W2-C09") as c:
        out = output_of(S["happy_desc"])
        c.observe(output={**out, "batch_id": out.get("batch_id") == f"{prefix}-b1"} if isinstance(out, dict) else out)
        assert out == {"batch_id": f"{prefix}-b1", "value": 42, "attempt": 0, "status": "done"}


def test_c11_happy_history(study_env, rec, S):
    with chk(rec, "W2-C11", "W2-C09") as c:
        events = history(study_env, S["executions"]["happy"])
        entered = [e for e in events if e["type"] == "WaitStateEntered"]
        exited = [e for e in events if e["type"] == "WaitStateExited"]
        waited = (as_dt(exited[0]["timestamp"]) - as_dt(entered[0]["timestamp"])).total_seconds() \
            if entered and exited else None
        c.observe(wait_events=bool(entered and exited), seconds=waited, lambda_attempts=lambda_attempts(events),
                  task_event_style=task_event_style(events))
        assert waited is not None and waited >= WAIT_SECONDS - 0.1, f"Wait lasted {waited} s"
        assert lambda_attempts(events) == 1


def test_c12_flaky_succeeds(study_env, rec, S, prefix):
    with chk(rec, "W2-C12", "W2-C05") as c:
        arn = start(study_env, S, "flaky", f"{prefix}-flaky", job(f"{prefix}-b2", n=5, fail_times=2))
        d = wait_done(study_env, arn)
        S["flaky_desc"] = d
        c.observe(status=d["status"], error=d.get("error"))
        assert d["status"] == "SUCCEEDED", f"status {d['status']}: {d.get('error')} {d.get('cause')}"


def test_c13_retry_count(study_env, rec, S):
    with chk(rec, "W2-C13", "W2-C12") as c:
        attempts = lambda_attempts(history(study_env, S["executions"]["flaky"]))
        out = output_of(S["flaky_desc"]) or {}
        c.observe(lambda_attempts=attempts, attempt=out.get("attempt"), value=out.get("value"))
        assert attempts == 3, f"{attempts} Lambda attempts, expected 3"
        assert out.get("attempt") == 2 and out.get("value") == 10


def test_c14_caught_failure(study_env, rec, S, prefix):
    with chk(rec, "W2-C14", "W2-C05") as c:
        arn = start(study_env, S, "fail", f"{prefix}-fail", job(f"{prefix}-b3", mode="fail"))
        d = wait_done(study_env, arn)
        c.observe(status=d["status"], error=d.get("error"), cause=d.get("cause"))
        assert d["status"] == "FAILED"
        assert d.get("error") == "BatchFailed" and d.get("cause") == "PermanentError caught"


def test_c15_not_retried(study_env, rec, S):
    with chk(rec, "W2-C15", "W2-C14") as c:
        attempts = lambda_attempts(history(study_env, S["executions"]["fail"]))
        c.observe(lambda_attempts=attempts)
        assert attempts == 1, f"{attempts} Lambda attempts, expected 1"


def test_c16_retries_exhausted(study_env, rec, S, prefix):
    with chk(rec, "W2-C16", "W2-C05") as c:
        arn = start(study_env, S, "exhausted", f"{prefix}-exhausted", job(f"{prefix}-b4", fail_times=10))
        d = wait_done(study_env, arn)
        attempts = lambda_attempts(history(study_env, d["executionArn"]))
        c.observe(status=d["status"], error=d.get("error"), lambda_attempts=attempts)
        assert d["status"] == "FAILED" and d.get("error") == "TransientError", \
            f"{d['status']} {d.get('error')}: {(d.get('cause') or '')[:300]}"
        assert attempts == MAX_ATTEMPTS + 1, f"{attempts} Lambda attempts, expected {MAX_ATTEMPTS + 1}"


def test_c17_choice_skip(study_env, rec, S, prefix):
    with chk(rec, "W2-C17", "W2-C05") as c:
        payload = job(f"{prefix}-b5", mode="skip")
        arn = start(study_env, S, "skip", f"{prefix}-skip", payload)
        d = wait_done(study_env, arn)
        attempts = lambda_attempts(history(study_env, d["executionArn"]))
        out = output_of(d)
        c.observe(status=d["status"], lambda_attempts=attempts, output_is_input=out == json.loads(payload))
        assert d["status"] == "SUCCEEDED" and attempts == 0
        assert out == json.loads(payload)


def test_c18_stop_execution(study_env, rec, S, prefix):
    with chk(rec, "W2-C18", "W2-C05") as c:
        sfn = study_env.client("stepfunctions")
        arn = start(study_env, S, "hold", f"{prefix}-hold", job(f"{prefix}-b6", mode="hold", wait_seconds=600))
        running = poll(lambda: sfn.describe_execution(executionArn=arn)["status"] == "RUNNING", 30, interval=1)
        sfn.stop_execution(executionArn=arn, error="StudyStop", cause="stopped by W2-C18")
        d = wait_done(study_env, arn, timeout=60)
        c.observe(was_running=bool(running), status=d["status"], error=d.get("error"), cause=d.get("cause"))
        assert d["status"] == "ABORTED"


# --- negative checks ------------------------------------------------------------------------

def _create_bad(study_env, S, c, name: str, bad: dict):
    sfn = study_env.client("stepfunctions")
    try:
        expect_error(c, lambda: sfn.create_state_machine(name=name, definition=json.dumps(bad),
                                                         roleArn=S["sm_role_arn"], type="STANDARD"))
    finally:
        if getattr(c, "accepted_result", None):
            S["extra_sms"].append(c.accepted_result["stateMachineArn"])


def test_c19_missing_start_state(study_env, rec, S, prefix):
    with chk(rec, "W2-C19", "W2-C05") as c:
        _create_bad(study_env, S, c, f"{prefix}-bad-start",
                    {"StartAt": "Nowhere", "States": {"Only": {"Type": "Pass", "End": True}}})


def test_c20_validate_fail(study_env, rec, S):
    with chk(rec, "W2-C20", "W2-C05") as c:
        bad = {"StartAt": "Pick", "States": {"Pick": {"Type": "Choice", "Choices": [], "Default": "Done"},
                                              "Done": {"Type": "Succeed"}}}
        resp = study_env.client("stepfunctions").validate_state_machine_definition(
            definition=json.dumps(bad), type="STANDARD")
        c.observe(result=resp.get("result"))
        if resp.get("result") != "FAIL":
            c.observe(accepted=True)
        assert resp.get("result") == "FAIL"


def test_c21_states_all_not_last(study_env, rec, S, prefix):
    with chk(rec, "W2-C21", "W2-C05") as c:
        bad = {"StartAt": "Call", "States": {"Call": {
            "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": {"FunctionName": S["fn_arn"], "Payload": {}},
            "Retry": [{"ErrorEquals": ["States.ALL", "TransientError"], "MaxAttempts": 1}],
            "End": True}}}
        _create_bad(study_env, S, c, f"{prefix}-bad-retry", bad)


def test_c22_fail_with_next(study_env, rec, S, prefix):
    with chk(rec, "W2-C22", "W2-C05") as c:
        bad = {"StartAt": "Stop", "States": {"Stop": {"Type": "Fail", "Error": "X", "Next": "Done"},
                                              "Done": {"Type": "Succeed"}}}
        _create_bad(study_env, S, c, f"{prefix}-bad-fail", bad)


def test_c23_wait_two_fields(study_env, rec, S, prefix):
    with chk(rec, "W2-C23", "W2-C05") as c:
        bad = {"StartAt": "Hold", "States": {"Hold": {"Type": "Wait", "Seconds": 1,
                                                      "Timestamp": "2030-01-01T00:00:00Z", "End": True}}}
        _create_bad(study_env, S, c, f"{prefix}-bad-wait", bad)


def test_c24_name_taken(study_env, rec, S):
    with chk(rec, "W2-C24", "W2-C05") as c:
        sfn = study_env.client("stepfunctions")
        expect_error(c, lambda: sfn.create_state_machine(
            name=S["names"]["sm"], definition=json.dumps(tiny()), roleArn=S["sm_role_arn"], type="STANDARD"))


def test_c25_bad_execution_name(study_env, rec, S, prefix):
    with chk(rec, "W2-C25", "W2-C05") as c:
        try:
            expect_error(c, lambda: study_env.client("stepfunctions").start_execution(
                stateMachineArn=S["sm_arn"], name=f"{prefix} bad name", input=job(f"{prefix}-b7", mode="skip")))
        finally:
            if getattr(c, "accepted_result", None):
                S["executions"]["bad_name"] = c.accepted_result["executionArn"]


def test_c26_input_not_json(study_env, rec, S, prefix):
    with chk(rec, "W2-C26", "W2-C05") as c:
        try:
            expect_error(c, lambda: study_env.client("stepfunctions").start_execution(
                stateMachineArn=S["sm_arn"], name=f"{prefix}-notjson", input="{not json"))
        finally:
            if getattr(c, "accepted_result", None):
                S["executions"]["not_json"] = c.accepted_result["executionArn"]


def test_c27_name_reused(study_env, rec, S, prefix):
    with chk(rec, "W2-C27", "W2-C09") as c:
        # The happy execution is closed (C09); reusing its name with other input must fail.
        expect_error(c, lambda: study_env.client("stepfunctions").start_execution(
            stateMachineArn=S["sm_arn"], name=S["happy_name"], input=job(f"{prefix}-other", mode="skip")))


# --- teardown --------------------------------------------------------------------------

def test_c28_teardown(study_env, rec, S):
    with chk(rec, "W2-C28", "W2-C05") as c:
        sfn, lam, iam = (study_env.client(s) for s in ("stepfunctions", "lambda", "iam"))
        steps = []
        sfn.delete_state_machine(stateMachineArn=S["sm_arn"]); steps.append("state_machine")
        lam.delete_function(FunctionName=S["names"]["function"]); steps.append("function")
        for role in (S["names"]["sm_role"], S["names"]["fn_role"]):
            iam.delete_role_policy(RoleName=role, PolicyName="workload")
            iam.delete_role(RoleName=role)
        steps.append("roles")
        c.observe(deleted=steps)


def test_c29_gone_after_delete(study_env, rec, S):
    with chk(rec, "W2-C29", "W2-C28") as c:
        codes = {}

        def probe(fn, deleting_ok=False):
            try:
                result = fn()
                if deleting_ok and result.get("status") == "DELETING":
                    return "DELETING"
                return "still-exists"
            except ClientError as exc:
                return code_of(exc)

        def all_gone():
            codes["state_machine"] = probe(lambda: study_env.client("stepfunctions").describe_state_machine(
                stateMachineArn=S["sm_arn"]), deleting_ok=True)
            codes["function"] = probe(lambda: study_env.client("lambda").get_function(
                FunctionName=S["names"]["function"]))
            return all(v != "still-exists" for v in codes.values())
        ok = poll(all_gone, 90, interval=5)
        c.observe(role_restarts=S.get("role_restarts", 0), **{f"{k}_code": v for k, v in codes.items()})
        assert ok, f"not all deleted: {codes}"
