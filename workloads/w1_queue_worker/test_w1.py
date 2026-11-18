"""W1 Queue worker: SQS -> Lambda -> DynamoDB, with a dead-letter queue and partial batch failures.

Resources are created through the service APIs (not CloudFormation), so W1 measures SQS,
Lambda and DynamoDB behavior on their own; CloudFormation is W6's job.

Checks run in file order and share state. A check whose prerequisite failed is recorded
as 'blocked' and skipped.
"""
from __future__ import annotations

import hashlib
import json
import time
from decimal import Decimal
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from harness.aws_helpers import create_function_retrying, create_workload_role, quietly, zip_dir
from harness.record import poll

WORKLOAD = "W1"
LAMBDA_DIR = Path(__file__).parent / "lambda"

# Waits. Generous, because real AWS is the yardstick and some steps take minutes there.
T_ACTIVE = 120       # table / function / mapping becoming ready
T_PROCESS = 120      # message -> DynamoDB item
T_DLQ = 300          # poison message -> DLQ (2 receives x 20 s visibility + backoff)
T_LOGS = 120
QUIET_WINDOW = 30    # how long a disabled mapping must leave a message alone
SETTLE = 90          # real AWS pollers keep running briefly after a mapping reports Disabled
MAX_RECEIVE = 2
VISIBILITY = 20

CHECKS = {
    "W1-C01": ("control", "Create the dead-letter queue and read its ARN"),
    "W1-C02": ("control", "Create the main queue with a redrive policy (maxReceiveCount 2) and 20 s visibility timeout"),
    "W1-C03": ("control", "Main queue attributes return the redrive policy and visibility timeout as set"),
    "W1-C04": ("control", "Create an on-demand DynamoDB table and wait for ACTIVE"),
    "W1-C05": ("control", "DescribeTable reports on-demand billing and the pk hash key"),
    "W1-C06": ("control", "Create the Lambda execution role with an inline policy"),
    "W1-C07": ("control", "Create the Python 3.12 function and wait for State Active"),
    "W1-C08": ("control", "GetFunctionConfiguration returns runtime, handler, timeout, memory and env vars as set"),
    "W1-C09": ("control", "Create the SQS event source mapping (batch 5, ReportBatchItemFailures)"),
    "W1-C10": ("control", "The event source mapping reaches State Enabled"),
    "W1-C11": ("control", "ListEventSourceMappings returns exactly this mapping with its settings"),
    "W1-C12": ("data", "SendMessage returns a MessageId and the correct MD5 of the body"),
    "W1-C13": ("data", "SendMessageBatch of 10 reports 10 successful, 0 failed"),
    "W1-C14": ("data", "SendMessage to a queue that does not exist raises an error"),
    "W1-C15": ("data", "GetItem for a missing key returns no Item"),
    "W1-C16": ("data", "A second conditional PutItem (attribute_not_exists) raises ConditionalCheckFailedException"),
    "W1-C17": ("data", "Direct Invoke with a synthetic SQS event returns 200 and no batch item failures"),
    "W1-C18": ("data", "Invoke with a payload the handler can't read returns FunctionError"),
    "W1-C19": ("functional", "A sent message becomes a DynamoDB item via the mapping"),
    "W1-C20": ("functional", "The item's amount, run marker and message ID match the message"),
    "W1-C21": ("functional", "All 10 batch messages become items"),
    "W1-C22": ("functional", "The main queue drains to 0 visible and 0 in-flight messages"),
    "W1-C23": ("functional", "A poison message reaches the DLQ after maxReceiveCount receives"),
    "W1-C24": ("functional", "The poison message is never written to the table"),
    "W1-C25": ("functional", "The DLQ message body equals the original body"),
    "W1-C26": ("functional", "Partial batch failure: 4 good items written, only the poison message goes to the DLQ"),
    "W1-C27": ("functional", "The function's log lines appear in CloudWatch Logs"),
    "W1-C28": ("functional", "A disabled mapping leaves a new message in the queue"),
    "W1-C29": ("functional", "Re-enabling the mapping processes the waiting message"),
    "W1-C30": ("control", "Delete the mapping, function, table, queues and role without errors"),
    "W1-C31": ("control", "After deletion, the table, function and queue report not found"),
    "W1-C32": ("data", "SendMessage with DelaySeconds 901 (max is 900) is rejected"),
    "W1-C33": ("data", "SendMessageBatch with two entries sharing one Id is rejected"),
    "W1-C34": ("control", "CreateQueue with a redrive policy naming a dead-letter queue that does not exist is rejected"),
    "W1-C35": ("data", "PutItem without the table's key attribute is rejected"),
    "W1-C36": ("control", "CreateTable with the name of an existing table is rejected"),
    "W1-C37": ("control", "An event source mapping on a queue whose visibility timeout (5 s) is below the function timeout (10 s) is rejected"),
}

# Negative checks: real AWS rejects the request. The check passes when the error occurs. If an
# emulator accepts the request instead, that is a false success (it accepts what AWS rejects).
NEGATIVE = {"W1-C14", "W1-C16", "W1-C18", "W1-C32", "W1-C33", "W1-C34", "W1-C35", "W1-C36", "W1-C37"}


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


def read_payload(resp) -> tuple[object, str]:
    """Invoke payload as JSON if it parses, plus the raw text (first 200 chars) for the record."""
    raw = resp["Payload"].read().decode("utf-8", "replace")
    try:
        return json.loads(raw), raw[:200]
    except ValueError:
        return None, raw[:200]


@pytest.fixture(scope="module")
def S(study_env, prefix):
    """Shared state; cleans up whatever exists when the module ends, pass or fail."""
    state = {"names": {
        "dlq": f"{prefix}-dlq", "queue": f"{prefix}-queue", "table": f"{prefix}-orders",
        "role": f"{prefix}-fn-role", "function": f"{prefix}-worker",
    }, "marker": f"{prefix}-marker", "extra_queues": [], "extra_esms": []}
    yield state
    sqs, lam, ddb, iam = (study_env.client(s) for s in ("sqs", "lambda", "dynamodb", "iam"))
    for uuid in [state.get("esm_uuid"), *state["extra_esms"]]:
        if uuid:
            quietly(lam.delete_event_source_mapping, UUID=uuid)
    for url in state["extra_queues"]:
        quietly(sqs.delete_queue, QueueUrl=url)
    quietly(lam.delete_function, FunctionName=state["names"]["function"])
    quietly(ddb.delete_table, TableName=state["names"]["table"])
    for key in ("queue_url", "dlq_url"):
        if state.get(key):
            quietly(sqs.delete_queue, QueueUrl=state[key])
    quietly(iam.delete_role_policy, RoleName=state["names"]["role"], PolicyName="workload")
    quietly(iam.delete_role, RoleName=state["names"]["role"])
    quietly(study_env.client("logs").delete_log_group, logGroupName=f"/aws/lambda/{state['names']['function']}")


def get_item(env, table: str, pk: str):
    return env.client("dynamodb").get_item(
        TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True
    ).get("Item")


def find_in_queue(env, url: str, needle: str, timeout: float, delete: bool = True) -> dict | None:
    """Receives from a queue until a message whose body contains needle shows up."""
    sqs = env.client("sqs")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for m in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=10, VisibilityTimeout=5,
            MessageSystemAttributeNames=["ApproximateReceiveCount"],
        ).get("Messages", []):
            if needle in m["Body"]:
                if delete:
                    sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
                return m
    return None


def queue_counts(env, url: str) -> tuple[int, int]:
    a = env.client("sqs").get_queue_attributes(
        QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"]
    )["Attributes"]
    return int(a.get("ApproximateNumberOfMessages", -1)), int(a.get("ApproximateNumberOfMessagesNotVisible", -1))


def mapping_state(env, uuid: str) -> str | None:
    return env.client("lambda").get_event_source_mapping(UUID=uuid).get("State")


# --- provisioning ----------------------------------------------------------------

def test_c01_create_dlq(study_env, rec, S, tags):
    sqs = study_env.client("sqs")
    with chk(rec, "W1-C01") as c:
        S["dlq_url"] = sqs.create_queue(QueueName=S["names"]["dlq"], tags=tags)["QueueUrl"]
        S["dlq_arn"] = sqs.get_queue_attributes(QueueUrl=S["dlq_url"], AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        c.observe(arn_suffix=S["dlq_arn"].rsplit(":", 1)[-1] == S["names"]["dlq"])
        assert S["dlq_arn"].startswith("arn:aws:sqs:")


def test_c02_create_main_queue(study_env, rec, S, tags):
    with chk(rec, "W1-C02", "W1-C01"):
        sqs = study_env.client("sqs")
        S["queue_url"] = sqs.create_queue(
            QueueName=S["names"]["queue"],
            Attributes={
                "VisibilityTimeout": str(VISIBILITY),
                "RedrivePolicy": json.dumps({"deadLetterTargetArn": S["dlq_arn"], "maxReceiveCount": str(MAX_RECEIVE)}),
            },
            tags=tags,
        )["QueueUrl"]
        S["queue_arn"] = sqs.get_queue_attributes(QueueUrl=S["queue_url"], AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def test_c03_redrive_readback(study_env, rec, S):
    with chk(rec, "W1-C03", "W1-C02") as c:
        a = study_env.client("sqs").get_queue_attributes(
            QueueUrl=S["queue_url"], AttributeNames=["RedrivePolicy", "VisibilityTimeout"]
        )["Attributes"]
        policy = json.loads(a.get("RedrivePolicy", "{}"))
        c.observe(max_receive=policy.get("maxReceiveCount"), visibility=a.get("VisibilityTimeout"),
                  max_receive_type=type(policy.get("maxReceiveCount")).__name__)
        assert int(policy["maxReceiveCount"]) == MAX_RECEIVE
        assert policy["deadLetterTargetArn"] == S["dlq_arn"]
        assert a["VisibilityTimeout"] == str(VISIBILITY)


def test_c04_create_table(study_env, rec, S, tags):
    ddb = study_env.client("dynamodb")
    with chk(rec, "W1-C04") as c:
        ddb.create_table(
            TableName=S["names"]["table"],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
            Tags=[{"Key": k, "Value": v} for k, v in tags.items()],
        )
        status = poll(lambda: ddb.describe_table(TableName=S["names"]["table"])["Table"]["TableStatus"] == "ACTIVE", T_ACTIVE)
        c.observe(active=bool(status))
        assert status, "table did not become ACTIVE"


def test_c05_describe_table(study_env, rec, S):
    with chk(rec, "W1-C05", "W1-C04") as c:
        t = study_env.client("dynamodb").describe_table(TableName=S["names"]["table"])["Table"]
        mode = t.get("BillingModeSummary", {}).get("BillingMode")
        c.observe(billing_mode=mode, key_schema=t.get("KeySchema"))
        assert mode == "PAY_PER_REQUEST"
        assert t["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}]


def test_c06_create_role(study_env, rec, S, tags):
    with chk(rec, "W1-C06", "W1-C02", "W1-C04"):
        table_arn = study_env.client("dynamodb").describe_table(TableName=S["names"]["table"])["Table"]["TableArn"]
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes",
                                               "sqs:ChangeMessageVisibility"], "Resource": S["queue_arn"]},
                {"Effect": "Allow", "Action": ["dynamodb:PutItem"], "Resource": table_arn},
                {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                 "Resource": "*"},
            ],
        }
        S["role_arn"] = create_workload_role(study_env, S["names"]["role"], "lambda.amazonaws.com", policy, tags)["Arn"]


def test_c07_create_function(study_env, rec, S, tags):
    with chk(rec, "W1-C07", "W1-C06") as c:
        resp = create_function_retrying(
            study_env,
            FunctionName=S["names"]["function"],
            Runtime="python3.12",
            Handler="handler.handler",
            Role=S["role_arn"],
            Code={"ZipFile": zip_dir(LAMBDA_DIR)},
            Timeout=10,
            MemorySize=128,
            Environment={"Variables": {"TABLE_NAME": S["names"]["table"],
                                       "STUDY_INNER_ENDPOINT": study_env.lambda_inner_endpoint}},
            Tags=tags,
        )
        lam = study_env.client("lambda")
        state = poll(lambda: lam.get_function_configuration(FunctionName=S["names"]["function"]).get("State") == "Active",
                     T_ACTIVE)
        last = lam.get_function_configuration(FunctionName=S["names"]["function"]).get("State")
        c.observe(role_retries=resp["emst_role_retries"], initial_state=resp.get("State"), final_state=last)
        assert state, f"function State is {last!r}, expected 'Active'"


def test_c08_function_configuration(study_env, rec, S):
    with chk(rec, "W1-C08", "W1-C07") as c:
        cfg = study_env.client("lambda").get_function_configuration(FunctionName=S["names"]["function"])
        env_vars = cfg.get("Environment", {}).get("Variables", {})
        c.observe(runtime=cfg.get("Runtime"), handler=cfg.get("Handler"), timeout=cfg.get("Timeout"),
                  memory=cfg.get("MemorySize"), env_keys=sorted(env_vars))
        assert cfg["Runtime"] == "python3.12" and cfg["Handler"] == "handler.handler"
        assert cfg["Timeout"] == 10 and cfg["MemorySize"] == 128
        assert env_vars.get("TABLE_NAME") == S["names"]["table"]


def test_c09_create_mapping(study_env, rec, S):
    with chk(rec, "W1-C09", "W1-C07") as c:
        resp = study_env.client("lambda").create_event_source_mapping(
            EventSourceArn=S["queue_arn"],
            FunctionName=S["names"]["function"],
            BatchSize=5,
            FunctionResponseTypes=["ReportBatchItemFailures"],
            Enabled=True,
        )
        S["esm_uuid"] = resp["UUID"]
        c.observe(initial_state=resp.get("State"))


def test_c10_mapping_enabled(study_env, rec, S):
    with chk(rec, "W1-C10", "W1-C09") as c:
        ok = poll(lambda: mapping_state(study_env, S["esm_uuid"]) == "Enabled", T_ACTIVE)
        c.observe(final_state=mapping_state(study_env, S["esm_uuid"]))
        assert ok


def test_c11_list_mappings(study_env, rec, S):
    with chk(rec, "W1-C11", "W1-C09") as c:
        maps = study_env.client("lambda").list_event_source_mappings(FunctionName=S["names"]["function"])["EventSourceMappings"]
        c.observe(count=len(maps), batch_size=maps[0].get("BatchSize") if maps else None,
                  response_types=maps[0].get("FunctionResponseTypes") if maps else None)
        assert len(maps) == 1
        assert maps[0]["EventSourceArn"] == S["queue_arn"] and maps[0]["BatchSize"] == 5
        assert maps[0].get("FunctionResponseTypes") == ["ReportBatchItemFailures"]


# --- data plane --------------------------------------------------------------------

def test_c12_send_md5(study_env, rec, S, prefix):
    with chk(rec, "W1-C12", "W1-C02") as c:
        S["o1"] = f"{prefix}-o1"
        body = json.dumps({"order_id": S["o1"], "amount": 12.5, "run_marker": S["marker"]})
        resp = study_env.client("sqs").send_message(QueueUrl=S["queue_url"], MessageBody=body)
        S["o1_message_id"] = resp.get("MessageId")
        c.observe(md5_match=resp.get("MD5OfMessageBody") == hashlib.md5(body.encode()).hexdigest())
        assert resp.get("MessageId")
        assert resp.get("MD5OfMessageBody") == hashlib.md5(body.encode()).hexdigest()


def test_c13_send_batch(study_env, rec, S, prefix):
    with chk(rec, "W1-C13", "W1-C02") as c:
        S["batch_ids"] = [f"{prefix}-b{i}" for i in range(10)]
        resp = study_env.client("sqs").send_message_batch(
            QueueUrl=S["queue_url"],
            Entries=[{"Id": f"e{i}", "MessageBody": json.dumps({"order_id": oid, "amount": i, "run_marker": S["marker"]})}
                     for i, oid in enumerate(S["batch_ids"])],
        )
        c.observe(successful=len(resp.get("Successful", [])), failed=len(resp.get("Failed", [])))
        assert len(resp.get("Successful", [])) == 10 and not resp.get("Failed")


def test_c14_send_missing_queue(study_env, rec, S, prefix):
    with chk(rec, "W1-C14", "W1-C02") as c:
        bad_url = S["queue_url"].rsplit("/", 1)[0] + f"/{prefix}-does-not-exist"
        expect_error(c, lambda: study_env.client("sqs").send_message(QueueUrl=bad_url, MessageBody="x"))


def test_c15_get_missing_item(study_env, rec, S, prefix):
    with chk(rec, "W1-C15", "W1-C04") as c:
        item = get_item(study_env, S["names"]["table"], f"{prefix}-missing")
        c.observe(item_present=item is not None)
        assert item is None


def test_c16_conditional_put(study_env, rec, S, prefix):
    with chk(rec, "W1-C16", "W1-C04") as c:
        ddb = study_env.client("dynamodb")
        args = dict(TableName=S["names"]["table"], Item={"pk": {"S": f"{prefix}-cond"}},
                    ConditionExpression="attribute_not_exists(pk)")
        ddb.put_item(**args)
        expect_error(c, lambda: ddb.put_item(**args))


def test_c17_direct_invoke(study_env, rec, S, prefix):
    with chk(rec, "W1-C17", "W1-C07") as c:
        event = {"Records": [{"messageId": "direct-1", "body": json.dumps({"order_id": f"{prefix}-direct", "amount": 1})}]}
        resp = study_env.client("lambda").invoke(FunctionName=S["names"]["function"], Payload=json.dumps(event).encode())
        payload, raw = read_payload(resp)
        c.observe(status=resp.get("StatusCode"), function_error=resp.get("FunctionError"), payload=payload,
                  raw_payload=None if payload is not None else raw)
        assert resp["StatusCode"] == 200 and not resp.get("FunctionError")
        assert payload == {"batchItemFailures": []}


def test_c18_invoke_unhandled(study_env, rec, S):
    with chk(rec, "W1-C18", "W1-C07") as c:
        resp = study_env.client("lambda").invoke(FunctionName=S["names"]["function"], Payload=b'"not-an-event"')
        payload, raw = read_payload(resp)
        c.observe(status=resp.get("StatusCode"), function_error=resp.get("FunctionError"),
                  error_type=payload.get("errorType") if isinstance(payload, dict) else None,
                  raw_payload=None if payload is not None else raw)
        if not resp.get("FunctionError"):
            c.observe(accepted=True)
        assert resp.get("FunctionError") == "Unhandled"


def test_c32_delay_too_long(study_env, rec, S):
    with chk(rec, "W1-C32", "W1-C01") as c:
        # Sent to the DLQ (no consumer), so an emulator that accepts it can't disturb later checks.
        expect_error(c, lambda: study_env.client("sqs").send_message(
            QueueUrl=S["dlq_url"], MessageBody=json.dumps({"order_id": "never", "fail": True}), DelaySeconds=901))


def test_c33_duplicate_batch_ids(study_env, rec, S):
    with chk(rec, "W1-C33", "W1-C01") as c:
        body = json.dumps({"order_id": "never", "fail": True})
        expect_error(c, lambda: study_env.client("sqs").send_message_batch(
            QueueUrl=S["dlq_url"], Entries=[{"Id": "same", "MessageBody": body}, {"Id": "same", "MessageBody": body}]))


def test_c34_redrive_to_missing_dlq(study_env, rec, S, prefix, tags):
    with chk(rec, "W1-C34", "W1-C01") as c:
        sqs = study_env.client("sqs")
        missing_arn = S["dlq_arn"].rsplit(":", 1)[0] + f":{prefix}-no-such-dlq"
        try:
            expect_error(c, lambda: sqs.create_queue(
                QueueName=f"{prefix}-bad-redrive",
                Attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": missing_arn, "maxReceiveCount": "2"})},
                tags=tags))
        finally:
            if getattr(c, "accepted_result", None):
                S["extra_queues"].append(c.accepted_result["QueueUrl"])


def test_c35_put_without_key(study_env, rec, S):
    with chk(rec, "W1-C35", "W1-C04") as c:
        expect_error(c, lambda: study_env.client("dynamodb").put_item(
            TableName=S["names"]["table"], Item={"not_the_key": {"S": "x"}}))


def test_c36_create_existing_table(study_env, rec, S):
    with chk(rec, "W1-C36", "W1-C04") as c:
        expect_error(c, lambda: study_env.client("dynamodb").create_table(
            TableName=S["names"]["table"],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST"))


def test_c37_mapping_low_visibility(study_env, rec, S, prefix, tags):
    with chk(rec, "W1-C37", "W1-C07") as c:
        sqs, lam = study_env.client("sqs"), study_env.client("lambda")
        url = sqs.create_queue(QueueName=f"{prefix}-lowvis", Attributes={"VisibilityTimeout": "5"}, tags=tags)["QueueUrl"]
        S["extra_queues"].append(url)
        arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        try:
            expect_error(c, lambda: lam.create_event_source_mapping(
                EventSourceArn=arn, FunctionName=S["names"]["function"], BatchSize=5, Enabled=False))
        finally:
            if getattr(c, "accepted_result", None):
                S["extra_esms"].append(c.accepted_result["UUID"])


# --- functional ------------------------------------------------------------------------

def test_c19_message_to_item(study_env, rec, S):
    with chk(rec, "W1-C19", "W1-C10", "W1-C12") as c:
        t0 = time.monotonic()
        item = poll(lambda: get_item(study_env, S["names"]["table"], S["o1"]), T_PROCESS)
        c.observe(found=item is not None, seconds=round(time.monotonic() - t0, 1))
        S["o1_item"] = item
        assert item, "message never reached the table"


def test_c20_item_attributes(study_env, rec, S):
    with chk(rec, "W1-C20", "W1-C19") as c:
        item = S["o1_item"]
        c.observe(amount=item.get("amount"), has_marker="run_marker" in item, has_message_id="message_id" in item)
        assert Decimal(item["amount"]["N"]) == Decimal("12.5")
        assert item["run_marker"]["S"] == S["marker"]
        assert item["message_id"]["S"] == S["o1_message_id"]


def test_c21_batch_items(study_env, rec, S):
    with chk(rec, "W1-C21", "W1-C10", "W1-C13") as c:
        def all_found():
            return all(get_item(study_env, S["names"]["table"], oid) for oid in S["batch_ids"])
        ok = poll(all_found, T_PROCESS, interval=4)
        found = sum(1 for oid in S["batch_ids"] if get_item(study_env, S["names"]["table"], oid))
        c.observe(found=found)
        assert ok, f"{found} of 10 batch messages became items"


def test_c22_queue_drained(study_env, rec, S):
    with chk(rec, "W1-C22", "W1-C10", "W1-C13") as c:
        ok = poll(lambda: queue_counts(study_env, S["queue_url"]) == (0, 0), T_PROCESS, interval=5)
        visible, in_flight = queue_counts(study_env, S["queue_url"])
        c.observe(visible=visible, in_flight=in_flight)
        assert ok


def test_c23_poison_to_dlq(study_env, rec, S, prefix):
    with chk(rec, "W1-C23", "W1-C10") as c:  # C10 already needs C02; listing C02 would blame the queue in type B
        S["poison_id"] = f"{prefix}-poison1"
        S["poison_body"] = json.dumps({"order_id": S["poison_id"], "fail": True, "run_marker": S["marker"]})
        study_env.client("sqs").send_message(QueueUrl=S["queue_url"], MessageBody=S["poison_body"])
        t0 = time.monotonic()
        msg = find_in_queue(study_env, S["dlq_url"], S["poison_id"], T_DLQ)
        c.observe(arrived=msg is not None, seconds=round(time.monotonic() - t0, 1),
                  receive_count=(msg or {}).get("Attributes", {}).get("ApproximateReceiveCount"))
        S["dlq_msg"] = msg
        assert msg, "poison message never reached the DLQ"


def test_c24_poison_not_written(study_env, rec, S):
    with chk(rec, "W1-C24", "W1-C23") as c:
        item = get_item(study_env, S["names"]["table"], S["poison_id"])
        c.observe(item_present=item is not None)
        assert item is None


def test_c25_dlq_body_intact(study_env, rec, S):
    with chk(rec, "W1-C25", "W1-C23") as c:
        c.observe(body_equal=S["dlq_msg"]["Body"] == S["poison_body"])
        assert S["dlq_msg"]["Body"] == S["poison_body"]


def test_c26_partial_batch(study_env, rec, S, prefix):
    with chk(rec, "W1-C26", "W1-C10") as c:  # see C23
        good = [f"{prefix}-p{i}" for i in range(4)]
        bad = f"{prefix}-p4-poison"
        entries = [{"Id": f"g{i}", "MessageBody": json.dumps({"order_id": oid, "amount": i})} for i, oid in enumerate(good)]
        entries.append({"Id": "bad", "MessageBody": json.dumps({"order_id": bad, "fail": True})})
        study_env.client("sqs").send_message_batch(QueueUrl=S["queue_url"], Entries=entries)
        poll(lambda: all(get_item(study_env, S["names"]["table"], g) for g in good), T_PROCESS, interval=4)
        written = sum(1 for g in good if get_item(study_env, S["names"]["table"], g))
        dlq_msg = find_in_queue(study_env, S["dlq_url"], bad, T_DLQ)
        good_in_dlq = find_in_queue(study_env, S["dlq_url"], f"{prefix}-p0", 15, delete=False)
        c.observe(good_written=written, poison_in_dlq=dlq_msg is not None, good_in_dlq=good_in_dlq is not None,
                  poison_written=get_item(study_env, S["names"]["table"], bad) is not None)
        assert written == 4 and dlq_msg is not None and good_in_dlq is None


def test_c27_logs(study_env, rec, S):
    with chk(rec, "W1-C27", "W1-C19") as c:
        logs = study_env.client("logs")
        group = f"/aws/lambda/{S['names']['function']}"

        def events():
            try:
                return logs.filter_log_events(logGroupName=group, filterPattern=f'"{S["marker"]}"').get("events", [])
            except ClientError as exc:
                if code_of(exc) == "ResourceNotFoundException":
                    return []
                raise
        found = poll(events, T_LOGS, interval=5)
        c.observe(events=len(found or []))
        assert found, "no log lines with the run marker"


def test_c28_disabled_mapping(study_env, rec, S, prefix):
    with chk(rec, "W1-C28", "W1-C10", "W1-C22") as c:
        lam = study_env.client("lambda")
        lam.update_event_source_mapping(UUID=S["esm_uuid"], Enabled=False)
        t0 = time.monotonic()
        disabled = poll(lambda: mapping_state(study_env, S["esm_uuid"]) == "Disabled", T_ACTIVE)
        c.observe(seconds=round(time.monotonic() - t0, 1))
        time.sleep(SETTLE)  # let in-flight pollers stop before sending the held message
        S["held_id"] = f"{prefix}-held"
        study_env.client("sqs").send_message(
            QueueUrl=S["queue_url"], MessageBody=json.dumps({"order_id": S["held_id"], "amount": 7})
        )
        time.sleep(QUIET_WINDOW)
        item = get_item(study_env, S["names"]["table"], S["held_id"])
        # ApproximateNumberOfMessages lags on real AWS: wait until the held message is counted.
        poll(lambda: sum(queue_counts(study_env, S["queue_url"])) >= 1, 90, interval=5)
        visible, in_flight = queue_counts(study_env, S["queue_url"])
        c.observe(state=mapping_state(study_env, S["esm_uuid"]), item_present=item is not None,
                  visible=visible, in_flight=in_flight)
        assert disabled, "mapping did not reach Disabled"
        assert item is None and visible + in_flight >= 1


def test_c29_reenabled_mapping(study_env, rec, S):
    with chk(rec, "W1-C29", "W1-C28") as c:
        study_env.client("lambda").update_event_source_mapping(UUID=S["esm_uuid"], Enabled=True)
        poll(lambda: mapping_state(study_env, S["esm_uuid"]) == "Enabled", T_ACTIVE)
        item = poll(lambda: get_item(study_env, S["names"]["table"], S["held_id"]), T_PROCESS)
        c.observe(state=mapping_state(study_env, S["esm_uuid"]), item_present=item is not None)
        assert item, "waiting message was not processed after re-enabling"


# --- teardown --------------------------------------------------------------------------

def test_c30_teardown(study_env, rec, S):
    with chk(rec, "W1-C30", "W1-C07") as c:
        lam, ddb, sqs, iam = (study_env.client(s) for s in ("lambda", "dynamodb", "sqs", "iam"))
        steps = []
        if S.get("esm_uuid"):
            lam.delete_event_source_mapping(UUID=S["esm_uuid"]); steps.append("esm")
            S["esm_uuid"] = None
        lam.delete_function(FunctionName=S["names"]["function"]); steps.append("function")
        ddb.delete_table(TableName=S["names"]["table"]); steps.append("table")
        sqs.delete_queue(QueueUrl=S["queue_url"]); steps.append("queue")
        sqs.delete_queue(QueueUrl=S["dlq_url"]); steps.append("dlq")
        iam.delete_role_policy(RoleName=S["names"]["role"], PolicyName="workload")
        iam.delete_role(RoleName=S["names"]["role"]); steps.append("role")
        c.observe(deleted=steps)


def test_c31_gone_after_delete(study_env, rec, S):
    with chk(rec, "W1-C31", "W1-C30") as c:
        codes = {}

        def probe(name, fn):
            try:
                result = fn()
                if name == "table" and result["Table"]["TableStatus"] == "DELETING":
                    return None
                return "still-exists"
            except ClientError as exc:
                return code_of(exc)

        def all_gone():
            codes["table"] = probe("table", lambda: study_env.client("dynamodb").describe_table(TableName=S["names"]["table"]))
            codes["function"] = probe("function", lambda: study_env.client("lambda").get_function(FunctionName=S["names"]["function"]))
            codes["queue"] = probe("queue", lambda: study_env.client("sqs").get_queue_url(QueueName=S["names"]["queue"]))
            return all(v not in (None, "still-exists") for v in codes.values())
        ok = poll(all_gone, 90, interval=5)
        c.observe(**{f"{k}_code": v for k, v in codes.items()})
        assert ok, f"not all deleted: {codes}"
