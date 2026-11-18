"""W4 Events: EventBridge rules on the default event bus deliver to SQS (one plain target, one
with an input transformer), and an SNS topic fans out to two SQS queues through filter policies
(one on message attributes with raw delivery, one on the message body).

Resources are created through the service APIs (not CloudFormation), like W1, W2, W3 and W5.
Checks run in file order and share state. A check whose prerequisite failed is recorded as
'blocked' and skipped.

The default event bus is used because the study role may only manage rules on it. Every event
carries a source unique to this run, so other traffic on the bus never matches.

Delivery is asynchronous. Every message carries an id unique to this run, and checks look only
for their own ids, so a late or duplicated delivery cannot confuse a later check. A brand-new
rule or subscription can take a few seconds to start delivering on real AWS, so the first
delivery checks resend (with a fresh id) until one arrives. "Not delivered" is shown by sending
the message that must be filtered out first, then a marker that must arrive, waiting for the
marker and then a further 10 s.

Recorded observations never contain run-specific values (names, ARNs, ids), so they can be
compared across runs and environments.
"""
from __future__ import annotations

import json
import time
import uuid

import pytest
from botocore.exceptions import ClientError

from harness.aws_helpers import quietly
from harness.record import poll

WORKLOAD = "W4"

QUEUES = ("events", "xform", "orders", "refunds")
DELIVERY_TIMEOUT = 120   # seconds to wait for a delivery
RESEND_EVERY = 15        # seconds between resends while waiting for the first delivery
QUIET_AFTER_MARKER = 10  # seconds to keep listening after the marker arrived

CHECKS = {
    # EventBridge
    "W4-C01": ("control", "CreateQueue creates the four target queues and each reports a QueueArn"),
    "W4-C02": ("control", "PutRule on the default bus is ENABLED and DescribeRule returns the same event pattern"),
    "W4-C03": ("control", "PutTargets adds the queue to the rule and ListTargetsByRule shows it"),
    "W4-C04": ("data", "PutEvents with a matching event returns no failed entries and an event id"),
    "W4-C05": ("functional", "A matching event is delivered to the target queue"),
    "W4-C06": ("data", "The delivered event has the standard envelope with the sent source, detail-type and detail"),
    "W4-C07": ("functional", "Events with another detail-type, another source or a small amount are not delivered"),
    "W4-C08": ("functional", "Numeric matching '> 100' drops amount 100 and delivers amount 100.5"),
    "W4-C09": ("control", "A second rule using exists, anything-but and prefix gets a target with an input transformer"),
    "W4-C10": ("data", "The input transformer delivers exactly the templated JSON"),
    "W4-C11": ("functional", "The second rule drops events without the field, with the excluded value or another prefix"),
    "W4-C12": ("functional", "After DisableRule the rule shows DISABLED and stops delivering while the other rule still delivers"),
    "W4-C13": ("control", "ListRules with the name prefix returns both rules"),
    # SNS
    "W4-C14": ("control", "CreateTopic with tags returns an ARN ending in the topic name"),
    "W4-C15": ("control", "Subscribing two SQS queues with filter policies returns confirmed subscription ARNs"),
    "W4-C16": ("control", "GetSubscriptionAttributes returns the filter policy, its scope and raw delivery"),
    "W4-C17": ("data", "A message matching the attribute filter arrives raw, with its message attributes"),
    "W4-C18": ("functional", "Messages with a small amount, another event or no attributes are filtered out"),
    "W4-C19": ("data", "A message matching the body filter arrives wrapped in the SNS notification envelope"),
    "W4-C20": ("functional", "A message whose body does not match the body filter is filtered out"),
    "W4-C21": ("functional", "PublishBatch of three messages succeeds and only the two matching ones arrive"),
    "W4-C22": ("control", "ListSubscriptionsByTopic shows the two SQS subscriptions"),
    # negative checks: real AWS rejects these
    "W4-C23": ("data", "PutRule with an event pattern that is not valid JSON is rejected"),
    "W4-C24": ("data", "PutRule with a pattern value that is not an array is rejected"),
    "W4-C25": ("data", "PutRule with the schedule expression rate(0 minutes) is rejected"),
    "W4-C26": ("data", "PutEvents with a Detail that is not JSON reports the entry as failed"),
    "W4-C27": ("data", "PutEvents with 11 entries (maximum 10) is rejected"),
    "W4-C28": ("control", "CreateTopic with a space and '!' in the name is rejected"),
    "W4-C29": ("data", "Subscribe with a filter policy whose value is not an array is rejected"),
    "W4-C30": ("data", "Publish with a Number message attribute that is not a number is rejected"),
    "W4-C31": ("data", "Publish with a message over 256 KB is rejected"),
    "W4-C32": ("control", "Publish to a topic that does not exist is rejected"),
    "W4-C33": ("control", "SetSubscriptionAttributes with an unknown attribute name is rejected"),
    # teardown
    "W4-C34": ("control", "Remove the targets, delete the rules, the topic and the queues"),
    "W4-C35": ("control", "After teardown the rules, the topic and the queues are gone"),
}

# Negative checks: real AWS rejects the request. The check passes when the error occurs.
NEGATIVE = {"W4-C23", "W4-C24", "W4-C25", "W4-C26", "W4-C27", "W4-C28", "W4-C29", "W4-C30",
            "W4-C31", "W4-C32", "W4-C33"}


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


def new_id() -> str:
    return uuid.uuid4().hex[:12]


# --- message helpers ----------------------------------------------------------------------

def msg_id(queue: str, m: dict) -> str | None:
    """The study id inside a received message, however that queue's messages are shaped."""
    try:
        body = json.loads(m["Body"])
        if queue == "events":
            return body["detail"]["id"]
        if queue == "xform":
            return body["order"]
        if queue == "orders":
            return body["id"]
        if queue == "refunds":
            return json.loads(body["Message"])["id"]
    except (ValueError, KeyError, TypeError):
        return None
    return None


def receive(S, queue: str, seconds: float) -> None:
    """Moves whatever arrives in `seconds` into S['inbox'][queue] (and deletes it from the queue)."""
    sqs, url = S["sqs"], S["q"][queue]["url"]
    deadline = time.monotonic() + seconds
    while True:
        wait = int(max(0, min(5, deadline - time.monotonic())))
        for m in sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait,
                                     MessageAttributeNames=["All"]).get("Messages", []):
            S["inbox"][queue].append(m)
            quietly(sqs.delete_message, QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        if time.monotonic() >= deadline:
            return


def found(S, queue: str, ids) -> dict | None:
    ids = {ids} if isinstance(ids, str) else set(ids)
    return next((m for m in S["inbox"][queue] if msg_id(queue, m) in ids), None)


def wait_for(S, queue: str, send, resend: bool = False, timeout: float = DELIVERY_TIMEOUT) -> dict | None:
    """Calls send() (which returns the id it sent) and waits for that id to arrive.

    With resend=True, sends again with a fresh id every RESEND_EVERY seconds until one arrives:
    used for the first delivery through a new rule or subscription."""
    sent = [send()]
    last = time.monotonic()
    deadline = last + timeout
    while time.monotonic() < deadline:
        m = found(S, queue, sent)
        if m:
            return m
        receive(S, queue, 3)
        if resend and time.monotonic() - last >= RESEND_EVERY:
            sent.append(send())
            last = time.monotonic()
    return found(S, queue, sent)


def filtered_out(S, queue: str, bad_ids: list[str], send_marker) -> dict:
    """Waits for the marker, listens QUIET_AFTER_MARKER seconds more, and reports what arrived."""
    marker = wait_for(S, queue, send_marker, resend=True)
    receive(S, queue, QUIET_AFTER_MARKER)
    leaked = [i for i in bad_ids if found(S, queue, i)]
    return {"marker_arrived": marker is not None, "leaked": len(leaked)}


def queue_policy(queue_arn: str, service: str, source_arns: list[str]) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowStudySource",
            "Effect": "Allow",
            "Principal": {"Service": service},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": source_arns}},
        }],
    })


# --- shared state -------------------------------------------------------------------------

@pytest.fixture(scope="module")
def S(study_env, prefix):
    """Shared state; cleans up whatever exists when the module ends, pass or fail."""
    state = {
        "src": f"study.{prefix}",
        "rule1": f"{prefix}-orders-over-100",
        "rule2": f"{prefix}-us-customers",
        "topic": f"{prefix}-orders",
        "rules": [],
        "topics": [],
        "q": {},
        "inbox": {q: [] for q in QUEUES},
        "sqs": study_env.client("sqs"),
    }
    yield state
    events, sns, sqs = study_env.client("events"), study_env.client("sns"), state["sqs"]
    for name in state["rules"]:
        quietly(events.remove_targets, Rule=name, Ids=["t1"], Force=True)
        quietly(events.delete_rule, Name=name, Force=True)
    for arn in state["topics"]:
        quietly(sns.delete_topic, TopicArn=arn)
    for q in state["q"].values():
        quietly(sqs.delete_queue, QueueUrl=q["url"])


def put_event(study_env, S, detail_type: str, detail: dict, source: str | None = None) -> str:
    """Sends one event with a fresh id in its detail and returns that id."""
    eid = new_id()
    r = study_env.client("events").put_events(Entries=[{
        "Source": source or S["src"], "DetailType": detail_type,
        "Detail": json.dumps({"id": eid, **detail}), "EventBusName": "default"}])
    assert not r.get("FailedEntryCount"), f"PutEvents failed: {r.get('Entries')}"
    return eid


def publish_attr(study_env, S, attrs: dict | None) -> str:
    """Publishes {"id": ...} with the given message attributes (String or Number) and returns the id."""
    pid = new_id()
    kwargs = {}
    if attrs:
        kwargs["MessageAttributes"] = {
            k: {"DataType": "Number" if isinstance(v, (int, float)) else "String", "StringValue": str(v)}
            for k, v in attrs.items()}
    study_env.client("sns").publish(TopicArn=S["topic_arn"], Message=json.dumps({"id": pid}), **kwargs)
    return pid


def publish_body(study_env, S, kind: str) -> str:
    pid = new_id()
    study_env.client("sns").publish(TopicArn=S["topic_arn"], Message=json.dumps({"id": pid, "type": kind}))
    return pid


RULE1_PATTERN = {"detail-type": ["OrderPlaced"], "detail": {"amount": [{"numeric": [">", 100]}]}}
RULE2_PATTERN = {
    "detail-type": ["OrderPlaced"],
    "detail": {
        "customer": [{"exists": True}],
        "status": [{"anything-but": ["test"]}],
        "region": [{"prefix": "us-"}],
    },
}
ORDERS_FILTER = {"event": ["order_placed"], "amount": [{"numeric": [">=", 100]}]}
REFUNDS_FILTER = {"type": ["refund"]}


# --- EventBridge --------------------------------------------------------------------------

def test_c01_queues(study_env, rec, S, prefix, tags):
    with chk(rec, "W4-C01") as c:
        sqs = S["sqs"]
        for q in QUEUES:
            url = sqs.create_queue(QueueName=f"{prefix}-{q}", tags=tags)["QueueUrl"]
            S["q"][q] = {"url": url}
            S["q"][q]["arn"] = sqs.get_queue_attributes(
                QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"].get("QueueArn", "")
        S["account"] = S["q"]["events"]["arn"].split(":")[4]
        S["region"] = study_env.region
        arns_ok = all(S["q"][q]["arn"].endswith(f":{prefix}-{q}") for q in QUEUES)
        c.observe(queues=len(S["q"]), arns_ok=arns_ok)
        assert arns_ok


def test_c02_rule(study_env, rec, S):
    with chk(rec, "W4-C02", "W4-C01") as c:
        events = study_env.client("events")
        pattern = {"source": [S["src"]], **RULE1_PATTERN}
        S["rules"].append(S["rule1"])
        S["rule1_arn"] = events.put_rule(Name=S["rule1"], EventPattern=json.dumps(pattern),
                                         State="ENABLED", EventBusName="default")["RuleArn"]
        d = events.describe_rule(Name=S["rule1"], EventBusName="default")
        same = json.loads(d.get("EventPattern") or "null") == pattern
        c.observe(state=d.get("State"), bus=d.get("EventBusName"), pattern_same=same,
                  arn_ok=S["rule1_arn"].endswith(f":rule/{S['rule1']}"))
        assert d.get("State") == "ENABLED" and same


def test_c03_target(study_env, rec, S):
    with chk(rec, "W4-C03", "W4-C02") as c:
        q = S["q"]["events"]
        S["sqs"].set_queue_attributes(QueueUrl=q["url"], Attributes={
            "Policy": queue_policy(q["arn"], "events.amazonaws.com", [S["rule1_arn"]])})
        events = study_env.client("events")
        r = events.put_targets(Rule=S["rule1"], EventBusName="default", Targets=[{"Id": "t1", "Arn": q["arn"]}])
        targets = events.list_targets_by_rule(Rule=S["rule1"], EventBusName="default").get("Targets", [])
        c.observe(failed=r.get("FailedEntryCount"), targets=len(targets),
                  target_ok=[t.get("Arn") for t in targets] == [q["arn"]])
        assert r.get("FailedEntryCount") == 0 and [t.get("Arn") for t in targets] == [q["arn"]]


def test_c04_put_events(study_env, rec, S):
    with chk(rec, "W4-C04", "W4-C03") as c:
        eid = new_id()
        S["first_detail"] = {"id": eid, "amount": 250, "customer": "c-1", "status": "new", "region": "us-west"}
        r = study_env.client("events").put_events(Entries=[{
            "Source": S["src"], "DetailType": "OrderPlaced", "Detail": json.dumps(S["first_detail"]),
            "EventBusName": "default"}])
        entry = (r.get("Entries") or [{}])[0]
        c.observe(failed=r.get("FailedEntryCount"), has_event_id=bool(entry.get("EventId")))
        assert r.get("FailedEntryCount") == 0 and entry.get("EventId")


def test_c05_delivered(study_env, rec, S):
    with chk(rec, "W4-C05", "W4-C04") as c:
        first = S["first_detail"]["id"]
        sent = []

        def send():
            # the first try waits for the event C04 sent; resends carry fresh ids
            if not sent:
                sent.append(first)
                return first
            d = {**S["first_detail"], "id": new_id()}
            study_env.client("events").put_events(Entries=[{
                "Source": S["src"], "DetailType": "OrderPlaced", "Detail": json.dumps(d), "EventBusName": "default"}])
            sent.append(d["id"])
            return d["id"]

        m = wait_for(S, "events", send, resend=True)
        S["first_event"] = m
        c.observe(delivered=m is not None)
        assert m is not None, f"no matching event arrived within {DELIVERY_TIMEOUT} s"


def test_c06_envelope(study_env, rec, S):
    with chk(rec, "W4-C06", "W4-C05") as c:
        body = json.loads(S["first_event"]["Body"])
        detail = body.get("detail") or {}
        detail_ok = {k: v for k, v in detail.items() if k != "id"} == \
            {k: v for k, v in S["first_detail"].items() if k != "id"}
        c.observe(keys=sorted(body), version=body.get("version"), resources=body.get("resources"),
                  source_ok=body.get("source") == S["src"], detail_type=body.get("detail-type"),
                  region_ok=body.get("region") == S["region"], account_ok=body.get("account") == S["account"],
                  detail_ok=detail_ok)
        assert detail_ok and body.get("source") == S["src"] and body.get("detail-type") == "OrderPlaced"


def test_c07_not_matching(study_env, rec, S):
    with chk(rec, "W4-C07", "W4-C05") as c:
        bad = [
            put_event(study_env, S, "OrderShipped", {"amount": 500}),
            put_event(study_env, S, "OrderPlaced", {"amount": 500}, source=S["src"] + ".other"),
            put_event(study_env, S, "OrderPlaced", {"amount": 50}),
        ]
        res = filtered_out(S, "events", bad, lambda: put_event(study_env, S, "OrderPlaced", {"amount": 500}))
        c.observe(**res)
        assert res["marker_arrived"], "the matching marker event never arrived"
        assert res["leaked"] == 0, f"{res['leaked']} non-matching events were delivered"


def test_c08_numeric_boundary(study_env, rec, S):
    with chk(rec, "W4-C08", "W4-C05") as c:
        bad = [put_event(study_env, S, "OrderPlaced", {"amount": 100})]
        res = filtered_out(S, "events", bad, lambda: put_event(study_env, S, "OrderPlaced", {"amount": 100.5}))
        c.observe(**res)
        assert res["marker_arrived"], "amount 100.5 was not delivered"
        assert res["leaked"] == 0, "amount 100 was delivered"


def test_c09_transformer_rule(study_env, rec, S):
    with chk(rec, "W4-C09", "W4-C01") as c:
        events = study_env.client("events")
        q = S["q"]["xform"]
        pattern = {"source": [S["src"]], **RULE2_PATTERN}
        S["rules"].append(S["rule2"])
        S["rule2_arn"] = events.put_rule(Name=S["rule2"], EventPattern=json.dumps(pattern),
                                         State="ENABLED", EventBusName="default")["RuleArn"]
        S["sqs"].set_queue_attributes(QueueUrl=q["url"], Attributes={
            "Policy": queue_policy(q["arn"], "events.amazonaws.com", [S["rule2_arn"]])})
        r = events.put_targets(Rule=S["rule2"], EventBusName="default", Targets=[{
            "Id": "t1", "Arn": q["arn"],
            "InputTransformer": {
                "InputPathsMap": {"id": "$.detail.id", "amt": "$.detail.amount"},
                "InputTemplate": '{"order": "<id>", "total": <amt>}',
            }}])
        t = (events.list_targets_by_rule(Rule=S["rule2"], EventBusName="default").get("Targets") or [{}])[0]
        has_tx = bool(t.get("InputTransformer", {}).get("InputTemplate"))
        c.observe(failed=r.get("FailedEntryCount"), has_transformer=has_tx)
        assert r.get("FailedEntryCount") == 0 and has_tx


def test_c10_transformed(study_env, rec, S):
    with chk(rec, "W4-C10", "W4-C09") as c:
        detail = {"amount": 42, "customer": "c-9", "status": "new", "region": "us-east"}
        m = wait_for(S, "xform", lambda: put_event(study_env, S, "OrderPlaced", detail), resend=True)
        assert m is not None, f"no transformed event arrived within {DELIVERY_TIMEOUT} s"
        try:
            body = json.loads(m["Body"])
        except ValueError:
            body = None
        shape_ok = isinstance(body, dict) and sorted(body) == ["order", "total"] and body["total"] == 42
        c.observe(json_ok=body is not None, shape_ok=shape_ok,
                  total_type=type(body.get("total")).__name__ if isinstance(body, dict) else None)
        assert shape_ok, f"transformed body {m['Body'][:200]!r}"


def test_c11_operators(study_env, rec, S):
    with chk(rec, "W4-C11", "W4-C10") as c:
        bad = [
            put_event(study_env, S, "OrderPlaced", {"amount": 1, "status": "new", "region": "us-east"}),
            put_event(study_env, S, "OrderPlaced", {"amount": 1, "customer": "c", "status": "test", "region": "us-east"}),
            put_event(study_env, S, "OrderPlaced", {"amount": 1, "customer": "c", "status": "new", "region": "eu-west"}),
        ]
        res = filtered_out(S, "xform", bad, lambda: put_event(
            study_env, S, "OrderPlaced", {"amount": 1, "customer": "c", "status": "paid", "region": "us-west"}))
        c.observe(**res)
        assert res["marker_arrived"], "the matching marker event never arrived"
        assert res["leaked"] == 0, f"{res['leaked']} events that should be filtered out were delivered"


def test_c12_disable_rule(study_env, rec, S):
    with chk(rec, "W4-C12", "W4-C05", "W4-C10") as c:
        events = study_env.client("events")
        events.disable_rule(Name=S["rule1"], EventBusName="default")
        state = events.describe_rule(Name=S["rule1"], EventBusName="default").get("State")
        time.sleep(30)  # let the change reach every EventBridge host before testing it
        both = {"amount": 300, "customer": "c", "status": "new", "region": "us-west"}
        eid = put_event(study_env, S, "OrderPlaced", both)
        in_xform = wait_for(S, "xform", lambda: eid)
        receive(S, "events", QUIET_AFTER_MARKER)
        leaked = found(S, "events", eid) is not None
        c.observe(state=state, other_rule_delivered=in_xform is not None, disabled_rule_delivered=leaked)
        assert state == "DISABLED" and in_xform is not None and not leaked


def test_c13_list_rules(study_env, rec, S, prefix):
    with chk(rec, "W4-C13", "W4-C02", "W4-C09") as c:
        rules = study_env.client("events").list_rules(NamePrefix=prefix, EventBusName="default").get("Rules", [])
        names = sorted(r["Name"] for r in rules)
        c.observe(count=len(names), both=names == sorted([S["rule1"], S["rule2"]]))
        assert names == sorted([S["rule1"], S["rule2"]])


# --- SNS ----------------------------------------------------------------------------------

def test_c14_topic(study_env, rec, S, tags):
    with chk(rec, "W4-C14", "W4-C01") as c:
        arn = study_env.client("sns").create_topic(
            Name=S["topic"], Tags=[{"Key": k, "Value": v} for k, v in tags.items()])["TopicArn"]
        S["topic_arn"] = arn
        S["topics"].append(arn)
        c.observe(arn_ok=arn.endswith(f":{S['topic']}"))
        assert arn.endswith(f":{S['topic']}")


def test_c15_subscribe(study_env, rec, S):
    with chk(rec, "W4-C15", "W4-C14") as c:
        sns = study_env.client("sns")
        for q in ("orders", "refunds"):
            S["sqs"].set_queue_attributes(QueueUrl=S["q"][q]["url"], Attributes={
                "Policy": queue_policy(S["q"][q]["arn"], "sns.amazonaws.com", [S["topic_arn"]])})
        S["sub_orders"] = sns.subscribe(
            TopicArn=S["topic_arn"], Protocol="sqs", Endpoint=S["q"]["orders"]["arn"], ReturnSubscriptionArn=True,
            Attributes={"FilterPolicy": json.dumps(ORDERS_FILTER), "RawMessageDelivery": "true"})["SubscriptionArn"]
        S["sub_refunds"] = sns.subscribe(
            TopicArn=S["topic_arn"], Protocol="sqs", Endpoint=S["q"]["refunds"]["arn"], ReturnSubscriptionArn=True,
            Attributes={"FilterPolicy": json.dumps(REFUNDS_FILTER), "FilterPolicyScope": "MessageBody"},
        )["SubscriptionArn"]
        confirmed = [a.startswith(S["topic_arn"] + ":") for a in (S["sub_orders"], S["sub_refunds"])]
        c.observe(confirmed=confirmed)
        assert all(confirmed), "subscriptions are not confirmed ARNs"


def test_c16_subscription_attributes(study_env, rec, S):
    with chk(rec, "W4-C16", "W4-C15") as c:
        sns = study_env.client("sns")
        o = sns.get_subscription_attributes(SubscriptionArn=S["sub_orders"])["Attributes"]
        r = sns.get_subscription_attributes(SubscriptionArn=S["sub_refunds"])["Attributes"]
        o_filter = json.loads(o.get("FilterPolicy") or "null") == ORDERS_FILTER
        r_filter = json.loads(r.get("FilterPolicy") or "null") == REFUNDS_FILTER
        c.observe(orders_filter=o_filter, orders_raw=o.get("RawMessageDelivery"),
                  orders_scope=o.get("FilterPolicyScope"), refunds_filter=r_filter,
                  refunds_raw=r.get("RawMessageDelivery"), refunds_scope=r.get("FilterPolicyScope"),
                  pending=[o.get("PendingConfirmation"), r.get("PendingConfirmation")])
        assert o_filter and r_filter and o.get("RawMessageDelivery") == "true"
        assert r.get("FilterPolicyScope") == "MessageBody"


def test_c17_raw_delivery(study_env, rec, S):
    with chk(rec, "W4-C17", "W4-C15") as c:
        m = wait_for(S, "orders", lambda: publish_attr(study_env, S, {"event": "order_placed", "amount": 150}),
                     resend=True)
        assert m is not None, f"no matching message arrived within {DELIVERY_TIMEOUT} s"
        attrs = {k: [v.get("DataType"), v.get("StringValue")] for k, v in (m.get("MessageAttributes") or {}).items()}
        try:
            body = json.loads(m["Body"])
        except ValueError:
            body = None
        raw = isinstance(body, dict) and sorted(body) == ["id"]
        c.observe(raw_body=raw, attributes=attrs)
        assert raw, f"body is not the raw message: {m['Body'][:200]!r}"
        assert attrs == {"event": ["String", "order_placed"], "amount": ["Number", "150"]}, f"attributes {attrs}"


def test_c18_attribute_filter(study_env, rec, S):
    with chk(rec, "W4-C18", "W4-C17") as c:
        bad = [
            publish_attr(study_env, S, {"event": "order_placed", "amount": 99}),
            publish_attr(study_env, S, {"event": "order_cancelled", "amount": 500}),
            publish_attr(study_env, S, None),
        ]
        res = filtered_out(S, "orders", bad,
                           lambda: publish_attr(study_env, S, {"event": "order_placed", "amount": 100}))
        c.observe(**res)
        assert res["marker_arrived"], "the matching marker (amount 100) never arrived"
        assert res["leaked"] == 0, f"{res['leaked']} filtered messages were delivered"


def test_c19_envelope(study_env, rec, S):
    with chk(rec, "W4-C19", "W4-C15") as c:
        m = wait_for(S, "refunds", lambda: publish_body(study_env, S, "refund"), resend=True)
        assert m is not None, f"no refund message arrived within {DELIVERY_TIMEOUT} s"
        env = json.loads(m["Body"])
        inner = json.loads(env.get("Message") or "{}")
        c.observe(keys=sorted(env), type=env.get("Type"), topic_ok=env.get("TopicArn") == S["topic_arn"],
                  message_ok=sorted(inner) == ["id", "type"] and inner.get("type") == "refund",
                  signature_version=env.get("SignatureVersion"))
        assert env.get("Type") == "Notification" and env.get("TopicArn") == S["topic_arn"]


def test_c20_body_filter(study_env, rec, S):
    with chk(rec, "W4-C20", "W4-C19") as c:
        bad = [publish_body(study_env, S, "order")]
        res = filtered_out(S, "refunds", bad, lambda: publish_body(study_env, S, "refund"))
        c.observe(**res)
        assert res["marker_arrived"], "the refund marker never arrived"
        assert res["leaked"] == 0, "a message with type 'order' reached the refunds queue"


def test_c21_publish_batch(study_env, rec, S):
    with chk(rec, "W4-C21", "W4-C18") as c:
        ids = [new_id() for _ in range(3)]
        amounts = [120, 130, 10]
        r = study_env.client("sns").publish_batch(TopicArn=S["topic_arn"], PublishBatchRequestEntries=[
            {"Id": f"e{i}", "Message": json.dumps({"id": pid}), "MessageAttributes": {
                "event": {"DataType": "String", "StringValue": "order_placed"},
                "amount": {"DataType": "Number", "StringValue": str(a)}}}
            for i, (pid, a) in enumerate(zip(ids, amounts))])
        poll(lambda: found(S, "orders", ids[0]) and found(S, "orders", ids[1]) or receive(S, "orders", 3),
             DELIVERY_TIMEOUT, interval=0)
        receive(S, "orders", QUIET_AFTER_MARKER)
        arrived = [found(S, "orders", pid) is not None for pid in ids]
        c.observe(successful=len(r.get("Successful", [])), failed=len(r.get("Failed", [])), arrived=arrived)
        assert len(r.get("Successful", [])) == 3 and arrived == [True, True, False]


def test_c22_list_subscriptions(study_env, rec, S):
    with chk(rec, "W4-C22", "W4-C15") as c:
        subs = study_env.client("sns").list_subscriptions_by_topic(TopicArn=S["topic_arn"]).get("Subscriptions", [])
        protocols = sorted(s.get("Protocol") for s in subs)
        endpoints_ok = sorted(s.get("Endpoint") for s in subs) == sorted(
            [S["q"]["orders"]["arn"], S["q"]["refunds"]["arn"]])
        c.observe(protocols=protocols, endpoints_ok=endpoints_ok)
        assert protocols == ["sqs", "sqs"] and endpoints_ok


# --- negative checks ----------------------------------------------------------------------

def bad_rule(study_env, S, suffix: str, **kwargs):
    name = f"{S['rule1']}-{suffix}"
    S["rules"].append(name)
    return study_env.client("events").put_rule(Name=name, EventBusName="default", **kwargs)


def test_c23_pattern_not_json(study_env, rec, S):
    with chk(rec, "W4-C23", "W4-C01") as c:
        expect_error(c, lambda: bad_rule(study_env, S, "badjson", EventPattern='{"source": ["x"'))


def test_c24_pattern_not_array(study_env, rec, S):
    with chk(rec, "W4-C24", "W4-C01") as c:
        expect_error(c, lambda: bad_rule(study_env, S, "notarray", EventPattern=json.dumps({"source": S["src"]})))


def test_c25_rate_zero(study_env, rec, S):
    with chk(rec, "W4-C25", "W4-C01") as c:
        expect_error(c, lambda: bad_rule(study_env, S, "rate0", ScheduleExpression="rate(0 minutes)"))


def test_c26_detail_not_json(study_env, rec, S):
    with chk(rec, "W4-C26", "W4-C01") as c:
        try:
            r = study_env.client("events").put_events(Entries=[{
                "Source": S["src"], "DetailType": "OrderPlaced", "Detail": "not json", "EventBusName": "default"}])
        except ClientError as exc:
            c.observe(error_code=code_of(exc), http_status=exc.response["ResponseMetadata"].get("HTTPStatusCode"))
            return
        entry = (r.get("Entries") or [{}])[0]
        if r.get("FailedEntryCount"):
            c.observe(error_code=entry.get("ErrorCode"), failed=r.get("FailedEntryCount"))
            return
        c.observe(accepted=True)
        raise AssertionError("the malformed Detail was accepted; real AWS rejects the entry")


def test_c27_too_many_entries(study_env, rec, S):
    with chk(rec, "W4-C27", "W4-C01") as c:
        entries = [{"Source": S["src"], "DetailType": "Bulk", "Detail": json.dumps({"n": i}),
                    "EventBusName": "default"} for i in range(11)]
        expect_error(c, lambda: study_env.client("events").put_events(Entries=entries))


def test_c28_bad_topic_name(study_env, rec, S):
    with chk(rec, "W4-C28", "W4-C01") as c:
        def create():
            arn = study_env.client("sns").create_topic(Name=f"{S['topic']}-bad name!")["TopicArn"]
            S["topics"].append(arn)
            return arn
        expect_error(c, create)


def test_c29_filter_not_array(study_env, rec, S):
    with chk(rec, "W4-C29", "W4-C14") as c:
        expect_error(c, lambda: study_env.client("sns").subscribe(
            TopicArn=S["topic_arn"], Protocol="sqs", Endpoint=S["q"]["refunds"]["arn"], ReturnSubscriptionArn=True,
            Attributes={"FilterPolicy": json.dumps({"type": "refund"})}))


def test_c30_bad_number_attribute(study_env, rec, S):
    with chk(rec, "W4-C30", "W4-C14") as c:
        expect_error(c, lambda: study_env.client("sns").publish(
            TopicArn=S["topic_arn"], Message=json.dumps({"id": new_id()}),
            MessageAttributes={"amount": {"DataType": "Number", "StringValue": "abc"}}))


def test_c31_message_too_long(study_env, rec, S):
    with chk(rec, "W4-C31", "W4-C14") as c:
        expect_error(c, lambda: study_env.client("sns").publish(TopicArn=S["topic_arn"], Message="x" * (256 * 1024 + 1)))


def test_c32_missing_topic(study_env, rec, S):
    with chk(rec, "W4-C32", "W4-C01") as c:
        arn = f"arn:aws:sns:{S['region']}:{S['account']}:{S['topic']}-missing"
        expect_error(c, lambda: study_env.client("sns").publish(TopicArn=arn, Message="x"))


def test_c33_unknown_attribute(study_env, rec, S):
    with chk(rec, "W4-C33", "W4-C15") as c:
        expect_error(c, lambda: study_env.client("sns").set_subscription_attributes(
            SubscriptionArn=S["sub_orders"], AttributeName="NotARealAttribute", AttributeValue="1"))


# --- teardown -----------------------------------------------------------------------------

def test_c34_teardown(study_env, rec, S):
    with chk(rec, "W4-C34", "W4-C01") as c:
        events, sns, sqs = study_env.client("events"), study_env.client("sns"), S["sqs"]
        rules = 0
        for name in dict.fromkeys(S["rules"]):
            try:
                ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name, EventBusName="default")["Targets"]]
            except ClientError as exc:
                if code_of(exc) == "ResourceNotFoundException":
                    continue  # a rejected negative check never created it
                raise
            if ids:
                events.remove_targets(Rule=name, EventBusName="default", Ids=ids)
            events.delete_rule(Name=name, EventBusName="default")
            rules += name in (S["rule1"], S["rule2"])  # extras come only from accepted negatives
        for arn in S["topics"]:
            sns.delete_topic(TopicArn=arn)
        for q in S["q"].values():
            sqs.delete_queue(QueueUrl=q["url"])
        c.observe(rules_deleted=rules, topic_deleted=S.get("topic_arn") in S["topics"], queues_deleted=len(S["q"]))


def test_c35_gone(study_env, rec, S, prefix):
    with chk(rec, "W4-C35", "W4-C34") as c:
        events, sns, sqs = study_env.client("events"), study_env.client("sns"), S["sqs"]

        def code(fn, **kw):
            try:
                fn(**kw)
                return "exists"
            except ClientError as exc:
                return code_of(exc)

        def all_gone():
            rule = code(events.describe_rule, Name=S["rule1"], EventBusName="default")
            topic = code(sns.get_topic_attributes, TopicArn=S["topic_arn"]) if S.get("topic_arn") else None
            queues = [code(sqs.get_queue_url, QueueName=f"{prefix}-{q}") for q in QUEUES]
            ok = rule != "exists" and topic != "exists" and "exists" not in queues
            return (rule, topic, queues) if ok else None

        result = poll(all_gone, 90, interval=5)
        if result is None:
            rule = code(events.describe_rule, Name=S["rule1"], EventBusName="default")
            topic = code(sns.get_topic_attributes, TopicArn=S["topic_arn"]) if S.get("topic_arn") else None
            queues = [code(sqs.get_queue_url, QueueName=f"{prefix}-{q}") for q in QUEUES]
        else:
            rule, topic, queues = result
        c.observe(rule=rule, topic=topic, queue=sorted(set(queues)))
        assert rule != "exists" and topic != "exists" and "exists" not in queues
        S["rules"].clear()
        S["topics"].clear()
        S["q"].clear()
