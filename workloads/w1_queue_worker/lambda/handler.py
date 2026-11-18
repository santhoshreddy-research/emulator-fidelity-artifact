"""W1 worker: reads orders from SQS, writes them to DynamoDB.

A message whose body has "fail": true is a poison message: the handler reports it as a
batch item failure, so SQS retries it and finally moves it to the dead-letter queue.
"""
import json
import os
from decimal import Decimal

import boto3

# Empty on real AWS. Set only if an emulator doesn't route a Lambda's SDK calls back to itself.
_endpoint = os.environ.get("STUDY_INNER_ENDPOINT") or None
_table = boto3.resource("dynamodb", endpoint_url=_endpoint).Table(os.environ["TABLE_NAME"])


def handler(event, context):
    failures = []
    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"], parse_float=Decimal)
            if body.get("fail"):
                raise ValueError("poison message")
            _table.put_item(
                Item={
                    "pk": body["order_id"],
                    "amount": body["amount"],
                    "run_marker": body.get("run_marker", ""),
                    "message_id": record["messageId"],
                },
            )
            print(json.dumps({"processed": record["messageId"], "run_marker": body.get("run_marker")}))
        except Exception as exc:  # noqa: BLE001 - every failure is reported per item
            print(json.dumps({"failed": record["messageId"], "error": str(exc)}))
            failures.append({"itemIdentifier": record["messageId"]})
    return {"batchItemFailures": failures}
