"""Smoke test: is the emulator up and answering basic S3 and SQS calls?

Not part of the paper's results; run it first on every new tool version.
"""
from harness.aws_helpers import quietly

WORKLOAD = "SMOKE"


def test_s3_round_trip(study_env, rec, prefix):
    s3 = study_env.client("s3")
    bucket = f"{prefix}-bucket"
    try:
        with rec.check("SMOKE-C01", "control", "Create an S3 bucket") as c:
            kwargs = {"Bucket": bucket}
            if study_env.region != "us-east-1":
                kwargs["CreateBucketConfiguration"] = {"LocationConstraint": study_env.region}
            s3.create_bucket(**kwargs)
        with rec.check("SMOKE-C02", "data", "Put and get one object; body matches") as c:
            s3.put_object(Bucket=bucket, Key="hello.txt", Body=b"hello from the study")
            body = s3.get_object(Bucket=bucket, Key="hello.txt")["Body"].read()
            c.observe(body_len=len(body))
            assert body == b"hello from the study"
    finally:
        quietly(s3.delete_object, Bucket=bucket, Key="hello.txt")
        quietly(s3.delete_bucket, Bucket=bucket)


def test_sqs_round_trip(study_env, rec, prefix):
    sqs = study_env.client("sqs")
    url = None
    try:
        with rec.check("SMOKE-C03", "control", "Create an SQS queue"):
            url = sqs.create_queue(QueueName=f"{prefix}-q")["QueueUrl"]
        with rec.check("SMOKE-C04", "data", "Send and receive one message; body matches") as c:
            sqs.send_message(QueueUrl=url, MessageBody="ping")
            msgs = sqs.receive_message(QueueUrl=url, WaitTimeSeconds=5, MaxNumberOfMessages=1).get("Messages", [])
            c.observe(received=len(msgs))
            assert msgs and msgs[0]["Body"] == "ping"
    finally:
        if url:
            quietly(sqs.delete_queue, QueueUrl=url)
