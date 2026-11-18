"""W5 Object storage: one S3 bucket with versioning, a lifecycle rule, presigned URLs and a
multipart upload.

Resources are created through the S3 API (not CloudFormation), like W1 and W2.
Checks run in file order and share state. A check whose prerequisite failed is recorded
as 'blocked' and skipped.

The lifecycle rule is only configured and read back: real expiry takes days, so its effect
is not measured. Presigned URLs are fetched with plain HTTP (requests), the way a browser
or curl would use them.

Recorded observations never contain run-specific values (bucket names, version ids), so
they can be compared across runs and environments. ETags are compared as "correct or not".
"""
from __future__ import annotations

import hashlib
import re
import time

import pytest
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

from harness.aws_helpers import quietly
from harness.record import poll

WORKLOAD = "W5"

MiB = 1024 * 1024
PART = 5 * MiB          # S3 minimum size for every part except the last
EXPIRES_SHORT = 2       # seconds, for the expired presigned URL check
LIFECYCLE_RULE = {
    "ID": "study-rule",
    "Filter": {"Prefix": "logs/"},
    "Status": "Enabled",
    "Expiration": {"Days": 30},
    "NoncurrentVersionExpiration": {"NoncurrentDays": 7},
    "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1},
}

CHECKS = {
    # control plane
    "W5-C01": ("control", "CreateBucket in the study region succeeds and HeadBucket finds it"),
    "W5-C02": ("control", "GetBucketLocation returns the study region"),
    "W5-C03": ("control", "Versioning can be enabled and reads back as Enabled"),
    "W5-C04": ("control", "A lifecycle rule (expiry, noncurrent expiry, abort multipart) reads back unchanged"),
    "W5-C05": ("control", "ListBuckets includes the bucket"),
    # data plane: objects and versions
    "W5-C06": ("data", "PutObject returns a version id, the body's MD5 as ETag, and default SSE-S3 encryption"),
    "W5-C07": ("data", "HeadObject returns content type, user metadata, length and encryption as written"),
    "W5-C08": ("functional", "A second PutObject to the same key creates a new version; both versions read back"),
    "W5-C09": ("functional", "ListObjectVersions shows two versions with only the newest marked latest"),
    "W5-C10": ("functional", "DeleteObject without a version id adds a delete marker and the key reads as NoSuchKey"),
    "W5-C11": ("functional", "ListObjectVersions shows the delete marker as latest and both versions kept"),
    "W5-C12": ("functional", "An older version still reads by version id while the delete marker is current"),
    "W5-C13": ("functional", "Deleting the delete marker restores the newest version"),
    "W5-C14": ("functional", "A ranged GET returns 206 and exactly the requested bytes"),
    "W5-C15": ("functional", "GetObject with If-None-Match of the current ETag returns 304 Not Modified"),
    # presigned URLs
    "W5-C16": ("functional", "A presigned GET URL downloads the object over plain HTTP"),
    "W5-C17": ("functional", "A presigned PUT URL uploads an object over plain HTTP"),
    # multipart
    "W5-C18": ("functional", "A 3-part multipart upload completes with an ETag ending in -3"),
    "W5-C19": ("functional", "The multipart object downloads intact (size and SHA-256 match)"),
    "W5-C20": ("functional", "An unfinished multipart upload is listed and AbortMultipartUpload removes it"),
    # negative checks: real AWS rejects these
    "W5-C21": ("functional", "A presigned GET URL is refused after it expires"),
    "W5-C22": ("functional", "A presigned GET URL with an altered signature is refused"),
    "W5-C23": ("data", "CompleteMultipartUpload with a non-final part under 5 MiB is rejected"),
    "W5-C24": ("data", "CompleteMultipartUpload with a wrong part ETag is rejected"),
    "W5-C25": ("data", "CompleteMultipartUpload with parts out of order is rejected"),
    "W5-C26": ("data", "PutObject with If-None-Match: * on an existing key is rejected"),
    "W5-C27": ("data", "GetObject with a version id that does not exist is rejected"),
    "W5-C28": ("control", "CreateBucket with an invalid name (uppercase, underscore) is rejected"),
    "W5-C29": ("control", "A lifecycle rule with Expiration Days 0 is rejected"),
    "W5-C30": ("control", "DeleteBucket on a bucket that still holds objects is rejected"),
    # teardown
    "W5-C31": ("control", "Delete every version, delete marker and the bucket without errors"),
    "W5-C32": ("control", "After deletion, HeadBucket reports the bucket gone"),
}

# Negative checks: real AWS rejects the request. The check passes when the error occurs.
NEGATIVE = {"W5-C21", "W5-C22", "W5-C23", "W5-C24", "W5-C25", "W5-C26", "W5-C27", "W5-C28",
            "W5-C29", "W5-C30"}


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


def xml_code(resp: requests.Response):
    m = re.search(r"<Code>([^<]+)</Code>", resp.text or "") if resp.status_code >= 400 else None
    return m.group(1) if m else None


def xml_message(resp: requests.Response):
    """Only the error message: S3 error bodies can also echo the signed request, token included."""
    m = re.search(r"<Message>([^<]+)</Message>", resp.text or "")
    return m.group(1)[:300] if m else None


def expect_http_error(c, resp: requests.Response):
    """Same as expect_error, for a plain HTTP response (presigned URLs)."""
    if resp.status_code >= 400:
        m = re.search(r"<Code>([^<]+)</Code>", resp.text or "")
        c.observe(error_code=m.group(1) if m else None, http_status=resp.status_code)
        return
    c.observe(accepted=True, http_status=resp.status_code)
    raise AssertionError(f"HTTP {resp.status_code}: request was accepted; real AWS refuses it")


def md5_etag(data: bytes) -> str:
    return '"' + hashlib.md5(data).hexdigest() + '"'


def multipart_etag(parts: list[bytes]) -> str:
    digest = hashlib.md5(b"".join(hashlib.md5(p).digest() for p in parts)).hexdigest()
    return f'"{digest}-{len(parts)}"'


def part_entry(n: int, resp: dict) -> dict:
    """A CompleteMultipartUpload part. Newer SDKs send a CRC32 per part by default; when the
    service returned one, S3 requires it back in the completion request."""
    # The upload is created without a checksum algorithm, so the completion lists ETags only.
    # (Echoing the per-part CRC32 the SDK adds makes real S3 answer InvalidPart.)
    return {"PartNumber": n, "ETag": resp["ETag"]}


def blob(seed: str, size: int) -> bytes:
    """Deterministic bytes, so expected ETags are the same in every run and environment."""
    out, block = bytearray(), hashlib.sha256(seed.encode()).digest()
    while len(out) < size:
        out += block
        block = hashlib.sha256(block).digest()
    return bytes(out[:size])


def s3_client(env):
    """S3 needs two settings the shared clients don't set: path-style addressing on emulators
    (bucket.localhost does not resolve everywhere) and SigV4 for presigned URLs everywhere."""
    # Real AWS: virtual-hosted style. With "auto", presigned URLs point at the global
    # s3.amazonaws.com host while being signed for the study region, and S3 refuses them.
    # Names that are not DNS-safe (C28) still fall back to path style.
    style = "virtual" if env.is_real else "path"
    cfg = env.botocore_config().merge(Config(signature_version="s3v4", s3={"addressing_style": style}))
    c = env.session.client("s3", endpoint_url=env.endpoint_url, verify=env.verify, config=cfg)
    env._attach_latency_hooks(c, "s3")
    return c


def bucket_code(s3, bucket: str) -> str:
    try:
        s3.head_bucket(Bucket=bucket)
        return "exists"
    except ClientError as exc:
        return code_of(exc)


def http_verify(env):
    return env.verify if env.verify not in (None, "") else True


def empty_and_delete(s3, bucket: str) -> None:
    """Removes every version, delete marker and unfinished upload, then the bucket."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        batch = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                 for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if batch:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": batch, "Quiet": True})
    for u in s3.list_multipart_uploads(Bucket=bucket).get("Uploads", []):
        quietly(s3.abort_multipart_upload, Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    s3.delete_bucket(Bucket=bucket)


@pytest.fixture(scope="module")
def S(study_env, prefix):
    """Shared state; cleans up whatever exists when the module ends, pass or fail."""
    state = {"bucket": f"{prefix}-bucket", "extra_buckets": [], "s3": s3_client(study_env)}
    yield state
    s3 = state["s3"]
    for b in [state["bucket"], *state["extra_buckets"]]:
        quietly(empty_and_delete, s3, b)


# --- control plane ------------------------------------------------------------------------

def test_c01_create_bucket(study_env, rec, S):
    with chk(rec, "W5-C01") as c:
        s3 = S["s3"]
        kwargs = {"Bucket": S["bucket"]}
        if study_env.region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": study_env.region}
        s3.create_bucket(**kwargs)
        found = poll(lambda: bucket_code(s3, S["bucket"]) == "exists", 30)
        c.observe(found=bool(found))
        assert found, "HeadBucket did not find the new bucket"


def test_c02_bucket_location(study_env, rec, S):
    with chk(rec, "W5-C02", "W5-C01") as c:
        loc = S["s3"].get_bucket_location(Bucket=S["bucket"]).get("LocationConstraint")
        # us-east-1 is reported as None (empty LocationConstraint) by real S3.
        normalized = loc or "us-east-1"
        c.observe(location_is_region=normalized == study_env.region, raw_is_none=loc is None)
        assert normalized == study_env.region, f"location {loc!r}, expected {study_env.region}"


def test_c03_versioning(rec, S):
    with chk(rec, "W5-C03", "W5-C01") as c:
        s3 = S["s3"]
        s3.put_bucket_versioning(Bucket=S["bucket"], VersioningConfiguration={"Status": "Enabled"})
        status = s3.get_bucket_versioning(Bucket=S["bucket"]).get("Status")
        c.observe(status=status)
        assert status == "Enabled"


def test_c04_lifecycle(rec, S):
    with chk(rec, "W5-C04", "W5-C01") as c:
        s3 = S["s3"]
        s3.put_bucket_lifecycle_configuration(Bucket=S["bucket"], LifecycleConfiguration={"Rules": [LIFECYCLE_RULE]})
        rules = s3.get_bucket_lifecycle_configuration(Bucket=S["bucket"]).get("Rules", [])
        c.observe(rules=rules)
        assert rules == [LIFECYCLE_RULE], f"read back {rules}"


def test_c05_list_buckets(rec, S):
    with chk(rec, "W5-C05", "W5-C01") as c:
        names = {b["Name"] for b in S["s3"].list_buckets().get("Buckets", [])}
        c.observe(listed=S["bucket"] in names)
        assert S["bucket"] in names


# --- objects and versions -----------------------------------------------------------------

def test_c06_put_object(rec, S):
    with chk(rec, "W5-C06", "W5-C03") as c:
        S["key"], S["v1_body"] = "data/report.txt", b"version one\n"
        r = S["s3"].put_object(Bucket=S["bucket"], Key=S["key"], Body=S["v1_body"],
                               ContentType="text/plain", Metadata={"owner": "study", "stage": "v1"})
        S["v1"] = r.get("VersionId")
        c.observe(has_version_id=bool(S["v1"]) and S["v1"] != "null",
                  etag_is_md5=r.get("ETag") == md5_etag(S["v1_body"]),
                  sse=r.get("ServerSideEncryption"),
                  checksum_crc32=bool(r.get("ChecksumCRC32")))
        assert S["v1"] and S["v1"] != "null", f"no version id: {r.get('VersionId')!r}"
        assert r.get("ETag") == md5_etag(S["v1_body"]), f"ETag {r.get('ETag')}"


def test_c07_head_object(rec, S):
    with chk(rec, "W5-C07", "W5-C06") as c:
        h = S["s3"].head_object(Bucket=S["bucket"], Key=S["key"])
        c.observe(content_type=h.get("ContentType"), metadata=h.get("Metadata"),
                  length=h.get("ContentLength"), sse=h.get("ServerSideEncryption"))
        assert h.get("ContentType") == "text/plain"
        assert h.get("Metadata") == {"owner": "study", "stage": "v1"}
        assert h.get("ContentLength") == len(S["v1_body"])


def test_c08_second_version(rec, S):
    with chk(rec, "W5-C08", "W5-C06") as c:
        s3 = S["s3"]
        S["v2_body"] = b"version two, a little longer\n"
        S["v2"] = s3.put_object(Bucket=S["bucket"], Key=S["key"], Body=S["v2_body"]).get("VersionId")
        current = s3.get_object(Bucket=S["bucket"], Key=S["key"])["Body"].read()
        old = s3.get_object(Bucket=S["bucket"], Key=S["key"], VersionId=S["v1"])["Body"].read()
        c.observe(new_version=bool(S["v2"]) and S["v2"] != S["v1"],
                  current_is_v2=current == S["v2_body"], old_is_v1=old == S["v1_body"])
        assert S["v2"] and S["v2"] != S["v1"], "second put did not create a new version"
        assert current == S["v2_body"] and old == S["v1_body"]


def versions_of(s3, bucket: str, key: str) -> tuple[list, list]:
    r = s3.list_object_versions(Bucket=bucket, Prefix=key)
    return ([v for v in r.get("Versions", []) if v["Key"] == key],
            [m for m in r.get("DeleteMarkers", []) if m["Key"] == key])


def test_c09_list_versions(rec, S):
    with chk(rec, "W5-C09", "W5-C08") as c:
        versions, markers = versions_of(S["s3"], S["bucket"], S["key"])
        latest = {v["VersionId"]: v["IsLatest"] for v in versions}
        c.observe(versions=len(versions), markers=len(markers),
                  v2_latest=latest.get(S["v2"]) is True, v1_latest=latest.get(S["v1"]))
        assert len(versions) == 2 and not markers
        assert latest.get(S["v2"]) is True and latest.get(S["v1"]) is False


def test_c10_delete_marker(rec, S):
    with chk(rec, "W5-C10", "W5-C08") as c:
        s3 = S["s3"]
        r = s3.delete_object(Bucket=S["bucket"], Key=S["key"])
        S["marker"] = r.get("VersionId")
        try:
            s3.get_object(Bucket=S["bucket"], Key=S["key"])
            code = None
        except ClientError as exc:
            code = code_of(exc)
        c.observe(delete_marker=r.get("DeleteMarker"), has_marker_id=bool(S["marker"]), get_code=code)
        assert r.get("DeleteMarker") is True and S["marker"], f"response {r}"
        assert code == "NoSuchKey", f"GetObject after delete: {code}"


def test_c11_list_with_marker(rec, S):
    with chk(rec, "W5-C11", "W5-C10") as c:
        versions, markers = versions_of(S["s3"], S["bucket"], S["key"])
        c.observe(versions=len(versions), markers=len(markers),
                  marker_latest=bool(markers) and markers[0].get("IsLatest") is True,
                  any_version_latest=any(v["IsLatest"] for v in versions))
        assert len(versions) == 2 and len(markers) == 1
        assert markers[0].get("IsLatest") is True and not any(v["IsLatest"] for v in versions)


def test_c12_read_old_version(rec, S):
    with chk(rec, "W5-C12", "W5-C10") as c:
        body = S["s3"].get_object(Bucket=S["bucket"], Key=S["key"], VersionId=S["v1"])["Body"].read()
        c.observe(old_is_v1=body == S["v1_body"])
        assert body == S["v1_body"]


def test_c13_undelete(rec, S):
    with chk(rec, "W5-C13", "W5-C10") as c:
        s3 = S["s3"]
        s3.delete_object(Bucket=S["bucket"], Key=S["key"], VersionId=S["marker"])
        body = s3.get_object(Bucket=S["bucket"], Key=S["key"])["Body"].read()
        c.observe(current_is_v2=body == S["v2_body"])
        assert body == S["v2_body"]


def test_c14_range_get(rec, S):
    with chk(rec, "W5-C14", "W5-C13") as c:
        r = S["s3"].get_object(Bucket=S["bucket"], Key=S["key"], Range="bytes=8-10")
        body = r["Body"].read()
        status = r["ResponseMetadata"]["HTTPStatusCode"]
        c.observe(status=status, body_ok=body == S["v2_body"][8:11], content_range=r.get("ContentRange", "")
                  .replace(str(len(S["v2_body"])), "LEN"))
        assert status == 206 and body == S["v2_body"][8:11]


def test_c15_if_none_match(rec, S):
    with chk(rec, "W5-C15", "W5-C13") as c:
        s3 = S["s3"]
        etag = s3.head_object(Bucket=S["bucket"], Key=S["key"])["ETag"]
        try:
            r = s3.get_object(Bucket=S["bucket"], Key=S["key"], IfNoneMatch=etag)
            status = r["ResponseMetadata"]["HTTPStatusCode"]
        except ClientError as exc:
            status = exc.response["ResponseMetadata"].get("HTTPStatusCode")
        c.observe(status=status)
        assert status == 304, f"HTTP {status}, expected 304"


# --- presigned URLs -----------------------------------------------------------------------

def test_c16_presigned_get(study_env, rec, S):
    with chk(rec, "W5-C16", "W5-C13") as c:
        url = S["s3"].generate_presigned_url("get_object", Params={"Bucket": S["bucket"], "Key": S["key"]},
                                             ExpiresIn=300)
        resp = requests.get(url, timeout=30, verify=http_verify(study_env))
        c.observe(status=resp.status_code, body_ok=resp.content == S["v2_body"], error_code=xml_code(resp))
        assert resp.status_code == 200 and resp.content == S["v2_body"], \
            f"HTTP {resp.status_code}: {xml_code(resp)}: {xml_message(resp)} | host {url.split('/', 3)[2]} params {sorted(q.split('=')[0] for q in url.split('?', 1)[-1].split('&'))}"


def test_c17_presigned_put(study_env, rec, S):
    with chk(rec, "W5-C17", "W5-C03") as c:
        key, body = "uploads/presigned.bin", blob("presigned-put", 2048)
        url = S["s3"].generate_presigned_url("put_object", Params={"Bucket": S["bucket"], "Key": key},
                                             ExpiresIn=300)
        resp = requests.put(url, data=body, timeout=30, verify=http_verify(study_env))
        stored = None
        if resp.status_code == 200:
            stored = S["s3"].get_object(Bucket=S["bucket"], Key=key)["Body"].read()
        c.observe(status=resp.status_code, stored_ok=stored == body, error_code=xml_code(resp))
        assert resp.status_code == 200 and stored == body, f"HTTP {resp.status_code}: {xml_code(resp)}: {xml_message(resp)}"


# --- multipart ----------------------------------------------------------------------------

def test_c18_multipart(rec, S):
    with chk(rec, "W5-C18", "W5-C03") as c:
        s3 = S["s3"]
        S["mp_key"] = "big/archive.bin"
        S["mp_parts"] = [blob("part-1", PART), blob("part-2", PART), blob("part-3", 1 * MiB)]
        up = s3.create_multipart_upload(Bucket=S["bucket"], Key=S["mp_key"])["UploadId"]
        parts = []
        for n, data in enumerate(S["mp_parts"], start=1):
            r = s3.upload_part(Bucket=S["bucket"], Key=S["mp_key"], UploadId=up, PartNumber=n, Body=data)
            parts.append(part_entry(n, r))
        r = s3.complete_multipart_upload(Bucket=S["bucket"], Key=S["mp_key"], UploadId=up,
                                         MultipartUpload={"Parts": parts})
        etag = r.get("ETag", "")
        c.observe(etag_suffix=etag.strip('"').rsplit("-", 1)[-1] if "-" in etag else None,
                  etag_is_md5_of_md5s=etag == multipart_etag(S["mp_parts"]),
                  has_version_id=bool(r.get("VersionId")))
        assert etag.endswith('-3"'), f"ETag {etag!r}"


def test_c19_multipart_download(rec, S):
    with chk(rec, "W5-C19", "W5-C18") as c:
        data = S["s3"].get_object(Bucket=S["bucket"], Key=S["mp_key"])["Body"].read()
        whole = b"".join(S["mp_parts"])
        c.observe(size_ok=len(data) == len(whole),
                  sha256_ok=hashlib.sha256(data).digest() == hashlib.sha256(whole).digest())
        assert len(data) == len(whole) and data == whole


def test_c20_abort_multipart(rec, S):
    with chk(rec, "W5-C20", "W5-C03") as c:
        s3 = S["s3"]
        key = "big/abandoned.bin"
        up = s3.create_multipart_upload(Bucket=S["bucket"], Key=key)["UploadId"]
        s3.upload_part(Bucket=S["bucket"], Key=key, UploadId=up, PartNumber=1, Body=blob("abandoned", 1024))
        listed = any(u["UploadId"] == up for u in s3.list_multipart_uploads(Bucket=S["bucket"]).get("Uploads", []))
        s3.abort_multipart_upload(Bucket=S["bucket"], Key=key, UploadId=up)
        after = any(u["UploadId"] == up for u in s3.list_multipart_uploads(Bucket=S["bucket"]).get("Uploads", []))
        c.observe(listed_before=listed, listed_after=after)
        assert listed and not after


# --- negative checks ----------------------------------------------------------------------

def test_c21_presigned_expired(study_env, rec, S):
    with chk(rec, "W5-C21", "W5-C16") as c:
        url = S["s3"].generate_presigned_url("get_object", Params={"Bucket": S["bucket"], "Key": S["key"]},
                                             ExpiresIn=EXPIRES_SHORT)
        time.sleep(EXPIRES_SHORT + 3)
        expect_http_error(c, requests.get(url, timeout=30, verify=http_verify(study_env)))


def test_c22_presigned_tampered(study_env, rec, S):
    with chk(rec, "W5-C22", "W5-C16") as c:
        url = S["s3"].generate_presigned_url("get_object", Params={"Bucket": S["bucket"], "Key": S["key"]},
                                             ExpiresIn=300)
        # Flip the last hex digit of the signature.
        tampered = re.sub(r"(X-Amz-Signature=[0-9a-f]*)([0-9a-f])",
                          lambda m: m.group(1) + ("0" if m.group(2) != "0" else "1"), url)
        assert tampered != url, "no X-Amz-Signature in the URL"
        expect_http_error(c, requests.get(tampered, timeout=30, verify=http_verify(study_env)))


def start_upload(s3, bucket: str, key: str, parts: list[bytes]) -> tuple[str, list[dict]]:
    up = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    done = []
    for n, data in enumerate(parts, start=1):
        done.append(part_entry(n, s3.upload_part(Bucket=bucket, Key=key, UploadId=up, PartNumber=n, Body=data)))
    return up, done


def test_c23_part_too_small(rec, S):
    with chk(rec, "W5-C23", "W5-C03") as c:
        s3, key = S["s3"], "neg/small-part.bin"
        up, parts = start_upload(s3, S["bucket"], key, [blob("small-1", 1 * MiB), blob("small-2", 1 * MiB)])
        try:
            expect_error(c, lambda: s3.complete_multipart_upload(
                Bucket=S["bucket"], Key=key, UploadId=up, MultipartUpload={"Parts": parts}))
        finally:
            quietly(s3.abort_multipart_upload, Bucket=S["bucket"], Key=key, UploadId=up)


def test_c24_wrong_part_etag(rec, S):
    with chk(rec, "W5-C24", "W5-C03") as c:
        s3, key = S["s3"], "neg/wrong-etag.bin"
        up, parts = start_upload(s3, S["bucket"], key, [blob("etag-1", 1024)])
        parts[0]["ETag"] = md5_etag(b"something else")
        try:
            expect_error(c, lambda: s3.complete_multipart_upload(
                Bucket=S["bucket"], Key=key, UploadId=up, MultipartUpload={"Parts": parts}))
        finally:
            quietly(s3.abort_multipart_upload, Bucket=S["bucket"], Key=key, UploadId=up)


def test_c25_parts_out_of_order(rec, S):
    with chk(rec, "W5-C25", "W5-C03") as c:
        s3, key = S["s3"], "neg/out-of-order.bin"
        up, parts = start_upload(s3, S["bucket"], key, [blob("order-1", PART), blob("order-2", 1024)])
        try:
            expect_error(c, lambda: s3.complete_multipart_upload(
                Bucket=S["bucket"], Key=key, UploadId=up, MultipartUpload={"Parts": list(reversed(parts))}))
        finally:
            quietly(s3.abort_multipart_upload, Bucket=S["bucket"], Key=key, UploadId=up)


def test_c26_conditional_put(rec, S):
    with chk(rec, "W5-C26", "W5-C13") as c:
        expect_error(c, lambda: S["s3"].put_object(Bucket=S["bucket"], Key=S["key"], Body=b"overwrite",
                                                   IfNoneMatch="*"))


def test_c27_missing_version(rec, S):
    with chk(rec, "W5-C27", "W5-C06") as c:
        bogus = "3HL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo"
        expect_error(c, lambda: S["s3"].get_object(Bucket=S["bucket"], Key=S["key"], VersionId=bogus))


def test_c28_invalid_bucket_name(study_env, rec, S, prefix):
    with chk(rec, "W5-C28") as c:
        name = f"{prefix}-Bad_Name"
        kwargs = {"Bucket": name}
        if study_env.region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": study_env.region}
        S["extra_buckets"].append(name)  # cleaned up if an environment accepts it
        expect_error(c, lambda: S["s3"].create_bucket(**kwargs))


def test_c29_lifecycle_zero_days(rec, S):
    with chk(rec, "W5-C29", "W5-C04") as c:
        bad = {**LIFECYCLE_RULE, "ID": "zero-days", "Expiration": {"Days": 0}}
        expect_error(c, lambda: S["s3"].put_bucket_lifecycle_configuration(
            Bucket=S["bucket"], LifecycleConfiguration={"Rules": [bad]}))


def test_c30_delete_nonempty_bucket(rec, S):
    with chk(rec, "W5-C30", "W5-C06") as c:
        expect_error(c, lambda: S["s3"].delete_bucket(Bucket=S["bucket"]))


# --- teardown -----------------------------------------------------------------------------

def test_c31_teardown(rec, S):
    with chk(rec, "W5-C31", "W5-C01"):
        empty_and_delete(S["s3"], S["bucket"])


def test_c32_gone(rec, S):
    with chk(rec, "W5-C32", "W5-C31") as c:
        s3 = S["s3"]

        gone = poll(lambda: bucket_code(s3, S["bucket"]) != "exists", 60, interval=3)
        last = bucket_code(s3, S["bucket"])
        c.observe(code=last)
        assert gone, "bucket still exists"
