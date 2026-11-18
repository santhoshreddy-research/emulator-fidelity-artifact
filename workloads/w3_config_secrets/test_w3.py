"""W3 Config and secrets: a customer-managed KMS key (with an alias), SSM parameters (String,
StringList and a SecureString encrypted with that key) and a Secrets Manager secret encrypted
with the same key.

Resources are created through the service APIs (not CloudFormation), like W1, W2 and W5.
Checks run in file order and share state. A check whose prerequisite failed is recorded
as 'blocked' and skipped.

The KMS key cannot be deleted at once: teardown schedules deletion with the 7-day minimum,
as real AWS requires. Recorded observations never contain run-specific values (names, ARNs,
version ids), so they can be compared across runs and environments.
"""
from __future__ import annotations

import json
import re
import string

import pytest
from botocore.exceptions import ClientError

from harness.aws_helpers import quietly
from harness.record import poll

WORKLOAD = "W3"

PLAINTEXT = b"study plaintext: 4111-1111-1111-1111"
CONTEXT = {"purpose": "w3-study"}

CHECKS = {
    # KMS
    "W3-C01": ("control", "CreateKey with tags returns an enabled symmetric ENCRYPT_DECRYPT key"),
    "W3-C02": ("control", "CreateAlias points an alias at the key and ListAliases shows it"),
    "W3-C03": ("data", "Encrypt through the alias and Decrypt with the same encryption context round-trips"),
    "W3-C04": ("data", "GenerateDataKey AES_256 returns 32 bytes whose ciphertext decrypts to the same bytes"),
    # SSM Parameter Store
    "W3-C05": ("control", "PutParameter String creates version 1 in the Standard tier"),
    "W3-C06": ("data", "A SecureString encrypted with the study key reads back decrypted"),
    "W3-C07": ("data", "Reading the SecureString without decryption does not return the plaintext"),
    "W3-C08": ("control", "DescribeParameters reports the SecureString's KMS key"),
    "W3-C09": ("functional", "Overwriting a parameter creates version 2 and GetParameterHistory shows both"),
    "W3-C10": ("functional", "GetParametersByPath returns 3 parameters recursively and 2 without recursion"),
    "W3-C11": ("data", "GetParameters with one missing name returns the found one and lists the missing one"),
    "W3-C12": ("data", "A StringList parameter reads back with its type and comma-separated value"),
    # Secrets Manager
    "W3-C13": ("control", "CreateSecret with the study key returns an ARN with the 6-character suffix"),
    "W3-C14": ("data", "GetSecretValue returns the JSON string with stage AWSCURRENT"),
    "W3-C15": ("control", "DescribeSecret reports the study key and the tags"),
    "W3-C16": ("functional", "PutSecretValue moves AWSCURRENT to the new value and AWSPREVIOUS to the old one"),
    "W3-C17": ("functional", "ListSecretVersionIds shows both versions with their stages"),
    "W3-C18": ("data", "GetRandomPassword returns 32 characters with no punctuation when asked"),
    "W3-C19": ("functional", "A secret scheduled for deletion cannot be read (InvalidRequestException)"),
    "W3-C20": ("functional", "RestoreSecret makes the secret readable again"),
    # negative checks: real AWS rejects these
    "W3-C21": ("data", "PutParameter on an existing name without Overwrite is rejected"),
    "W3-C22": ("data", "GetParameter on a name that does not exist is rejected"),
    "W3-C23": ("data", "A Standard-tier String parameter over 4096 characters is rejected"),
    "W3-C24": ("data", "A value that breaks the parameter's AllowedPattern is rejected"),
    "W3-C25": ("data", "A parameter name containing a space is rejected"),
    "W3-C26": ("control", "CreateSecret with a name that already exists is rejected"),
    "W3-C27": ("control", "DeleteSecret with a recovery window of 3 days (minimum 7) is rejected"),
    "W3-C28": ("data", "CreateSecret with both SecretString and SecretBinary is rejected"),
    "W3-C29": ("data", "Decrypt with a different encryption context is rejected"),
    "W3-C30": ("data", "Encrypt with more than 4096 bytes of plaintext is rejected"),
    "W3-C31": ("control", "ScheduleKeyDeletion with a 6-day window (minimum 7) is rejected"),
    # teardown
    "W3-C32": ("control", "Delete the parameters, the secret and the alias, and schedule the key for deletion"),
    "W3-C33": ("control", "After teardown the parameters and secret are gone and the key is PendingDeletion"),
    "W3-C34": ("data", "Encrypt with a key that is pending deletion is rejected"),
}

# Negative checks: real AWS rejects the request. The check passes when the error occurs.
NEGATIVE = {"W3-C21", "W3-C22", "W3-C23", "W3-C24", "W3-C25", "W3-C26", "W3-C27", "W3-C28",
            "W3-C29", "W3-C30", "W3-C31", "W3-C34"}


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


def key_ref_kind(value: str | None, S: dict) -> str | None:
    """How a service reports the KMS key: by alias name, key id, key ARN or alias ARN."""
    if not value:
        return None
    if value == S["alias"]:
        return "alias-name"
    if value == S["key_id"]:
        return "key-id"
    if value == S["key_arn"]:
        return "key-arn"
    if value.endswith(":" + S["alias"]):
        return "alias-arn"
    return "other"


@pytest.fixture(scope="module")
def S(study_env, prefix):
    """Shared state; cleans up whatever exists when the module ends, pass or fail."""
    state = {
        "alias": f"alias/{prefix}-key",
        "path": f"/{prefix}/app",
        "secret": f"{prefix}-db-credentials",
        "extra_secrets": [],
        "params": [],
    }
    yield state
    ssm, sm, kms = (study_env.client(s) for s in ("ssm", "secretsmanager", "kms"))
    for name in state["params"]:
        quietly(ssm.delete_parameter, Name=name)
    for sid in [state["secret"], *state["extra_secrets"]]:
        quietly(sm.delete_secret, SecretId=sid, ForceDeleteWithoutRecovery=True)
    quietly(kms.delete_alias, AliasName=state["alias"])
    if state.get("key_id"):
        quietly(kms.schedule_key_deletion, KeyId=state["key_id"], PendingWindowInDays=7)


def put_param(study_env, S, name: str, **kwargs) -> dict:
    S["params"].append(name)
    return study_env.client("ssm").put_parameter(Name=name, **kwargs)


# --- KMS ----------------------------------------------------------------------------------

def test_c01_create_key(study_env, rec, S, tags):
    with chk(rec, "W3-C01") as c:
        meta = study_env.client("kms").create_key(
            Description="emulator study W3", KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
            Tags=[{"TagKey": k, "TagValue": v} for k, v in tags.items()],
        )["KeyMetadata"]
        S["key_id"], S["key_arn"] = meta["KeyId"], meta["Arn"]
        c.observe(state=meta.get("KeyState"), usage=meta.get("KeyUsage"), spec=meta.get("KeySpec"),
                  manager=meta.get("KeyManager"), enabled=meta.get("Enabled"))
        assert meta.get("KeyState") == "Enabled" and meta.get("Enabled") is True
        assert meta.get("KeyUsage") == "ENCRYPT_DECRYPT" and meta.get("KeySpec") == "SYMMETRIC_DEFAULT"


def test_c02_alias(study_env, rec, S):
    with chk(rec, "W3-C02", "W3-C01") as c:
        kms = study_env.client("kms")
        kms.create_alias(AliasName=S["alias"], TargetKeyId=S["key_id"])
        aliases = [a for page in kms.get_paginator("list_aliases").paginate() for a in page["Aliases"]]
        mine = next((a for a in aliases if a["AliasName"] == S["alias"]), None)
        c.observe(listed=mine is not None, targets_key=bool(mine) and mine.get("TargetKeyId") == S["key_id"])
        assert mine and mine.get("TargetKeyId") == S["key_id"]


def test_c03_encrypt_decrypt(study_env, rec, S):
    with chk(rec, "W3-C03", "W3-C02") as c:
        kms = study_env.client("kms")
        enc = kms.encrypt(KeyId=S["alias"], Plaintext=PLAINTEXT, EncryptionContext=CONTEXT)
        S["ciphertext"] = enc["CiphertextBlob"]
        dec = kms.decrypt(CiphertextBlob=S["ciphertext"], EncryptionContext=CONTEXT)
        c.observe(roundtrip=dec["Plaintext"] == PLAINTEXT, encrypt_key=key_ref_kind(enc.get("KeyId"), S),
                  decrypt_key=key_ref_kind(dec.get("KeyId"), S),
                  algorithm=dec.get("EncryptionAlgorithm"))
        assert dec["Plaintext"] == PLAINTEXT
        assert dec.get("KeyId") == S["key_arn"], f"Decrypt KeyId is {key_ref_kind(dec.get('KeyId'), S)}"


def test_c04_data_key(study_env, rec, S):
    with chk(rec, "W3-C04", "W3-C01") as c:
        kms = study_env.client("kms")
        dk = kms.generate_data_key(KeyId=S["key_id"], KeySpec="AES_256")
        back = kms.decrypt(CiphertextBlob=dk["CiphertextBlob"])["Plaintext"]
        c.observe(length=len(dk["Plaintext"]), roundtrip=back == dk["Plaintext"])
        assert len(dk["Plaintext"]) == 32 and back == dk["Plaintext"]


# --- SSM Parameter Store ------------------------------------------------------------------

def test_c05_string_parameter(study_env, rec, S):
    with chk(rec, "W3-C05") as c:
        S["p_url"] = f"{S['path']}/db_url"
        r = put_param(study_env, S, S["p_url"], Value="postgres://db.internal:5432/app", Type="String")
        c.observe(version=r.get("Version"), tier=r.get("Tier"))
        assert r.get("Version") == 1


def test_c06_secure_string(study_env, rec, S):
    with chk(rec, "W3-C06", "W3-C02") as c:
        S["p_secure"] = f"{S['path']}/api_token"
        S["secure_value"] = "tok-1234567890-secret"
        put_param(study_env, S, S["p_secure"], Value=S["secure_value"], Type="SecureString", KeyId=S["alias"])
        p = study_env.client("ssm").get_parameter(Name=S["p_secure"], WithDecryption=True)["Parameter"]
        c.observe(type=p.get("Type"), value_ok=p.get("Value") == S["secure_value"], version=p.get("Version"))
        assert p.get("Type") == "SecureString" and p.get("Value") == S["secure_value"]


def test_c07_secure_string_encrypted(study_env, rec, S):
    with chk(rec, "W3-C07", "W3-C06") as c:
        p = study_env.client("ssm").get_parameter(Name=S["p_secure"], WithDecryption=False)["Parameter"]
        c.observe(plaintext_returned=p.get("Value") == S["secure_value"])
        assert p.get("Value") != S["secure_value"], "the SecureString came back in plain text"


def test_c08_describe_secure_string(study_env, rec, S):
    with chk(rec, "W3-C08", "W3-C06") as c:
        params = study_env.client("ssm").describe_parameters(
            ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [S["p_secure"]]}]
        ).get("Parameters", [])
        key = params[0].get("KeyId") if params else None
        c.observe(found=bool(params), key_ref=key_ref_kind(key, S))
        assert params and key_ref_kind(key, S) not in (None, "other"), f"KeyId reported as {key!r}"


def test_c09_overwrite_history(study_env, rec, S):
    with chk(rec, "W3-C09", "W3-C05") as c:
        ssm = study_env.client("ssm")
        r = ssm.put_parameter(Name=S["p_url"], Value="postgres://db2.internal:5432/app", Type="String",
                              Overwrite=True)
        hist = [h for page in ssm.get_paginator("get_parameter_history").paginate(Name=S["p_url"])
                for h in page["Parameters"]]
        c.observe(version=r.get("Version"), history=len(hist),
                  versions=sorted(h.get("Version") for h in hist))
        assert r.get("Version") == 2 and sorted(h.get("Version") for h in hist) == [1, 2]


def test_c10_by_path(study_env, rec, S):
    with chk(rec, "W3-C10", "W3-C06") as c:
        ssm = study_env.client("ssm")
        put_param(study_env, S, f"{S['path']}/nested/flag", Value="on", Type="String")

        def names(recursive: bool) -> list[str]:
            pages = ssm.get_paginator("get_parameters_by_path").paginate(
                Path=S["path"], Recursive=recursive, WithDecryption=False)
            return sorted(p["Name"] for page in pages for p in page["Parameters"])
        deep, flat = names(True), names(False)
        c.observe(recursive=len(deep), non_recursive=len(flat))
        assert len(deep) == 3 and len(flat) == 2, f"recursive {len(deep)}, non-recursive {len(flat)}"


def test_c11_get_parameters_mixed(study_env, rec, S):
    with chk(rec, "W3-C11", "W3-C05") as c:
        missing = f"{S['path']}/does_not_exist"
        r = study_env.client("ssm").get_parameters(Names=[S["p_url"], missing])
        c.observe(found=len(r.get("Parameters", [])), invalid=len(r.get("InvalidParameters", [])),
                  invalid_is_missing=r.get("InvalidParameters") == [missing])
        assert len(r.get("Parameters", [])) == 1 and r.get("InvalidParameters") == [missing]


def test_c12_string_list(study_env, rec, S):
    with chk(rec, "W3-C12") as c:
        name = f"{S['path']}/regions"
        put_param(study_env, S, name, Value="us-west-1,us-west-2,eu-west-1", Type="StringList")
        p = study_env.client("ssm").get_parameter(Name=name)["Parameter"]
        c.observe(type=p.get("Type"), value=p.get("Value"))
        assert p.get("Type") == "StringList" and p.get("Value") == "us-west-1,us-west-2,eu-west-1"


# --- Secrets Manager ----------------------------------------------------------------------

def test_c13_create_secret(study_env, rec, S, tags):
    with chk(rec, "W3-C13", "W3-C02") as c:
        S["secret_v1"] = json.dumps({"username": "app", "password": "first-password"})
        r = study_env.client("secretsmanager").create_secret(
            Name=S["secret"], SecretString=S["secret_v1"], KmsKeyId=S["alias"],
            Tags=[{"Key": k, "Value": v} for k, v in tags.items()])
        S["secret_arn"] = r["ARN"]
        suffix_ok = re.fullmatch(re.escape(f":secret:{S['secret']}") + r"-[A-Za-z0-9]{6}",
                                 r["ARN"][r["ARN"].index(":secret:"):]) is not None
        c.observe(arn_suffix_ok=suffix_ok, has_version=bool(r.get("VersionId")))
        assert suffix_ok, "ARN does not end in -XXXXXX"


def test_c14_get_secret(study_env, rec, S):
    with chk(rec, "W3-C14", "W3-C13") as c:
        sm = study_env.client("secretsmanager")

        def fresh():
            try:
                r = sm.get_secret_value(SecretId=S["secret"])
            except ClientError:
                return None
            return r if r.get("SecretString") == S["secret_v1"] else None

        # Secrets Manager is eventually consistent: wait for the new secret to be readable.
        r = poll(fresh, 30, interval=2) or sm.get_secret_value(SecretId=S["secret"])
        c.observe(value_ok=r.get("SecretString") == S["secret_v1"], stages=r.get("VersionStages"))
        assert r.get("SecretString") == S["secret_v1"] and r.get("VersionStages") == ["AWSCURRENT"]


def test_c15_describe_secret(study_env, rec, S):
    with chk(rec, "W3-C15", "W3-C13") as c:
        d = study_env.client("secretsmanager").describe_secret(SecretId=S["secret"])
        tag_keys = sorted(t["Key"] for t in d.get("Tags", []))
        c.observe(key_ref=key_ref_kind(d.get("KmsKeyId"), S), tag_keys=tag_keys)
        assert key_ref_kind(d.get("KmsKeyId"), S) not in (None, "other"), f"KmsKeyId {d.get('KmsKeyId')!r}"
        assert "Project" in tag_keys


def _quiet(fn):
    """Returns fn(), or None if it raised a ClientError (used while waiting for a write to show)."""
    try:
        return fn()
    except ClientError:
        return None


def test_c16_rotate_value(study_env, rec, S):
    with chk(rec, "W3-C16", "W3-C14") as c:
        sm = study_env.client("secretsmanager")
        S["secret_v2"] = json.dumps({"username": "app", "password": "second-password"})
        sm.put_secret_value(SecretId=S["secret"], SecretString=S["secret_v2"])
        def both():
            cur = sm.get_secret_value(SecretId=S["secret"])
            prev = sm.get_secret_value(SecretId=S["secret"], VersionStage="AWSPREVIOUS")
            ok = cur.get("SecretString") == S["secret_v2"] and prev.get("SecretString") == S["secret_v1"]
            return (cur, prev) if ok else None

        # Wait for the new value to become AWSCURRENT (it lags a few seconds on real AWS).
        found = poll(lambda: _quiet(both), 30, interval=2)
        if found:
            cur, prev = found
        else:
            cur = sm.get_secret_value(SecretId=S["secret"])
            prev = sm.get_secret_value(SecretId=S["secret"], VersionStage="AWSPREVIOUS")
        c.observe(current_ok=cur.get("SecretString") == S["secret_v2"],
                  previous_ok=prev.get("SecretString") == S["secret_v1"])
        assert cur.get("SecretString") == S["secret_v2"] and prev.get("SecretString") == S["secret_v1"]


def test_c17_version_ids(study_env, rec, S):
    with chk(rec, "W3-C17", "W3-C16") as c:
        sm = study_env.client("secretsmanager")

        def listing():
            versions = sm.list_secret_version_ids(SecretId=S["secret"])["Versions"]
            stages = sorted(tuple(sorted(v.get("VersionStages", []))) for v in versions)
            return versions, stages

        found = poll(lambda: (lambda vs: vs if vs[1] == [("AWSCURRENT",), ("AWSPREVIOUS",)] else None)(listing()),
                     30, interval=2)
        versions, stages = found or listing()
        c.observe(versions=len(versions), stages=[list(s) for s in stages])
        assert stages == [("AWSCURRENT",), ("AWSPREVIOUS",)]


def test_c18_random_password(study_env, rec, S):
    with chk(rec, "W3-C18") as c:
        pw = study_env.client("secretsmanager").get_random_password(
            PasswordLength=32, ExcludePunctuation=True)["RandomPassword"]
        c.observe(length=len(pw), has_punctuation=any(ch in string.punctuation for ch in pw))
        assert len(pw) == 32 and not any(ch in string.punctuation for ch in pw)


def test_c19_scheduled_deletion(study_env, rec, S):
    with chk(rec, "W3-C19", "W3-C16") as c:
        sm = study_env.client("secretsmanager")
        r = sm.delete_secret(SecretId=S["secret"], RecoveryWindowInDays=7)

        def read_code():
            try:
                sm.get_secret_value(SecretId=S["secret"])
                return None
            except ClientError as exc:
                return code_of(exc)

        # The delete takes a few seconds to show on real AWS, so wait for the read to be rejected.
        code = poll(read_code, 30, interval=2)
        c.observe(has_deletion_date=bool(r.get("DeletionDate")), read_code=code)
        assert code == "InvalidRequestException", f"reading a secret scheduled for deletion gave {code}"


def test_c20_restore(study_env, rec, S):
    with chk(rec, "W3-C20", "W3-C19") as c:
        sm = study_env.client("secretsmanager")
        sm.restore_secret(SecretId=S["secret"])

        last = {}

        def readable():
            try:
                r = sm.get_secret_value(SecretId=S["secret"])
            except ClientError as exc:
                last["code"] = code_of(exc)
                return None
            last["code"] = "wrong value"
            return r if r.get("SecretString") == S["secret_v2"] else None

        # Restore can take well over 30 s to show on real AWS.
        r = poll(readable, 120, interval=3) or {}
        c.observe(value_ok=r.get("SecretString") == S["secret_v2"])
        assert r.get("SecretString") == S["secret_v2"], f"restored secret not readable after 120 s: {last.get('code')}"


# --- negative checks ----------------------------------------------------------------------

def test_c21_put_without_overwrite(study_env, rec, S):
    with chk(rec, "W3-C21", "W3-C05") as c:
        expect_error(c, lambda: study_env.client("ssm").put_parameter(Name=S["p_url"], Value="x", Type="String"))


def test_c22_missing_parameter(study_env, rec, S):
    with chk(rec, "W3-C22") as c:
        expect_error(c, lambda: study_env.client("ssm").get_parameter(Name=f"{S['path']}/never_created"))


def test_c23_value_too_long(study_env, rec, S):
    with chk(rec, "W3-C23") as c:
        name = f"{S['path']}/too_long"
        S["params"].append(name)
        expect_error(c, lambda: study_env.client("ssm").put_parameter(
            Name=name, Value="x" * 4097, Type="String", Tier="Standard"))


def test_c24_allowed_pattern(study_env, rec, S):
    with chk(rec, "W3-C24") as c:
        name = f"{S['path']}/port"
        S["params"].append(name)
        expect_error(c, lambda: study_env.client("ssm").put_parameter(
            Name=name, Value="not-a-number", Type="String", AllowedPattern="^[0-9]+$"))


def test_c25_name_with_space(study_env, rec, S):
    with chk(rec, "W3-C25") as c:
        name = f"{S['path']}/bad name"
        S["params"].append(name)
        expect_error(c, lambda: study_env.client("ssm").put_parameter(Name=name, Value="x", Type="String"))


def test_c26_secret_name_taken(study_env, rec, S):
    with chk(rec, "W3-C26", "W3-C13") as c:
        expect_error(c, lambda: study_env.client("secretsmanager").create_secret(
            Name=S["secret"], SecretString="another"))


def test_c27_short_recovery_window(study_env, rec, S, prefix):
    with chk(rec, "W3-C27") as c:
        sm = study_env.client("secretsmanager")
        name = f"{prefix}-throwaway"
        sm.create_secret(Name=name, SecretString="throwaway")
        S["extra_secrets"].append(name)
        expect_error(c, lambda: sm.delete_secret(SecretId=name, RecoveryWindowInDays=3))


def test_c28_string_and_binary(study_env, rec, S, prefix):
    with chk(rec, "W3-C28") as c:
        name = f"{prefix}-both-values"
        S["extra_secrets"].append(name)  # cleaned up if an environment accepts it
        expect_error(c, lambda: study_env.client("secretsmanager").create_secret(
            Name=name, SecretString="text", SecretBinary=b"bytes"))


def test_c29_wrong_context(study_env, rec, S):
    with chk(rec, "W3-C29", "W3-C03") as c:
        expect_error(c, lambda: study_env.client("kms").decrypt(
            CiphertextBlob=S["ciphertext"], EncryptionContext={"purpose": "something-else"}))


def test_c30_plaintext_too_large(study_env, rec, S):
    with chk(rec, "W3-C30", "W3-C01") as c:
        expect_error(c, lambda: study_env.client("kms").encrypt(KeyId=S["key_id"], Plaintext=b"x" * 4097))


def test_c31_short_deletion_window(study_env, rec, S):
    with chk(rec, "W3-C31", "W3-C01") as c:
        expect_error(c, lambda: study_env.client("kms").schedule_key_deletion(
            KeyId=S["key_id"], PendingWindowInDays=6))


# --- teardown -----------------------------------------------------------------------------

def test_c32_teardown(study_env, rec, S):
    with chk(rec, "W3-C32", "W3-C01") as c:
        ssm, sm, kms = (study_env.client(s) for s in ("ssm", "secretsmanager", "kms"))
        existing = [n for n in dict.fromkeys(S["params"])
                    if n.endswith(("db_url", "api_token", "flag", "regions"))]
        for i in range(0, len(existing), 10):
            ssm.delete_parameters(Names=existing[i:i + 10])
        sm.delete_secret(SecretId=S["secret"], ForceDeleteWithoutRecovery=True)
        kms.delete_alias(AliasName=S["alias"])
        state = kms.describe_key(KeyId=S["key_id"])["KeyMetadata"]["KeyState"]
        if state != "PendingDeletion":  # C31 may have scheduled it already on a lenient environment
            kms.schedule_key_deletion(KeyId=S["key_id"], PendingWindowInDays=7)
        c.observe(parameters_deleted=len(existing))  # key state is not recorded: it only echoes C31


def test_c33_gone(study_env, rec, S):
    with chk(rec, "W3-C33", "W3-C32") as c:
        ssm, sm, kms = (study_env.client(s) for s in ("ssm", "secretsmanager", "kms"))

        def code(fn):
            try:
                fn()
                return "still-exists"
            except ClientError as exc:
                return code_of(exc)
        codes = {}

        def all_gone():
            codes["parameter"] = code(lambda: ssm.get_parameter(Name=S["p_url"]))
            codes["secret"] = code(lambda: sm.describe_secret(SecretId=S["secret"]))
            codes["key_state"] = kms.describe_key(KeyId=S["key_id"])["KeyMetadata"]["KeyState"]
            return (codes["parameter"] != "still-exists" and codes["secret"] != "still-exists"
                    and codes["key_state"] == "PendingDeletion")
        ok = poll(all_gone, 60, interval=3)
        c.observe(**codes)
        assert ok, f"not all gone: {codes}"


def test_c34_encrypt_pending_deletion(study_env, rec, S):
    with chk(rec, "W3-C34", "W3-C32") as c:
        expect_error(c, lambda: study_env.client("kms").encrypt(KeyId=S["key_id"], Plaintext=PLAINTEXT))
