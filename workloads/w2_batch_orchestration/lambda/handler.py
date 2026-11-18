"""W2 worker: one step of a batch, called by the Step Functions state machine.

Input (from the Process state's Payload):
  mode        "work" (default) or "fail"
  n           number to double
  fail_times  raise TransientError while retry < fail_times (Retry should absorb these)
  retry       $$.State.RetryCount, supplied by Step Functions

Raises PermanentError for mode "fail" (the state machine catches it). The exception class
name becomes the Step Functions error name, so the class names are part of the contract.
Pure compute: it makes no AWS calls, so no emulator networking setup is needed.
"""


class TransientError(Exception):
    pass


class PermanentError(Exception):
    pass


def handler(event, context):
    retry = int(event.get("retry", 0))
    if event.get("mode") == "fail":
        raise PermanentError("order rejected")
    if retry < int(event.get("fail_times", 0)):
        raise TransientError(f"transient failure on attempt {retry}")
    print({"processed": event.get("n"), "attempt": retry})
    return {"value": int(event["n"]) * 2, "attempt": retry}
