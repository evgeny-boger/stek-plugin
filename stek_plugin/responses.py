"""Protocol response objects serialized by Python's standard JSON encoder.

The original builds the envelope by string concatenation (0x462e70 for a
scalar `Data`, 0x4632d0 for an array).  Semantics recovered from both:

    {"Status": true|false, "Data": <value|null>, "Errors": [<str>...]}

`Data` is null when the value is empty.  A scalar `Data` is Base64-encoded
(0xa9a9b0) unless the caller passes the "raw" flag (r9b=1) — only the
async task id and the version string are emitted raw.
"""
import base64
import json
from typing import Optional, Sequence, Union


def _dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def encode_data(data: Union[bytes, str, None], raw: bool = False) -> Optional[str]:
    if data is None or data == b"" or data == "":
        return None
    if raw:
        return data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def build_json(status: bool, data: Union[bytes, str, None] = None,
               errors: Optional[Sequence[str]] = None, raw: bool = False) -> str:
    return _dumps({
        "Status": bool(status),
        "Data": encode_data(data, raw),
        "Errors": list(errors or ()),
    })


def build_json_array(status: bool, data: Sequence,
                     errors: Optional[Sequence[str]] = None) -> str:
    return _dumps({
        "Status": bool(status),
        "Data": list(data) if data else None,
        "Errors": list(errors or ()),
    })


def cert_entry_json(cert) -> dict:
    """Field names and order recovered from 0x4660ca..0x46640b."""
    return {
        "Serial": cert.serial_hex.upper(),
        "Thumbprint": cert.thumbprint.upper(),
        "Subject": cert.subject_full,
        "SubjectName": cert.subject_name,
        "Issuer": cert.issuer_full,
        "IssuerName": cert.issuer_name,
        "SubjectFIO": cert.subject_fio,
        "ValidFrom": cert.valid_from.strftime("%Y-%m-%d"),
        "ValidFor": cert.valid_to.strftime("%Y-%m-%d"),
    }


def task_entry_json(task) -> dict:
    """Record layout of the GETLOGINFO serializer (0x4672b8..0x467a58).

    InData/Result are Base64 (0xa9a9b0); Error is plain escaped text.
    """
    from . import STATUS_NAMES, STATUS_SUCCESS, TASK_TYPE_NAMES
    record = {
        "StartTime": _fmt(task.start_time),
        "ModifyTime": _fmt(task.modify_time),
    }
    if task.cert_thumb:
        record["Thumbprint"] = task.cert_thumb
    else:
        record["Serial"] = task.cert_sn
    record["Status"] = STATUS_NAMES.get(task.status, "")
    record["Type"] = TASK_TYPE_NAMES.get(task.ttype, "")
    record["Params"] = task.str_param or ""
    record["InData"] = encode_data(task.in_data) or ""
    if task.status == STATUS_SUCCESS:
        record["Result"] = encode_data(task.out_data) or ""
    else:
        record["Error"] = (task.out_data or b"").decode("utf-8", "replace")
    record["Id"] = task.id
    return record


def _fmt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else ""
