"""Verifier-issued, ledger-bound authorization for the v0.2.1 campaign."""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import cast

from reproassert.benchmark_v021_preregistration import (
    VerifiedV021Preregistration,
    require_v021_preregistration,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

ALGORITHM = "reproassert-v021-execution-authorization-v1"
CLAIM_ALGORITHM = "reproassert-v021-execution-authorization-claim-v1"
SCHEMA_VERSION = "1.0.0"
MODEL = "gpt-5.4-mini-2026-03-17"
REQUEST_SET_ALGORITHM = "reproassert-v021-provider-request-envelope-set-v1"
LEGACY_REQUEST_SET_ALGORITHM = "reproassert-v02-provider-request-envelope-set-v1"
TOTAL_CAP_USD = "5.00"
PER_CASE_CAP_USD = "0.25"
CASE_IDS = tuple(f"rk-v0.2-{number:03d}" for number in range(1, 21))
MAX_BYTES = 2 * 1024 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIME = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_AUTHORIZATION_REF = re.compile(r"[ -~]{3,200}\Z")
_ISSUER = object()


@dataclass(frozen=True, init=False)
class VerifiedV021ExecutionAuthorization:
    path: Path
    sha256: str
    preregistration_sha256: str
    lineage_commitment_sha256: str
    request_set_sha256: str
    preregistration_request_set_sha256: str
    request_sha256_by_case: Mapping[str, str]
    tool_git_sha: str
    model: str
    pricing_snapshot_sha256: str
    pricing_effective_at: str
    case_ids: tuple[str, ...]
    ledger_path: Path
    ledger_identity_sha256: str
    total_cap_usd: str
    per_case_cap_usd: str
    authorized_at: str
    authorization_ref: str
    operator_nonce: str
    execution_statement: str
    execution_statement_sha256: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV021ExecutionAuthorization is verifier-issued only")


def prepare_v021_execution_authorization(
    *,
    preregistration: VerifiedV021Preregistration,
    execution_statement: str,
    authorization_ref: str,
    operator_nonce: str,
    case_ids: tuple[str, ...] | list[str],
    request_envelope_sha256_by_case: Mapping[str, str],
    ledger_path: Path,
    authorized_at: str,
    output_path: Path,
) -> VerifiedV021ExecutionAuthorization:
    authority = require_v021_preregistration(preregistration)
    destination = Path(output_path)
    require_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite execution authorization.")
    prereg = _read_preregistration(authority)
    record = _derive(
        authority=authority,
        prereg=prereg,
        execution_statement=execution_statement,
        authorization_ref=authorization_ref,
        operator_nonce=operator_nonce,
        case_ids=case_ids,
        request_envelope_sha256_by_case=request_envelope_sha256_by_case,
        ledger_path=ledger_path,
        authorized_at=authorized_at,
    )
    record["authorization_sha256"] = _self_hash(record)
    _write_issuance_claim(record)
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v021_execution_authorization(
        destination, preregistration=authority, expected_ledger_path=ledger_path
    )


def verify_v021_execution_authorization(
    path: Path,
    *,
    preregistration: VerifiedV021Preregistration,
    expected_ledger_path: Path,
) -> VerifiedV021ExecutionAuthorization:
    authority = require_v021_preregistration(preregistration)
    raw = _read(Path(path), MAX_BYTES, "execution authorization")
    record = _decode(raw, "execution authorization")
    if set(record) != {
        "algorithm",
        "authorization",
        "authorization_sha256",
        "authorized_at",
        "benchmark_version",
        "case_ids",
        "ledger",
        "policy",
        "preregistration",
        "requests",
        "schema_version",
        "status",
    }:
        raise _reject("Execution authorization fields are invalid.")
    if (
        record.get("algorithm") != ALGORITHM
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("benchmark_version") != "0.2.1"
        or record.get("status") != "authorized_not_started"
        or record.get("authorization_sha256") != _self_hash(record)
    ):
        raise _reject("Execution authorization identity is invalid.")
    prereg = _read_preregistration(authority)
    authorization = _object(record.get("authorization"), "execution authorization operator data")
    expected = _derive(
        authority=authority,
        prereg=prereg,
        execution_statement=cast(str, authorization.get("execution_statement")),
        authorization_ref=cast(str, authorization.get("authorization_ref")),
        operator_nonce=cast(str, authorization.get("operator_nonce")),
        case_ids=cast(list[str], record["case_ids"]),
        request_envelope_sha256_by_case={
            cast(str, row["case_id"]): cast(str, row["request_envelope_sha256"])
            for row in cast(list[dict[str, object]], record["requests"])
        },
        ledger_path=expected_ledger_path,
        authorized_at=cast(str, record["authorized_at"]),
    )
    unsigned = dict(record)
    unsigned.pop("authorization_sha256")
    if unsigned != expected:
        raise _reject("Execution authorization differs from freshly verified preregistration.")
    _verify_issuance_claim(record)
    ledger = cast(dict[str, object], record["ledger"])
    prereg_ref = cast(dict[str, object], record["preregistration"])
    policy = cast(dict[str, object], record["policy"])
    issued = object.__new__(VerifiedV021ExecutionAuthorization)
    values: dict[str, object] = {
        "path": Path(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "preregistration_sha256": authority.sha256,
        "lineage_commitment_sha256": prereg_ref["lineage_commitment_sha256"],
        "request_set_sha256": prereg_ref["request_set_sha256"],
        "preregistration_request_set_sha256": prereg_ref["preregistration_request_set_sha256"],
        "request_sha256_by_case": MappingProxyType(
            {
                cast(str, row["case_id"]): cast(str, row["request_envelope_sha256"])
                for row in cast(list[dict[str, object]], record["requests"])
            }
        ),
        "tool_git_sha": prereg_ref["tool_git_sha"],
        "model": policy["model"],
        "pricing_snapshot_sha256": prereg_ref["pricing_snapshot_sha256"],
        "pricing_effective_at": policy["pricing_effective_at"],
        "case_ids": tuple(cast(list[str], record["case_ids"])),
        "ledger_path": Path(cast(str, ledger["absolute_path"])),
        "ledger_identity_sha256": ledger["identity_sha256"],
        "total_cap_usd": policy["total_cap_usd"],
        "per_case_cap_usd": policy["per_case_cap_usd"],
        "authorized_at": record["authorized_at"],
        "authorization_ref": authorization["authorization_ref"],
        "operator_nonce": authorization["operator_nonce"],
        "execution_statement": authorization["execution_statement"],
        "execution_statement_sha256": authorization["execution_statement_sha256"],
        "_issuer": _ISSUER,
    }
    for name, value in values.items():
        object.__setattr__(issued, name, value)
    return issued


def require_v021_execution_authorization(value: object) -> VerifiedV021ExecutionAuthorization:
    if type(value) is not VerifiedV021ExecutionAuthorization or value._issuer is not _ISSUER:
        raise _reject("Fresh verifier-issued v0.2.1 execution authorization is required.")
    expected_statement = required_v021_execution_statement(
        preregistration_raw_sha256=value.preregistration_sha256,
        request_set_sha256=value.request_set_sha256,
        ledger_absolute_path=value.ledger_path,
        ledger_identity_sha256=value.ledger_identity_sha256,
        model=value.model,
        total_cap_usd=value.total_cap_usd,
        per_case_cap_usd=value.per_case_cap_usd,
        overage_allowed=False,
        authorized_at=value.authorized_at,
        authorization_ref=value.authorization_ref,
        operator_nonce=value.operator_nonce,
    )
    if (
        value.case_ids != CASE_IDS
        or value.total_cap_usd != TOTAL_CAP_USD
        or value.per_case_cap_usd != PER_CASE_CAP_USD
        or value.model != MODEL
        or not value.ledger_path.is_absolute()
        or value.execution_statement != expected_statement
        or hashlib.sha256(value.execution_statement.encode()).hexdigest()
        != value.execution_statement_sha256
    ):
        raise _reject("Execution authorization policy is invalid.")
    return value


def _derive(
    *,
    authority: VerifiedV021Preregistration,
    prereg: dict[str, object],
    execution_statement: str,
    authorization_ref: str,
    operator_nonce: str,
    case_ids: tuple[str, ...] | list[str],
    request_envelope_sha256_by_case: Mapping[str, str],
    ledger_path: Path,
    authorized_at: str,
) -> dict[str, object]:
    approval = _object(prereg.get("approval"), "preregistration approval")
    evidence = _object(prereg.get("evidence"), "preregistration evidence")
    commitments = _object(evidence.get("internal_commitments"), "internal commitments")
    policy = _object(prereg.get("policy"), "preregistration policy")
    cases = tuple(case_ids)
    if cases != CASE_IDS or len(set(cases)) != 20:
        raise _reject("Authorization requires the exact sorted 20-case cohort.")
    if tuple(request_envelope_sha256_by_case) != CASE_IDS:
        raise _reject("Request envelopes require the exact sorted 20-case cohort.")
    rows = [
        {
            "case_id": case_id,
            "request_envelope_sha256": _sha(request_envelope_sha256_by_case[case_id]),
        }
        for case_id in CASE_IDS
    ]
    legacy_request_set = hashlib.sha256(
        _canonical(
            {
                "algorithm": LEGACY_REQUEST_SET_ALGORITHM,
                "sha256": [row["request_envelope_sha256"] for row in rows],
            }
        )
    ).hexdigest()
    if legacy_request_set != commitments.get("case_request_set_sha256"):
        raise _reject("Request set differs from the preregistered request set.")
    request_set = hashlib.sha256(
        _canonical({"algorithm": REQUEST_SET_ALGORITHM, "requests": rows})
    ).hexdigest()
    if (
        prereg.get("algorithm") != "reproassert-v021-provider-disabled-preregistration-v1"
        or prereg.get("schema_version") != "1.0.0"
        or prereg.get("benchmark_version") != "0.2.1"
        or prereg.get("status") != "execution_disabled_until_v021_runtime_migration"
        or approval.get("authorized") is not False
        or approval.get("required_exact_statement") != authority.approval_statement
        or approval.get("required_exact_statement_sha256") != authority.approval_statement_sha256
        or policy.get("total_cap_usd") != TOTAL_CAP_USD
        or policy.get("case_cap_usd") != PER_CASE_CAP_USD
        or policy.get("overage_allowed") is not False
        or policy.get("model") != MODEL
        or policy.get("execution_enabled") is not False
        or policy.get("credential_fields_allowed") is not False
        or policy.get("pricing_snapshot_status") != "exact_public_snapshot_hash_bound"
        or prereg.get("case_count") != 20
    ):
        raise _reject("Preregistration does not preserve the exact spend and model policy.")
    producer = _git_sha(prereg.get("tool_git_sha"))
    lineage = _sha(prereg.get("lineage_commitment_sha256"))
    pricing = _sha(evidence.get("pricing_snapshot_raw_sha256"))
    timestamp = _timestamp(authorized_at)
    frozen = _timestamp(cast(str, prereg.get("frozen_at")))
    if _time_value(timestamp) < _time_value(frozen):
        raise _reject("Authorization predates the preregistration freeze.")
    ledger = Path(ledger_path)
    if not ledger.is_absolute() or ledger.name in {"", ".", ".."}:
        raise _reject("Ledger path must be a specific absolute path.")
    ledger_absolute = ledger.resolve(strict=False)
    require_private_directory(ledger_absolute.parent)
    ledger_identity = hashlib.sha256(
        _canonical(
            {"absolute_path": str(ledger_absolute), "preregistration_sha256": authority.sha256}
        )
    ).hexdigest()
    reference = _authorization_ref(authorization_ref)
    nonce = _sha(operator_nonce)
    required_statement = required_v021_execution_statement(
        preregistration_raw_sha256=authority.sha256,
        request_set_sha256=request_set,
        ledger_absolute_path=ledger_absolute,
        ledger_identity_sha256=ledger_identity,
        model=MODEL,
        total_cap_usd=TOTAL_CAP_USD,
        per_case_cap_usd=PER_CASE_CAP_USD,
        overage_allowed=False,
        authorized_at=timestamp,
        authorization_ref=reference,
        operator_nonce=nonce,
    )
    if execution_statement != required_statement:
        raise _reject("Exact operator execution statement is required.")
    return {
        "algorithm": ALGORITHM,
        "authorization": {
            "authorization_ref": reference,
            "execution_statement": required_statement,
            "execution_statement_sha256": hashlib.sha256(required_statement.encode()).hexdigest(),
            "operator_nonce": nonce,
        },
        "authorized_at": timestamp,
        "benchmark_version": "0.2.1",
        "case_ids": list(cases),
        "ledger": {"absolute_path": str(ledger_absolute), "identity_sha256": ledger_identity},
        "policy": {
            "model": MODEL,
            "overage_allowed": False,
            "per_case_cap_usd": PER_CASE_CAP_USD,
            "pricing_effective_at": _timestamp(policy.get("pricing_effective_at")),
            "total_cap_usd": TOTAL_CAP_USD,
        },
        "preregistration": {
            "approval_statement_sha256": approval["required_exact_statement_sha256"],
            "lineage_commitment_sha256": lineage,
            "pricing_snapshot_sha256": pricing,
            "preregistration_request_set_sha256": legacy_request_set,
            "raw_sha256": authority.sha256,
            "request_set_sha256": request_set,
            "tool_git_sha": producer,
        },
        "requests": rows,
        "schema_version": SCHEMA_VERSION,
        "status": "authorized_not_started",
    }


def required_v021_execution_statement(
    *,
    preregistration_raw_sha256: str,
    request_set_sha256: str,
    ledger_absolute_path: Path | str,
    ledger_identity_sha256: str,
    model: str,
    total_cap_usd: str,
    per_case_cap_usd: str,
    overage_allowed: bool,
    authorized_at: str,
    authorization_ref: str,
    operator_nonce: str,
) -> str:
    """Return the one exact, campaign-specific statement an operator must supply."""

    prereg_sha = _sha(preregistration_raw_sha256)
    request_sha = _sha(request_set_sha256)
    identity = _sha(ledger_identity_sha256)
    nonce = _sha(operator_nonce)
    reference = _authorization_ref(authorization_ref)
    timestamp = _timestamp(authorized_at)
    ledger = Path(ledger_absolute_path)
    if not ledger.is_absolute() or ledger.name in {"", ".", ".."}:
        raise _reject("Ledger path must be a specific absolute path.")
    absolute = ledger.resolve(strict=False)
    if model != MODEL or total_cap_usd != TOTAL_CAP_USD or per_case_cap_usd != PER_CASE_CAP_USD:
        raise _reject("Execution statement policy is invalid.")
    if overage_allowed is not False:
        raise _reject("Execution statement must forbid overage.")
    return (
        "Authorize ReproAssert v0.2.1 execution exactly: "
        f"preregistration_raw_sha256={prereg_sha}; request_set_sha256={request_sha}; "
        f"ledger_absolute_path={absolute}; ledger_identity_sha256={identity}; model={model}; "
        f"total_cap_usd={total_cap_usd}; per_case_cap_usd={per_case_cap_usd}; "
        f"overage_allowed=false; authorized_at={timestamp}; authorization_ref={reference}; "
        f"operator_nonce={nonce}."
    )


def _write_issuance_claim(record: dict[str, object]) -> None:
    claim = _issuance_claim(record)
    path = _claim_path(record)
    if path.exists() or path.is_symlink():
        raise _reject("This preregistration and request set already has an issuance claim.")
    write_bytes_exclusive(path, _canonical(claim) + b"\n")


def _verify_issuance_claim(record: dict[str, object]) -> None:
    expected = _issuance_claim(record)
    path = _claim_path(record)
    raw = _read(path, MAX_BYTES, "execution authorization issuance claim")
    if _decode(raw, "execution authorization issuance claim") != expected:
        raise _reject("Execution authorization issuance claim does not match.")


def _issuance_claim(record: dict[str, object]) -> dict[str, object]:
    prereg = _object(record.get("preregistration"), "authorization preregistration")
    ledger = _object(record.get("ledger"), "authorization ledger")
    authorization = _object(record.get("authorization"), "authorization operator data")
    claim: dict[str, object] = {
        "algorithm": CLAIM_ALGORITHM,
        "authorization_ref": authorization.get("authorization_ref"),
        "authorization_sha256": _sha(record.get("authorization_sha256")),
        "execution_statement_sha256": _sha(authorization.get("execution_statement_sha256")),
        "ledger_absolute_path": ledger.get("absolute_path"),
        "ledger_identity_sha256": _sha(ledger.get("identity_sha256")),
        "operator_nonce": _sha(authorization.get("operator_nonce")),
        "preregistration_raw_sha256": _sha(prereg.get("raw_sha256")),
        "request_set_sha256": _sha(prereg.get("request_set_sha256")),
        "schema_version": SCHEMA_VERSION,
    }
    claim["claim_sha256"] = _self_hash_named(claim, "claim_sha256")
    return claim


def _claim_path(record: dict[str, object]) -> Path:
    prereg = _object(record.get("preregistration"), "authorization preregistration")
    key = hashlib.sha256(
        _canonical(
            {
                "preregistration_raw_sha256": _sha(prereg.get("raw_sha256")),
                "request_set_sha256": _sha(prereg.get("request_set_sha256")),
            }
        )
    ).hexdigest()
    return _claim_state_root() / f"{key}.issuance-claim.json"


def _claim_state_root() -> Path:
    """Return trusted user state outside caller-controlled campaign directories."""

    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
    except (KeyError, OSError, RuntimeError) as exc:
        raise _reject("Cannot resolve the trusted authorization-claim state root.") from exc
    root = home / ".local" / "state" / "reproassert" / "v021-execution-authorizations"
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(root, 0o700)
    except OSError as exc:
        raise _reject("Cannot prepare the trusted authorization-claim state root.") from exc
    require_private_directory(root)
    return root


def _read_preregistration(authority: VerifiedV021Preregistration) -> dict[str, object]:
    raw = _read(authority.path, MAX_BYTES, "v0.2.1 preregistration")
    if hashlib.sha256(raw).hexdigest() != authority.sha256:
        raise _reject("Preregistration changed after verification.")
    record = _decode(raw, "v0.2.1 preregistration")
    if (
        record.get("preregistration_sha256") != _self_hash_named(record, "preregistration_sha256")
        or record.get("lineage_commitment_sha256") != authority.lineage_commitment_sha256
    ):
        raise _reject("Preregistration authority and canonical record differ.")
    return record


def _read(path: Path, maximum: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            raw = stream.read(maximum + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label.capitalize()} could not be read safely.") from exc
    if not raw or len(raw) > maximum:
        raise _reject(f"{label.capitalize()} exceeds its byte bound.")
    return raw


def _decode(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw, object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject(f"{label.capitalize()} is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject(f"{label.capitalize()} is not canonical JSON.")
    return cast(dict[str, object], value)


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _reject(f"{label.capitalize()} must be an object.")
    return cast(dict[str, object], value)


def _sha(value: object) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise _reject("SHA-256 commitment is invalid.")
    return value


def _authorization_ref(value: object) -> str:
    if not isinstance(value, str) or _AUTHORIZATION_REF.fullmatch(value) is None:
        raise _reject("Authorization reference must be 3-200 printable ASCII characters.")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Tool Git SHA is invalid.")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        raise _reject("Timestamp is invalid.")
    try:
        _time_value(value)
    except ValueError as exc:
        raise _reject("Timestamp is invalid.") from exc
    return value


def _time_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _self_hash(record: dict[str, object]) -> str:
    return _self_hash_named(record, "authorization_sha256")


def _self_hash_named(record: dict[str, object], name: str) -> str:
    unsigned = dict(record)
    unsigned.pop(name, None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_authorization", message)
