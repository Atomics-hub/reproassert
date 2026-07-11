"""Provider-disabled freeze for the exact-image v0.2 scored campaign."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from reproassert.benchmark_v02_campaign import verify_v02_campaign_freeze
from reproassert.benchmark_v02_cases import verify_v02_cases
from reproassert.benchmark_v02_instance_controller import verify_instance_gold_smoke_receipt
from reproassert.benchmark_v02_instance_runtime import load_instance_runtime_manifest
from reproassert.benchmark_v02_package import EXPECTED_CASE_COUNT, load_v02_preregistration
from reproassert.benchmark_v02_runner import (
    V02PricingSnapshot,
    _pricing_from_record,
)
from reproassert.candidate import MAX_TEST_BYTES
from reproassert.context import V02_SOURCE_CONTEXT_POLICY_SHA256
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

EXECUTION_FREEZE_SCHEMA_VERSION = "1.0.0"
EXECUTION_FREEZE_ALGORITHM = "reproassert-v02-exact-image-execution-freeze-v1"
EXECUTION_AUTHORIZATION_ALGORITHM = "reproassert-v02-exact-image-execution-authorization-v1"
MAX_EXECUTION_FREEZE_BYTES = 512 * 1024
MAX_PREPARATION_RECEIPT_BYTES = 512 * 1024
MAX_PACKAGE_BYTES = 512 * 1024
MAX_APPROVAL_BYTES = 4 * 1024
MAX_CAMPAIGN_MICROUSD = 5_000_000
MAX_CASE_MICROUSD = 250_000
MAX_CASE_WALL_MS = 600_000
PROVIDER_TIMEOUT_MS = 120_000
MAX_OUTPUT_TOKENS = 4_096
OUTBOUND_REQUEST_SET_ALGORITHM = "reproassert-v02-outbound-request-set-v1"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")


@dataclass(frozen=True)
class VerifiedV02ExecutionFreeze:
    path: Path
    sha256: str
    campaign_id: str
    request_set_sha256: str
    requested_model: str
    max_campaign_microusd: int
    max_case_microusd: int
    provider_calls: int = 0


@dataclass(frozen=True)
class VerifiedV02ExactImageAuthorization:
    path: Path
    sha256: str
    execution_freeze_sha256: str
    campaign_id: str
    authorized_at: str
    provider_calls: int = 0


def exact_approval_statement(execution_freeze_sha256: str) -> str:
    digest = _digest(execution_freeze_sha256, "execution freeze")
    return (
        f"I authorize ReproAssert execution freeze {digest} with a hard USD 5.00 total cap "
        "and hard USD 0.25 per-case cap, with zero overage."
    )


def prepare_v02_exact_image_execution_freeze(
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    cases_preparation_receipt: Path,
    instance_runtime_manifest_path: Path,
    gold_smoke_receipt_path: Path,
    prepared_at: str,
    controller_git_sha: str,
    requested_model: str,
    output_path: Path,
) -> VerifiedV02ExecutionFreeze:
    """Freeze exact requests and cap evidence before asking for final approval."""

    controller_sha = _git_sha(controller_git_sha, "controller Git SHA")
    model = _text(requested_model, _MODEL, "requested model")
    timestamp = _timestamp(prepared_at)
    if _timestamp_value(timestamp) > datetime.now(timezone.utc):
        raise _reject("Execution freeze cannot be dated in the future.")

    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    prepared = verify_v02_cases(cases_preparation_receipt)
    runtime = load_instance_runtime_manifest(instance_runtime_manifest_path)
    smoke = verify_instance_gold_smoke_receipt(gold_smoke_receipt_path)
    preregistration = load_v02_preregistration(preregistration_path)
    case_ids = tuple(case.id for case in preregistration.cases)
    if len(case_ids) != EXPECTED_CASE_COUNT or freeze.case_ids != case_ids:
        raise _reject("Campaign freeze does not preserve the exact 20-case preregistration.")
    if tuple(entry.case_id for entry in runtime.entries) != case_ids:
        raise _reject("Instance runtime manifest does not preserve the exact campaign cohort.")
    if smoke.selected_case_count != EXPECTED_CASE_COUNT:
        raise _reject("Gold smoke must execute the complete 20-case denominator before freezing.")

    preparation = _json_object(
        prepared.receipt_path, MAX_PREPARATION_RECEIPT_BYTES, "case preparation receipt"
    )
    pricing = _preparation_pricing(prepared.root, preparation)
    if pricing.requested_model != model:
        raise _reject("Requested model differs from the verified preparation pricing snapshot.")
    request_rows = _preparation_requests(
        prepared.root, preparation, case_ids, controller_git_sha=controller_sha
    )
    requests = tuple((case_id, outbound_digest) for case_id, _, outbound_digest, _ in request_rows)
    reservations = tuple(
        (case_id, _required_reservation(pricing, outbound_bytes))
        for case_id, _, _, outbound_bytes in request_rows
    )
    over_cap = tuple(case_id for case_id, reserve in reservations if reserve > MAX_CASE_MICROUSD)
    if over_cap:
        raise _reject(
            "Rendered requests exceed the approved per-case cap: " + ", ".join(over_cap) + "."
        )
    reservation_total = sum(reserve for _, reserve in reservations)
    if reservation_total > MAX_CAMPAIGN_MICROUSD:
        raise _reject("Outbound request reservations exceed the approved campaign cap.")
    request_set_sha256 = _outbound_request_set_sha256(
        campaign_id=freeze.campaign_id,
        preregistration_sha256=freeze.preregistration_sha256,
        cohort_sha256=freeze.cohort_sha256,
        requests=requests,
    )
    campaign_prepared_at = _timestamp(cast(str, freeze.decoded["prepared_at"]))
    if _timestamp_value(timestamp) < _timestamp_value(campaign_prepared_at):
        raise _reject("Exact-image freeze cannot predate the campaign freeze.")
    if _timestamp_value(pricing.effective_at) > _timestamp_value(timestamp):
        raise _reject("Exact-image freeze cannot predate its pricing snapshot.")

    record: dict[str, object] = {
        "algorithm": EXECUTION_FREEZE_ALGORITHM,
        "benchmark_version": "0.2",
        "campaign": {
            "campaign_freeze_sha256": freeze.raw_sha256,
            "campaign_id": freeze.campaign_id,
            "case_count": EXPECTED_CASE_COUNT,
            "cohort_sha256": freeze.cohort_sha256,
            "preregistration_sha256": freeze.preregistration_sha256,
        },
        "claims": {
            "credentials_read": False,
            "hidden_data_included": False,
            "provider_calls": 0,
            "provider_invoked_by_this_command": False,
        },
        "controller_git_sha": controller_sha,
        "evidence": {
            "cases_preparation_receipt_sha256": prepared.receipt_sha256,
            "gold_smoke_receipt_sha256": smoke.sha256,
            "instance_runtime_manifest_sha256": runtime.sha256,
            "source_context_policy_sha256": V02_SOURCE_CONTEXT_POLICY_SHA256,
        },
        "execution": {
            "authorization_scope": "one_campaign_one_attempt_per_case",
            "max_campaign_attributable_microusd": MAX_CAMPAIGN_MICROUSD,
            "max_case_attributable_microusd": MAX_CASE_MICROUSD,
            "max_case_wall_ms": MAX_CASE_WALL_MS,
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "overage_permitted": False,
            "provider_timeout_ms": PROVIDER_TIMEOUT_MS,
            "reservation_total_microusd": reservation_total,
            "reservations": [
                {"case_id": case_id, "worst_case_microusd": reserve}
                for case_id, reserve in reservations
            ],
        },
        "pricing_snapshot": pricing.record(),
        "pricing_snapshot_sha256": pricing.sha256,
        "prepared_at": timestamp,
        "provider": {
            "endpoint_host": "api.openai.com",
            "name": "openai",
            "requested_model": model,
        },
        "request_set": {
            "algorithm": OUTBOUND_REQUEST_SET_ALGORITHM,
            "preparation_request_set_sha256": _digest(
                preparation.get("request_set_sha256"), "preparation request set"
            ),
            "request_count": EXPECTED_CASE_COUNT,
            "request_set_sha256": request_set_sha256,
            "requests": [
                {"case_id": case_id, "outbound_request_sha256": digest}
                for case_id, digest in requests
            ],
        },
        "schema_version": EXECUTION_FREEZE_SCHEMA_VERSION,
        "status": "prepared_exact_inputs_provider_not_authorized",
    }
    record["execution_freeze_sha256"] = _self_hash(record)
    destination = Path(output_path)
    require_private_directory(destination.parent)
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v02_exact_image_execution_freeze(
        destination,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
        cases_preparation_receipt=cases_preparation_receipt,
        instance_runtime_manifest_path=instance_runtime_manifest_path,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
    )


def verify_v02_exact_image_execution_freeze(
    path: Path,
    *,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    cases_preparation_receipt: Path,
    instance_runtime_manifest_path: Path,
    gold_smoke_receipt_path: Path,
) -> VerifiedV02ExecutionFreeze:
    """Reverify all public-safe commitments in one exact execution freeze."""

    raw = _read_regular(Path(path), MAX_EXECUTION_FREEZE_BYTES, "execution freeze")
    record = _decode_canonical(raw, "execution freeze")
    if set(record) != {
        "algorithm",
        "benchmark_version",
        "campaign",
        "claims",
        "controller_git_sha",
        "evidence",
        "execution",
        "execution_freeze_sha256",
        "pricing_snapshot",
        "pricing_snapshot_sha256",
        "prepared_at",
        "provider",
        "request_set",
        "schema_version",
        "status",
    }:
        raise _reject("Execution freeze fields are invalid.")
    if (
        record["algorithm"] != EXECUTION_FREEZE_ALGORITHM
        or record["schema_version"] != EXECUTION_FREEZE_SCHEMA_VERSION
        or record["benchmark_version"] != "0.2"
        or record["status"] != "prepared_exact_inputs_provider_not_authorized"
        or record["execution_freeze_sha256"] != _self_hash(record)
    ):
        raise _reject("Execution freeze identity is invalid.")
    freeze = verify_v02_campaign_freeze(campaign_freeze_path, preregistration_path)
    prepared = verify_v02_cases(cases_preparation_receipt)
    runtime = load_instance_runtime_manifest(instance_runtime_manifest_path)
    smoke = verify_instance_gold_smoke_receipt(gold_smoke_receipt_path)
    preregistration = load_v02_preregistration(preregistration_path)
    case_ids = tuple(case.id for case in preregistration.cases)
    if (
        tuple(entry.case_id for entry in runtime.entries) != case_ids
        or smoke.selected_case_count != 20
    ):
        raise _reject("Execution freeze evidence does not cover the exact denominator.")
    evidence = _mapping(record["evidence"], "execution evidence")
    if evidence != {
        "cases_preparation_receipt_sha256": prepared.receipt_sha256,
        "gold_smoke_receipt_sha256": smoke.sha256,
        "instance_runtime_manifest_sha256": runtime.sha256,
        "source_context_policy_sha256": V02_SOURCE_CONTEXT_POLICY_SHA256,
    }:
        raise _reject("Execution freeze evidence commitments are invalid.")
    campaign = _mapping(record["campaign"], "campaign")
    if campaign != {
        "campaign_freeze_sha256": freeze.raw_sha256,
        "campaign_id": freeze.campaign_id,
        "case_count": 20,
        "cohort_sha256": freeze.cohort_sha256,
        "preregistration_sha256": freeze.preregistration_sha256,
    }:
        raise _reject("Execution freeze campaign commitments are invalid.")
    preparation = _json_object(prepared.receipt_path, MAX_PREPARATION_RECEIPT_BYTES, "preparation")
    pricing = _preparation_pricing(prepared.root, preparation)
    if (
        record["pricing_snapshot"] != pricing.record()
        or record["pricing_snapshot_sha256"] != pricing.sha256
    ):
        raise _reject("Execution freeze pricing commitment is invalid.")
    request_rows = _preparation_requests(
        prepared.root,
        preparation,
        case_ids,
        controller_git_sha=cast(str, record["controller_git_sha"]),
    )
    requests = tuple((case_id, outbound_digest) for case_id, _, outbound_digest, _ in request_rows)
    reservations = tuple(
        (case_id, _required_reservation(pricing, outbound_bytes))
        for case_id, _, _, outbound_bytes in request_rows
    )
    if any(reserve > MAX_CASE_MICROUSD for _, reserve in reservations):
        raise _reject("Execution freeze contains a request above the approved per-case cap.")
    reservation_total = sum(reserve for _, reserve in reservations)
    if reservation_total > MAX_CAMPAIGN_MICROUSD:
        raise _reject("Execution freeze request reservations exceed the campaign cap.")
    expected_set = _outbound_request_set_sha256(
        campaign_id=freeze.campaign_id,
        preregistration_sha256=freeze.preregistration_sha256,
        cohort_sha256=freeze.cohort_sha256,
        requests=requests,
    )
    request_set = _mapping(record["request_set"], "request set")
    if request_set != {
        "algorithm": OUTBOUND_REQUEST_SET_ALGORITHM,
        "preparation_request_set_sha256": preparation["request_set_sha256"],
        "request_count": 20,
        "request_set_sha256": expected_set,
        "requests": [
            {"case_id": case_id, "outbound_request_sha256": digest} for case_id, digest in requests
        ],
    }:
        raise _reject("Execution freeze request bindings are invalid.")
    prepared_at = _timestamp(record["prepared_at"])
    campaign_prepared_at = _timestamp(cast(str, freeze.decoded["prepared_at"]))
    if (
        _timestamp_value(prepared_at) > datetime.now(timezone.utc)
        or _timestamp_value(prepared_at) < _timestamp_value(campaign_prepared_at)
        or _timestamp_value(prepared_at) < _timestamp_value(pricing.effective_at)
    ):
        raise _reject("Execution freeze chronology is invalid.")
    execution = _mapping(record["execution"], "execution limits")
    if execution != {
        "authorization_scope": "one_campaign_one_attempt_per_case",
        "max_campaign_attributable_microusd": MAX_CAMPAIGN_MICROUSD,
        "max_case_attributable_microusd": MAX_CASE_MICROUSD,
        "max_case_wall_ms": MAX_CASE_WALL_MS,
        "max_output_tokens": MAX_OUTPUT_TOKENS,
        "overage_permitted": False,
        "provider_timeout_ms": PROVIDER_TIMEOUT_MS,
        "reservation_total_microusd": reservation_total,
        "reservations": [
            {"case_id": case_id, "worst_case_microusd": reserve}
            for case_id, reserve in reservations
        ],
    }:
        raise _reject("Execution freeze limits are not the approved hard caps.")
    provider = _mapping(record["provider"], "provider")
    if provider != {
        "endpoint_host": "api.openai.com",
        "name": "openai",
        "requested_model": pricing.requested_model,
    }:
        raise _reject("Execution freeze provider differs from frozen pricing.")
    if record["claims"] != {
        "credentials_read": False,
        "hidden_data_included": False,
        "provider_calls": 0,
        "provider_invoked_by_this_command": False,
    }:
        raise _reject("Execution freeze provider-disabled claims are invalid.")
    _git_sha(record["controller_git_sha"], "controller Git SHA")
    return VerifiedV02ExecutionFreeze(
        path=Path(path),
        sha256=hashlib.sha256(raw).hexdigest(),
        campaign_id=freeze.campaign_id,
        request_set_sha256=expected_set,
        requested_model=pricing.requested_model,
        max_campaign_microusd=MAX_CAMPAIGN_MICROUSD,
        max_case_microusd=MAX_CASE_MICROUSD,
    )


def authorize_v02_exact_image_execution(
    *,
    execution_freeze_path: Path,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    cases_preparation_receipt: Path,
    instance_runtime_manifest_path: Path,
    gold_smoke_receipt_path: Path,
    approval_file: Path,
    approval_ref: str,
    authorized_at: str,
    output_path: Path,
) -> VerifiedV02ExactImageAuthorization:
    """Authorize one already-frozen hash; never reads credentials or calls a provider."""

    freeze = verify_v02_exact_image_execution_freeze(
        execution_freeze_path,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
        cases_preparation_receipt=cases_preparation_receipt,
        instance_runtime_manifest_path=instance_runtime_manifest_path,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
    )
    raw_freeze = _read_regular(
        execution_freeze_path, MAX_EXECUTION_FREEZE_BYTES, "execution freeze"
    )
    freeze_record = _decode_canonical(raw_freeze, "execution freeze")
    statement = exact_approval_statement(freeze.sha256)
    approval_raw = _read_regular(Path(approval_file), MAX_APPROVAL_BYTES, "approval file")
    if approval_raw != (statement + "\n").encode("utf-8"):
        raise _reject("Approval file does not authorize the exact execution-freeze hash.")
    reference = _bounded_text(approval_ref, "approval reference", 3, 200)
    timestamp = _timestamp(authorized_at)
    prepared_at = _timestamp(freeze_record["prepared_at"])
    if _timestamp_value(timestamp) <= _timestamp_value(prepared_at) or _timestamp_value(
        timestamp
    ) > datetime.now(timezone.utc):
        raise _reject("Authorization must occur after the exact execution freeze.")
    record: dict[str, object] = {
        "algorithm": EXECUTION_AUTHORIZATION_ALGORITHM,
        "authorization": {
            "approval_ref": reference,
            "approval_statement": statement,
            "approval_statement_sha256": hashlib.sha256(statement.encode("utf-8")).hexdigest(),
            "authorized_at": timestamp,
            "kind": "explicit_post_freeze_user_approval",
        },
        "benchmark_version": "0.2",
        "campaign_id": freeze.campaign_id,
        "claims": {
            "credentials_read": False,
            "provider_calls": 0,
            "provider_invoked_by_this_command": False,
        },
        "execution_freeze_sha256": freeze.sha256,
        "limits": {
            "max_campaign_attributable_microusd": MAX_CAMPAIGN_MICROUSD,
            "max_case_attributable_microusd": MAX_CASE_MICROUSD,
            "overage_permitted": False,
        },
        "provider": "openai",
        "request_set_sha256": freeze.request_set_sha256,
        "requested_model": freeze.requested_model,
        "schema_version": EXECUTION_FREEZE_SCHEMA_VERSION,
        "status": "authorized_exact_freeze_provider_not_started",
    }
    record["execution_authorization_sha256"] = _self_hash_named(
        record, "execution_authorization_sha256"
    )
    destination = Path(output_path)
    require_private_directory(destination.parent)
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v02_exact_image_authorization(
        destination,
        execution_freeze_path=execution_freeze_path,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
        cases_preparation_receipt=cases_preparation_receipt,
        instance_runtime_manifest_path=instance_runtime_manifest_path,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
    )


def verify_v02_exact_image_authorization(
    path: Path,
    *,
    execution_freeze_path: Path,
    campaign_freeze_path: Path,
    preregistration_path: Path,
    cases_preparation_receipt: Path,
    instance_runtime_manifest_path: Path,
    gold_smoke_receipt_path: Path,
) -> VerifiedV02ExactImageAuthorization:
    freeze = verify_v02_exact_image_execution_freeze(
        execution_freeze_path,
        campaign_freeze_path=campaign_freeze_path,
        preregistration_path=preregistration_path,
        cases_preparation_receipt=cases_preparation_receipt,
        instance_runtime_manifest_path=instance_runtime_manifest_path,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
    )
    freeze_record = _decode_canonical(
        _read_regular(execution_freeze_path, MAX_EXECUTION_FREEZE_BYTES, "execution freeze"),
        "execution freeze",
    )
    raw = _read_regular(path, MAX_EXECUTION_FREEZE_BYTES, "execution authorization")
    record = _decode_canonical(raw, "execution authorization")
    if set(record) != {
        "algorithm",
        "authorization",
        "benchmark_version",
        "campaign_id",
        "claims",
        "execution_authorization_sha256",
        "execution_freeze_sha256",
        "limits",
        "provider",
        "request_set_sha256",
        "requested_model",
        "schema_version",
        "status",
    }:
        raise _reject("Exact-image authorization fields are invalid.")
    if (
        record["algorithm"] != EXECUTION_AUTHORIZATION_ALGORITHM
        or record["schema_version"] != EXECUTION_FREEZE_SCHEMA_VERSION
        or record["benchmark_version"] != "0.2"
        or record["status"] != "authorized_exact_freeze_provider_not_started"
        or record["execution_authorization_sha256"]
        != _self_hash_named(record, "execution_authorization_sha256")
        or record["execution_freeze_sha256"] != freeze.sha256
        or record["campaign_id"] != freeze.campaign_id
        or record["request_set_sha256"] != freeze.request_set_sha256
        or record["requested_model"] != freeze.requested_model
        or record["provider"] != "openai"
    ):
        raise _reject("Exact-image authorization bindings are invalid.")
    if record["limits"] != {
        "max_campaign_attributable_microusd": MAX_CAMPAIGN_MICROUSD,
        "max_case_attributable_microusd": MAX_CASE_MICROUSD,
        "overage_permitted": False,
    } or record["claims"] != {
        "credentials_read": False,
        "provider_calls": 0,
        "provider_invoked_by_this_command": False,
    }:
        raise _reject("Exact-image authorization limits or claims are invalid.")
    approval = _mapping(record["authorization"], "authorization")
    statement = exact_approval_statement(freeze.sha256)
    if (
        approval.get("approval_statement") != statement
        or approval.get("approval_statement_sha256")
        != hashlib.sha256(statement.encode("utf-8")).hexdigest()
        or approval.get("kind") != "explicit_post_freeze_user_approval"
    ):
        raise _reject("Authorization statement does not bind the exact freeze hash.")
    _bounded_text(approval.get("approval_ref"), "approval reference", 3, 200)
    authorized_at = _timestamp(approval.get("authorized_at"))
    if _timestamp_value(authorized_at) <= _timestamp_value(
        _timestamp(freeze_record["prepared_at"])
    ) or _timestamp_value(authorized_at) > datetime.now(timezone.utc):
        raise _reject("Authorization chronology is not post-freeze.")
    return VerifiedV02ExactImageAuthorization(
        path=Path(path),
        sha256=hashlib.sha256(raw).hexdigest(),
        execution_freeze_sha256=freeze.sha256,
        campaign_id=freeze.campaign_id,
        authorized_at=authorized_at,
    )


def _preparation_pricing(root: Path, receipt: Mapping[str, object]) -> V02PricingSnapshot:
    inputs = _mapping(receipt.get("inputs"), "preparation inputs")
    ref = _mapping(inputs.get("pricing_snapshot"), "pricing snapshot reference")
    relative = _safe_relative(ref.get("path"))
    raw = _read_regular(root / relative, 64 * 1024, "pricing snapshot")
    if hashlib.sha256(raw).hexdigest() != _digest(ref.get("sha256"), "pricing reference"):
        raise _reject("Pricing snapshot reference digest is invalid.")
    value = _decode_canonical(raw, "pricing snapshot")
    pricing = _pricing_from_record(value)
    if pricing.record() != value:
        raise _reject("Pricing snapshot is not canonical.")
    return pricing


def _preparation_requests(
    root: Path,
    receipt: Mapping[str, object],
    case_ids: tuple[str, ...],
    *,
    controller_git_sha: str,
) -> tuple[tuple[str, str, str, int], ...]:
    rows = receipt.get("packages")
    if not isinstance(rows, list) or len(rows) != len(case_ids):
        raise _reject("Preparation package index is invalid.")
    requests: list[tuple[str, str, str, int]] = []
    for expected, raw_row in zip(case_ids, rows, strict=True):
        row = _mapping(raw_row, "preparation package row")
        if row.get("case_id") != expected:
            raise _reject("Preparation package ordering differs from the frozen cohort.")
        package = _decode_canonical(
            _read_regular(
                root / _safe_relative(row.get("path")), MAX_PACKAGE_BYTES, "case package"
            ),
            "case package",
        )
        request_ref = _mapping(package.get("request_envelope"), "request envelope reference")
        request_raw = _read_regular(
            root / _safe_relative(request_ref.get("path")), MAX_PACKAGE_BYTES, "request envelope"
        )
        if hashlib.sha256(request_raw).hexdigest() != _digest(
            request_ref.get("sha256"), "request envelope"
        ):
            raise _reject("Request envelope reference digest is invalid.")
        request = _decode_canonical(request_raw, "request envelope")
        if request.get("case_id") != expected:
            raise _reject("Request envelope case identity is invalid.")
        if request.get("tool_git_sha") != controller_git_sha:
            raise _reject(
                f"Request envelope for {expected} is not frozen at the execution controller SHA."
            )
        provider_request = _mapping(request.get("provider_request"), "provider request")
        rendered = provider_request.get("input")
        if not isinstance(rendered, str):
            raise _reject("Provider request rendered input is invalid.")
        digest = _digest(request.get("rendered_input_sha256"), "rendered input")
        if hashlib.sha256(rendered.encode("utf-8")).hexdigest() != digest:
            raise _reject("Rendered input hash differs from the exact provider request bytes.")
        outbound_raw = _canonical(provider_request)
        outbound_digest = _digest(request.get("outbound_request_sha256"), "outbound request")
        if hashlib.sha256(outbound_raw).hexdigest() != outbound_digest:
            raise _reject("Outbound request hash differs from the exact canonical provider body.")
        requests.append((expected, digest, outbound_digest, len(outbound_raw)))
    return tuple(requests)


def _required_reservation(pricing: V02PricingSnapshot, outbound_bytes: int) -> int:
    token_numerator = (
        outbound_bytes * pricing.input_microusd_per_million_tokens
        + MAX_OUTPUT_TOKENS * pricing.output_microusd_per_million_tokens
    )
    model = _ceil_per_million(token_numerator)
    sandbox = math.ceil(MAX_CASE_WALL_MS * pricing.sandbox_microusd_per_second / 1_000)
    artifact = _ceil_per_million(MAX_TEST_BYTES * pricing.artifact_microusd_per_million_bytes)
    return model + sandbox + artifact + pricing.paid_storage_microusd


def _outbound_request_set_sha256(
    *,
    campaign_id: str,
    preregistration_sha256: str,
    cohort_sha256: str,
    requests: tuple[tuple[str, str], ...],
) -> str:
    return hashlib.sha256(
        _canonical(
            {
                "algorithm": OUTBOUND_REQUEST_SET_ALGORITHM,
                "campaign_id": campaign_id,
                "preregistration_sha256": preregistration_sha256,
                "cohort_sha256": cohort_sha256,
                "requests": [
                    {"case_id": case_id, "outbound_request_sha256": digest}
                    for case_id, digest in requests
                ],
            }
        )
    ).hexdigest()


def _ceil_per_million(value: int) -> int:
    return (value + 999_999) // 1_000_000


def _json_object(path: Path, limit: int, label: str) -> dict[str, object]:
    return _decode_canonical(_read_regular(path, limit, label), label)


def _decode_canonical(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject(f"{label.capitalize()} is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject(f"{label.capitalize()} is not canonical JSON.")
    return cast(dict[str, object], value)


def _read_regular(path: Path, limit: int, label: str) -> bytes:
    with open_regular_file(path) as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise _reject(f"{label.capitalize()} exceeds the size limit.")
    return raw


def _safe_relative(value: object) -> Path:
    if not isinstance(value, str):
        raise _reject("Artifact reference path is invalid.")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise _reject("Artifact reference path escapes the preparation root.")
    return path


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise _reject(f"{label.capitalize()} must be an object.")
    return dict(value)


def _digest(value: object, label: str) -> str:
    return _text(value, _SHA256, label)


def _git_sha(value: object, label: str) -> str:
    return _text(value, _GIT_SHA, label)


def _text(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} is invalid.")
    return value


def _bounded_text(value: object, label: str, minimum: int, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or not value.isprintable()
    ):
        raise _reject(f"{label.capitalize()} is invalid.")
    return value


def _timestamp(value: object) -> str:
    return _text(value, _TIMESTAMP, "authorization timestamp")


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _self_hash(record: Mapping[str, object]) -> str:
    return _self_hash_named(record, "execution_freeze_sha256")


def _self_hash_named(record: Mapping[str, object], field: str) -> str:
    unsigned = {key: value for key, value in record.items() if key != field}
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> object:
    raise ValueError(f"invalid numeric constant: {value}")


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("v02_execution_freeze", message)
