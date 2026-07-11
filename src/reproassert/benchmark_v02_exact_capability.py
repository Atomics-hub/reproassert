"""Nominal authority for exact-image v0.2 candidate evaluation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from reproassert.benchmark_v02_hidden import (
    VerifiedV02HiddenExtraction,
    hidden_case_artifacts,
)
from reproassert.benchmark_v02_instance_controller import (
    MAX_GOLD_SMOKE_RECEIPT_BYTES,
    verify_instance_gold_smoke_receipt,
)
from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntime,
    load_instance_runtime_manifest,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file

CAPABILITY_ALGORITHM = "reproassert-v02-exact-image-evaluator-capability-v1"
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_ISSUER = object()


@dataclass(frozen=True, init=False)
class VerifiedV02ExactImageEvaluatorCapability:
    """Process-local authority issued only after all private/public evidence verifies."""

    case_id: str
    runtime_manifest_sha256: str
    runtime: InstanceRuntime
    gold_smoke_receipt_sha256: str
    gold_smoke_receipt_commitment_sha256: str
    gold_smoke_classification: str
    gold_smoke_reason: str
    hidden_extraction_receipt_sha256: str
    production_patch_sha256: str
    production_patch_bytes: int
    developer_tests_sha256: str
    developer_tests_bytes: int
    evaluator_public_commitment_sha256: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV02ExactImageEvaluatorCapability is verifier-issued only")

    def public_record(self) -> dict[str, object]:
        """Return the complete redacted binding carried into evaluation receipts."""

        return {
            "algorithm": CAPABILITY_ALGORITHM,
            "case_id": self.case_id,
            "gold_smoke": {
                "case_classification": self.gold_smoke_classification,
                "case_reason": self.gold_smoke_reason,
                "receipt_commitment_sha256": self.gold_smoke_receipt_commitment_sha256,
                "receipt_sha256": self.gold_smoke_receipt_sha256,
            },
            "hidden_inputs": {
                "developer_tests_bytes": self.developer_tests_bytes,
                "developer_tests_sha256": self.developer_tests_sha256,
                "hidden_extraction_receipt_sha256": self.hidden_extraction_receipt_sha256,
                "production_patch_bytes": self.production_patch_bytes,
                "production_patch_sha256": self.production_patch_sha256,
            },
            "runtime": _runtime_record(self.runtime),
            "runtime_manifest_sha256": self.runtime_manifest_sha256,
        }


def issue_verified_v02_exact_image_evaluator_capability(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    verified_hidden: VerifiedV02HiddenExtraction,
    case_id: str,
) -> VerifiedV02ExactImageEvaluatorCapability:
    """Verify the complete frozen evidence chain and issue authority for one exact case."""

    checked_case = _case(case_id)
    manifest = load_instance_runtime_manifest(manifest_path)
    if manifest.sha256 != expected_manifest_sha256:
        raise _reject("Runtime manifest differs from its explicit commitment.")
    expected_cases = tuple(f"rk-v0.2-{number:03d}" for number in range(1, 21))
    if tuple(entry.case_id for entry in manifest.entries) != expected_cases:
        raise _reject("Exact-image evaluator capability requires the complete 20-case manifest.")
    runtime = next(entry for entry in manifest.entries if entry.case_id == checked_case)

    verified_gold = verify_instance_gold_smoke_receipt(gold_smoke_receipt_path)
    raw = _read_gold(gold_smoke_receipt_path)
    if hashlib.sha256(raw).hexdigest() != verified_gold.sha256:
        raise _reject("Gold-smoke receipt changed after verification.")
    record = cast(dict[str, object], json.loads(raw))
    if record.get("selection") != "all" or record.get("status") != "complete":
        raise _reject("Evaluator capability requires a complete all-case gold-smoke receipt.")
    if record.get("counts") != {
        "infrastructure_failure": 1,
        "not_run": 0,
        "selected": 20,
        "semantic_failure": 0,
        "semantic_valid": 19,
    }:
        raise _reject(
            "Gold-smoke denominator must preserve 19 valid cases and the case 014 "
            "infrastructure failure."
        )
    inputs = cast(dict[str, object], record["inputs"])
    if inputs["instance_runtime_manifest_sha256"] != manifest.sha256:
        raise _reject("Gold-smoke receipt does not bind the exact runtime manifest.")
    prepared = verified_hidden.prepared
    if inputs["hidden_extraction_receipt_sha256"] != prepared.receipt_sha256:
        raise _reject("Gold-smoke receipt does not bind the freshly verified hidden extraction.")

    rows = cast(list[dict[str, object]], record["results"])
    row = next(item for item in rows if item["case_id"] == checked_case)
    if (
        row["instance_id"] != runtime.instance_id
        or row["test_command_profile"] != runtime.test_command_profile
    ):
        raise _reject("Gold-smoke case does not bind the exact runtime entry.")
    if checked_case == "rk-v0.2-014":
        if (
            row["classification"] != "infrastructure_failure"
            or row["reason"] != "network_dependency"
        ):
            raise _reject("Case 014 must remain the recorded network infrastructure failure.")
    elif (
        row["classification"] != "semantic_valid"
        or row["reason"] != "fails_on_base_passes_on_fixed"
    ):
        raise _reject("Non-014 case lacks valid hidden gold-smoke evidence.")

    refs = hidden_case_artifacts(verified_hidden, checked_case)
    hidden = cast(dict[str, object], row["hidden_inputs"])
    _require_hidden_binding(hidden, refs)
    capability = object.__new__(VerifiedV02ExactImageEvaluatorCapability)
    values: dict[str, object] = {
        "case_id": checked_case,
        "runtime_manifest_sha256": manifest.sha256,
        "runtime": runtime,
        "gold_smoke_receipt_sha256": verified_gold.sha256,
        "gold_smoke_receipt_commitment_sha256": cast(str, record["receipt_sha256"]),
        "gold_smoke_classification": row["classification"],
        "gold_smoke_reason": row["reason"],
        "hidden_extraction_receipt_sha256": prepared.receipt_sha256,
        "production_patch_sha256": cast(str, hidden["production_patch_sha256"]),
        "production_patch_bytes": cast(int, hidden["production_patch_bytes"]),
        "developer_tests_sha256": cast(str, hidden["developer_tests_sha256"]),
        "developer_tests_bytes": cast(int, hidden["developer_tests_bytes"]),
        "_issuer": _ISSUER,
    }
    for name, value in values.items():
        object.__setattr__(capability, name, value)
    object.__setattr__(capability, "evaluator_public_commitment_sha256", "")
    commitment = hashlib.sha256(_canonical(capability.public_record())).hexdigest()
    object.__setattr__(capability, "evaluator_public_commitment_sha256", commitment)
    return capability


def require_v02_exact_image_evaluator_capability(
    value: object,
) -> VerifiedV02ExactImageEvaluatorCapability:
    """Reject structural lookalikes and the legacy directly constructible capability."""

    if type(value) is not VerifiedV02ExactImageEvaluatorCapability or value._issuer is not _ISSUER:
        raise _reject("Fresh verifier-issued exact-image evaluator capability is required.")
    expected = hashlib.sha256(_canonical(value.public_record())).hexdigest()
    if value.evaluator_public_commitment_sha256 != expected:
        raise _reject("Exact-image evaluator public commitment is invalid.")
    return value


def _require_hidden_binding(row: dict[str, object], refs: dict[str, dict[str, object]]) -> None:
    expected = {
        "developer_tests_bytes": refs["developer_tests"]["bytes"],
        "developer_tests_sha256": refs["developer_tests"]["sha256"],
        "production_patch_bytes": refs["production_patch"]["bytes"],
        "production_patch_sha256": refs["production_patch"]["sha256"],
    }
    if row != expected:
        raise _reject("Gold-smoke hidden commitments differ from verified private artifacts.")


def _runtime_record(runtime: InstanceRuntime) -> dict[str, str]:
    return {
        "base_sha": runtime.base_sha,
        "base_tree_oid": runtime.base_tree_oid,
        "case_id": runtime.case_id,
        "image_digest": runtime.image_digest,
        "image_id": runtime.image_id,
        "image_tag": runtime.image_tag,
        "instance_id": runtime.instance_id,
        "spec_sha256": runtime.spec_sha256,
        "test_command_profile": runtime.test_command_profile,
    }


def _read_gold(path: Path) -> bytes:
    with open_regular_file(path) as stream:
        raw = stream.read(MAX_GOLD_SMOKE_RECEIPT_BYTES + 1)
    if len(raw) > MAX_GOLD_SMOKE_RECEIPT_BYTES:
        raise _reject("Gold-smoke receipt exceeds the verifier limit.")
    return raw


def _case(value: object) -> str:
    if not isinstance(value, str) or _CASE_ID.fullmatch(value) is None:
        raise _reject("Exact-image evaluator case ID is invalid.")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_exact_image_evaluator_capability", message)
