"""Nominal authority for exact-image v0.2 candidate evaluation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from reproassert.benchmark_v02_hidden import (
    VerifiedV02HiddenExtraction,
    hidden_case_artifacts,
    verify_v02_hidden_gold,
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
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

CAPABILITY_ALGORITHM = "reproassert-v02-exact-image-evaluator-capability-v1"
CAPABILITY_ALGORITHM_V2 = "reproassert-v02-exact-image-evaluator-capability-v2"
INDEX_ALGORITHM_V1 = "reproassert-v02-exact-image-capability-index-v1"
INDEX_ALGORITHM_V2 = "reproassert-v02-exact-image-capability-index-v2"
LEGACY_GOLD_SPECS_SHA256 = "f9cdfa3b0fa7aa8d26a7c4720af36095fe429f098daa5dcea41a436895f63544"
AMENDED_GOLD_SPECS_SHA256 = "8fa460abb6d72fcaa19f3588277216aa8b483eb28e27ea78985cb7e6f6ceb1db"
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
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
    capability_algorithm: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV02ExactImageEvaluatorCapability is verifier-issued only")

    def public_record(self) -> dict[str, object]:
        """Return the complete redacted binding carried into evaluation receipts."""

        return {
            "algorithm": self.capability_algorithm,
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


@dataclass(frozen=True)
class VerifiedV02ExactImageCapabilityIndex:
    path: Path
    sha256: str
    case_count: int
    runtime_attested_count: int
    evaluator_preflight_ready_count: int
    infrastructure_failure_count: int
    provider_calls: int = 0


def prepare_v02_exact_image_capability_index(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    hidden_extraction_receipt: Path,
    prepared_at: str,
    tool_git_sha: str,
    output_path: Path,
) -> VerifiedV02ExactImageCapabilityIndex:
    """Persist 20 redacted commitments while keeping nominal authority process-local."""

    destination = Path(output_path)
    require_private_directory(destination.parent)
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite exact-image capability index.")
    record = _derive_index(
        manifest_path=Path(manifest_path),
        expected_manifest_sha256=expected_manifest_sha256,
        gold_smoke_receipt_path=Path(gold_smoke_receipt_path),
        hidden_extraction_receipt=Path(hidden_extraction_receipt),
        prepared_at=prepared_at,
        tool_git_sha=tool_git_sha,
    )
    record["index_sha256"] = _index_hash(record)
    write_bytes_exclusive(destination, _canonical(record) + b"\n")
    return verify_v02_exact_image_capability_index(
        destination,
        manifest_path=manifest_path,
        expected_manifest_sha256=expected_manifest_sha256,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
        hidden_extraction_receipt=hidden_extraction_receipt,
    )


def verify_v02_exact_image_capability_index(
    path: Path,
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    hidden_extraction_receipt: Path,
) -> VerifiedV02ExactImageCapabilityIndex:
    raw = _read_bounded(Path(path), 1024 * 1024, "capability index")
    try:
        record = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _reject("Exact-image capability index is invalid JSON.") from exc
    if not isinstance(record, dict) or raw != _canonical(record) + b"\n":
        raise _reject("Exact-image capability index is not canonical JSON.")
    if set(record) != {
        "algorithm",
        "benchmark_version",
        "case_count",
        "cases",
        "claims",
        "index_sha256",
        "prepared_at",
        "schema_version",
        "status",
        "tool_git_sha",
    }:
        raise _reject("Exact-image capability index fields are invalid.")
    if record.get("case_count") != 20 or record.get("index_sha256") != _index_hash(record):
        raise _reject("Exact-image capability index identity is invalid.")
    claims = record.get("claims")
    if not isinstance(claims, dict):
        raise _reject("Exact-image capability index claims are invalid.")
    ready_count, infrastructure_count = _capability_counts(claims)
    expected_identity = (
        (INDEX_ALGORITHM_V2, "2.0.0", "0.2.1")
        if ready_count == 20
        else (INDEX_ALGORITHM_V1, "1.0.0", "0.2")
    )
    if (
        record.get("algorithm"),
        record.get("schema_version"),
        record.get("benchmark_version"),
    ) != expected_identity or record.get(
        "status"
    ) != f"runtime_attested_20_evaluator_preflight_{ready_count}":
        raise _reject("Exact-image capability index identity is invalid.")
    expected = _derive_index(
        manifest_path=Path(manifest_path),
        expected_manifest_sha256=expected_manifest_sha256,
        gold_smoke_receipt_path=Path(gold_smoke_receipt_path),
        hidden_extraction_receipt=Path(hidden_extraction_receipt),
        prepared_at=_timestamp(record.get("prepared_at")),
        tool_git_sha=_git_sha(record.get("tool_git_sha")),
    )
    unsigned = dict(record)
    unsigned.pop("index_sha256")
    if unsigned != expected:
        raise _reject("Exact-image capability index differs from freshly verified evidence.")
    return VerifiedV02ExactImageCapabilityIndex(
        path=Path(path),
        sha256=hashlib.sha256(raw).hexdigest(),
        case_count=20,
        runtime_attested_count=20,
        evaluator_preflight_ready_count=ready_count,
        infrastructure_failure_count=infrastructure_count,
    )


def _derive_index(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    hidden_extraction_receipt: Path,
    prepared_at: str,
    tool_git_sha: str,
) -> dict[str, object]:
    timestamp = _timestamp(prepared_at)
    if _timestamp_value(timestamp) > datetime.now(timezone.utc):
        raise _reject("Exact-image capability index cannot be future-dated.")
    producer_sha = _git_sha(tool_git_sha)
    hidden = verify_v02_hidden_gold(hidden_extraction_receipt)
    rows: list[dict[str, object]] = []
    for number in range(1, 21):
        capability = issue_verified_v02_exact_image_evaluator_capability(
            manifest_path=manifest_path,
            expected_manifest_sha256=expected_manifest_sha256,
            gold_smoke_receipt_path=gold_smoke_receipt_path,
            verified_hidden=hidden,
            case_id=f"rk-v0.2-{number:03d}",
        )
        require_v02_exact_image_evaluator_capability(capability)
        rows.append(
            {
                "case_id": capability.case_id,
                "evaluator_public_commitment_sha256": (
                    capability.evaluator_public_commitment_sha256
                ),
                "evidence": capability.public_record(),
                "status": (
                    "runtime_attested_evaluator_preflight_ready"
                    if capability.gold_smoke_classification == "semantic_valid"
                    else "runtime_attested_gold_smoke_infrastructure_failure"
                ),
            }
        )
    ready_count = sum(row["status"] == "runtime_attested_evaluator_preflight_ready" for row in rows)
    infrastructure_count = 20 - ready_count
    return {
        "algorithm": INDEX_ALGORITHM_V2 if ready_count == 20 else INDEX_ALGORITHM_V1,
        "benchmark_version": "0.2.1" if ready_count == 20 else "0.2",
        "case_count": 20,
        "cases": rows,
        "claims": {
            "evaluator_preflight_ready_count": ready_count,
            "infrastructure_failure_count": infrastructure_count,
            "nominal_authority_serialized": False,
            "provider_calls": 0,
            "runtime_attested_count": 20,
        },
        "prepared_at": timestamp,
        "schema_version": "2.0.0" if ready_count == 20 else "1.0.0",
        "status": f"runtime_attested_20_evaluator_preflight_{ready_count}",
        "tool_git_sha": producer_sha,
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
    counts = record.get("counts")
    if not isinstance(counts, dict) or set(counts) != {
        "infrastructure_failure",
        "not_run",
        "selected",
        "semantic_failure",
        "semantic_valid",
    }:
        raise _reject("Gold-smoke denominator is invalid.")
    semantic_valid = counts.get("semantic_valid")
    infrastructure_failure = counts.get("infrastructure_failure")
    if (
        type(semantic_valid) is not int
        or type(infrastructure_failure) is not int
        or (semantic_valid, infrastructure_failure) not in {(19, 1), (20, 0)}
        or counts.get("selected") != 20
        or counts.get("not_run") != 0
        or counts.get("semantic_failure") != 0
    ):
        raise _reject(
            "Gold-smoke denominator must be complete and preserve either legacy 19/1 "
            "evidence or fresh all-20 semantic-valid evidence."
        )
    expected_specs_sha = (
        AMENDED_GOLD_SPECS_SHA256 if semantic_valid == 20 else LEGACY_GOLD_SPECS_SHA256
    )
    inputs = cast(dict[str, object], record["inputs"])
    if inputs.get("gold_specs_sha256") != expected_specs_sha:
        raise _reject("Gold-smoke specs do not match the versioned benchmark amendment.")
    if inputs["instance_runtime_manifest_sha256"] != manifest.sha256:
        raise _reject("Gold-smoke receipt does not bind the exact runtime manifest.")
    prepared = verified_hidden.prepared
    if inputs["hidden_extraction_receipt_sha256"] != prepared.receipt_sha256:
        raise _reject("Gold-smoke receipt does not bind the freshly verified hidden extraction.")

    rows_value = record.get("results")
    if not isinstance(rows_value, list) or len(rows_value) != 20:
        raise _reject("Gold-smoke results must contain all 20 cases.")
    rows = cast(list[dict[str, object]], rows_value)
    semantic_rows = 0
    infrastructure_rows = 0
    for position, result in enumerate(rows, start=1):
        expected_case = f"rk-v0.2-{position:03d}"
        if not isinstance(result, dict) or result.get("case_id") != expected_case:
            raise _reject("Gold-smoke results are reordered, duplicated, or cross-case swapped.")
        classification = result.get("classification")
        reason = result.get("reason")
        if classification == "semantic_valid" and reason == "fails_on_base_passes_on_fixed":
            semantic_rows += 1
        elif (
            expected_case == "rk-v0.2-014"
            and classification == "infrastructure_failure"
            and reason == "network_dependency"
        ):
            infrastructure_rows += 1
        elif expected_case == "rk-v0.2-014":
            raise _reject("Case 014 gold-smoke classification is invalid.")
        else:
            raise _reject("Non-014 case lacks valid hidden gold-smoke evidence.")
    if (semantic_rows, infrastructure_rows) != (semantic_valid, infrastructure_failure):
        raise _reject("Gold-smoke result counts differ from the claimed denominator.")
    row = next(item for item in rows if item["case_id"] == checked_case)
    if (
        row["instance_id"] != runtime.instance_id
        or row["test_command_profile"] != runtime.test_command_profile
    ):
        raise _reject("Gold-smoke case does not bind the exact runtime entry.")
    if row["classification"] == "semantic_valid":
        if row["reason"] != "fails_on_base_passes_on_fixed":
            raise _reject("Semantic-valid gold-smoke evidence has an invalid reason.")
    elif (
        checked_case != "rk-v0.2-014"
        or semantic_valid != 19
        or row["classification"] != "infrastructure_failure"
        or row["reason"] != "network_dependency"
    ):
        raise _reject("Gold-smoke case classification differs from the accepted denominator.")

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
        "capability_algorithm": (
            CAPABILITY_ALGORITHM_V2 if semantic_valid == 20 else CAPABILITY_ALGORITHM
        ),
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


def _capability_counts(claims: dict[str, object]) -> tuple[int, int]:
    if set(claims) != {
        "evaluator_preflight_ready_count",
        "infrastructure_failure_count",
        "nominal_authority_serialized",
        "provider_calls",
        "runtime_attested_count",
    }:
        raise _reject("Exact-image capability index claims are invalid.")
    ready = claims.get("evaluator_preflight_ready_count")
    infrastructure = claims.get("infrastructure_failure_count")
    if (
        type(ready) is not int
        or type(infrastructure) is not int
        or (ready, infrastructure) not in {(19, 1), (20, 0)}
        or claims.get("nominal_authority_serialized") is not False
        or claims.get("provider_calls") != 0
        or claims.get("runtime_attested_count") != 20
    ):
        raise _reject("Exact-image capability index claims are invalid.")
    return ready, infrastructure


def _read_gold(path: Path) -> bytes:
    with open_regular_file(path) as stream:
        raw = stream.read(MAX_GOLD_SMOKE_RECEIPT_BYTES + 1)
    if len(raw) > MAX_GOLD_SMOKE_RECEIPT_BYTES:
        raise _reject("Gold-smoke receipt exceeds the verifier limit.")
    return raw


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            raw = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label.capitalize()} could not be read safely.") from exc
    if len(raw) > limit:
        raise _reject(f"{label.capitalize()} exceeds its size limit.")
    return raw


def _case(value: object) -> str:
    if not isinstance(value, str) or _CASE_ID.fullmatch(value) is None:
        raise _reject("Exact-image evaluator case ID is invalid.")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Exact-image capability index tool Git SHA is invalid.")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Exact-image capability index timestamp is invalid.")
    try:
        _timestamp_value(value)
    except ValueError as exc:
        raise _reject("Exact-image capability index timestamp is invalid.") from exc
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _index_hash(record: dict[str, object]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "index_sha256"}
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_exact_image_evaluator_capability", message)
