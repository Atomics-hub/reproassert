"""Provider-free authority for the narrowly scoped v0.2.1 gold-spec amendment."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from reproassert.benchmark_v02_hidden import hidden_case_artifacts, verify_v02_hidden_gold
from reproassert.benchmark_v02_instance_controller import (
    MAX_GOLD_SMOKE_RECEIPT_BYTES,
    MAX_GOLD_SPECS_BYTES,
    GoldSmokeSpec,
    _load_gold_specs,
    verify_instance_gold_smoke_receipt,
)
from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntime,
    load_instance_runtime_manifest,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

AMENDMENT_ALGORITHM = "reproassert-v02-gold-spec-amendment-v1"
AMENDMENT_SCHEMA_VERSION = "1.0.0"
LEGACY_GOLD_SPECS_SHA256 = "f9cdfa3b0fa7aa8d26a7c4720af36095fe429f098daa5dcea41a436895f63544"
AMENDED_GOLD_SPECS_SHA256 = "8fa460abb6d72fcaa19f3588277216aa8b483eb28e27ea78985cb7e6f6ceb1db"
AMENDED_INSTANCE_ID = "psf__requests-1921"
AMENDED_CASE_ID = "rk-v0.2-014"
MAX_AMENDMENT_RECEIPT_BYTES = 128 * 1024
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_ISSUER = object()


@dataclass(frozen=True, init=False)
class VerifiedV02BenchmarkAmendment:
    """Process-local authority; serialized receipts are evidence, never authority."""

    receipt_path: Path
    receipt_sha256: str
    runtime_manifest_sha256: str
    hidden_extraction_receipt_sha256: str
    original_gold_smoke_receipt_sha256: str
    amended_gold_smoke_receipt_sha256: str
    review_status: str
    reviewer_ids: tuple[str, ...]
    tool_git_sha: str
    provider_calls: int
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV02BenchmarkAmendment is verifier-issued only")


def prepare_v02_benchmark_amendment(
    *,
    original_gold_specs: Path,
    amended_gold_specs: Path,
    original_gold_smoke_receipt: Path,
    amended_gold_smoke_receipt: Path,
    instance_runtime_manifest: Path,
    expected_runtime_manifest_sha256: str,
    hidden_extraction_receipt: Path,
    prepared_at: str,
    tool_git_sha: str,
    review_status: str,
    reviewer_ids: tuple[str, ...],
    output_path: Path,
) -> VerifiedV02BenchmarkAmendment:
    """Verify the six private inputs and persist only redacted commitments."""

    output = Path(output_path)
    require_private_directory(output.parent)
    if output.exists() or output.is_symlink():
        raise _reject("Refusing to overwrite a benchmark amendment receipt.")
    evidence = _verify_private_inputs(
        original_gold_specs=Path(original_gold_specs),
        amended_gold_specs=Path(amended_gold_specs),
        original_gold_smoke_receipt=Path(original_gold_smoke_receipt),
        amended_gold_smoke_receipt=Path(amended_gold_smoke_receipt),
        instance_runtime_manifest=Path(instance_runtime_manifest),
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        hidden_extraction_receipt=Path(hidden_extraction_receipt),
    )
    timestamp = _timestamp(prepared_at)
    if _timestamp_value(timestamp) > datetime.now(timezone.utc):
        raise _reject("Benchmark amendment receipt cannot be future-dated.")
    if cast(str, evidence["amended_executed_at"]) > timestamp:
        raise _reject("Benchmark amendment predates its amended smoke evidence.")
    status, reviewers = _review(review_status, reviewer_ids)
    record: dict[str, object] = {
        "algorithm": AMENDMENT_ALGORITHM,
        "benchmark_version": "0.2.1",
        "change": {
            "added_fail_to_pass_targets": 0,
            "amended_case_id": AMENDED_CASE_ID,
            "amended_instance_id": AMENDED_INSTANCE_ID,
            "fail_to_pass_after": 1,
            "fail_to_pass_before": 6,
            "removed_fail_to_pass_targets": 5,
            "scope": "strict_subset_only",
        },
        "claims": {
            "hidden_paths_emitted": False,
            "hidden_test_names_emitted": False,
            "logs_emitted": False,
            "nominal_authority_serialized": False,
            "provider_calls": 0,
        },
        "evidence": evidence,
        "prepared_at": timestamp,
        "receipt_sha256": "0" * 64,
        "review": {"reviewer_ids": list(reviewers), "status": status},
        "schema_version": AMENDMENT_SCHEMA_VERSION,
        "status": (
            "provider_free_packaging_ready_review_pending"
            if status == "pending"
            else "provider_free_packaging_ready_review_approved"
        ),
        "tool_git_sha": _git_sha(tool_git_sha),
    }
    record["receipt_sha256"] = _self_hash(record)
    write_bytes_exclusive(output, _canonical(record) + b"\n")
    return verify_v02_benchmark_amendment(
        output,
        original_gold_specs=original_gold_specs,
        amended_gold_specs=amended_gold_specs,
        original_gold_smoke_receipt=original_gold_smoke_receipt,
        amended_gold_smoke_receipt=amended_gold_smoke_receipt,
        instance_runtime_manifest=instance_runtime_manifest,
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        hidden_extraction_receipt=hidden_extraction_receipt,
    )


def verify_v02_benchmark_amendment(
    path: Path,
    *,
    original_gold_specs: Path,
    amended_gold_specs: Path,
    original_gold_smoke_receipt: Path,
    amended_gold_smoke_receipt: Path,
    instance_runtime_manifest: Path,
    expected_runtime_manifest_sha256: str,
    hidden_extraction_receipt: Path,
) -> VerifiedV02BenchmarkAmendment:
    """Freshly rederive a receipt from all six private inputs and issue authority."""

    raw = _read(Path(path), MAX_AMENDMENT_RECEIPT_BYTES, "amendment receipt")
    try:
        record = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _reject("Benchmark amendment receipt is invalid JSON.") from exc
    if not isinstance(record, dict) or raw != _canonical(record) + b"\n":
        raise _reject("Benchmark amendment receipt is not canonical JSON.")
    if set(record) != {
        "algorithm",
        "benchmark_version",
        "change",
        "claims",
        "evidence",
        "prepared_at",
        "receipt_sha256",
        "review",
        "schema_version",
        "status",
        "tool_git_sha",
    }:
        raise _reject("Benchmark amendment receipt fields are invalid.")
    if (
        record.get("algorithm") != AMENDMENT_ALGORITHM
        or record.get("benchmark_version") != "0.2.1"
        or record.get("schema_version") != AMENDMENT_SCHEMA_VERSION
        or record.get("receipt_sha256") != _self_hash(record)
    ):
        raise _reject("Benchmark amendment receipt identity is invalid.")
    expected_evidence = _verify_private_inputs(
        original_gold_specs=Path(original_gold_specs),
        amended_gold_specs=Path(amended_gold_specs),
        original_gold_smoke_receipt=Path(original_gold_smoke_receipt),
        amended_gold_smoke_receipt=Path(amended_gold_smoke_receipt),
        instance_runtime_manifest=Path(instance_runtime_manifest),
        expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
        hidden_extraction_receipt=Path(hidden_extraction_receipt),
    )
    timestamp = _timestamp(record.get("prepared_at"))
    if _timestamp_value(timestamp) > datetime.now(timezone.utc):
        raise _reject("Benchmark amendment receipt cannot be future-dated.")
    if cast(str, expected_evidence["amended_executed_at"]) > timestamp:
        raise _reject("Benchmark amendment predates its amended smoke evidence.")
    review = record.get("review")
    if not isinstance(review, dict) or set(review) != {"reviewer_ids", "status"}:
        raise _reject("Benchmark amendment review fields are invalid.")
    ids = review.get("reviewer_ids")
    if not isinstance(ids, list):
        raise _reject("Benchmark amendment reviewer IDs are invalid.")
    status, reviewers = _review(review.get("status"), tuple(ids))
    expected = {
        "algorithm": AMENDMENT_ALGORITHM,
        "benchmark_version": "0.2.1",
        "change": {
            "added_fail_to_pass_targets": 0,
            "amended_case_id": AMENDED_CASE_ID,
            "amended_instance_id": AMENDED_INSTANCE_ID,
            "fail_to_pass_after": 1,
            "fail_to_pass_before": 6,
            "removed_fail_to_pass_targets": 5,
            "scope": "strict_subset_only",
        },
        "claims": {
            "hidden_paths_emitted": False,
            "hidden_test_names_emitted": False,
            "logs_emitted": False,
            "nominal_authority_serialized": False,
            "provider_calls": 0,
        },
        "evidence": expected_evidence,
        "prepared_at": timestamp,
        "review": {"reviewer_ids": list(reviewers), "status": status},
        "schema_version": AMENDMENT_SCHEMA_VERSION,
        "status": (
            "provider_free_packaging_ready_review_pending"
            if status == "pending"
            else "provider_free_packaging_ready_review_approved"
        ),
        "tool_git_sha": _git_sha(record.get("tool_git_sha")),
    }
    unsigned = dict(record)
    unsigned.pop("receipt_sha256")
    if unsigned != expected:
        raise _reject("Benchmark amendment receipt differs from freshly verified evidence.")
    authority = object.__new__(VerifiedV02BenchmarkAmendment)
    for name, value in {
        "receipt_path": Path(path),
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "runtime_manifest_sha256": expected_evidence["runtime_manifest_sha256"],
        "hidden_extraction_receipt_sha256": expected_evidence["hidden_extraction_receipt_sha256"],
        "original_gold_smoke_receipt_sha256": expected_evidence[
            "original_gold_smoke_receipt_sha256"
        ],
        "amended_gold_smoke_receipt_sha256": expected_evidence["amended_gold_smoke_receipt_sha256"],
        "review_status": status,
        "reviewer_ids": reviewers,
        "tool_git_sha": cast(str, record["tool_git_sha"]),
        "provider_calls": 0,
        "_issuer": _ISSUER,
    }.items():
        object.__setattr__(authority, name, value)
    return authority


def require_v02_benchmark_amendment(value: object) -> VerifiedV02BenchmarkAmendment:
    if type(value) is not VerifiedV02BenchmarkAmendment or value._issuer is not _ISSUER:
        raise _reject("Fresh verifier-issued benchmark amendment authority is required.")
    return value


def require_approved_v02_benchmark_amendment(value: object) -> VerifiedV02BenchmarkAmendment:
    authority = require_v02_benchmark_amendment(value)
    if authority.review_status != "approved":
        raise _reject("Benchmark amendment review is pending; execution remains disabled.")
    return authority


def _verify_private_inputs(
    *,
    original_gold_specs: Path,
    amended_gold_specs: Path,
    original_gold_smoke_receipt: Path,
    amended_gold_smoke_receipt: Path,
    instance_runtime_manifest: Path,
    expected_runtime_manifest_sha256: str,
    hidden_extraction_receipt: Path,
) -> dict[str, object]:
    original_raw = _read(original_gold_specs, MAX_GOLD_SPECS_BYTES, "original gold specs")
    amended_raw = _read(amended_gold_specs, MAX_GOLD_SPECS_BYTES, "amended gold specs")
    if hashlib.sha256(original_raw).hexdigest() != LEGACY_GOLD_SPECS_SHA256:
        raise _reject("Original gold specs differ from the frozen raw commitment.")
    if hashlib.sha256(amended_raw).hexdigest() != AMENDED_GOLD_SPECS_SHA256:
        raise _reject("Amended gold specs differ from the frozen raw commitment.")
    original_specs = _load_gold_specs(original_raw)
    amended_specs = _load_gold_specs(amended_raw)
    _verify_spec_delta(original_specs, amended_specs)

    manifest = load_instance_runtime_manifest(instance_runtime_manifest)
    manifest_raw = _read(instance_runtime_manifest, 1024 * 1024, "runtime manifest")
    manifest_raw_sha = hashlib.sha256(manifest_raw).hexdigest()
    manifest_sha = _sha256(expected_runtime_manifest_sha256, "runtime manifest commitment")
    if manifest.sha256 != manifest_sha:
        raise _reject("Runtime manifest differs from its explicit commitment.")
    expected_cases = tuple(f"rk-v0.2-{number:03d}" for number in range(1, 21))
    if tuple(entry.case_id for entry in manifest.entries) != expected_cases or {
        entry.instance_id for entry in manifest.entries
    } != {spec.instance_id for spec in original_specs}:
        raise _reject("Gold specs do not preserve the exact 20-case runtime denominator.")

    old_verified = verify_instance_gold_smoke_receipt(original_gold_smoke_receipt)
    new_verified = verify_instance_gold_smoke_receipt(amended_gold_smoke_receipt)
    old_raw = _read(original_gold_smoke_receipt, MAX_GOLD_SMOKE_RECEIPT_BYTES, "original smoke")
    new_raw = _read(amended_gold_smoke_receipt, MAX_GOLD_SMOKE_RECEIPT_BYTES, "amended smoke")
    if hashlib.sha256(old_raw).hexdigest() != old_verified.sha256:
        raise _reject("Original smoke changed after verification.")
    if hashlib.sha256(new_raw).hexdigest() != new_verified.sha256:
        raise _reject("Amended smoke changed after verification.")
    verified_hidden = verify_v02_hidden_gold(hidden_extraction_receipt)
    hidden_raw = _read(hidden_extraction_receipt, 512 * 1024, "hidden extraction receipt")
    hidden_sha = hashlib.sha256(hidden_raw).hexdigest()
    if hidden_sha != verified_hidden.prepared.receipt_sha256:
        raise _reject("Hidden extraction receipt changed after verification.")
    old = cast(dict[str, object], json.loads(old_raw))
    new = cast(dict[str, object], json.loads(new_raw))
    old_inputs = cast(dict[str, object], old["inputs"])
    if old_inputs["hidden_extraction_receipt_sha256"] != hidden_sha:
        raise _reject("Smoke receipts do not bind the supplied hidden extraction receipt.")
    try:
        hidden_record = cast(dict[str, object], json.loads(hidden_raw))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _reject("Hidden extraction receipt is invalid JSON.") from exc
    hidden_commitment = _sha256(
        hidden_record.get("receipt_sha256"), "hidden extraction internal commitment"
    )
    specs_by_instance = {spec.instance_id: spec for spec in original_specs}
    amended_by_instance = {spec.instance_id: spec for spec in amended_specs}
    hidden_bindings = {
        entry.case_id: _hidden_binding(hidden_case_artifacts(verified_hidden, entry.case_id))
        for entry in manifest.entries
    }
    target_counts = {
        entry.case_id: (
            len(specs_by_instance[entry.instance_id].fail_to_pass),
            len(specs_by_instance[entry.instance_id].pass_to_pass),
            len(amended_by_instance[entry.instance_id].fail_to_pass),
            len(amended_by_instance[entry.instance_id].pass_to_pass),
        )
        for entry in manifest.entries
    }
    _verify_smoke_pair(
        old,
        new,
        manifest_sha,
        manifest_entries=manifest.entries,
        hidden_bindings=hidden_bindings,
        target_counts=target_counts,
    )
    return {
        "amended_executed_at": new["executed_at"],
        "amended_gold_smoke_commitment_sha256": new["receipt_sha256"],
        "amended_gold_smoke_receipt_sha256": new_verified.sha256,
        "amended_gold_specs_sha256": AMENDED_GOLD_SPECS_SHA256,
        "hidden_extraction_commitment_sha256": hidden_commitment,
        "hidden_extraction_receipt_sha256": hidden_sha,
        "original_executed_at": old["executed_at"],
        "original_gold_smoke_commitment_sha256": old["receipt_sha256"],
        "original_gold_smoke_receipt_sha256": old_verified.sha256,
        "original_gold_specs_sha256": LEGACY_GOLD_SPECS_SHA256,
        "runtime_manifest_sha256": manifest_sha,
        "runtime_manifest_raw_sha256": manifest_raw_sha,
        "smoke_tool_git_sha": old["tool_git_sha"],
    }


def _verify_spec_delta(
    original: tuple[GoldSmokeSpec, ...], amended: tuple[GoldSmokeSpec, ...]
) -> None:
    if tuple(spec.instance_id for spec in original) != tuple(spec.instance_id for spec in amended):
        raise _reject("Amended gold specs reorder or replace benchmark instances.")
    changed = []
    for before, after in zip(original, amended, strict=True):
        if before == after:
            continue
        changed.append(before.instance_id)
        if (
            before.instance_id != AMENDED_INSTANCE_ID
            or before.version != after.version
            or before.pass_to_pass != after.pass_to_pass
            or len(before.fail_to_pass) != 6
            or len(after.fail_to_pass) != 1
            or not set(after.fail_to_pass) < set(before.fail_to_pass)
        ):
            raise _reject("Gold-spec amendment exceeds the one-case strict-subset policy.")
    if changed != [AMENDED_INSTANCE_ID]:
        raise _reject("Gold-spec amendment must change exactly psf__requests-1921.")


def _verify_smoke_pair(
    old: dict[str, object],
    new: dict[str, object],
    manifest_sha: str,
    *,
    manifest_entries: tuple[InstanceRuntime, ...],
    hidden_bindings: dict[str, dict[str, object]],
    target_counts: dict[str, tuple[int, int, int, int]],
) -> None:
    for record, specs_sha, counts in (
        (old, LEGACY_GOLD_SPECS_SHA256, (19, 1)),
        (new, AMENDED_GOLD_SPECS_SHA256, (20, 0)),
    ):
        claims = cast(dict[str, object], record.get("claims"))
        policy = cast(dict[str, object], record.get("policy"))
        sandbox = cast(dict[str, object], policy.get("sandbox"))
        inputs = cast(dict[str, object], record.get("inputs"))
        actual_counts = cast(dict[str, object], record.get("counts"))
        if (
            record.get("selection") != "all"
            or record.get("status") != "complete"
            or actual_counts.get("selected") != 20
            or actual_counts.get("not_run") != 0
            or (actual_counts.get("semantic_valid"), actual_counts.get("infrastructure_failure"))
            != counts
            or claims.get("provider_calls") != 0
            or claims.get("model_or_provider_invoked") is not False
            or sandbox.get("network_mode") != "none"
            or inputs.get("gold_specs_sha256") != specs_sha
            or inputs.get("instance_runtime_manifest_sha256") != manifest_sha
        ):
            raise _reject(
                "Gold-smoke pair does not prove the required provider-free 19/1 to 20/0 transition."
            )
    old_inputs = cast(dict[str, object], old["inputs"])
    new_inputs = cast(dict[str, object], new["inputs"])
    if (
        old_inputs["hidden_extraction_receipt_sha256"]
        != new_inputs["hidden_extraction_receipt_sha256"]
    ):
        raise _reject("Gold-smoke pair does not bind a common hidden extraction.")
    if old["tool_git_sha"] != new["tool_git_sha"]:
        raise _reject("Gold-smoke pair was produced by different tool revisions.")
    old_time = _timestamp(cast(str, old["executed_at"]))
    new_time = _timestamp(cast(str, new["executed_at"]))
    if new_time <= old_time:
        raise _reject("Amended gold smoke must chronologically follow original smoke.")
    old_rows = old.get("results")
    new_rows = new.get("results")
    if not isinstance(old_rows, list) or not isinstance(new_rows, list):
        raise _reject("Gold-smoke pair lacks ordered per-case results.")
    expected_cases = [f"rk-v0.2-{number:03d}" for number in range(1, 21)]
    for rows in (old_rows, new_rows):
        if [
            row.get("case_id") if isinstance(row, dict) else None for row in rows
        ] != expected_cases:
            raise _reject("Gold-smoke pair result ordering is invalid.")
    if len(manifest_entries) != 20:
        raise _reject("Gold-smoke pair manifest denominator is invalid.")
    for entry, old_row_value, new_row_value in zip(
        manifest_entries, old_rows, new_rows, strict=True
    ):
        old_row = cast(dict[str, object], old_row_value)
        new_row = cast(dict[str, object], new_row_value)
        case_id = entry.case_id
        common = {
            "case_id": case_id,
            "hidden_inputs": hidden_bindings[case_id],
            "instance_id": entry.instance_id,
            "selected": True,
            "test_command_profile": entry.test_command_profile,
        }
        for name, expected in common.items():
            if old_row.get(name) != expected or new_row.get(name) != expected:
                raise _reject(f"Gold-smoke pair case binding differs for {case_id}.")
        old_fail, old_pass, new_fail, new_pass = target_counts[case_id]
        if old_row.get("test_counts") != {
            "fail_to_pass": old_fail,
            "pass_to_pass_not_executed": old_pass,
        } or new_row.get("test_counts") != {
            "fail_to_pass": new_fail,
            "pass_to_pass_not_executed": new_pass,
        }:
            raise _reject(f"Gold-smoke target counts differ for {case_id}.")
        expected_old = (
            ("infrastructure_failure", "network_dependency")
            if case_id == AMENDED_CASE_ID
            else ("semantic_valid", "fails_on_base_passes_on_fixed")
        )
        if (
            old_row.get("classification"),
            old_row.get("reason"),
        ) != expected_old or (
            new_row.get("classification"),
            new_row.get("reason"),
        ) != ("semantic_valid", "fails_on_base_passes_on_fixed"):
            raise _reject(f"Gold-smoke per-case transition is invalid for {case_id}.")


def _hidden_binding(refs: dict[str, dict[str, object]]) -> dict[str, object]:
    return {
        "developer_tests_bytes": refs["developer_tests"]["bytes"],
        "developer_tests_sha256": refs["developer_tests"]["sha256"],
        "production_patch_bytes": refs["production_patch"]["bytes"],
        "production_patch_sha256": refs["production_patch"]["sha256"],
    }


def _review(status: object, reviewer_ids: tuple[object, ...]) -> tuple[str, tuple[str, ...]]:
    if status == "pending" and reviewer_ids == ():
        return "pending", ()
    raise _reject(
        "Amendment approval cannot be caller-declared; a genuine consensus artifact is required."
    )


def _read(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            raw = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label.capitalize()} could not be read safely.") from exc
    if len(raw) > limit:
        raise _reject(f"{label.capitalize()} exceeds its size limit.")
    return raw


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Benchmark amendment tool Git SHA is invalid.")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject(f"Benchmark amendment {label} is invalid.")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Benchmark amendment timestamp is invalid.")
    try:
        _timestamp_value(value)
    except ValueError as exc:
        raise _reject("Benchmark amendment timestamp is invalid.") from exc
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _self_hash(record: dict[str, object]) -> str:
    unsigned = {key: value for key, value in record.items() if key != "receipt_sha256"}
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_amendment", message)
