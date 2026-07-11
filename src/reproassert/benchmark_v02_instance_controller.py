"""Provider-disabled controller for frozen SWE-bench instance gold smoke runs."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from reproassert.benchmark_v02_hidden import (
    hidden_case_artifacts,
    verify_v02_hidden_gold,
)
from reproassert.benchmark_v02_instance_executor import (
    InstancePytestResult,
    InstanceRuntimeExecutor,
)
from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntimeManifest,
    load_instance_runtime_manifest,
)
from reproassert.errors import PolicyRejection, ReproAssertError
from reproassert.safeio import open_regular_file, write_bytes_exclusive

GOLD_SMOKE_SCHEMA_VERSION = "0.1.0"
GOLD_SMOKE_ALGORITHM = "reproassert-v02-instance-gold-smoke-v1"
MAX_GOLD_SPECS_BYTES = 512 * 1024
MAX_GOLD_SMOKE_RECEIPT_BYTES = 512 * 1024
MAX_PRIVATE_PATCH_BYTES = 1024 * 1024
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_INSTANCE_ID = re.compile(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[0-9]+\Z")
_VERSION = re.compile(r"[A-Za-z0-9_.-]{1,40}\Z")
_NETWORK_MARKERS = (
    "network is unreachable",
    "temporary failure in name resolution",
    "name or service not known",
    "failed to establish a new connection",
    "connectionerror",
    "socket.gaierror",
)
_SETUP_MARKERS = (
    "modulenotfounderror",
    "importerror while importing test module",
    "command not found",
    "permission denied",
    "no such file or directory",
)


@dataclass(frozen=True)
class GoldSmokeSpec:
    instance_id: str
    version: str
    fail_to_pass: tuple[str, ...]
    pass_to_pass: tuple[str, ...]


@dataclass(frozen=True)
class GoldSmokeReceipt:
    path: Path
    sha256: str
    selected_case_count: int
    semantic_valid_count: int
    infrastructure_failure_count: int


def verify_instance_gold_smoke_receipt(path: Path) -> GoldSmokeReceipt:
    """Verify canonical identity, denominator accounting, and redacted execution evidence."""

    raw = _read_regular(path, MAX_GOLD_SMOKE_RECEIPT_BYTES, "gold-smoke receipt")
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates, parse_constant=_bad_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("Gold-smoke receipt is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject("Gold-smoke receipt is not canonical JSON.")
    required = {
        "algorithm",
        "benchmark_version",
        "case_count",
        "claims",
        "counts",
        "executed_at",
        "inputs",
        "policy",
        "receipt_sha256",
        "results",
        "schema_version",
        "selection",
        "status",
        "tool_git_sha",
    }
    if (
        set(value) != required
        or value.get("algorithm") != GOLD_SMOKE_ALGORITHM
        or value.get("benchmark_version") != "0.2"
        or value.get("schema_version") != GOLD_SMOKE_SCHEMA_VERSION
        or value.get("case_count") != 20
        or value.get("receipt_sha256") != _self_hash(value)
    ):
        raise _reject("Gold-smoke receipt identity is invalid.")
    if value.get("claims") != {
        "hidden_patch_contents_emitted": False,
        "model_or_provider_invoked": False,
        "network_during_sandbox_execution": False,
        "provider_calls": 0,
    } or value.get("policy") != {
        "image_acquisition": "bounded_exact-digest-pull-before-sandbox-execution",
        "provider_execution_enabled": False,
        "sandbox_network_mode": "none",
    }:
        raise _reject("Gold-smoke receipt trust claims are invalid.")
    _timestamp(value.get("executed_at"))
    _git_sha(value.get("tool_git_sha"))
    inputs = value.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != {
        "gold_specs_sha256",
        "hidden_extraction_receipt_sha256",
        "instance_runtime_manifest_sha256",
    }:
        raise _reject("Gold-smoke receipt inputs are invalid.")
    for digest in inputs.values():
        _digest(digest, "receipt input")
    rows = value.get("results")
    if not isinstance(rows, list) or len(rows) != 20:
        raise _reject("Gold-smoke receipt must preserve exactly 20 result rows.")
    expected_cases = [f"rk-v0.2-{number:03d}" for number in range(1, 21)]
    if [row.get("case_id") if isinstance(row, dict) else None for row in rows] != expected_cases:
        raise _reject("Gold-smoke result ordering is invalid.")
    checked_rows = [cast(dict[str, object], row) for row in rows]
    for row in checked_rows:
        _verify_result_row(row)
    counts = _counts(checked_rows)
    if value.get("counts") != counts:
        raise _reject("Gold-smoke denominator counts are invalid.")
    selection = value.get("selection")
    status = value.get("status")
    if selection == "all":
        if status != "complete" or counts["selected"] != 20:
            raise _reject("Complete gold-smoke selection is invalid.")
    elif isinstance(selection, str) and _CASE_ID.fullmatch(selection):
        selected_rows = [row for row in checked_rows if row["selected"] is True]
        if (
            status != "partial_explicit_case"
            or len(selected_rows) != 1
            or selected_rows[0]["case_id"] != selection
        ):
            raise _reject("Partial gold-smoke selection is invalid.")
    else:
        raise _reject("Gold-smoke receipt selection is invalid.")
    return GoldSmokeReceipt(
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        selected_case_count=counts["selected"],
        semantic_valid_count=counts["semantic_valid"],
        infrastructure_failure_count=counts["infrastructure_failure"],
    )


ExecutorFactory = Callable[[InstanceRuntimeManifest, str], InstanceRuntimeExecutor]


def run_instance_gold_smoke(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    hidden_extraction_receipt: Path,
    gold_specs_path: Path,
    expected_gold_specs_sha256: str,
    output_path: Path,
    executed_at: str,
    tool_git_sha: str,
    case_id: str | None = None,
    executor_factory: ExecutorFactory | None = None,
) -> GoldSmokeReceipt:
    """Run hidden gold tests with no provider and retain the full 20-case denominator."""

    manifest = load_instance_runtime_manifest(manifest_path)
    if manifest.sha256 != _digest(expected_manifest_sha256, "expected manifest"):
        raise _reject("Instance runtime manifest differs from its explicit frozen commitment.")
    if len(manifest.entries) != 20:
        raise _reject("Gold smoke requires the complete frozen 20-case runtime manifest.")
    expected_cases = tuple(f"rk-v0.2-{number:03d}" for number in range(1, 21))
    if tuple(entry.case_id for entry in manifest.entries) != expected_cases:
        raise _reject("Instance runtime manifest does not preserve the full v0.2 denominator.")
    selected = _case_id(case_id) if case_id is not None else None
    if selected is not None and selected not in expected_cases:
        raise _reject("Selected gold-smoke case is outside the frozen denominator.")

    gold_raw = _read_regular(gold_specs_path, MAX_GOLD_SPECS_BYTES, "gold specs")
    gold_sha256 = hashlib.sha256(gold_raw).hexdigest()
    if gold_sha256 != _digest(expected_gold_specs_sha256, "expected gold specs"):
        raise _reject("Gold specs differ from their explicit frozen commitment.")
    specs = _load_gold_specs(gold_raw)
    by_instance = {spec.instance_id: spec for spec in specs}
    if set(by_instance) != {entry.instance_id for entry in manifest.entries}:
        raise _reject("Gold specs do not bind exactly the frozen runtime instances.")

    verified_hidden = verify_v02_hidden_gold(hidden_extraction_receipt)
    artifacts = {
        entry.case_id: hidden_case_artifacts(verified_hidden, entry.case_id)
        for entry in manifest.entries
    }
    factory = executor_factory or _executor_factory
    results: list[dict[str, object]] = []
    for entry in manifest.entries:
        if selected is not None and entry.case_id != selected:
            results.append(_not_run(entry.case_id, entry.instance_id))
            continue
        spec = by_instance[entry.instance_id]
        results.append(
            _run_case(
                manifest=manifest,
                case_id=entry.case_id,
                spec=spec,
                test_command_profile=entry.test_command_profile,
                artifact_refs=artifacts[entry.case_id],
                executor_factory=factory,
            )
        )

    counts = _counts(results)
    receipt: dict[str, object] = {
        "algorithm": GOLD_SMOKE_ALGORITHM,
        "benchmark_version": "0.2",
        "case_count": 20,
        "claims": {
            "hidden_patch_contents_emitted": False,
            "model_or_provider_invoked": False,
            "network_during_sandbox_execution": False,
            "provider_calls": 0,
        },
        "counts": counts,
        "executed_at": _timestamp(executed_at),
        "inputs": {
            "gold_specs_sha256": gold_sha256,
            "hidden_extraction_receipt_sha256": verified_hidden.prepared.receipt_sha256,
            "instance_runtime_manifest_sha256": manifest.sha256,
        },
        "policy": {
            "image_acquisition": "bounded_exact-digest-pull-before-sandbox-execution",
            "provider_execution_enabled": False,
            "sandbox_network_mode": "none",
        },
        "receipt_sha256": "0" * 64,
        "results": results,
        "schema_version": GOLD_SMOKE_SCHEMA_VERSION,
        "selection": selected or "all",
        "status": "complete" if selected is None else "partial_explicit_case",
        "tool_git_sha": _git_sha(tool_git_sha),
    }
    receipt["receipt_sha256"] = _self_hash(receipt)
    encoded = _canonical(receipt) + b"\n"
    write_bytes_exclusive(output_path, encoded)
    return GoldSmokeReceipt(
        path=output_path,
        sha256=hashlib.sha256(encoded).hexdigest(),
        selected_case_count=counts["selected"],
        semantic_valid_count=counts["semantic_valid"],
        infrastructure_failure_count=counts["infrastructure_failure"],
    )


def _run_case(
    *,
    manifest: InstanceRuntimeManifest,
    case_id: str,
    spec: GoldSmokeSpec,
    test_command_profile: str,
    artifact_refs: dict[str, dict[str, object]],
    executor_factory: ExecutorFactory,
) -> dict[str, object]:
    fixed_ref = artifact_refs["production_patch"]
    tests_ref = artifact_refs["developer_tests"]
    production = _read_committed_artifact(fixed_ref, "production patch")
    developer_tests = _read_committed_artifact(tests_ref, "developer tests")
    phases: dict[str, object] = {}
    classification = "infrastructure_failure"
    reason = "controller_failure"
    try:
        with executor_factory(manifest, case_id) as executor:
            executor.acquire()
            executor.prepare_workspaces(fixed_patch=production)
            executor.apply_patch(workspace="base", patch=developer_tests)
            executor.apply_patch(workspace="fixed", patch=developer_tests)
            collect_reason = None
            if test_command_profile == "pytest-v1":
                base_collect = executor.run_test_command(
                    workspace="base", targets=spec.fail_to_pass, collect_only=True
                )
                fixed_collect = executor.run_test_command(
                    workspace="fixed", targets=spec.fail_to_pass, collect_only=True
                )
                phases["base_collect"] = _result_evidence(base_collect)
                phases["fixed_collect"] = _result_evidence(fixed_collect)
                collect_reason = _infrastructure_reason(
                    base_collect, fixed_collect, collecting=True
                )
            if collect_reason is not None:
                reason = collect_reason
            else:
                base = executor.run_test_command(workspace="base", targets=spec.fail_to_pass)
                fixed = executor.run_test_command(workspace="fixed", targets=spec.fail_to_pass)
                phases["base"] = _result_evidence(base)
                phases["fixed"] = _result_evidence(fixed)
                runtime_reason = _infrastructure_reason(base, fixed, collecting=False)
                if runtime_reason is not None:
                    reason = runtime_reason
                elif base.exit_code != 0 and fixed.exit_code == 0:
                    classification, reason = "semantic_valid", "fails_on_base_passes_on_fixed"
                elif base.exit_code == 0 and fixed.exit_code == 0:
                    classification, reason = "semantic_failure", "does_not_fail_on_base"
                else:
                    classification, reason = "semantic_failure", "does_not_pass_on_fixed"
    except (ReproAssertError, OSError, ValueError) as exc:
        reason = _bounded_error_reason(exc)
    return {
        "case_id": case_id,
        "classification": classification,
        "hidden_inputs": {
            "developer_tests_bytes": tests_ref["bytes"],
            "developer_tests_sha256": tests_ref["sha256"],
            "production_patch_bytes": fixed_ref["bytes"],
            "production_patch_sha256": fixed_ref["sha256"],
        },
        "instance_id": spec.instance_id,
        "phases": phases,
        "reason": reason,
        "selected": True,
        "test_counts": {
            "fail_to_pass": len(spec.fail_to_pass),
            "pass_to_pass_not_executed": len(spec.pass_to_pass),
        },
        "test_command_profile": test_command_profile,
    }


def _not_run(case_id: str, instance_id: str) -> dict[str, object]:
    return {
        "case_id": case_id,
        "classification": "not_run",
        "hidden_inputs": None,
        "instance_id": instance_id,
        "phases": {},
        "reason": "not_selected",
        "selected": False,
        "test_counts": None,
        "test_command_profile": None,
    }


def _result_evidence(result: InstancePytestResult) -> dict[str, object]:
    encoded = result.output.encode("utf-8", errors="replace")
    return {
        "exit_code": result.exit_code,
        "output_bytes": len(encoded),
        "output_sha256": hashlib.sha256(encoded).hexdigest(),
        "output_stored": False,
        "output_truncated": result.output_truncated,
        "timed_out": result.timed_out,
    }


def _infrastructure_reason(*results: InstancePytestResult, collecting: bool) -> str | None:
    if any(result.timed_out for result in results):
        return "timeout"
    if any(result.output_truncated for result in results):
        return "output_limit"
    lowered = "\n".join(result.output.lower() for result in results)
    if any(marker in lowered for marker in _NETWORK_MARKERS):
        return "network_dependency"
    failed_output = "\n".join(result.output.lower() for result in results if result.exit_code != 0)
    if any(marker in failed_output for marker in _SETUP_MARKERS):
        return "setup_failure"
    if collecting and any(result.exit_code != 0 for result in results):
        return "collection_or_setup_failure"
    return None


def _bounded_error_reason(exc: Exception) -> str:
    if isinstance(exc, ReproAssertError):
        code = exc.code.lower()
        if "network" in exc.message.lower():
            return "network_dependency"
        if "cleanup" in exc.message.lower():
            return "cleanup_failure"
        if "docker" in code or "instance" in code:
            return "sandbox_setup_failure"
    return "controller_failure"


def _load_gold_specs(raw: bytes) -> tuple[GoldSmokeSpec, ...]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates, parse_constant=_bad_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("Gold specs are invalid JSON.") from exc
    if not isinstance(value, list) or len(value) != 20 or raw != _canonical(value) + b"\n":
        raise _reject("Gold specs must be canonical JSON with exactly 20 entries.")
    specs: list[GoldSmokeSpec] = []
    for position, item in enumerate(value, start=1):
        if not isinstance(item, Mapping) or set(item) != {
            "FAIL_TO_PASS",
            "PASS_TO_PASS",
            "instance_id",
            "version",
        }:
            raise _reject(f"Gold spec {position} fields are invalid.")
        specs.append(
            GoldSmokeSpec(
                instance_id=_text(item["instance_id"], _INSTANCE_ID, "instance ID"),
                version=_text(item["version"], _VERSION, "version"),
                fail_to_pass=_targets(item["FAIL_TO_PASS"], "FAIL_TO_PASS"),
                pass_to_pass=_targets(
                    item["PASS_TO_PASS"], "PASS_TO_PASS", allow_empty=True, max_items=1000
                ),
            )
        )
    if len({spec.instance_id for spec in specs}) != 20:
        raise _reject("Gold specs contain duplicate instances.")
    return tuple(specs)


def _targets(
    value: object,
    label: str,
    *,
    allow_empty: bool = False,
    max_items: int = 64,
) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty) or len(value) > max_items:
        raise _reject(f"Gold {label} targets are invalid.")
    targets: list[str] = []
    for target in value:
        if (
            not isinstance(target, str)
            or not target.isascii()
            or not 1 <= len(target) <= 500
            or target.startswith(("-", "/"))
            or "\x00" in target
            or ".." in Path(target.split("::", 1)[0]).parts
        ):
            raise _reject(f"Gold {label} target is unsafe.")
        targets.append(target)
    if len(set(targets)) != len(targets):
        raise _reject(f"Gold {label} targets contain duplicates.")
    return tuple(targets)


def _read_committed_artifact(reference: dict[str, object], label: str) -> bytes:
    path = reference.get("path")
    expected_bytes = reference.get("bytes")
    expected_sha256 = reference.get("sha256")
    if (
        not isinstance(path, Path)
        or type(expected_bytes) is not int
        or not isinstance(expected_sha256, str)
    ):
        raise _reject(f"Verified {label} reference is invalid.")
    content = _read_regular(path, MAX_PRIVATE_PATCH_BYTES, label)
    if len(content) != expected_bytes or hashlib.sha256(content).hexdigest() != expected_sha256:
        raise _reject(f"Verified {label} changed before execution.")
    return content


def _read_regular(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            content = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label.capitalize()} could not be read safely.") from exc
    if len(content) > limit:
        raise _reject(f"{label.capitalize()} exceeds its byte limit.")
    return content


def _counts(results: list[dict[str, object]]) -> dict[str, int]:
    counts = {
        "infrastructure_failure": 0,
        "not_run": 0,
        "selected": 0,
        "semantic_failure": 0,
        "semantic_valid": 0,
    }
    for result in results:
        classification = cast(str, result["classification"])
        counts[classification] += 1
        counts["selected"] += int(result["selected"] is True)
    return counts


def _verify_result_row(row: dict[str, object]) -> None:
    if set(row) != {
        "case_id",
        "classification",
        "hidden_inputs",
        "instance_id",
        "phases",
        "reason",
        "selected",
        "test_command_profile",
        "test_counts",
    }:
        raise _reject("Gold-smoke result fields are invalid.")
    _case_id(row.get("case_id"))
    _text(row.get("instance_id"), _INSTANCE_ID, "instance ID")
    classification = row.get("classification")
    selected = row.get("selected")
    if (
        classification
        not in {
            "infrastructure_failure",
            "not_run",
            "semantic_failure",
            "semantic_valid",
        }
        or type(selected) is not bool
    ):
        raise _reject("Gold-smoke result classification is invalid.")
    if (classification == "not_run") != (selected is False):
        raise _reject("Gold-smoke selected state is invalid.")
    reasons = {
        "not_selected",
        "fails_on_base_passes_on_fixed",
        "does_not_fail_on_base",
        "does_not_pass_on_fixed",
        "timeout",
        "output_limit",
        "network_dependency",
        "collection_or_setup_failure",
        "setup_failure",
        "cleanup_failure",
        "sandbox_setup_failure",
        "controller_failure",
    }
    if row.get("reason") not in reasons:
        raise _reject("Gold-smoke result reason is invalid.")
    phases = row.get("phases")
    if not isinstance(phases, dict) or not set(phases) <= {
        "base",
        "base_collect",
        "fixed",
        "fixed_collect",
    }:
        raise _reject("Gold-smoke execution phases are invalid.")
    for evidence in phases.values():
        _verify_phase(evidence)
    if selected is False:
        if (
            phases
            or row.get("hidden_inputs") is not None
            or row.get("test_counts") is not None
            or row.get("test_command_profile") is not None
            or row.get("reason") != "not_selected"
        ):
            raise _reject("Unselected gold-smoke row contains execution evidence.")
        return
    if row.get("test_command_profile") not in {"pytest-v1", "sympy-bin-test-v1"}:
        raise _reject("Gold-smoke command profile is invalid.")
    hidden = row.get("hidden_inputs")
    if not isinstance(hidden, dict) or set(hidden) != {
        "developer_tests_bytes",
        "developer_tests_sha256",
        "production_patch_bytes",
        "production_patch_sha256",
    }:
        raise _reject("Gold-smoke hidden-input commitments are invalid.")
    for prefix in ("developer_tests", "production_patch"):
        size = hidden.get(f"{prefix}_bytes")
        if type(size) is not int or not 1 <= size <= MAX_PRIVATE_PATCH_BYTES:
            raise _reject("Gold-smoke hidden-input size is invalid.")
        _digest(hidden.get(f"{prefix}_sha256"), "hidden input")
    test_counts = row.get("test_counts")
    if not isinstance(test_counts, dict) or set(test_counts) != {
        "fail_to_pass",
        "pass_to_pass_not_executed",
    }:
        raise _reject("Gold-smoke test counts are invalid.")
    fail_count = test_counts.get("fail_to_pass")
    pass_count = test_counts.get("pass_to_pass_not_executed")
    if (
        type(fail_count) is not int
        or not 1 <= fail_count <= 64
        or type(pass_count) is not int
        or not 0 <= pass_count <= 1000
    ):
        raise _reject("Gold-smoke test counts are outside policy.")


def _verify_phase(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "exit_code",
        "output_bytes",
        "output_sha256",
        "output_stored",
        "output_truncated",
        "timed_out",
    }:
        raise _reject("Gold-smoke phase evidence is invalid.")
    if (
        type(value.get("exit_code")) is not int
        or type(value.get("output_bytes")) is not int
        or not 0 <= cast(int, value["output_bytes"]) <= 2 * 1024 * 1024
        or value.get("output_stored") is not False
        or type(value.get("output_truncated")) is not bool
        or type(value.get("timed_out")) is not bool
    ):
        raise _reject("Gold-smoke phase evidence values are invalid.")
    _digest(value.get("output_sha256"), "phase output")


def _executor_factory(manifest: InstanceRuntimeManifest, case_id: str) -> InstanceRuntimeExecutor:
    return InstanceRuntimeExecutor(manifest, case_id=case_id)


def _self_hash(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned["receipt_sha256"] = "0" * 64
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _bad_constant(_value: str) -> object:
    raise ValueError("non-finite number")


def _text(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not value.isascii() or pattern.fullmatch(value) is None:
        raise _reject(f"Gold {label} is invalid.")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} SHA-256 is invalid.")
    return value


def _case_id(value: object) -> str:
    if not isinstance(value, str) or _CASE_ID.fullmatch(value) is None:
        raise _reject("Selected case ID is invalid.")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise _reject("Tool Git SHA is invalid.")
    return value


def _timestamp(value: object) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(
            r"20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z",
            value,
        )
        is None
    ):
        raise _reject("Gold-smoke execution timestamp is invalid.")
    return value


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_instance_controller", message)
