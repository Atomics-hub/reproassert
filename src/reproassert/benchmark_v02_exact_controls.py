"""Executed, provider-disabled causal controls in frozen v0.2 instance images."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import Literal, cast

from reproassert.benchmark_v02_candidate_evaluator import (
    CandidateArtifact,
    CandidateExecutionProfile,
    _candidate_fingerprint_or_none,
    _evaluation_policy,
    _evidence,
    _require_clean_collection,
    _resolve_hidden_evaluator_inputs,
    _verify_evidence,
    candidate_execution_profile,
    verify_instance_candidate_receipt,
)
from reproassert.benchmark_v02_exact_capability import (
    VerifiedV02ExactImageEvaluatorCapability,
    require_v02_exact_image_evaluator_capability,
)
from reproassert.benchmark_v02_hidden import VerifiedV02HiddenExtraction
from reproassert.benchmark_v02_instance_executor import InstanceRuntimeExecutor
from reproassert.benchmark_v02_instance_runtime import (
    InstanceRuntimeManifest,
    load_instance_runtime_manifest,
)
from reproassert.benchmark_v02_mapping_packets import (
    inventory_unified_diff,
    verify_v02_mapping_consensus,
)
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, write_bytes_exclusive
from reproassert.sandbox import SandboxPolicy

ALGORITHM = "reproassert-v02-exact-image-causal-controls-v1"
SCHEMA_VERSION = "1.0.0"
RUNS_PER_CONTROL = 3
MAX_JSON_BYTES = 2 * 1024 * 1024
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_EXECUTION_ISSUER = object()

Control = Literal["full_fix", "fix_minus_selected", "base_plus_selected"]
ExecutorFactory = Callable[[InstanceRuntimeManifest, str, SandboxPolicy], InstanceRuntimeExecutor]


@dataclass(frozen=True, init=False)
class VerifiedExactCausalControlExecution:
    """Nominal L2 execution authority issued only by the production executor path."""

    path: Path
    sha256: str
    case_id: str
    l2_causal_controls_passed: bool
    status: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedExactCausalControlExecution is executor-issued only")

    def public_record(self) -> dict[str, object]:
        return {
            "case_id": self.case_id,
            "l2_causal_controls_passed": self.l2_causal_controls_passed,
            "path": self.path,
            "sha256": self.sha256,
            "status": self.status,
            "verification_scope": "execution_authority",
        }


@dataclass(frozen=True)
class StructuralExactCausalControlReceipt:
    """Non-authoritative result of path-only canonical receipt inspection."""

    path: Path
    sha256: str
    case_id: str
    status: str = "structural_valid_non_authoritative"
    verification_scope: str = "structural_only_no_l2_authority"


def run_exact_image_causal_controls(
    *,
    evaluator_capability: VerifiedV02ExactImageEvaluatorCapability,
    verified_hidden: VerifiedV02HiddenExtraction,
    manifest_path: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    gold_specs_path: Path,
    mapping_consensus_path: Path,
    mapping_preparation_path: Path,
    candidate_evaluation_receipt_path: Path,
    candidate: CandidateArtifact,
    output_path: Path,
    executed_at: str,
    tool_git_sha: str,
) -> VerifiedExactCausalControlExecution:
    """Execute controls with the production exact-image executor only."""

    return _run_exact_image_causal_controls_with_factory(
        evaluator_capability=evaluator_capability,
        verified_hidden=verified_hidden,
        manifest_path=manifest_path,
        expected_manifest_sha256=expected_manifest_sha256,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
        gold_specs_path=gold_specs_path,
        mapping_consensus_path=mapping_consensus_path,
        mapping_preparation_path=mapping_preparation_path,
        candidate_evaluation_receipt_path=candidate_evaluation_receipt_path,
        candidate=candidate,
        output_path=output_path,
        executed_at=executed_at,
        tool_git_sha=tool_git_sha,
        executor_factory=_executor_factory,
    )


def _run_exact_image_causal_controls_with_factory(
    *,
    evaluator_capability: VerifiedV02ExactImageEvaluatorCapability,
    verified_hidden: VerifiedV02HiddenExtraction,
    manifest_path: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt_path: Path,
    gold_specs_path: Path,
    mapping_consensus_path: Path,
    mapping_preparation_path: Path,
    candidate_evaluation_receipt_path: Path,
    candidate: CandidateArtifact,
    output_path: Path,
    executed_at: str,
    tool_git_sha: str,
    executor_factory: ExecutorFactory,
) -> VerifiedExactCausalControlExecution:
    """Execute all three preregistered controls in three fresh exact-image contexts each."""

    capability = require_v02_exact_image_evaluator_capability(evaluator_capability)
    case_id = capability.case_id
    manifest = load_instance_runtime_manifest(manifest_path)
    if (
        manifest.sha256 != expected_manifest_sha256
        or manifest.sha256 != capability.runtime_manifest_sha256
    ):
        raise _reject("Runtime manifest differs from the exact evaluator capability.")
    runtime = capability.runtime
    profile = candidate_execution_profile(runtime, case_id=case_id, candidate=candidate)
    hidden = _resolve_hidden_evaluator_inputs(
        evaluator_capability=capability,
        verified_hidden=verified_hidden,
        gold_smoke_receipt_path=gold_smoke_receipt_path,
        gold_specs_path=gold_specs_path,
    )
    baseline_sha, baseline_fingerprint = _verified_candidate_baseline(
        candidate_evaluation_receipt_path, case_id=case_id, candidate=candidate, profile=profile
    )
    mapping = verify_v02_mapping_consensus(
        mapping_consensus_path, preparation_path=mapping_preparation_path
    )
    selected_ids = _selected_consensus_ids(mapping.path, case_id)
    selected_patch, remainder_patch, separation = _partition_patch(
        hidden.production_patch, case_id=case_id, selected_ids=selected_ids
    )
    control_names: tuple[Control, ...] = (
        "full_fix",
        "fix_minus_selected",
        "base_plus_selected",
    )
    controls: list[dict[str, object]]
    if separation is not None:
        controls = [_inconclusive_control(name, separation) for name in control_names]
    else:
        if selected_patch is None or remainder_patch is None:
            raise _reject("Separated patch controls are unexpectedly absent.")
        controls = [
            _run_control(
                name=name,
                manifest=manifest,
                case_id=case_id,
                profile=profile,
                candidate=candidate,
                full_patch=hidden.production_patch,
                selected_patch=selected_patch,
                remainder_patch=remainder_patch,
                expected_failure_fingerprint=baseline_fingerprint,
                executor_factory=executor_factory,
            )
            for name in control_names
        ]
    passed = all(control["status"] == "conclusive_pass" for control in controls)
    status = "l2_controls_passed" if passed else "inconclusive_no_l2_claim"
    record: dict[str, object] = {
        "algorithm": ALGORITHM,
        "benchmark_version": "0.2",
        "case_id": case_id,
        "candidate": {
            "evaluation_receipt_sha256": baseline_sha,
            "failure_fingerprint_sha256": baseline_fingerprint,
            "profile_sha256": profile.sha256,
            "sha256": hashlib.sha256(candidate.content).hexdigest(),
        },
        "claims": {
            "hidden_bytes_emitted": False,
            "l2_causal_controls_passed": passed,
            "network_during_sandbox_execution": False,
            "provider_calls": 0,
        },
        "controls": controls,
        "evaluator_public_commitment_sha256": capability.evaluator_public_commitment_sha256,
        "executed_at": _timestamp(executed_at),
        "mapping": {
            "consensus_sha256": mapping.sha256,
            "selected_hunk_count": len(selected_ids),
            "selected_hunks_sha256": _json_sha(
                {"algorithm": "reproassert-v02-selected-hunk-set-v1", "atomic_ids": selected_ids}
            ),
        },
        "policy": {
            "fresh_contexts_per_control": RUNS_PER_CONTROL,
            "network_mode": "none",
            "profile": "reproassert-v02-exact-image-causal-controls-v1",
        },
        "receipt_sha256": "0" * 64,
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "tool_git_sha": _git_sha(tool_git_sha),
    }
    record["receipt_sha256"] = _self_hash(record)
    encoded = _canonical(record) + b"\n"
    write_bytes_exclusive(output_path, encoded)
    issued = object.__new__(VerifiedExactCausalControlExecution)
    for name, value in {
        "path": output_path,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "case_id": case_id,
        "l2_causal_controls_passed": passed,
        "status": status,
        "_issuer": _EXECUTION_ISSUER,
    }.items():
        object.__setattr__(issued, name, value)
    return issued


def verify_exact_image_causal_control_receipt(path: Path) -> StructuralExactCausalControlReceipt:
    raw = _read(path, MAX_JSON_BYTES)
    try:
        record = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _reject("Causal-control receipt is invalid JSON.") from exc
    if not isinstance(record, dict) or raw != _canonical(record) + b"\n":
        raise _reject("Causal-control receipt is not canonical JSON.")
    required = {
        "algorithm",
        "benchmark_version",
        "candidate",
        "case_id",
        "claims",
        "controls",
        "evaluator_public_commitment_sha256",
        "executed_at",
        "mapping",
        "policy",
        "receipt_sha256",
        "schema_version",
        "status",
        "tool_git_sha",
    }
    if (
        set(record) != required
        or record.get("algorithm") != ALGORITHM
        or record.get("benchmark_version") != "0.2"
        or record.get("schema_version") != SCHEMA_VERSION
        or record.get("receipt_sha256") != _self_hash(record)
    ):
        raise _reject("Causal-control receipt identity is invalid.")
    case_id = _case(record.get("case_id"))
    _timestamp(record.get("executed_at"))
    _git_sha(record.get("tool_git_sha"))
    controls = record.get("controls")
    if not isinstance(controls, list) or len(controls) != 3:
        raise _reject("Causal-control receipt must contain exactly three controls.")
    names = [control.get("name") if isinstance(control, dict) else None for control in controls]
    if names != ["full_fix", "fix_minus_selected", "base_plus_selected"]:
        raise _reject("Causal-control ordering is invalid.")
    candidate_row = record.get("candidate")
    if not isinstance(candidate_row, dict) or set(candidate_row) != {
        "evaluation_receipt_sha256",
        "failure_fingerprint_sha256",
        "profile_sha256",
        "sha256",
    }:
        raise _reject("Causal-control candidate binding is invalid.")
    for value in candidate_row.values():
        _digest(value, "candidate binding")
    baseline_fingerprint = candidate_row.get("failure_fingerprint_sha256")
    if (
        not isinstance(baseline_fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{64}", baseline_fingerprint) is None
    ):
        raise _reject("Causal-control baseline fingerprint is invalid.")
    for control in controls:
        _verify_control(cast(dict[str, object], control), baseline_fingerprint)
    _digest(record.get("evaluator_public_commitment_sha256"), "evaluator commitment")
    mapping = record.get("mapping")
    if not isinstance(mapping, dict) or set(mapping) != {
        "consensus_sha256",
        "selected_hunk_count",
        "selected_hunks_sha256",
    }:
        raise _reject("Causal-control mapping binding is invalid.")
    _digest(mapping.get("consensus_sha256"), "mapping consensus")
    _digest(mapping.get("selected_hunks_sha256"), "selected hunks")
    if (
        type(mapping.get("selected_hunk_count")) is not int
        or cast(int, mapping["selected_hunk_count"]) < 1
    ):
        raise _reject("Causal-control selected hunk count is invalid.")
    if record.get("policy") != {
        "fresh_contexts_per_control": RUNS_PER_CONTROL,
        "network_mode": "none",
        "profile": "reproassert-v02-exact-image-causal-controls-v1",
    }:
        raise _reject("Causal-control execution policy is invalid.")
    passed = all(control.get("status") == "conclusive_pass" for control in controls)
    claims = record.get("claims")
    if claims != {
        "hidden_bytes_emitted": False,
        "l2_causal_controls_passed": passed,
        "network_during_sandbox_execution": False,
        "provider_calls": 0,
    } or record.get("status") != ("l2_controls_passed" if passed else "inconclusive_no_l2_claim"):
        raise _reject("Causal-control claims disagree with executed evidence.")
    return StructuralExactCausalControlReceipt(path, hashlib.sha256(raw).hexdigest(), case_id)


def require_exact_causal_control_execution(
    value: object,
) -> VerifiedExactCausalControlExecution:
    """Require the live authority issued by the production exact-image executor."""

    if (
        type(value) is not VerifiedExactCausalControlExecution
        or value._issuer is not _EXECUTION_ISSUER
    ):
        raise _reject("Fresh executor-issued exact causal-control authority is required.")
    return value


def _run_control(
    *,
    name: Control,
    manifest: InstanceRuntimeManifest,
    case_id: str,
    profile: CandidateExecutionProfile,
    candidate: CandidateArtifact,
    full_patch: bytes,
    selected_patch: bytes,
    remainder_patch: bytes,
    expected_failure_fingerprint: str,
    executor_factory: ExecutorFactory,
) -> dict[str, object]:
    runs: list[dict[str, object]] = []
    expected = "fail_same_fingerprint" if name == "fix_minus_selected" else "pass"
    for _ in range(RUNS_PER_CONTROL):
        if name == "fix_minus_selected" and not remainder_patch:
            # When every production hunk is issue-relevant, subtracting the selected set is the
            # exact buggy base.  Execute that real endpoint instead of making one-hunk fixes
            # structurally ineligible for causal validation.
            fixed_patch = full_patch
            workspace: Literal["base", "fixed"] = "base"
        else:
            fixed_patch = remainder_patch if name == "fix_minus_selected" else full_patch
            workspace = "base" if name == "base_plus_selected" else "fixed"
        with executor_factory(
            manifest,
            case_id,
            _evaluation_policy(
                manifest.entries[[e.case_id for e in manifest.entries].index(case_id)].image_id
            ),
        ) as executor:
            executor.acquire()
            executor.prepare_workspaces(fixed_patch=fixed_patch)
            if name == "base_plus_selected":
                executor.apply_patch(workspace="base", patch=selected_patch)
            executor.stage_candidate(relative_path=profile.staging_path, content=candidate.content)
            collection: object = None
            if profile.profile_id == "pytest-v1":
                target = f"{profile.staging_path}::{profile.required_function}"
                collect = executor.run_pytest(
                    workspace=workspace, targets=(target,), collect_only=True
                )
                try:
                    _require_clean_collection(collect, collect, "causal control")
                except PolicyRejection:
                    runs.append(
                        {
                            "collection": _evidence(collect),
                            "failure_fingerprint_sha256": None,
                            "result": None,
                        }
                    )
                    continue
                collection = _evidence(collect)
                result = executor.run_pytest(workspace=workspace, targets=(target,))
            else:
                result = executor.run_test_command(
                    workspace=workspace,
                    sympy_test_file=profile.staging_path,
                    sympy_test_identifier=profile.required_function,
                )
            fingerprint = _candidate_fingerprint_or_none(result, profile=profile)
            runs.append(
                {
                    "collection": collection,
                    "failure_fingerprint_sha256": fingerprint,
                    "result": _evidence(result),
                }
            )
    conclusive = _control_matches(runs, expected, expected_failure_fingerprint)
    return {
        "expected": expected,
        "name": name,
        "reason": "observed_3_of_3" if conclusive else "execution_or_fingerprint_mismatch",
        "runs": runs,
        "status": "conclusive_pass" if conclusive else "inconclusive",
    }


def _control_matches(runs: list[dict[str, object]], expected: str, fingerprint: str) -> bool:
    if len(runs) != RUNS_PER_CONTROL or any(run.get("result") is None for run in runs):
        return False
    evidence = [cast(dict[str, object], run["result"]) for run in runs]
    if any(row["timed_out"] or row["oom_killed"] or row["output_truncated"] for row in evidence):
        return False
    if expected == "pass":
        return all(row["exit_code"] == 0 for row in evidence)
    return all(row["exit_code"] == 1 for row in evidence) and all(
        run["failure_fingerprint_sha256"] == fingerprint for run in runs
    )


def _partition_patch(
    patch: bytes, *, case_id: str, selected_ids: tuple[str, ...]
) -> tuple[bytes | None, bytes | None, str | None]:
    inventory = inventory_unified_diff(patch, case_id=case_id)
    all_ids = tuple(cast(str, row["atomic_id"]) for row in inventory)
    if not selected_ids or not set(selected_ids).issubset(all_ids):
        return None, None, "inseparable_mapping"
    selected = set(selected_ids)
    if selected == set(all_ids) and len(all_ids) > 1:
        return None, None, "multi_hunk_all_selected_requires_leave_one_out"
    # Splitting one file across both subsets can make offsets/order matter under git apply.
    for left, right in pairwise(inventory):
        if left["path"] == right["path"] and (
            (left["atomic_id"] in selected) != (right["atomic_id"] in selected)
        ):
            return None, None, "noncommutative_same_file_hunks"
    return (
        _subset_patch(patch, inventory, selected),
        _subset_patch(patch, inventory, set(all_ids) - selected),
        None,
    )


def _subset_patch(patch: bytes, inventory: list[dict[str, object]], keep: set[str]) -> bytes:
    lines = patch.splitlines(keepends=True)
    output: list[bytes] = []
    prefix: list[bytes] = []
    ordinal = 0
    i = 0
    while i < len(lines):
        if lines[i].startswith(b"diff --git "):
            prefix = []
        if not lines[i].startswith(b"@@ "):
            prefix.append(lines[i])
            i += 1
            continue
        ordinal += 1
        hunk = [lines[i]]
        i += 1
        while i < len(lines) and not lines[i].startswith((b"@@ ", b"diff --git ")):
            hunk.append(lines[i])
            i += 1
        if cast(str, inventory[ordinal - 1]["atomic_id"]) in keep:
            output.extend(prefix)
            prefix = []
            output.extend(hunk)
    return b"".join(output)


def _verified_candidate_baseline(
    path: Path, *, case_id: str, candidate: CandidateArtifact, profile: CandidateExecutionProfile
) -> tuple[str, str]:
    verified = verify_instance_candidate_receipt(path)
    if not verified.accepted or verified.case_id != case_id:
        raise _reject("Candidate baseline is not an accepted exact-image reproduction.")
    raw = _read(path, MAX_JSON_BYTES)
    record = cast(dict[str, object], json.loads(raw))
    candidate_row = cast(dict[str, object], record["candidate"])
    if (
        candidate_row.get("sha256") != hashlib.sha256(candidate.content).hexdigest()
        or candidate_row.get("relative_path") != profile.staging_path
    ):
        raise _reject("Candidate bytes or profile differ from the accepted baseline.")
    runs = cast(dict[str, object], record["phases"])["candidate_runs"]
    fingerprints = {
        cast(dict[str, object], run).get("failure_fingerprint_sha256")
        for run in cast(list[object], runs)
        if cast(dict[str, object], run).get("workspace") == "base"
    }
    if len(fingerprints) != 1 or None in fingerprints:
        raise _reject("Candidate baseline lacks one stable failure fingerprint.")
    return verified.sha256, cast(str, fingerprints.pop())


def _selected_consensus_ids(path: Path, case_id: str) -> tuple[str, ...]:
    record = cast(dict[str, object], json.loads(_read(path, MAX_JSON_BYTES)))
    rows = cast(list[dict[str, object]], record["cases"])
    row = next(item for item in rows if item["case_id"] == case_id)
    decision = cast(dict[str, object], row["consensus"])
    if decision.get("verdict") != "approved":
        raise _reject("Mapping consensus is not approved for causal controls.")
    ids = decision.get("selected_hunk_ids")
    if not isinstance(ids, list) or not ids or not all(isinstance(item, str) for item in ids):
        raise _reject("Mapping consensus selected hunk set is invalid.")
    return tuple(cast(list[str], ids))


def _inconclusive_control(name: str, reason: str) -> dict[str, object]:
    return {
        "expected": "fail_same_fingerprint" if name == "fix_minus_selected" else "pass",
        "name": name,
        "reason": reason,
        "runs": [],
        "status": "inconclusive",
    }


def _verify_control(value: dict[str, object], baseline_fingerprint: str) -> None:
    if set(value) != {"expected", "name", "reason", "runs", "status"} or value.get(
        "status"
    ) not in {"conclusive_pass", "inconclusive"}:
        raise _reject("Causal-control evidence shape is invalid.")
    runs = value.get("runs")
    if not isinstance(runs, list) or len(runs) not in {0, 3}:
        raise _reject("Causal-control run count is invalid.")
    if value["status"] == "conclusive_pass" and len(runs) != 3:
        raise _reject("Conclusive control lacks three fresh runs.")
    expected = "fail_same_fingerprint" if value.get("name") == "fix_minus_selected" else "pass"
    if value.get("expected") != expected:
        raise _reject("Causal-control expectation is invalid.")
    for run in runs:
        if not isinstance(run, dict) or set(run) != {
            "collection",
            "failure_fingerprint_sha256",
            "result",
        }:
            raise _reject("Causal-control run evidence is invalid.")
        if run["collection"] is not None:
            _verify_evidence(run["collection"])
        if run["result"] is not None:
            _verify_evidence(run["result"])
    if value["status"] == "conclusive_pass" and not _control_matches(
        cast(list[dict[str, object]], runs), expected, baseline_fingerprint
    ):
        raise _reject("Conclusive causal-control evidence does not match its expectation.")


def _executor_factory(
    manifest: InstanceRuntimeManifest, case_id: str, policy: SandboxPolicy
) -> InstanceRuntimeExecutor:
    return InstanceRuntimeExecutor(manifest, case_id=case_id, policy=policy)


def _self_hash(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned["receipt_sha256"] = "0" * 64
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _json_sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _read(path: Path, limit: int) -> bytes:
    with open_regular_file(path) as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise _reject("Causal-control input exceeds its size limit.")
    return raw


def _case(value: object) -> str:
    if not isinstance(value, str) or _CASE_ID.fullmatch(value) is None:
        raise _reject("Causal-control case ID is invalid.")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Causal-control tool Git SHA is invalid.")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Causal-control timestamp is invalid.")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise _reject(f"Causal-control {label} digest is invalid.")
    return value


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_exact_controls", message)
