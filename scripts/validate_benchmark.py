#!/usr/bin/env python3
"""Validate ReproAssert's frozen public benchmark using only the standard library."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from reproassert.benchmark import (  # noqa: E402
    canonical_json_bytes,
    is_exact_prefix,
    read_ledger,
    sanitize_public_excerpt,
)
from reproassert.errors import ReproAssertError  # noqa: E402

BENCHMARK_VERSION = "0.1.0"
EXPECTED_CASE_COUNT = 20
EXPECTED_REPOSITORY_COUNT = 10
EXPECTED_DIFFICULTY_COUNTS = {"lt_15m": 14, "15m_to_1h": 6}
EXPECTED_SMOKE_IDS = {
    "rk-v0.1-004",
    "rk-v0.1-006",
    "rk-v0.1-010",
    "rk-v0.1-011",
    "rk-v0.1-018",
}
EXPECTED_IDS = {f"rk-v0.1-{index:03d}" for index in range(1, 21)}
EXPECTED_SCHEDULE = ["base", "fixed", "fixed", "base", "base", "fixed"]
EXPECTED_CLAIM_LEVELS = ["L0", "L1", "L2", "L3"]
EXPECTED_OUTCOMES = [
    "benchmark_infrastructure_error",
    "no_output",
    "invalid_patch",
    "policy_violation",
    "setup_failure",
    "collect_failure",
    "pass_on_base",
    "wrong_failure",
    "flaky_base",
    "fail_on_fix",
    "flaky_fix",
    "plausible_f2p_semantic_invalid",
    "semantic_valid",
]
EARLY_REJECTED_OUTCOMES = {
    "benchmark_infrastructure_error",
    "no_output",
    "invalid_patch",
    "policy_violation",
    "setup_failure",
    "collect_failure",
    "pass_on_base",
    "wrong_failure",
    "flaky_base",
}
L0_OUTCOMES = {"fail_on_fix", "flaky_fix"}
SEMANTIC_RUBRIC_KEYS = {
    "trigger_faithful",
    "oracle_supported",
    "failure_causal",
    "implementation_independent",
    "minimal_and_readable",
}
EXPECTED_CASE_KEYS = {
    "id",
    "repo",
    "issue_url",
    "base_sha",
    "difficulty",
    "title",
    "smoke",
}
EVENT_PAYLOAD_DEFS = {
    "attempt_started": "attemptStarted",
    "phase_started": "phaseStarted",
    "phase_finished": "phaseFinished",
    "model_call_started": "modelCallStarted",
    "model_call_finished": "modelCallFinished",
    "cost_recorded": "costRecorded",
    "candidate_submitted": "candidateSubmitted",
    "semantic_review_recorded": "semanticReviewRecorded",
    "gold_unblinded": "goldUnblinded",
    "attempt_finished": "attemptFinished",
}
WARM_PHASES = {
    "preflight",
    "issue_snapshot",
    "generation",
    "candidate_policy",
    "collection",
    "base_verify",
    "fixed_verify",
    "causal_controls",
}
REQUIRED_ATTRIBUTABLE_COST_CATEGORIES = {
    "model_inference",
    "sandbox_compute",
    "artifact_transfer",
    "paid_storage",
}
RESULT_COST_FIELD_BY_CATEGORY = {
    "model_inference": "model_usd",
    "sandbox_compute": "sandbox_compute_usd",
    "artifact_transfer": "artifact_transfer_usd",
    "paid_storage": "paid_storage_usd",
}
RESULT_EVIDENCE_PHASES = {
    "issue_snapshot": ("issue_snapshot", "result_issue_snapshot"),
    "policy": ("candidate_policy", "result_policy"),
    "base": ("base_verify", "result_base_executions"),
    "fixed": ("fixed_verify", "result_fixed_executions"),
    "causal_controls": ("causal_controls", "result_causal_controls"),
    "semantic_review": ("semantic_review", "result_semantic_review"),
}
CANDIDATE_RESULT_FIELDS = {
    "patch_sha256",
    "artifact_path",
    "changed_files",
    "nodeids",
    "added_lines",
    "deleted_lines",
    "selected_rank",
}
FORBIDDEN_ORACLE_KEYS = {
    "fix",
    "fix_patch",
    "fix_pr",
    "fix_pr_url",
    "fixed_sha",
    "gold_patch",
    "gold_test",
    "oracle",
    "oracle_rubric",
    "pr_url",
    "source_instance_id",
    "test_patch",
}
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ISSUE_RE = re.compile(
    r"^https://github\.com/"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)/"
    r"issues/(?P<number>[1-9][0-9]*)$"
)
SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$")
RFC3339_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
FIX_PULL_URL_RE = re.compile(
    r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[1-9][0-9]*$"
)


def load_json(path: Path, errors: list[str]) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        errors.append(f"missing file: {path}")
    except json.JSONDecodeError as exc:
        errors.append(f"invalid JSON in {path}: line {exc.lineno}, column {exc.colno}: {exc.msg}")
    return None


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def reject_oracle_material(value: Any, location: str, errors: list[str]) -> None:
    """Reject concrete fix/oracle fields and fixing-PR URLs anywhere in the manifest."""

    if isinstance(value, dict):
        for key, child in value.items():
            child_location = f"{location}.{key}"
            if key in FORBIDDEN_ORACLE_KEYS:
                errors.append(f"{child_location}: evaluator-only field is forbidden")
            reject_oracle_material(child, child_location, errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_oracle_material(child, f"{location}[{index}]", errors)
    elif isinstance(value, str) and FIX_PULL_URL_RE.fullmatch(value):
        errors.append(f"{location}: fixing pull request URL is evaluator-only")


def validate_schema_file(path: Path, title: str, errors: list[str]) -> dict[str, Any] | None:
    schema = load_json(path, errors)
    if not isinstance(schema, dict):
        return None
    require(
        schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
        f"{title}: must use JSON Schema draft 2020-12",
        errors,
    )
    require(schema.get("type") == "object", f"{title}: root type must be object", errors)
    require(schema.get("additionalProperties") is False, f"{title}: root must be strict", errors)
    require(isinstance(schema.get("required"), list), f"{title}: required must be an array", errors)
    return schema


def json_type_matches(instance: Any, expected: str) -> bool:
    """Match JSON Schema primitive types without treating bool as an integer."""

    if expected == "object":
        return isinstance(instance, dict)
    if expected == "array":
        return isinstance(instance, list)
    if expected == "string":
        return isinstance(instance, str)
    if expected == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected == "boolean":
        return isinstance(instance, bool)
    if expected == "null":
        return instance is None
    return False


def resolve_local_ref(ref: str, root_schema: dict[str, Any]) -> dict[str, Any] | None:
    if not ref.startswith("#/"):
        return None
    target: Any = root_schema
    for component in ref[2:].split("/"):
        component = component.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or component not in target:
            return None
        target = target[component]
    return target if isinstance(target, dict) else None


def validate_json_schema_instance(
    instance: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any],
    location: str,
    errors: list[str],
) -> None:
    """Validate the JSON Schema subset used by the checked-in benchmark schemas."""

    ref = schema.get("$ref")
    if isinstance(ref, str):
        target = resolve_local_ref(ref, root_schema)
        if target is None:
            errors.append(f"{location}: unresolved schema reference {ref!r}")
            return
        validate_json_schema_instance(instance, target, root_schema, location, errors)
        return

    alternatives = schema.get("oneOf")
    if isinstance(alternatives, list):
        successful = 0
        for alternative in alternatives:
            branch_errors: list[str] = []
            if isinstance(alternative, dict):
                validate_json_schema_instance(
                    instance,
                    alternative,
                    root_schema,
                    location,
                    branch_errors,
                )
            else:
                branch_errors.append("invalid schema branch")
            successful += not branch_errors
        if successful != 1:
            errors.append(
                f"{location}: must satisfy exactly one oneOf branch; matched {successful}"
            )
        return

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{location}: must equal {schema['const']!r}")
        return
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{location}: must be one of {schema['enum']!r}")
        return

    expected_types = schema.get("type")
    if isinstance(expected_types, str):
        expected_types = [expected_types]
    if isinstance(expected_types, list):
        matches = any(
            isinstance(expected, str) and json_type_matches(instance, expected)
            for expected in expected_types
        )
        if not matches:
            errors.append(f"{location}: expected type {expected_types!r}")
            return

    if isinstance(instance, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            missing = [key for key in required if key not in instance]
            if missing:
                errors.append(f"{location}: missing required key(s) {missing!r}")
        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}
        if schema.get("additionalProperties") is False:
            extra = sorted(set(instance) - set(properties))
            if extra:
                errors.append(f"{location}: unexpected key(s) {extra!r}")
        for key, value in instance.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                validate_json_schema_instance(
                    value,
                    child_schema,
                    root_schema,
                    f"{location}.{key}",
                    errors,
                )

    if isinstance(instance, list):
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if isinstance(min_items, int) and len(instance) < min_items:
            errors.append(f"{location}: must contain at least {min_items} item(s)")
        if isinstance(max_items, int) and len(instance) > max_items:
            errors.append(f"{location}: must contain at most {max_items} item(s)")
        if schema.get("uniqueItems") is True:
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in instance]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{location}: items must be unique")
        child_schema = schema.get("items")
        if isinstance(child_schema, dict):
            for index, value in enumerate(instance):
                validate_json_schema_instance(
                    value,
                    child_schema,
                    root_schema,
                    f"{location}[{index}]",
                    errors,
                )

    if isinstance(instance, str):
        min_length = schema.get("minLength")
        max_length = schema.get("maxLength")
        if isinstance(min_length, int) and len(instance) < min_length:
            errors.append(f"{location}: must contain at least {min_length} character(s)")
        if isinstance(max_length, int) and len(instance) > max_length:
            errors.append(f"{location}: must contain at most {max_length} character(s)")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, instance) is None:
            errors.append(f"{location}: does not match required pattern")
        format_name = schema.get("format")
        if format_name == "date-time":
            try:
                if RFC3339_RE.fullmatch(instance) is None:
                    raise ValueError
                datetime.fromisoformat(instance.replace("Z", "+00:00"))
            except ValueError:
                errors.append(f"{location}: must be an RFC 3339 date-time")
        elif format_name == "uri" and not re.match(r"^https?://[^\s]+$", instance):
            errors.append(f"{location}: must be an absolute HTTP(S) URI")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        exclusive_minimum = schema.get("exclusiveMinimum")
        if isinstance(minimum, (int, float)) and instance < minimum:
            errors.append(f"{location}: must be at least {minimum}")
        if isinstance(maximum, (int, float)) and instance > maximum:
            errors.append(f"{location}: must be at most {maximum}")
        if isinstance(exclusive_minimum, (int, float)) and instance <= exclusive_minimum:
            errors.append(f"{location}: must be greater than {exclusive_minimum}")


def validate_case(case: Any, index: int, errors: list[str]) -> None:
    label = f"case[{index}]"
    if not isinstance(case, dict):
        errors.append(f"{label}: must be an object")
        return

    keys = set(case)
    require(
        keys == EXPECTED_CASE_KEYS,
        f"{label}: keys must be exactly {sorted(EXPECTED_CASE_KEYS)}",
        errors,
    )
    leaked = keys & FORBIDDEN_ORACLE_KEYS
    require(not leaked, f"{label}: contains evaluator-only key(s): {sorted(leaked)}", errors)

    case_id = case.get("id")
    require(
        isinstance(case_id, str) and case_id in EXPECTED_IDS, f"{label}: invalid neutral id", errors
    )

    repo = case.get("repo")
    require(
        isinstance(repo, str) and REPO_RE.fullmatch(repo) is not None,
        f"{label}: invalid repo",
        errors,
    )

    issue_url = case.get("issue_url")
    issue_match = ISSUE_RE.fullmatch(issue_url) if isinstance(issue_url, str) else None
    require(
        issue_match is not None, f"{label}: issue_url must be a canonical GitHub issue URL", errors
    )
    if issue_match and isinstance(repo, str):
        url_repo = f"{issue_match.group('owner')}/{issue_match.group('repo')}"
        require(
            url_repo == repo,
            f"{label}: issue URL repository {url_repo!r} does not match {repo!r}",
            errors,
        )

    base_sha = case.get("base_sha")
    require(
        isinstance(base_sha, str) and SHA40_RE.fullmatch(base_sha) is not None,
        f"{label}: base_sha must be 40 lowercase hexadecimal characters",
        errors,
    )
    require(
        case.get("difficulty") in EXPECTED_DIFFICULTY_COUNTS, f"{label}: invalid difficulty", errors
    )
    title = case.get("title")
    require(
        isinstance(title, str) and 1 <= len(title) <= 300,
        f"{label}: title must contain 1-300 characters",
        errors,
    )
    require(type(case.get("smoke")) is bool, f"{label}: smoke must be boolean", errors)


def validate_manifest(manifest: Any, errors: list[str]) -> set[str]:
    if not isinstance(manifest, dict):
        errors.append("manifest root must be an object")
        return set()

    required_top_level = {
        "benchmark_version",
        "name",
        "frozen_at",
        "status",
        "case_schema",
        "run_schema",
        "source",
        "selection",
        "protocol",
        "claim_ladder",
        "outcome_taxonomy",
        "gates",
        "cost_semantics",
        "contamination",
        "cases",
    }
    require(
        required_top_level <= set(manifest), "manifest is missing required top-level fields", errors
    )
    reject_oracle_material(manifest, "manifest", errors)
    require(
        manifest.get("benchmark_version") == BENCHMARK_VERSION,
        "unexpected benchmark_version",
        errors,
    )
    require(
        manifest.get("status") == "preregistered_no_results",
        "v0.1 status must be preregistered_no_results",
        errors,
    )

    source = manifest.get("source")
    require(isinstance(source, dict), "source must be an object", errors)
    if isinstance(source, dict):
        require(source.get("name") == "TDD-Bench-Verified", "unexpected source name", errors)
        require(
            source.get("upstream_case_count") == 449,
            "upstream verified case count must be 449",
            errors,
        )

    cases = manifest.get("cases")
    if not isinstance(cases, list):
        errors.append("cases must be an array")
        return set()
    require(
        len(cases) == EXPECTED_CASE_COUNT, f"expected exactly {EXPECTED_CASE_COUNT} cases", errors
    )
    for index, case in enumerate(cases):
        validate_case(case, index, errors)

    ids = [
        case.get("id")
        for case in cases
        if isinstance(case, dict) and isinstance(case.get("id"), str)
    ]
    issue_urls = [
        case.get("issue_url")
        for case in cases
        if isinstance(case, dict) and isinstance(case.get("issue_url"), str)
    ]
    require(len(ids) == len(set(ids)), "case ids must be unique", errors)
    require(
        set(ids) == EXPECTED_IDS, "case ids must be the complete rk-v0.1-001..020 sequence", errors
    )
    require(len(issue_urls) == len(set(issue_urls)), "issue URLs must be unique", errors)

    repo_count = len(
        {
            case.get("repo")
            for case in cases
            if isinstance(case, dict) and isinstance(case.get("repo"), str)
        }
    )
    difficulty_counts = Counter(case.get("difficulty") for case in cases if isinstance(case, dict))
    smoke_ids = {
        case.get("id")
        for case in cases
        if isinstance(case, dict) and isinstance(case.get("id"), str) and case.get("smoke") is True
    }
    require(
        repo_count == EXPECTED_REPOSITORY_COUNT,
        f"expected {EXPECTED_REPOSITORY_COUNT} unique repositories",
        errors,
    )
    require(
        dict(difficulty_counts) == EXPECTED_DIFFICULTY_COUNTS,
        f"unexpected difficulty counts: {dict(difficulty_counts)}",
        errors,
    )
    require(
        smoke_ids == EXPECTED_SMOKE_IDS,
        f"smoke cases must be exactly {sorted(EXPECTED_SMOKE_IDS)}",
        errors,
    )

    selection = manifest.get("selection")
    require(isinstance(selection, dict), "selection must be an object", errors)
    if isinstance(selection, dict):
        require(
            selection.get("preinference_freeze") is True,
            "selection must be frozen before inference",
            errors,
        )
        require(
            selection.get("case_count") == len(cases),
            "selection.case_count does not match cases",
            errors,
        )
        require(
            selection.get("repository_count") == repo_count,
            "selection.repository_count does not match cases",
            errors,
        )
        require(
            selection.get("difficulty_counts") == EXPECTED_DIFFICULTY_COUNTS,
            "selection difficulty counts do not match cases",
            errors,
        )
        selected_smoke_ids = selection.get("smoke_case_ids")
        require(
            isinstance(selected_smoke_ids, list)
            and all(isinstance(item, str) for item in selected_smoke_ids)
            and set(selected_smoke_ids) == smoke_ids,
            "selection smoke IDs do not match case flags",
            errors,
        )

    protocol = manifest.get("protocol")
    require(isinstance(protocol, dict), "protocol must be an object", errors)
    if isinstance(protocol, dict):
        require(
            protocol.get("primary_metric") == "semantic_valid_success_at_1",
            "unexpected primary metric",
            errors,
        )
        require(
            protocol.get("submitted_candidates_per_case") == 1,
            "exactly one submitted candidate is required",
            errors,
        )
        require(
            protocol.get("candidate_selection_uses_oracle") is False,
            "candidate selection must not use an oracle",
            errors,
        )
        require(
            protocol.get("network_after_dependency_prep") == "disabled",
            "post-prep network must be disabled",
            errors,
        )
        require(
            protocol.get("clean_environment_per_execution") is True,
            "each execution must use a clean environment",
            errors,
        )
        require(
            protocol.get("execution_schedule") == EXPECTED_SCHEDULE,
            "unexpected execution schedule",
            errors,
        )
        require(protocol.get("base_repetitions") == 3, "expected three base repetitions", errors)
        require(protocol.get("fixed_repetitions") == 3, "expected three fixed repetitions", errors)
        visible = set(protocol.get("generator_visible_case_fields", []))
        require(
            not (visible & FORBIDDEN_ORACLE_KEYS),
            "generator-visible fields expose evaluator-only data",
            errors,
        )

    ladder = manifest.get("claim_ladder")
    levels = (
        [item.get("level") for item in ladder if isinstance(item, dict)]
        if isinstance(ladder, list)
        else []
    )
    require(
        levels == EXPECTED_CLAIM_LEVELS, f"claim ladder must be {EXPECTED_CLAIM_LEVELS}", errors
    )

    taxonomy = manifest.get("outcome_taxonomy")
    outcome_ids = (
        [item.get("id") for item in taxonomy if isinstance(item, dict)]
        if isinstance(taxonomy, list)
        else []
    )
    require(
        outcome_ids == EXPECTED_OUTCOMES, "outcome taxonomy does not match the frozen order", errors
    )

    gates = manifest.get("gates")
    require(isinstance(gates, dict), "gates must be an object", errors)
    if isinstance(gates, dict):
        require(gates.get("semantic_valid_minimum") == 6, "semantic-valid gate must be 6", errors)
        require(
            gates.get("semantic_valid_denominator") == 20,
            "semantic-valid denominator must be 20",
            errors,
        )
        require(
            gates.get("median_warm_runtime_seconds_max") == 600,
            "warm runtime gate must be 600 seconds",
            errors,
        )
        require(
            gates.get("target_attributable_cost_per_semantic_valid_usd_max") == 1.0,
            "cost gate must be 1 USD",
            errors,
        )
        require(
            gates.get("maintainer_validated_test_minimum") == 1,
            "maintainer validation gate must be 1",
            errors,
        )
        require(
            gates.get("maintainers_willing_to_reuse_minimum") == 3, "reuse gate must be 3", errors
        )
        require(
            gates.get("external_validation_is_separate") is True,
            "external validation must remain a separate gate",
            errors,
        )

    contamination = manifest.get("contamination")
    require(isinstance(contamination, dict), "contamination must be an object", errors)
    if isinstance(contamination, dict):
        require(
            contamination.get("classification") == "historical_public_contamination_exposed",
            "contamination class must remain explicit",
            errors,
        )

    return {case_id for case_id in ids if isinstance(case_id, str)}


def validate_results(
    path: Path,
    known_case_ids: set[str],
    run_schema: dict[str, Any] | None,
    errors: list[str],
) -> int:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        errors.append(f"missing file: {path}")
        return 0

    rows = 0
    seen_pairs: set[tuple[str, str]] = set()
    seen_case_ids: set[str] = set()
    canonical_run_id: str | None = None
    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue
        rows += 1
        label = f"{path}:line {line_number}"
        try:
            row = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            errors.append(f"{label}: invalid JSON: {exc.msg}")
            continue
        if not isinstance(row, dict):
            errors.append(f"{label}: result must be an object")
            continue
        if run_schema is not None:
            validate_json_schema_instance(row, run_schema, run_schema, label, errors)

        required = {
            "schema_version",
            "benchmark_version",
            "run_id",
            "case_id",
            "claim_level",
            "outcome",
        }
        require(required <= set(row), f"{label}: missing required identity/verdict fields", errors)
        require(
            row.get("schema_version") == BENCHMARK_VERSION,
            f"{label}: unexpected schema_version",
            errors,
        )
        require(
            row.get("benchmark_version") == BENCHMARK_VERSION,
            f"{label}: unexpected benchmark_version",
            errors,
        )
        run_id = row.get("run_id")
        case_id = row.get("case_id")
        require(
            isinstance(run_id, str) and RUN_ID_RE.fullmatch(run_id) is not None,
            f"{label}: invalid run_id",
            errors,
        )
        require(
            isinstance(case_id, str) and case_id in known_case_ids,
            f"{label}: unknown case_id",
            errors,
        )
        claim_level = row.get("claim_level")
        require(
            isinstance(claim_level, str) and claim_level in {"rejected", *EXPECTED_CLAIM_LEVELS},
            f"{label}: invalid claim_level",
            errors,
        )
        require(row.get("outcome") in EXPECTED_OUTCOMES, f"{label}: invalid outcome", errors)

        validate_result_invariants(row, label, errors)

        if isinstance(run_id, str) and isinstance(case_id, str):
            pair = (run_id, case_id)
            require(pair not in seen_pairs, f"{label}: duplicate run_id/case_id pair", errors)
            seen_pairs.add(pair)
            require(
                case_id not in seen_case_ids,
                f"{label}: case_id already has a result; best-of-rerun selection is forbidden",
                errors,
            )
            seen_case_ids.add(case_id)
            if canonical_run_id is None:
                canonical_run_id = run_id
            else:
                require(
                    run_id == canonical_run_id,
                    f"{label}: every v0.1 result must use canonical run_id {canonical_run_id!r}",
                    errors,
                )

    return rows


def validate_event_ledger(
    path: Path,
    *,
    lane: str,
    known_case_ids: set[str],
    smoke_case_ids: set[str],
    event_schema: dict[str, Any] | None,
    errors: list[str],
) -> dict[str, Any]:
    """Validate event shape, hash chain, spend state, and scientific lifecycle rules."""

    try:
        snapshot = read_ledger(path, expected_lane=lane)
    except (OSError, ReproAssertError) as exc:
        errors.append(f"{path}: cannot read ledger safely: {exc}")
        return {"events": [], "attempts": {}, "cases": {}}
    errors.extend(f"{path}: {error}" for error in snapshot.errors)

    attempts: dict[str, dict[str, Any]] = {}
    cases: dict[str, dict[str, Any]] = {}
    call_owner: dict[str, str] = {}
    cost_entry_ids: set[str] = set()
    freeze_sha256: str | None = None
    scored_batch_id: str | None = None

    for index, event in enumerate(snapshot.events, start=1):
        label = f"{path}:line {index}"
        if event_schema is not None:
            validate_json_schema_instance(event, event_schema, event_schema, label, errors)
        event_type = event.get("event_type")
        payload = event.get("payload")
        payload_def = EVENT_PAYLOAD_DEFS.get(event_type) if isinstance(event_type, str) else None
        definitions = event_schema.get("$defs") if isinstance(event_schema, dict) else None
        if payload_def and isinstance(definitions, dict):
            payload_schema = definitions.get(payload_def)
            if isinstance(payload_schema, dict):
                payload_errors: list[str] = []
                validate_json_schema_instance(
                    payload,
                    payload_schema,
                    event_schema,
                    f"{label}.payload",
                    payload_errors,
                )
                require(
                    not payload_errors,
                    f"{label}: payload does not match event_type {event_type!r}",
                    errors,
                )
        elif event_type not in EVENT_PAYLOAD_DEFS:
            errors.append(f"{label}: unknown event_type")

        case_id = event.get("case_id")
        attempt_id = event.get("attempt_id")
        batch_id = event.get("batch_id")
        if not isinstance(case_id, str) or case_id not in known_case_ids:
            errors.append(f"{label}: unknown case_id")
            continue
        if lane == "smoke" and case_id not in smoke_case_ids:
            errors.append(f"{label}: non-smoke case is forbidden in smoke ledger")
        if not isinstance(attempt_id, str) or not isinstance(payload, dict):
            continue

        case = cases.setdefault(
            case_id,
            {
                "attempt_ids": [],
                "model_call_ids": [],
                "candidate": None,
                "counted_finish": None,
                "known_scored_cost_microusd": 0,
                "known_scored_cost_by_category": {
                    category: 0 for category in REQUIRED_ATTRIBUTABLE_COST_CATEGORIES
                },
                "unknown_cost": False,
                "estimated_cost": False,
                "input_tokens": 0,
                "output_tokens": 0,
                "unknown_usage": False,
            },
        )
        attempt = attempts.get(attempt_id)
        if event_type == "attempt_started":
            if attempt is not None:
                errors.append(f"{label}: attempt_started is duplicated")
                continue
            require(
                case["counted_finish"] is None,
                f"{label}: case already has a counted terminal outcome",
                errors,
            )
            prior_primary_count = sum(
                attempts[prior_id]["start"]["payload"].get("disposition") == "primary_score"
                for prior_id in case["attempt_ids"]
            )
            if payload.get("disposition") == "primary_score":
                require(
                    prior_primary_count == 0,
                    f"{label}: case already has its one primary scored attempt",
                    errors,
                )
            require(
                all(attempts[prior_id]["finished"] is not None for prior_id in case["attempt_ids"]),
                f"{label}: a case cannot start another attempt while one is open",
                errors,
            )
            attempt = {
                "case_id": case_id,
                "batch_id": batch_id,
                "start": event,
                "finished": None,
                "phase_starts": {},
                "phase_finishes": {},
                "call_starts": {},
                "call_finishes": {},
                "call_cost_ids": {},
                "scored_cost_categories": set(),
                "estimated_cost": False,
                "unknown_cost": False,
                "candidate": None,
                "reviews": [],
                "gold": None,
            }
            attempts[attempt_id] = attempt
            case["attempt_ids"].append(attempt_id)
            _validate_attempt_start(
                event,
                attempt=attempt,
                case=case,
                attempts=attempts,
                lane=lane,
                label=label,
                errors=errors,
            )
            if lane == "scored":
                if scored_batch_id is None:
                    scored_batch_id = batch_id if isinstance(batch_id, str) else ""
                else:
                    require(
                        batch_id == scored_batch_id,
                        f"{label}: scored ledger must use one canonical batch_id",
                        errors,
                    )
                payload_for_freeze = dict(payload)
                payload_for_freeze.pop("case_entry_sha256", None)
                payload_for_freeze.pop("attempt_ordinal", None)
                payload_for_freeze.pop("retry_of", None)
                payload_for_freeze.pop("disposition", None)
                digest = hashlib.sha256(canonical_json_bytes(payload_for_freeze)).hexdigest()
                if freeze_sha256 is None:
                    freeze_sha256 = digest
                else:
                    require(
                        digest == freeze_sha256,
                        f"{label}: scored tool/model/prompt/config/budget freeze drifted",
                        errors,
                    )
            continue

        if attempt is None:
            errors.append(f"{label}: first event for an attempt must be attempt_started")
            continue
        require(
            attempt["case_id"] == case_id and attempt["batch_id"] == batch_id,
            f"{label}: attempt identity changed after start",
            errors,
        )
        if attempt["finished"] is not None:
            errors.append(f"{label}: event appears after attempt_finished")
            continue
        if attempt["gold"] is not None and event_type != "attempt_finished":
            errors.append(f"{label}: only attempt_finished may follow gold_unblinded")
            continue

        if event_type == "phase_started":
            key = (payload.get("phase"), payload.get("phase_ordinal"))
            require(
                key not in attempt["phase_starts"],
                f"{label}: phase_started is duplicated",
                errors,
            )
            attempt["phase_starts"][key] = event
        elif event_type == "phase_finished":
            key = (payload.get("phase"), payload.get("phase_ordinal"))
            start_event = attempt["phase_starts"].get(key)
            require(start_event is not None, f"{label}: phase_finished has no start", errors)
            if isinstance(start_event, dict):
                require(
                    start_event["payload"].get("started_at") == payload.get("started_at"),
                    f"{label}: phase_finished changed the durable phase start timestamp",
                    errors,
                )
            require(
                key not in attempt["phase_finishes"],
                f"{label}: phase_finished is duplicated",
                errors,
            )
            attempt["phase_finishes"][key] = event
            _validate_interval(payload, label, errors)
            _validate_public_phase_log(payload.get("log"), label, errors)
        elif event_type == "model_call_started":
            call_id = payload.get("call_id")
            if not isinstance(call_id, str):
                continue
            for prior_attempt in attempts.values():
                for prior_call_id in prior_attempt["call_starts"]:
                    prior_cost = prior_attempt["call_cost_ids"].get(prior_call_id)
                    require(
                        prior_call_id in prior_attempt["call_finishes"]
                        and isinstance(prior_cost, dict)
                        and prior_cost.get("status") in {"measured", "zero_verified"},
                        f"{label}: a prior model call has unresolved usage or cost",
                        errors,
                    )
            require(call_id not in call_owner, f"{label}: call_id is duplicated", errors)
            call_owner[call_id] = attempt_id
            attempt["call_starts"][call_id] = event
            case["model_call_ids"].append(call_id)
            require(
                len(case["model_call_ids"]) <= 1,
                f"{label}: v0.1 permits at most one model call per case",
                errors,
            )
            _validate_call_reservation(event, attempt, label, errors)
        elif event_type == "model_call_finished":
            call_id = payload.get("call_id")
            if not isinstance(call_id, str):
                continue
            require(
                call_owner.get(call_id) == attempt_id,
                f"{label}: model_call_finished has no matching start in this attempt",
                errors,
            )
            require(
                call_id not in attempt["call_finishes"],
                f"{label}: model_call_finished is duplicated",
                errors,
            )
            attempt["call_finishes"][call_id] = event
            _validate_interval(payload, label, errors)
            _accumulate_usage(payload.get("usage"), case, label, errors)
        elif event_type == "cost_recorded":
            entry_id = payload.get("entry_id")
            if isinstance(entry_id, str):
                require(
                    entry_id not in cost_entry_ids, f"{label}: cost entry_id is duplicated", errors
                )
                cost_entry_ids.add(entry_id)
            _validate_and_accumulate_cost(
                payload,
                attempt_id=attempt_id,
                call_owner=call_owner,
                attempt=attempt,
                case=case,
                label=label,
                errors=errors,
            )
        elif event_type == "candidate_submitted":
            require(attempt["candidate"] is None, f"{label}: attempt has two candidates", errors)
            require(
                case["candidate"] is None, f"{label}: case has two submitted candidates", errors
            )
            _validate_candidate_event(payload, attempt, label, errors)
            attempt["candidate"] = event
            case["candidate"] = event
        elif event_type == "semantic_review_recorded":
            _validate_review_event(payload, attempt, label, errors)
            attempt["reviews"].append(event)
        elif event_type == "gold_unblinded":
            require(attempt["gold"] is None, f"{label}: gold_unblinded is duplicated", errors)
            _validate_gold_event(payload, attempt, label, errors)
            attempt["gold"] = event
        elif event_type == "attempt_finished":
            _validate_attempt_finish(event, attempt, case, lane, label, errors)
            attempt["finished"] = event

    for attempt in attempts.values():
        for call_id in attempt["call_starts"]:
            if call_id not in attempt["call_finishes"]:
                cases[attempt["case_id"]]["unknown_usage"] = True
                cases[attempt["case_id"]]["unknown_cost"] = True
            if call_id not in attempt["call_cost_ids"]:
                cases[attempt["case_id"]]["unknown_cost"] = True
        _validate_model_generation_intervals(attempt, errors)

    campaign_cap: int | None = None
    for attempt in attempts.values():
        campaign = attempt["start"]["payload"].get("campaign")
        if isinstance(campaign, dict):
            cap = campaign.get("max_campaign_attributable_microusd")
            if isinstance(cap, int):
                campaign_cap = cap
                break
    known_campaign_cost = sum(case["known_scored_cost_microusd"] for case in cases.values())
    if campaign_cap is not None:
        require(
            known_campaign_cost <= campaign_cap,
            f"{path}: known scored cost exceeds the frozen campaign cap",
            errors,
        )
    for case_id, case in cases.items():
        case_attempts = [attempts[attempt_id] for attempt_id in case["attempt_ids"]]
        if not case_attempts:
            continue
        campaign = case_attempts[0]["start"]["payload"].get("campaign")
        wall_cap = campaign.get("max_case_wall_ms") if isinstance(campaign, dict) else None
        observed_ms = sum(
            event["payload"].get("duration_ms", 0)
            for attempt in case_attempts
            for event in attempt["phase_finishes"].values()
            if isinstance(event["payload"].get("duration_ms"), int)
        )
        observed_ms += sum(
            _model_duration_outside_generation_ms(attempt) for attempt in case_attempts
        )
        if isinstance(wall_cap, int):
            require(
                observed_ms <= wall_cap,
                f"{path}: case {case_id} exceeds the frozen wall-time cap",
                errors,
            )

    return {
        "events": list(snapshot.events),
        "attempts": attempts,
        "cases": cases,
        "sha256": snapshot.sha256,
        "head_event_sha256": snapshot.head_event_sha256,
        "batch_id": scored_batch_id,
        "freeze_sha256": freeze_sha256,
    }


def _validate_attempt_start(
    event: dict[str, Any],
    *,
    attempt: dict[str, Any],
    case: dict[str, Any],
    attempts: dict[str, dict[str, Any]],
    lane: str,
    label: str,
    errors: list[str],
) -> None:
    payload = event["payload"]
    disposition = payload.get("disposition")
    campaign = payload.get("campaign")
    expected_tier = "public_smoke" if lane == "smoke" else "historical_scored"
    if lane == "smoke":
        require(disposition == "smoke_only", f"{label}: smoke attempts must be smoke_only", errors)
    else:
        require(
            disposition in {"primary_score", "infrastructure_retry"},
            f"{label}: scored ledger forbids diagnostic attempts",
            errors,
        )
    if isinstance(campaign, dict):
        require(
            campaign.get("cohort_tier") == expected_tier,
            f"{label}: campaign cohort_tier does not match ledger lane",
            errors,
        )
        authorization = campaign.get("spend_authorization")
        if isinstance(authorization, dict):
            status = authorization.get("status")
            reference = authorization.get("authorization_ref")
            if status == "offline_zero_cost":
                require(
                    reference is None, f"{label}: zero-cost mode cannot cite spend approval", errors
                )
                require(
                    campaign.get("max_case_attributable_microusd") == 0
                    and campaign.get("max_campaign_attributable_microusd") == 0,
                    f"{label}: offline_zero_cost requires zero case and campaign caps",
                    errors,
                )
            elif status == "explicit_user_approval":
                require(
                    isinstance(reference, str) and len(reference) >= 3,
                    f"{label}: paid mode requires an explicit authorization reference",
                    errors,
                )
    ordinal = payload.get("attempt_ordinal")
    require(
        ordinal == len(case["attempt_ids"]),
        f"{label}: attempt_ordinal must be contiguous within the case",
        errors,
    )
    retry_of = payload.get("retry_of")
    if disposition == "infrastructure_retry":
        prior = attempts.get(retry_of) if isinstance(retry_of, str) else None
        require(
            prior is not None, f"{label}: infrastructure retry must link a prior attempt", errors
        )
        if prior is not None:
            previous_attempt_id = case["attempt_ids"][-2] if len(case["attempt_ids"]) >= 2 else None
            require(
                retry_of == previous_attempt_id,
                f"{label}: infrastructure retries must form one linear chain",
                errors,
            )
            prior_finish = prior.get("finished")
            prior_payload = prior_finish.get("payload") if isinstance(prior_finish, dict) else None
            require(
                prior.get("case_id") == event.get("case_id")
                and isinstance(prior_payload, dict)
                and prior_payload.get("outcome") == "benchmark_infrastructure_error",
                f"{label}: only a same-case infrastructure error may be retried",
                errors,
            )
            require(
                set(prior["phase_starts"]) == set(prior["phase_finishes"]),
                f"{label}: infrastructure retry cannot follow unknown phase time",
                errors,
            )
            if prior.get("candidate") is not None:
                require(
                    case.get("candidate") is prior.get("candidate"),
                    f"{label}: infrastructure retry must reuse the existing candidate",
                    errors,
                )
    else:
        require(retry_of is None, f"{label}: primary/smoke attempt cannot set retry_of", errors)
    if isinstance(campaign, dict):
        max_retries = campaign.get("max_infrastructure_retries_per_case")
        retry_count = sum(
            attempts[case_attempt_id]["start"]["payload"].get("disposition")
            == "infrastructure_retry"
            for case_attempt_id in case["attempt_ids"]
        )
        if isinstance(max_retries, int):
            require(
                retry_count <= max_retries,
                f"{label}: infrastructure retry count exceeds the frozen cap",
                errors,
            )


def _validate_call_reservation(
    event: dict[str, Any], attempt: dict[str, Any], label: str, errors: list[str]
) -> None:
    payload = event["payload"]
    start_payload = attempt["start"]["payload"]
    campaign = start_payload.get("campaign")
    generator = start_payload.get("generator")
    if not isinstance(campaign, dict):
        return
    if isinstance(generator, dict):
        require(
            payload.get("provider") == generator.get("provider")
            and payload.get("requested_model") == generator.get("requested_model")
            and payload.get("model_identity") == generator.get("model_identity")
            and payload.get("config_sha256") == generator.get("config_sha256")
            and payload.get("pricing_snapshot_sha256")
            == start_payload.get("pricing_snapshot_sha256"),
            f"{label}: model call drifted from the durable generator/pricing freeze",
            errors,
        )
    reserved = payload.get("reserved_worst_case_microusd")
    case_cap = campaign.get("max_case_attributable_microusd")
    campaign_cap = campaign.get("max_campaign_attributable_microusd")
    if isinstance(reserved, int) and isinstance(case_cap, int):
        require(reserved <= case_cap, f"{label}: call reservation exceeds case spend cap", errors)
    if isinstance(reserved, int) and isinstance(campaign_cap, int):
        require(
            reserved <= campaign_cap,
            f"{label}: call reservation exceeds campaign spend cap",
            errors,
        )
    authorization = campaign.get("spend_authorization")
    if campaign.get("cohort_tier") == "public_smoke":
        require(
            payload.get("provider") == "offline-fixture",
            f"{label}: public smoke permits only deterministic offline fixtures",
            errors,
        )
    if isinstance(authorization, dict) and authorization.get("status") == "offline_zero_cost":
        require(reserved == 0, f"{label}: paid provider request is not authorized", errors)
        require(
            payload.get("provider") in {"offline-fixture", "local-model"},
            f"{label}: zero-cost mode permits only declared offline providers",
            errors,
        )


def _validate_interval(payload: dict[str, Any], label: str, errors: list[str]) -> None:
    started = _parse_datetime(payload.get("started_at"))
    completed = _parse_datetime(payload.get("completed_at"))
    duration_ms = payload.get("duration_ms")
    if started is None or completed is None:
        return
    require(completed >= started, f"{label}: completed_at precedes started_at", errors)
    if isinstance(duration_ms, int):
        elapsed_ms = (completed - started).total_seconds() * 1000
        require(
            abs(elapsed_ms - duration_ms) <= 1000,
            f"{label}: duration_ms disagrees with timestamps by more than one second",
            errors,
        )


def _generation_intervals(
    attempt: dict[str, Any],
) -> list[tuple[dict[str, Any], dict[str, Any], datetime, datetime, int]]:
    intervals: list[tuple[dict[str, Any], dict[str, Any], datetime, datetime, int]] = []
    for key, finish_event in attempt["phase_finishes"].items():
        if key[0] != "generation":
            continue
        start_event = attempt["phase_starts"].get(key)
        if not isinstance(start_event, dict) or not isinstance(finish_event, dict):
            continue
        finish_payload = finish_event.get("payload")
        if not isinstance(finish_payload, dict):
            continue
        started = _parse_datetime(finish_payload.get("started_at"))
        completed = _parse_datetime(finish_payload.get("completed_at"))
        duration_ms = finish_payload.get("duration_ms")
        if (
            started is not None
            and completed is not None
            and isinstance(duration_ms, int)
            and not isinstance(duration_ms, bool)
        ):
            intervals.append((start_event, finish_event, started, completed, duration_ms))
    return intervals


def _enclosing_generation_intervals(
    attempt: dict[str, Any],
    call_id: str,
) -> list[tuple[dict[str, Any], dict[str, Any], datetime, datetime, int]]:
    start_event = attempt["call_starts"].get(call_id)
    finish_event = attempt["call_finishes"].get(call_id)
    if not isinstance(start_event, dict) or not isinstance(finish_event, dict):
        return []
    start_payload = start_event.get("payload")
    finish_payload = finish_event.get("payload")
    if not isinstance(start_payload, dict) or not isinstance(finish_payload, dict):
        return []
    started = _parse_datetime(start_payload.get("started_at"))
    finished_started = _parse_datetime(finish_payload.get("started_at"))
    completed = _parse_datetime(finish_payload.get("completed_at"))
    duration_ms = finish_payload.get("duration_ms")
    if (
        started is None
        or finished_started != started
        or completed is None
        or isinstance(duration_ms, bool)
        or not isinstance(duration_ms, int)
    ):
        return []
    return [
        interval
        for interval in _generation_intervals(attempt)
        if interval[2] <= started
        and completed <= interval[3]
        and duration_ms <= interval[4]
        and _sequence_before(interval[0], start_event)
        and _sequence_before(finish_event, interval[1])
    ]


def _sequence_before(first: dict[str, Any], second: dict[str, Any]) -> bool:
    first_sequence = first.get("sequence")
    second_sequence = second.get("sequence")
    return (
        isinstance(first_sequence, int)
        and not isinstance(first_sequence, bool)
        and isinstance(second_sequence, int)
        and not isinstance(second_sequence, bool)
        and first_sequence < second_sequence
    )


def _validate_model_generation_intervals(attempt: dict[str, Any], errors: list[str]) -> None:
    attempt_id = attempt["start"].get("attempt_id", "unknown")
    for call_id, finish_event in attempt["call_finishes"].items():
        start_event = attempt["call_starts"].get(call_id)
        start_payload = start_event.get("payload") if isinstance(start_event, dict) else None
        finish_payload = finish_event.get("payload") if isinstance(finish_event, dict) else None
        if isinstance(start_payload, dict) and isinstance(finish_payload, dict):
            require(
                finish_payload.get("started_at") == start_payload.get("started_at"),
                f"attempt {attempt_id}: model call {call_id} changed its durable start timestamp",
                errors,
            )
        enclosing = _enclosing_generation_intervals(attempt, call_id)
        if _generation_intervals(attempt) or attempt.get("finished") is not None:
            require(
                len(enclosing) == 1,
                f"attempt {attempt_id}: model call {call_id} must be enclosed by exactly one "
                "generation phase and cannot exceed its duration",
                errors,
            )


def _model_duration_outside_generation_ms(attempt: dict[str, Any]) -> int:
    total = 0
    for call_id, finish_event in attempt["call_finishes"].items():
        if len(_enclosing_generation_intervals(attempt, call_id)) == 1:
            continue
        payload = finish_event.get("payload") if isinstance(finish_event, dict) else None
        duration_ms = payload.get("duration_ms") if isinstance(payload, dict) else None
        if isinstance(duration_ms, int) and not isinstance(duration_ms, bool) and duration_ms >= 0:
            total += duration_ms
    return total


def _validate_public_phase_log(log: Any, label: str, errors: list[str]) -> None:
    if log is None or not isinstance(log, dict):
        return
    excerpt = log.get("excerpt")
    if not isinstance(excerpt, str):
        return
    encoded = excerpt.encode("utf-8")
    require(
        log.get("excerpt_bytes") == len(encoded),
        f"{label}: log excerpt_bytes does not match UTF-8 bytes",
        errors,
    )
    require(
        log.get("excerpt_sha256") == hashlib.sha256(encoded).hexdigest(),
        f"{label}: log excerpt_sha256 does not match excerpt",
        errors,
    )
    captured = log.get("captured_bytes")
    require(
        isinstance(captured, int) and captured >= 0,
        f"{label}: log captured_bytes must be non-negative",
        errors,
    )
    sanitized = sanitize_public_excerpt(excerpt)
    require(
        sanitized.get("excerpt") == excerpt,
        f"{label}: public log excerpt still contains secrets, host paths, or controls",
        errors,
    )


def _accumulate_usage(usage: Any, case: dict[str, Any], label: str, errors: list[str]) -> None:
    if not isinstance(usage, dict):
        return
    status = usage.get("status")
    values = [
        usage.get("input_tokens"),
        usage.get("cached_input_tokens"),
        usage.get("output_tokens"),
        usage.get("total_tokens"),
    ]
    if status in {"reported", "estimated"}:
        require(
            all(isinstance(value, int) for value in values),
            f"{label}: known usage needs counts",
            errors,
        )
        input_tokens, cached, output_tokens, total_tokens = values
        if all(isinstance(value, int) for value in values):
            require(cached <= input_tokens, f"{label}: cached tokens exceed input tokens", errors)
            require(
                total_tokens == input_tokens + output_tokens,
                f"{label}: total tokens must equal input + output",
                errors,
            )
            case["input_tokens"] += input_tokens
            case["output_tokens"] += output_tokens
    elif status == "not_applicable":
        require(values == [0, 0, 0, 0], f"{label}: not_applicable usage must be zero", errors)
    elif status == "unknown":
        require(
            values == [None, None, None, None],
            f"{label}: unknown usage must use null counts",
            errors,
        )
        case["unknown_usage"] = True


def _validate_and_accumulate_cost(
    payload: dict[str, Any],
    *,
    attempt_id: str,
    call_owner: dict[str, str],
    attempt: dict[str, Any],
    case: dict[str, Any],
    label: str,
    errors: list[str],
) -> None:
    status = payload.get("status")
    amount = payload.get("amount_microusd")
    unit_price = payload.get("unit_price_microusd")
    source_call_id = payload.get("source_call_id")
    category = payload.get("category")
    attribution = payload.get("attribution")
    quantity_decimal: Decimal | None = None
    if status in {"measured", "estimated"}:
        require(isinstance(amount, int), f"{label}: known cost requires amount_microusd", errors)
    elif status == "zero_verified":
        require(amount == 0, f"{label}: zero_verified cost requires amount 0", errors)
    elif status == "unknown":
        require(amount is None, f"{label}: unknown cost must not contain an amount", errors)
        case["unknown_cost"] = True
    quantity = payload.get("quantity")
    if isinstance(quantity, str) and isinstance(unit_price, int) and isinstance(amount, int):
        try:
            quantity_decimal = Decimal(quantity)
            calculated = (quantity_decimal * Decimal(unit_price)).quantize(
                Decimal("1"), rounding=ROUND_HALF_UP
            )
        except InvalidOperation:
            errors.append(f"{label}: cost quantity cannot be calculated")
        else:
            require(
                int(calculated) == amount,
                f"{label}: cost amount does not equal quantity times unit price",
                errors,
            )
    elif status in {"measured", "estimated"}:
        require(
            quantity is None and unit_price is None,
            f"{label}: known cost needs both quantity and unit price, or neither",
            errors,
        )
    if category == "model_inference":
        require(
            attribution == "scored",
            f"{label}: model inference cost must be attributable to the scored campaign",
            errors,
        )
        require(
            isinstance(source_call_id, str) and call_owner.get(source_call_id) == attempt_id,
            f"{label}: model cost must reference a call in the same attempt",
            errors,
        )
        if isinstance(source_call_id, str):
            require(
                source_call_id in attempt["call_finishes"],
                f"{label}: model cost cannot precede model_call_finished",
                errors,
            )
            require(
                source_call_id not in attempt["call_cost_ids"],
                f"{label}: model call has two monetary records",
                errors,
            )
            attempt["call_cost_ids"][source_call_id] = payload
            call_start = attempt["call_starts"].get(source_call_id)
            if isinstance(call_start, dict):
                reserved = call_start["payload"].get("reserved_worst_case_microusd")
                if isinstance(reserved, int) and isinstance(amount, int):
                    require(
                        amount <= reserved,
                        f"{label}: model cost exceeds its worst-case reservation",
                        errors,
                    )
            call_finish = attempt["call_finishes"].get(source_call_id)
            if (
                isinstance(call_finish, dict)
                and payload.get("unit") == "million_tokens"
                and quantity_decimal is not None
            ):
                usage = call_finish["payload"].get("usage")
                total_tokens = usage.get("total_tokens") if isinstance(usage, dict) else None
                if isinstance(total_tokens, int):
                    require(
                        quantity_decimal == Decimal(total_tokens) / Decimal(1_000_000),
                        f"{label}: token cost quantity does not match provider usage",
                        errors,
                    )
        else:
            require(
                status == "zero_verified" and amount == 0 and not attempt["call_starts"],
                f"{label}: model cost without a call must be verified zero before transmission",
                errors,
            )
    else:
        require(
            source_call_id is None, f"{label}: non-model cost cannot reference a model call", errors
        )
    if status == "estimated":
        case["estimated_cost"] = True
        attempt["estimated_cost"] = True
    elif status == "unknown":
        attempt["unknown_cost"] = True
    if attribution == "scored" and isinstance(category, str):
        attempt["scored_cost_categories"].add(category)
    if attribution == "scored" and isinstance(amount, int):
        case["known_scored_cost_microusd"] += amount
        if category in REQUIRED_ATTRIBUTABLE_COST_CATEGORIES:
            case["known_scored_cost_by_category"][category] += amount
        campaign = attempt["start"]["payload"].get("campaign")
        if isinstance(campaign, dict):
            case_cap = campaign.get("max_case_attributable_microusd")
            if isinstance(case_cap, int):
                require(
                    case["known_scored_cost_microusd"] <= case_cap,
                    f"{label}: known scored cost exceeds the frozen case cap",
                    errors,
                )
    if isinstance(unit_price, int) and isinstance(payload.get("quantity"), str):
        # Decimal quantity stays auditable in source; totals use integer micro-USD.
        require(unit_price >= 0, f"{label}: unit price must be non-negative", errors)


def _validate_candidate_event(
    payload: dict[str, Any], attempt: dict[str, Any], label: str, errors: list[str]
) -> None:
    require(
        payload.get("oracle_consulted") is False,
        f"{label}: oracle-assisted selection forbidden",
        errors,
    )
    call_ids = payload.get("generation_call_ids")
    if isinstance(call_ids, list):
        require(
            all(
                call_id in attempt["call_finishes"]
                and attempt["call_finishes"][call_id]["payload"].get("status") == "succeeded"
                for call_id in call_ids
            ),
            f"{label}: candidate references an unfinished or foreign model call",
            errors,
        )
        campaign = attempt["start"]["payload"].get("campaign")
        if isinstance(campaign, dict) and campaign.get("cohort_tier") == "historical_scored":
            generator = attempt["start"]["payload"].get("generator")
            provider = generator.get("provider") if isinstance(generator, dict) else None
            if provider != "offline-fixture":
                require(
                    len(call_ids) == 1,
                    f"{label}: scored candidate must reference the case's one model call",
                    errors,
                )


def _validate_review_event(
    payload: dict[str, Any], attempt: dict[str, Any], label: str, errors: list[str]
) -> None:
    require(
        attempt["candidate"] is not None, f"{label}: review requires a submitted candidate", errors
    )
    require(attempt["gold"] is None, f"{label}: review cannot occur after gold unblinding", errors)
    required_phases = {
        "candidate_policy",
        "collection",
        "base_verify",
        "fixed_verify",
        "causal_controls",
    }
    require(
        all(_phase_succeeded(attempt, phase) for phase in required_phases),
        f"{label}: blinded review requires completed policy/base/fixed/control evidence",
        errors,
    )
    reviewer_ids = {
        review["payload"].get("reviewer_id")
        for review in attempt["reviews"]
        if isinstance(review.get("payload"), dict)
    }
    require(
        payload.get("reviewer_id") not in reviewer_ids,
        f"{label}: semantic reviewer_id is duplicated",
        errors,
    )
    primaries = [
        review for review in attempt["reviews"] if review["payload"].get("role") == "primary"
    ]
    if payload.get("role") == "primary":
        require(len(primaries) < 2, f"{label}: at most two primary reviewers", errors)
    elif payload.get("role") == "tie_break":
        primary_verdicts = {review["payload"].get("verdict") for review in primaries}
        require(
            len(primaries) == 2 and primary_verdicts == {"valid", "invalid"},
            f"{label}: tie-break reviewer is allowed only after primary disagreement",
            errors,
        )
    if payload.get("verdict") == "valid":
        require(
            all(payload.get(key) is True for key in SEMANTIC_RUBRIC_KEYS),
            f"{label}: valid review requires all five rubric answers",
            errors,
        )


def _validate_gold_event(
    payload: dict[str, Any], attempt: dict[str, Any], label: str, errors: list[str]
) -> None:
    reviews = attempt["reviews"]
    require(
        _phase_succeeded(attempt, "semantic_review"),
        f"{label}: gold unblind requires the blinded review phase to be committed",
        errors,
    )
    require(
        len(reviews) in {2, 3}, f"{label}: gold unblind requires a committed review verdict", errors
    )
    verdicts = [review["payload"].get("verdict") for review in reviews]
    require(
        verdicts.count("valid") >= 2 or verdicts.count("invalid") >= 2,
        f"{label}: gold unblind requires a majority semantic verdict",
        errors,
    )
    if reviews:
        require(
            payload.get("committed_semantic_event_sha256") == reviews[-1].get("event_sha256"),
            f"{label}: gold unblind must commit to the final blinded review event",
            errors,
        )


def _phase_succeeded(attempt: dict[str, Any], phase: str) -> bool:
    return any(
        key[0] == phase and event["payload"].get("status") == "succeeded"
        for key, event in attempt["phase_finishes"].items()
    )


def _validate_attempt_finish(
    event: dict[str, Any],
    attempt: dict[str, Any],
    case: dict[str, Any],
    lane: str,
    label: str,
    errors: list[str],
) -> None:
    payload = event["payload"]
    outcome = payload.get("outcome")
    claim = payload.get("claim_level")
    disposition = payload.get("scoring_disposition")
    expected_claim = "rejected"
    if outcome in L0_OUTCOMES:
        expected_claim = "L0"
    elif outcome == "plausible_f2p_semantic_invalid":
        expected_claim = "L1"
    elif outcome == "semantic_valid":
        expected_claim = "L2"
    require(claim == expected_claim, f"{label}: attempt outcome/claim_level is incoherent", errors)
    require(
        payload.get("plausible_f2p") is (claim in {"L1", "L2"}),
        f"{label}: attempt plausible_f2p is incoherent",
        errors,
    )
    if lane == "smoke":
        require(disposition == "non_scoring", f"{label}: smoke attempt cannot be scored", errors)
        require(
            payload.get("result_row_sha256") is None, f"{label}: smoke has no result row", errors
        )
    elif outcome == "benchmark_infrastructure_error":
        require(
            disposition == "retriable_infrastructure",
            f"{label}: infrastructure error must remain retriable/incomplete",
            errors,
        )
        require(
            payload.get("result_row_sha256") is None,
            f"{label}: infra retry has no result row",
            errors,
        )
    else:
        require(
            disposition == "counted", f"{label}: terminal scored outcome must be counted", errors
        )
        require(
            isinstance(payload.get("result_row_sha256"), str),
            f"{label}: counted attempt must commit its result row hash",
            errors,
        )
        require(
            case["counted_finish"] is None, f"{label}: case already has a counted finish", errors
        )
        case["counted_finish"] = event
    if claim in {"L0", "L1", "L2"}:
        require(
            case["candidate"] is not None, f"{label}: verified claim requires a candidate", errors
        )
    if claim in {"L1", "L2"}:
        require(
            attempt["gold"] is not None,
            f"{label}: F2P verdict requires post-review unblind",
            errors,
        )
    review_verdicts = [review["payload"].get("verdict") for review in attempt["reviews"]]
    if outcome == "semantic_valid":
        require(
            review_verdicts.count("valid") >= 2,
            f"{label}: semantic_valid requires a valid reviewer majority",
            errors,
        )
    elif outcome == "plausible_f2p_semantic_invalid":
        require(
            review_verdicts.count("invalid") >= 2,
            f"{label}: semantic-invalid outcome requires an invalid reviewer majority",
            errors,
        )
    completed = _parse_datetime(payload.get("completed_at"))
    started = _parse_datetime(attempt["start"].get("recorded_at"))
    if completed is not None and started is not None:
        require(completed >= started, f"{label}: attempt completed before it started", errors)


def reconcile_results_with_events(
    result_rows: list[dict[str, Any]],
    scored_index: dict[str, Any],
    errors: list[str],
) -> None:
    """Require every terminal projection to be derivable from one scored event trace."""

    cases = scored_index.get("cases")
    if not isinstance(cases, dict):
        return
    for row_number, row in enumerate(result_rows, start=1):
        label = f"results:event reconciliation row {row_number}"
        case_id = row.get("case_id")
        case = cases.get(case_id) if isinstance(case_id, str) else None
        require(isinstance(case, dict), f"{label}: result has no scored attempt trace", errors)
        if not isinstance(case, dict):
            continue
        finish = case.get("counted_finish")
        require(
            isinstance(finish, dict), f"{label}: result has no counted attempt_finished", errors
        )
        expected_hash = canonical_row_sha256(row)
        attempt: dict[str, Any] | None = None
        if isinstance(finish, dict):
            finish_payload = finish.get("payload")
            require(
                isinstance(finish_payload, dict)
                and finish_payload.get("result_row_sha256") == expected_hash,
                f"{label}: result row hash does not match attempt_finished",
                errors,
            )
            attempts = scored_index.get("attempts")
            attempt_id = finish.get("attempt_id")
            attempt = attempts.get(attempt_id) if isinstance(attempts, dict) else None
            start = attempt.get("start") if isinstance(attempt, dict) else None
            start_payload = start.get("payload") if isinstance(start, dict) else None
            if isinstance(finish_payload, dict):
                for field in ("outcome", "claim_level", "plausible_f2p", "limitations"):
                    require(
                        row.get(field) == finish_payload.get(field),
                        f"{label}: result {field} does not match attempt_finished",
                        errors,
                    )
                require(
                    row.get("completed_at") == finish_payload.get("completed_at"),
                    f"{label}: result completed_at does not match attempt_finished",
                    errors,
                )
            if isinstance(start, dict):
                require(
                    row.get("started_at") == start.get("recorded_at"),
                    f"{label}: result started_at does not match attempt_started",
                    errors,
                )
            if isinstance(start_payload, dict):
                frozen_tool = start_payload.get("tool")
                result_tool = row.get("tool")
                require(
                    isinstance(frozen_tool, dict)
                    and isinstance(result_tool, dict)
                    and result_tool.get("name") == frozen_tool.get("name")
                    and result_tool.get("version") == frozen_tool.get("version")
                    and result_tool.get("git_sha") == frozen_tool.get("git_sha"),
                    f"{label}: result tool identity does not match attempt freeze",
                    errors,
                )
                frozen_generator = start_payload.get("generator")
                result_generator = row.get("generator")
                model_identity = (
                    frozen_generator.get("model_identity")
                    if isinstance(frozen_generator, dict)
                    else None
                )
                call_starts = attempt.get("call_starts") if isinstance(attempt, dict) else None
                rendered_input_sha256 = None
                if isinstance(call_starts, dict) and len(call_starts) == 1:
                    only_call = next(iter(call_starts.values()))
                    rendered_input_sha256 = only_call["payload"].get("rendered_input_sha256")
                require(
                    isinstance(frozen_generator, dict)
                    and isinstance(result_generator, dict)
                    and result_generator.get("provider") == frozen_generator.get("provider")
                    and result_generator.get("model") == frozen_generator.get("requested_model")
                    and isinstance(model_identity, dict)
                    and result_generator.get("model_version") == model_identity.get("value")
                    and result_generator.get("prompt_template_sha256")
                    == frozen_generator.get("prompt_template_sha256")
                    and result_generator.get("rendered_input_sha256") == rendered_input_sha256
                    and result_generator.get("config_sha256")
                    == frozen_generator.get("config_sha256"),
                    f"{label}: result generator identity does not match attempt freeze",
                    errors,
                )
            require(
                finish.get("batch_id") == row.get("run_id"),
                f"{label}: result run_id must equal the canonical event batch_id",
                errors,
            )
        candidate_event = case.get("candidate")
        candidate = row.get("candidate")
        if isinstance(candidate, dict):
            candidate_payload = (
                candidate_event.get("payload") if isinstance(candidate_event, dict) else None
            )
            event_candidate = (
                {field: candidate_payload.get(field) for field in CANDIDATE_RESULT_FIELDS}
                if isinstance(candidate_payload, dict)
                else None
            )
            require(
                event_candidate == candidate,
                f"{label}: selected candidate does not match event trace",
                errors,
            )
        else:
            require(
                candidate_event is None,
                f"{label}: result omitted a submitted candidate from the event trace",
                errors,
            )
        if isinstance(attempt, dict):
            _reconcile_result_evidence(row, attempt, label, errors)
        require(
            not case.get("unknown_cost"),
            f"{label}: result cannot project an attempt with unknown cost",
            errors,
        )
        attempts = scored_index.get("attempts")
        if isinstance(attempts, dict):
            for attempt_id in case.get("attempt_ids", []):
                attempt_row = attempts.get(attempt_id)
                if not isinstance(attempt_row, dict):
                    continue
                require(
                    attempt_row["scored_cost_categories"].issuperset(
                        REQUIRED_ATTRIBUTABLE_COST_CATEGORIES
                    ),
                    f"{label}: attempt {attempt_id} lacks explicit attributable cost closure",
                    errors,
                )
                require(
                    not attempt_row["unknown_cost"] and not attempt_row["estimated_cost"],
                    f"{label}: attempt {attempt_id} cost is not fully measured or verified zero",
                    errors,
                )
        cost = row.get("cost")
        if isinstance(cost, dict):
            total_usd = cost.get("attributable_total_usd")
            if _is_number(total_usd):
                require(
                    round(float(total_usd) * 1_000_000) == case["known_scored_cost_microusd"],
                    f"{label}: result cost does not equal all-attempt ledger cost",
                    errors,
                )
            category_costs = case.get("known_scored_cost_by_category")
            if isinstance(category_costs, dict):
                for category, field in RESULT_COST_FIELD_BY_CATEGORY.items():
                    value = cost.get(field)
                    if _is_number(value):
                        require(
                            round(float(value) * 1_000_000) == category_costs.get(category),
                            f"{label}: result {field} does not match ledger category cost",
                            errors,
                        )
            require(
                cost.get("input_tokens") == case["input_tokens"]
                and cost.get("output_tokens") == case["output_tokens"],
                f"{label}: result tokens do not equal all model calls",
                errors,
            )
        generator = row.get("generator")
        if isinstance(generator, dict):
            require(
                generator.get("internal_attempts") == len(case["model_call_ids"]),
                f"{label}: internal_attempts must equal started model calls",
                errors,
            )


def _reconcile_result_evidence(
    row: dict[str, Any],
    attempt: dict[str, Any],
    label: str,
    errors: list[str],
) -> None:
    claim = row.get("claim_level")
    outcome = row.get("outcome")
    executions = row.get("executions")
    evidence: list[tuple[str, Any, set[str]]] = []
    if claim in {"L0", "L1", "L2"}:
        for phase in (
            "preflight",
            "issue_snapshot",
            "generation",
            "candidate_policy",
            "collection",
            "base_verify",
        ):
            _require_phase_terminal_status(
                attempt,
                phase=phase,
                allowed_statuses={"succeeded"},
                label=label,
                errors=errors,
            )
        evidence.extend(
            [
                ("issue_snapshot", row.get("issue_snapshot"), {"succeeded"}),
                ("policy", row.get("policy"), {"succeeded"}),
                (
                    "base",
                    executions.get("base") if isinstance(executions, dict) else None,
                    {"succeeded"},
                ),
            ]
        )
    if claim in {"L1", "L2"} or outcome in L0_OUTCOMES:
        fixed_statuses = {"succeeded"} if claim in {"L1", "L2"} else {"failed"}
        _require_phase_terminal_status(
            attempt,
            phase="fixed_verify",
            allowed_statuses=fixed_statuses,
            label=label,
            errors=errors,
        )
        evidence.append(
            (
                "fixed",
                executions.get("fixed") if isinstance(executions, dict) else None,
                fixed_statuses,
            )
        )
    if claim in {"L1", "L2"}:
        for phase in ("causal_controls", "semantic_review"):
            _require_phase_terminal_status(
                attempt,
                phase=phase,
                allowed_statuses={"succeeded"},
                label=label,
                errors=errors,
            )
        evidence.extend(
            [
                (
                    "causal_controls",
                    executions.get("causal_controls") if isinstance(executions, dict) else None,
                    {"succeeded"},
                ),
                ("semantic_review", row.get("semantic_review"), {"succeeded"}),
            ]
        )

    for evidence_name, value, allowed_statuses in evidence:
        phase, kind = RESULT_EVIDENCE_PHASES[evidence_name]
        _require_phase_evidence_commitment(
            attempt,
            phase=phase,
            kind=kind,
            value=value,
            allowed_statuses=allowed_statuses,
            label=label,
            errors=errors,
        )

    if claim in {"L0", "L1", "L2"}:
        execution_phases = {"collection", "base_verify", "fixed_verify"}
        if claim in {"L1", "L2"}:
            execution_phases.add("causal_controls")
        _reconcile_result_environment(
            row.get("environment"),
            attempt,
            phases=execution_phases,
            label=label,
            errors=errors,
        )

    if claim not in {"L1", "L2"}:
        return
    semantic_review = row.get("semantic_review")
    row_reviewers = semantic_review.get("reviewers") if isinstance(semantic_review, dict) else None
    event_reviewers = [
        review.get("payload") for review in attempt["reviews"] if isinstance(review, dict)
    ]
    require(
        row_reviewers == event_reviewers,
        f"{label}: semantic reviewers do not match semantic_review_recorded events",
        errors,
    )
    if isinstance(semantic_review, dict):
        require(
            semantic_review.get("gold_unblinded_after_decision")
            is (attempt.get("gold") is not None),
            f"{label}: semantic review gold-unblind state does not match the event trace",
            errors,
        )


def _require_phase_evidence_commitment(
    attempt: dict[str, Any],
    *,
    phase: str,
    kind: str,
    value: Any,
    allowed_statuses: set[str],
    label: str,
    errors: list[str],
) -> None:
    try:
        encoded = canonical_json_bytes(value)
    except ReproAssertError:
        errors.append(f"{label}: {kind} evidence cannot be canonically encoded")
        return
    expected_sha256 = hashlib.sha256(encoded).hexdigest()
    expected_path = f"evidence/{kind}.json"
    commitments: list[dict[str, Any]] = []
    for key, event in attempt["phase_finishes"].items():
        if key[0] != phase or not isinstance(event, dict):
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict) or payload.get("status") not in allowed_statuses:
            continue
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list):
            continue
        commitments.extend(
            artifact
            for artifact in artifacts
            if isinstance(artifact, dict) and artifact.get("kind") == kind
        )
    require(
        len(commitments) == 1,
        f"{label}: {phase} must contain exactly one {kind} evidence commitment",
        errors,
    )
    if len(commitments) != 1:
        return
    commitment = commitments[0]
    require(
        commitment.get("path") == expected_path
        and commitment.get("sha256") == expected_sha256
        and commitment.get("bytes") == len(encoded),
        f"{label}: {kind} evidence commitment does not match the result row",
        errors,
    )


def _require_phase_terminal_status(
    attempt: dict[str, Any],
    *,
    phase: str,
    allowed_statuses: set[str],
    label: str,
    errors: list[str],
) -> None:
    statuses = [
        event["payload"].get("status")
        for key, event in attempt["phase_finishes"].items()
        if key[0] == phase and isinstance(event, dict) and isinstance(event.get("payload"), dict)
    ]
    require(
        len(statuses) == 1 and statuses[0] in allowed_statuses,
        f"{label}: {phase} must finish exactly once with status {sorted(allowed_statuses)!r}",
        errors,
    )


def _reconcile_result_environment(
    environment: Any,
    attempt: dict[str, Any],
    *,
    phases: set[str],
    label: str,
    errors: list[str],
) -> None:
    try:
        expected_sha256 = hashlib.sha256(canonical_json_bytes(environment)).hexdigest()
    except ReproAssertError:
        errors.append(f"{label}: environment evidence cannot be canonically encoded")
        return
    for phase in sorted(phases):
        finishes = [
            event
            for key, event in attempt["phase_finishes"].items()
            if key[0] == phase and isinstance(event, dict)
        ]
        require(
            len(finishes) == 1
            and isinstance(finishes[0].get("payload"), dict)
            and finishes[0]["payload"].get("environment_sha256") == expected_sha256,
            f"{label}: {phase} environment_sha256 does not match the result environment",
            errors,
        )


def load_result_rows(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(lines, start=1):
        if not raw_line.strip():
            continue
        try:
            row = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            errors.append(f"{path}:line {line_number}: result must be an object")
    return rows


def validate_ledger_prefix(path: Path, base_ref: str, errors: list[str]) -> None:
    previous = _git_blob_at_ref(path, base_ref, errors)
    if previous is None:
        previous = b""
    try:
        current = path.read_bytes()
    except FileNotFoundError:
        errors.append(f"missing file: {path}")
        return
    require(
        is_exact_prefix(previous, current),
        f"{path}: existing ledger bytes from {base_ref!r} are not an exact prefix",
        errors,
    )


def _git_blob_at_ref(path: Path, base_ref: str, errors: list[str]) -> bytes | None:
    relative = path.relative_to(ROOT).as_posix()
    completed = subprocess.run(
        ["git", "show", f"{base_ref}:{relative}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        ref_check = subprocess.run(
            ["git", "cat-file", "-e", f"{base_ref}^{{commit}}"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        if ref_check.returncode != 0:
            errors.append(f"{path}: unable to resolve prefix git ref {base_ref!r}")
        return None
    return completed.stdout if completed.returncode == 0 else None


def validate_frozen_history(base_ref: str, errors: list[str]) -> None:
    manifest_path = ROOT / "benchmarks" / "v0.1" / "manifest.json"
    results_path = ROOT / "benchmarks" / "v0.1" / "results.jsonl"
    campaign_path = ROOT / "benchmarks" / "v0.1" / "campaign.json"
    scored_path = ROOT / "benchmarks" / "v0.1" / "ledger" / "scored-events.jsonl"

    previous_manifest = _git_blob_at_ref(manifest_path, base_ref, errors)
    if previous_manifest is not None:
        require(
            manifest_path.read_bytes() == previous_manifest,
            "frozen benchmark manifest bytes may not change in v0.1",
            errors,
        )
    previous_results = _git_blob_at_ref(results_path, base_ref, errors)
    if previous_results is not None:
        current_results = results_path.read_bytes()
        blank_normalization = not previous_results.strip() and not current_results.strip()
        require(
            blank_normalization or is_exact_prefix(previous_results, current_results),
            "existing scored result bytes must remain an exact prefix",
            errors,
        )
    previous_scored = _git_blob_at_ref(scored_path, base_ref, errors)
    previous_campaign = _git_blob_at_ref(campaign_path, base_ref, errors)
    if previous_scored and previous_campaign is not None:
        require(
            _campaign_history_transition_allowed(
                previous_campaign,
                campaign_path.read_bytes(),
            ),
            "campaign freeze may only make the terminal running-to-complete transition after "
            "the first scored event",
            errors,
        )


def _campaign_history_transition_allowed(previous: bytes, current: bytes) -> bool:
    """Keep the experiment freeze immutable while allowing its terminal status projection."""

    if current == previous:
        return True
    try:
        previous_campaign = json.loads(previous)
        current_campaign = json.loads(current)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return False
    if not isinstance(previous_campaign, dict) or not isinstance(current_campaign, dict):
        return False
    if previous_campaign.get("status") != "running" or current_campaign.get("status") != "complete":
        return False
    previous_freeze = dict(previous_campaign)
    current_freeze = dict(current_campaign)
    previous_freeze.pop("status", None)
    current_freeze.pop("status", None)
    return previous_freeze == current_freeze


def validate_campaign(
    campaign: Any,
    *,
    campaign_schema: dict[str, Any] | None,
    known_case_ids: set[str],
    scored_index: dict[str, Any],
    result_row_count: int,
    errors: list[str],
    manifest: dict[str, Any] | None = None,
    manifest_sha256: str | None = None,
    summary: dict[str, Any] | None = None,
) -> None:
    if not isinstance(campaign, dict):
        errors.append("campaign root must be an object")
        return
    if campaign_schema is not None:
        validate_json_schema_instance(
            campaign,
            campaign_schema,
            campaign_schema,
            "campaign",
            errors,
        )
    require(
        campaign.get("case_ids") == sorted(known_case_ids),
        "campaign case_ids must be the exact frozen cohort in canonical order",
        errors,
    )
    status = campaign.get("status")
    configuration = campaign.get("configuration")
    prerequisites = campaign.get("prerequisites")
    blockers = campaign.get("blockers")
    scored_events = scored_index.get("events")
    has_scored_events = isinstance(scored_events, list) and bool(scored_events)

    if status == "blocked_pending_prerequisites":
        require(campaign.get("campaign_id") is None, "blocked campaign_id must be null", errors)
        require(campaign.get("run_id") is None, "blocked run_id must be null", errors)
        require(campaign.get("started_at") is None, "blocked campaign has not started", errors)
        require(not has_scored_events, "blocked campaign cannot contain scored events", errors)
        require(result_row_count == 0, "blocked campaign cannot contain result rows", errors)
        require(
            isinstance(blockers, list) and blockers, "blocked campaign must list blockers", errors
        )
        if isinstance(configuration, dict):
            frozen_fields = (
                "tool_git_sha",
                "provider",
                "requested_model",
                "model_version",
                "prompt_template_sha256",
                "request_builder_sha256",
                "config_sha256",
                "context_algorithm_sha256",
                "policy_sha256",
                "pricing_snapshot_sha256",
            )
            require(
                all(configuration.get(field) is None for field in frozen_fields),
                "blocked campaign must not pretend its generator configuration is frozen",
                errors,
            )
            authorization = configuration.get("spend_authorization")
            require(
                isinstance(authorization, dict)
                and authorization.get("status") == "not_authorized"
                and authorization.get("authorization_ref") is None,
                "blocked campaign must keep paid spend unauthorized",
                errors,
            )
            require(
                configuration.get("max_case_attributable_microusd") == 0
                and configuration.get("max_campaign_attributable_microusd") == 0,
                "unauthorized campaign must enforce zero spend caps",
                errors,
            )
        return

    require(
        isinstance(campaign.get("campaign_id"), str)
        and campaign.get("campaign_id") == campaign.get("run_id"),
        "ready/running campaign_id and run_id must be the same frozen identifier",
        errors,
    )
    require(
        isinstance(prerequisites, dict) and all(prerequisites.values()),
        "ready/running campaign requires every isolation prerequisite",
        errors,
    )
    require(blockers == [], "ready/running campaign cannot retain blockers", errors)
    if status == "frozen_ready":
        require(campaign.get("started_at") is None, "frozen-ready campaign has not started", errors)
        require(not has_scored_events, "frozen-ready campaign cannot contain scored events", errors)
        require(result_row_count == 0, "frozen-ready campaign cannot contain results", errors)
    else:
        require(
            _parse_datetime(campaign.get("started_at")) is not None,
            "running/complete campaign requires started_at",
            errors,
        )
    if isinstance(configuration, dict):
        frozen_fields = (
            "tool_git_sha",
            "provider",
            "requested_model",
            "model_version",
            "prompt_template_sha256",
            "request_builder_sha256",
            "config_sha256",
            "context_algorithm_sha256",
            "policy_sha256",
            "pricing_snapshot_sha256",
        )
        require(
            all(configuration.get(field) is not None for field in frozen_fields),
            "ready/running campaign requires every generator freeze field",
            errors,
        )
        authorization = configuration.get("spend_authorization")
        if isinstance(authorization, dict):
            auth_status = authorization.get("status")
            if auth_status == "offline_zero_cost":
                require(
                    configuration.get("max_case_attributable_microusd") == 0
                    and configuration.get("max_campaign_attributable_microusd") == 0,
                    "offline campaign requires zero spend caps",
                    errors,
                )
                require(
                    configuration.get("provider") == "local-model",
                    "scored offline campaign requires a real declared local model, not a fixture",
                    errors,
                )
            elif auth_status == "explicit_user_approval":
                require(
                    isinstance(authorization.get("authorization_ref"), str),
                    "paid campaign requires explicit authorization_ref",
                    errors,
                )
                errors.append(
                    "paid scored campaign remains disabled until component pricing and trusted "
                    "reservation calculation are implemented"
                )
            else:
                errors.append("ready/running campaign cannot use not_authorized spend state")
    if has_scored_events:
        require(
            status in {"running", "complete"},
            "scored events require campaign status running or complete",
            errors,
        )
        require(
            scored_index.get("batch_id") == campaign.get("run_id"),
            "scored ledger batch_id must match campaign run_id",
            errors,
        )
        _validate_campaign_attempt_freeze(
            campaign,
            scored_index=scored_index,
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            errors=errors,
        )
    if status == "complete":
        require(result_row_count == 20, "complete campaign requires all 20 result rows", errors)
        completeness = summary.get("completeness") if isinstance(summary, dict) else None
        require(
            isinstance(completeness, dict)
            and completeness.get("complete") is True
            and completeness.get("status") == "complete",
            "complete campaign requires a complete deterministic summary",
            errors,
        )
    elif isinstance(summary, dict):
        completeness = summary.get("completeness")
        require(
            not isinstance(completeness, dict) or completeness.get("complete") is not True,
            "complete deterministic summary requires campaign status complete",
            errors,
        )


def _validate_campaign_attempt_freeze(
    campaign: dict[str, Any],
    *,
    scored_index: dict[str, Any],
    manifest: dict[str, Any] | None,
    manifest_sha256: str | None,
    errors: list[str],
) -> None:
    configuration = campaign.get("configuration")
    attempts = scored_index.get("attempts")
    if not isinstance(configuration, dict) or not isinstance(attempts, dict):
        errors.append("scored ledger is missing reducible attempt freezes")
        return
    cases = manifest.get("cases") if isinstance(manifest, dict) else None
    case_map = (
        {
            case.get("id"): case
            for case in cases
            if isinstance(case, dict) and isinstance(case.get("id"), str)
        }
        if isinstance(cases, list)
        else {}
    )
    for attempt_id, attempt in attempts.items():
        start = attempt.get("start") if isinstance(attempt, dict) else None
        payload = start.get("payload") if isinstance(start, dict) else None
        if not isinstance(payload, dict):
            errors.append(f"attempt {attempt_id}: missing attempt_started payload")
            continue
        label = f"attempt {attempt_id}"
        event_campaign = payload.get("campaign")
        generator = payload.get("generator")
        tool = payload.get("tool")
        authorization = configuration.get("spend_authorization")
        event_authorization = (
            event_campaign.get("spend_authorization") if isinstance(event_campaign, dict) else None
        )
        require(
            isinstance(event_campaign, dict)
            and event_campaign.get("campaign_id") == campaign.get("campaign_id")
            and event_campaign.get("cohort_tier") == "historical_scored"
            and event_campaign.get("max_model_calls_per_case")
            == configuration.get("max_model_calls_per_case")
            and event_campaign.get("max_submitted_candidates_per_case")
            == configuration.get("max_submitted_candidates_per_case")
            and event_campaign.get("max_infrastructure_retries_per_case")
            == configuration.get("max_infrastructure_retries_per_case")
            and event_campaign.get("max_case_wall_ms") == configuration.get("max_case_wall_ms")
            and event_campaign.get("max_case_attributable_microusd")
            == configuration.get("max_case_attributable_microusd")
            and event_campaign.get("max_campaign_attributable_microusd")
            == configuration.get("max_campaign_attributable_microusd")
            and event_authorization == authorization,
            f"{label}: event campaign/budget does not match campaign.json",
            errors,
        )
        model_identity = generator.get("model_identity") if isinstance(generator, dict) else None
        require(
            isinstance(generator, dict)
            and generator.get("provider") == configuration.get("provider")
            and generator.get("requested_model") == configuration.get("requested_model")
            and isinstance(model_identity, dict)
            and model_identity.get("value") == configuration.get("model_version")
            and generator.get("prompt_template_sha256")
            == configuration.get("prompt_template_sha256")
            and generator.get("request_builder_sha256")
            == configuration.get("request_builder_sha256")
            and generator.get("config_sha256") == configuration.get("config_sha256")
            and generator.get("context_algorithm_sha256")
            == configuration.get("context_algorithm_sha256")
            and generator.get("feedback_policy") == configuration.get("feedback_policy"),
            f"{label}: event generator does not match campaign.json",
            errors,
        )
        require(
            isinstance(tool, dict) and tool.get("git_sha") == configuration.get("tool_git_sha"),
            f"{label}: event tool commit does not match campaign.json",
            errors,
        )
        require(
            payload.get("policy_sha256") == configuration.get("policy_sha256")
            and payload.get("pricing_snapshot_sha256")
            == configuration.get("pricing_snapshot_sha256"),
            f"{label}: event policy/pricing does not match campaign.json",
            errors,
        )
        if manifest_sha256 is not None:
            require(
                payload.get("manifest_sha256") == manifest_sha256,
                f"{label}: event manifest hash does not match manifest.json bytes",
                errors,
            )
        case_id = start.get("case_id") if isinstance(start, dict) else None
        case_entry = case_map.get(case_id)
        if isinstance(case_entry, dict):
            expected_case_hash = hashlib.sha256(canonical_json_bytes(case_entry)).hexdigest()
            require(
                payload.get("case_entry_sha256") == expected_case_hash,
                f"{label}: event case hash does not match the frozen manifest entry",
                errors,
            )


def validate_summary_projection(
    summary_path: Path,
    *,
    summary_schema: dict[str, Any] | None,
    manifest_path: Path,
    results_path: Path,
    scored_ledger_path: Path,
    smoke_ledger_path: Path,
    errors: list[str],
    summary: Any = None,
) -> None:
    if summary is None:
        summary = load_json(summary_path, errors)
    if isinstance(summary, dict) and summary_schema is not None:
        validate_json_schema_instance(
            summary,
            summary_schema,
            summary_schema,
            "summary",
            errors,
        )
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "summarize_benchmark.py"),
            "--manifest",
            str(manifest_path),
            "--results",
            str(results_path),
            "--scored-ledger",
            str(scored_ledger_path),
            "--smoke-ledger",
            str(smoke_ledger_path),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        errors.append(
            "summary reducer failed: " + completed.stderr.decode("utf-8", errors="replace")
        )
        return
    try:
        checked_in = summary_path.read_bytes()
    except FileNotFoundError:
        return
    require(
        completed.stdout == checked_in,
        "summary.json is stale or not the byte-identical deterministic projection",
        errors,
    )


def validate_result_invariants(row: dict[str, Any], label: str, errors: list[str]) -> None:
    """Reject structurally valid rows that make scientifically impossible claims."""

    outcome = row.get("outcome")
    claim_level = row.get("claim_level")
    candidate = row.get("candidate")
    plausible_f2p = row.get("plausible_f2p")
    policy = row.get("policy")
    executions = row.get("executions")
    semantic_review = row.get("semantic_review")

    expected_claim: str | None = None
    if outcome in EARLY_REJECTED_OUTCOMES:
        expected_claim = "rejected"
    elif outcome in L0_OUTCOMES:
        expected_claim = "L0"
    elif outcome == "plausible_f2p_semantic_invalid":
        expected_claim = "L1"
    elif outcome == "semantic_valid":
        expected_claim = "L2"
    if expected_claim is not None:
        require(
            claim_level == expected_claim,
            f"{label}: outcome {outcome!r} requires claim_level {expected_claim!r}",
            errors,
        )
    require(claim_level != "L3", f"{label}: internal benchmark rows cannot claim L3", errors)

    if outcome == "no_output":
        require(candidate is None, f"{label}: no_output must not contain a candidate", errors)
    if claim_level in {"L0", "L1", "L2"}:
        require(candidate is not None, f"{label}: {claim_level} requires a candidate", errors)

    if claim_level in {"L1", "L2"}:
        require(
            plausible_f2p is True,
            f"{label}: {claim_level} requires plausible_f2p=true",
            errors,
        )
    else:
        require(
            plausible_f2p is False,
            f"{label}: {claim_level!r} cannot set plausible_f2p=true",
            errors,
        )

    if claim_level in {"L0", "L1", "L2"}:
        _validate_passing_policy(policy, label, errors)
        _validate_base_evidence(executions, candidate, label, errors)
    if claim_level in {"L1", "L2"}:
        _validate_fixed_evidence(executions, label, errors)
        _validate_complete_schedule(executions, label, errors)

    _validate_semantic_review(
        semantic_review,
        outcome=outcome if isinstance(outcome, str) else "",
        label=label,
        errors=errors,
    )
    if outcome == "semantic_valid":
        _validate_causal_controls(executions, label, errors)

    _validate_time_and_cost(row, label, errors)


def _validate_passing_policy(policy: Any, label: str, errors: list[str]) -> None:
    require(isinstance(policy, dict), f"{label}: verified claims require policy evidence", errors)
    if not isinstance(policy, dict):
        return
    require(policy.get("passed") is True, f"{label}: verified claim requires policy pass", errors)
    require(
        policy.get("violations") == [], f"{label}: verified claim has policy violations", errors
    )
    for field in (
        "production_files_changed",
        "dependency_files_changed",
        "unconditional_failure_detected",
        "network_use_detected",
    ):
        require(policy.get(field) is False, f"{label}: verified claim violates {field}", errors)


def _execution_lists(executions: Any) -> tuple[list[Any], list[Any]]:
    if not isinstance(executions, dict):
        return [], []
    base = executions.get("base")
    fixed = executions.get("fixed")
    return (base if isinstance(base, list) else [], fixed if isinstance(fixed, list) else [])


def _validate_base_evidence(executions: Any, candidate: Any, label: str, errors: list[str]) -> None:
    base, _ = _execution_lists(executions)
    require(len(base) == 3, f"{label}: L0+ requires exactly three base executions", errors)
    fingerprints: list[str] = []
    candidate_nodes = (
        set(candidate.get("nodeids", []))
        if isinstance(candidate, dict) and isinstance(candidate.get("nodeids"), list)
        else set()
    )
    commands: list[tuple[Any, ...]] = []
    for index, execution in enumerate(base):
        execution_label = f"{label}.executions.base[{index}]"
        if not isinstance(execution, dict):
            continue
        require(
            execution.get("status") in {"assertion_failure", "issue_specified_exception"},
            f"{execution_label}: base result must be an issue-aligned call failure",
            errors,
        )
        require(execution.get("exit_code") == 1, f"{execution_label}: exit_code must be 1", errors)
        for field in ("timed_out", "oom_killed", "output_truncated"):
            require(
                execution.get(field) is False, f"{execution_label}: {field} must be false", errors
            )
        failure = execution.get("failure")
        require(
            isinstance(failure, dict), f"{execution_label}: failure evidence is required", errors
        )
        if isinstance(failure, dict):
            require(
                failure.get("phase") == "call",
                f"{execution_label}: only call-phase failures can reproduce an issue",
                errors,
            )
            fingerprint = failure.get("fingerprint_sha256")
            if isinstance(fingerprint, str):
                fingerprints.append(fingerprint)
            nodeid = failure.get("nodeid")
            require(
                isinstance(nodeid, str) and nodeid in candidate_nodes,
                f"{execution_label}: failure nodeid must be a submitted candidate node",
                errors,
            )
        command = execution.get("command")
        if isinstance(command, list):
            commands.append(tuple(command))
    if len(fingerprints) == 3:
        require(
            len(set(fingerprints)) == 1,
            f"{label}: all base failures must share one normalized fingerprint",
            errors,
        )
    if len(commands) == 3:
        require(len(set(commands)) == 1, f"{label}: base commands must be identical", errors)


def _validate_fixed_evidence(executions: Any, label: str, errors: list[str]) -> None:
    _, fixed = _execution_lists(executions)
    require(len(fixed) == 3, f"{label}: L1+ requires exactly three fixed executions", errors)
    commands: list[tuple[Any, ...]] = []
    for index, execution in enumerate(fixed):
        execution_label = f"{label}.executions.fixed[{index}]"
        if not isinstance(execution, dict):
            continue
        require(execution.get("status") == "pass", f"{execution_label}: must pass", errors)
        require(execution.get("exit_code") == 0, f"{execution_label}: exit_code must be 0", errors)
        require(
            execution.get("failure") is None, f"{execution_label}: failure must be null", errors
        )
        for field in ("timed_out", "oom_killed", "output_truncated"):
            require(
                execution.get(field) is False, f"{execution_label}: {field} must be false", errors
            )
        command = execution.get("command")
        if isinstance(command, list):
            commands.append(tuple(command))
    if len(commands) == 3:
        require(len(set(commands)) == 1, f"{label}: fixed commands must be identical", errors)


def _validate_complete_schedule(executions: Any, label: str, errors: list[str]) -> None:
    base, fixed = _execution_lists(executions)
    combined = [item for item in [*base, *fixed] if isinstance(item, dict)]
    ordinals = [item.get("ordinal") for item in combined]
    require(
        sorted(value for value in ordinals if isinstance(value, int)) == list(range(1, 7)),
        f"{label}: execution ordinals must be exactly 1 through 6",
        errors,
    )
    if len(combined) == 6 and all(isinstance(value, int) for value in ordinals):
        schedule = [item.get("tree") for item in sorted(combined, key=lambda item: item["ordinal"])]
        require(
            schedule == EXPECTED_SCHEDULE,
            f"{label}: execution schedule must be {EXPECTED_SCHEDULE!r}",
            errors,
        )


def _validate_semantic_review(review: Any, *, outcome: str, label: str, errors: list[str]) -> None:
    if not isinstance(review, dict):
        return
    status = review.get("status")
    reviewers = review.get("reviewers")
    reviewer_rows = reviewers if isinstance(reviewers, list) else []
    tie_break_required = review.get("tie_break_required") is True

    if outcome == "semantic_valid":
        require(status == "valid", f"{label}: semantic_valid requires valid review", errors)
    elif outcome == "plausible_f2p_semantic_invalid":
        require(
            status == "invalid",
            f"{label}: semantic-invalid outcome requires invalid review",
            errors,
        )
    else:
        require(
            status in {"not_reached", "pending"},
            f"{label}: non-F2P outcome cannot contain a semantic verdict",
            errors,
        )
        return

    expected_reviewers = 3 if tie_break_required else 2
    require(
        len(reviewer_rows) == expected_reviewers,
        f"{label}: semantic verdict requires {expected_reviewers} independent reviewers",
        errors,
    )
    reviewer_ids = [
        reviewer.get("reviewer_id") for reviewer in reviewer_rows if isinstance(reviewer, dict)
    ]
    require(
        len(reviewer_ids) == len(set(reviewer_ids)),
        f"{label}: semantic reviewer IDs must be distinct",
        errors,
    )
    for index, reviewer in enumerate(reviewer_rows):
        if not isinstance(reviewer, dict):
            continue
        verdict = reviewer.get("verdict")
        rubric_values = [reviewer.get(key) for key in SEMANTIC_RUBRIC_KEYS]
        if verdict == "valid":
            require(
                all(value is True for value in rubric_values),
                f"{label}.semantic_review.reviewers[{index}]: "
                "valid verdict requires five yes answers",
                errors,
            )
        elif verdict == "invalid":
            require(
                any(value is False for value in rubric_values),
                f"{label}.semantic_review.reviewers[{index}]: "
                "invalid verdict requires a failed rubric item",
                errors,
            )
    valid_votes = sum(
        isinstance(reviewer, dict) and reviewer.get("verdict") == "valid"
        for reviewer in reviewer_rows
    )
    if status == "valid":
        require(valid_votes >= 2, f"{label}: final valid status requires a valid majority", errors)
    elif status == "invalid":
        require(
            len(reviewer_rows) - valid_votes >= 2,
            f"{label}: final invalid status requires an invalid majority",
            errors,
        )
    require(
        review.get("gold_unblinded_after_decision") is True,
        f"{label}: final semantic verdict requires gold unblinding only after decision",
        errors,
    )


def _validate_causal_controls(executions: Any, label: str, errors: list[str]) -> None:
    controls = executions.get("causal_controls") if isinstance(executions, dict) else None
    rows = controls if isinstance(controls, list) else []
    conclusive = [
        row for row in rows if isinstance(row, dict) and row.get("status") in {"pass", "fail"}
    ]
    require(conclusive, f"{label}: L2 requires at least one conclusive causal control", errors)
    by_kind = {row.get("kind"): row.get("status") for row in conclusive}
    paired_hunks = (
        by_kind.get("issue_hunks_only") == "pass" and by_kind.get("fix_minus_issue_hunks") == "fail"
    )
    alternative = by_kind.get("alternative_fix") == "pass"
    require(
        paired_hunks or alternative,
        f"{label}: L2 requires paired fix-hunk controls or a passing alternative fix",
        errors,
    )


def _validate_time_and_cost(row: dict[str, Any], label: str, errors: list[str]) -> None:
    started = _parse_datetime(row.get("started_at"))
    completed = _parse_datetime(row.get("completed_at"))
    if started is not None and completed is not None:
        require(completed >= started, f"{label}: completed_at precedes started_at", errors)

    timing = row.get("timing")
    if isinstance(timing, dict):
        components = [
            timing.get("dependency_prep_seconds"),
            timing.get("generation_seconds"),
            timing.get("verification_seconds"),
        ]
        total = timing.get("total_seconds")
        if all(_is_number(value) for value in [*components, total]):
            require(
                float(total) + 1e-6 >= sum(float(value) for value in components),
                f"{label}: total_seconds is smaller than recorded phase time",
                errors,
            )

    cost = row.get("cost")
    if isinstance(cost, dict):
        components = [
            cost.get("model_usd"),
            cost.get("sandbox_compute_usd"),
            cost.get("artifact_transfer_usd"),
            cost.get("paid_storage_usd"),
        ]
        total = cost.get("attributable_total_usd")
        if all(_is_number(value) for value in [*components, total]):
            require(
                math.isclose(
                    float(total),
                    sum(float(value) for value in components),
                    abs_tol=1e-9,
                ),
                f"{label}: attributable cost must equal model + sandbox + transfer + storage",
                errors,
            )


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or RFC3339_RE.fullmatch(value) is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def canonical_row_sha256(row: dict[str, Any]) -> str:
    encoded = json.dumps(
        row, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "benchmarks" / "v0.1" / "manifest.json",
        help="path to the frozen manifest",
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=ROOT / "benchmarks" / "v0.1" / "results.jsonl",
        help="path to the JSONL scored-results ledger",
    )
    parser.add_argument(
        "--campaign",
        type=Path,
        default=ROOT / "benchmarks" / "v0.1" / "campaign.json",
        help="path to the deny-by-default scored campaign freeze",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=ROOT / "benchmarks" / "v0.1" / "summary.json",
        help="path to the deterministic aggregate projection",
    )
    parser.add_argument(
        "--smoke-events",
        type=Path,
        default=ROOT / "benchmarks" / "v0.1" / "ledger" / "smoke-events.jsonl",
        help="path to the non-scoring smoke event ledger",
    )
    parser.add_argument(
        "--scored-events",
        type=Path,
        default=ROOT / "benchmarks" / "v0.1" / "ledger" / "scored-events.jsonl",
        help="path to the scored all-attempt event ledger",
    )
    parser.add_argument(
        "--prefix-ref",
        help="optional git ref whose ledger bytes must remain an exact prefix",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    errors: list[str] = []

    manifest = load_json(args.manifest, errors)
    case_ids = validate_manifest(manifest, errors) if manifest is not None else set()
    case_schema = validate_schema_file(
        ROOT / "schemas" / "benchmark-case.schema.json", "case schema", errors
    )
    run_schema = validate_schema_file(
        ROOT / "schemas" / "benchmark-run.schema.json", "run schema", errors
    )
    event_schema = validate_schema_file(
        ROOT / "schemas" / "benchmark-event.schema.json", "event schema", errors
    )
    campaign_schema = validate_schema_file(
        ROOT / "schemas" / "benchmark-campaign.schema.json", "campaign schema", errors
    )
    summary_schema = validate_schema_file(
        ROOT / "schemas" / "benchmark-summary.schema.json", "summary schema", errors
    )
    if (
        case_schema is not None
        and isinstance(manifest, dict)
        and isinstance(manifest.get("cases"), list)
    ):
        for index, case in enumerate(manifest["cases"]):
            validate_json_schema_instance(
                case,
                case_schema,
                case_schema,
                f"manifest.cases[{index}]",
                errors,
            )
    result_rows = validate_results(args.results, case_ids, run_schema, errors)
    smoke_index = validate_event_ledger(
        args.smoke_events,
        lane="smoke",
        known_case_ids=case_ids,
        smoke_case_ids=EXPECTED_SMOKE_IDS,
        event_schema=event_schema,
        errors=errors,
    )
    scored_index = validate_event_ledger(
        args.scored_events,
        lane="scored",
        known_case_ids=case_ids,
        smoke_case_ids=EXPECTED_SMOKE_IDS,
        event_schema=event_schema,
        errors=errors,
    )
    decoded_result_rows = load_result_rows(args.results, errors)
    reconcile_results_with_events(decoded_result_rows, scored_index, errors)
    campaign = load_json(args.campaign, errors)
    summary = load_json(args.summary, errors)
    validate_campaign(
        campaign,
        campaign_schema=campaign_schema,
        known_case_ids=case_ids,
        scored_index=scored_index,
        result_row_count=result_rows,
        errors=errors,
        manifest=manifest if isinstance(manifest, dict) else None,
        manifest_sha256=(
            hashlib.sha256(args.manifest.read_bytes()).hexdigest()
            if isinstance(manifest, dict)
            else None
        ),
        summary=summary if isinstance(summary, dict) else None,
    )
    validate_summary_projection(
        args.summary,
        summary_schema=summary_schema,
        manifest_path=args.manifest,
        results_path=args.results,
        scored_ledger_path=args.scored_events,
        smoke_ledger_path=args.smoke_events,
        errors=errors,
        summary=summary,
    )
    if args.prefix_ref:
        validate_ledger_prefix(args.smoke_events, args.prefix_ref, errors)
        validate_ledger_prefix(args.scored_events, args.prefix_ref, errors)
        validate_frozen_history(args.prefix_ref, errors)

    if errors:
        print(f"benchmark validation failed with {len(errors)} error(s):", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        "benchmark v0.1.0 valid: "
        f"{EXPECTED_CASE_COUNT} cases, {EXPECTED_REPOSITORY_COUNT} repositories, "
        f"{len(EXPECTED_SMOKE_IDS)} smoke cases, {result_rows} result rows, "
        f"{len(smoke_index['events'])} smoke events, {len(scored_index['events'])} scored events"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
