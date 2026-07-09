#!/usr/bin/env python3
"""Validate ReproAssert's frozen public benchmark using only the standard library."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

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
EXPECTED_CASE_KEYS = {
    "id",
    "repo",
    "issue_url",
    "base_sha",
    "difficulty",
    "title",
    "smoke",
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

        if isinstance(run_id, str) and isinstance(case_id, str):
            pair = (run_id, case_id)
            require(pair not in seen_pairs, f"{label}: duplicate run_id/case_id pair", errors)
            seen_pairs.add(pair)

    return rows


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=root / "benchmarks" / "v0.1" / "manifest.json",
        help="path to the frozen manifest",
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=root / "benchmarks" / "v0.1" / "results.jsonl",
        help="path to the JSONL scored-results ledger",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    errors: list[str] = []
    root = Path(__file__).resolve().parents[1]

    manifest = load_json(args.manifest, errors)
    case_ids = validate_manifest(manifest, errors) if manifest is not None else set()
    case_schema = validate_schema_file(
        root / "schemas" / "benchmark-case.schema.json", "case schema", errors
    )
    run_schema = validate_schema_file(
        root / "schemas" / "benchmark-run.schema.json", "run schema", errors
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

    if errors:
        print(f"benchmark validation failed with {len(errors)} error(s):", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        "benchmark v0.1.0 valid: "
        f"{EXPECTED_CASE_COUNT} cases, {EXPECTED_REPOSITORY_COUNT} repositories, "
        f"{len(EXPECTED_SMOKE_IDS)} smoke cases, {result_rows} result rows"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
