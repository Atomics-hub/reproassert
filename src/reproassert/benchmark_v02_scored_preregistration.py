"""Canonical structural loader shared by legacy and exact v0.2 scored workflows."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from reproassert.benchmark_v02_package import (
    EXPECTED_SMOKE_CASE_IDS,
    PreregisteredV02Case,
    load_v02_preregistration,
)
from reproassert.errors import PolicyRejection
from reproassert.intake import parse_issue_url
from reproassert.safeio import open_regular_file

MAX_BYTES = 2 * 1024 * 1024
EXACT_ALGORITHM = "reproassert-v02-exact-image-preregistration-v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CASE_ID = re.compile(r"rk-v0\.2-(?:00[1-9]|01[0-9]|020)\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_INSTANCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")
_EXACT_ROOT_KEYS = {
    "algorithm",
    "benchmark_version",
    "case_count",
    "case_set_sha256",
    "cases",
    "claims",
    "cohort_sha256",
    "evidence",
    "frozen_at",
    "policy",
    "preregistration_sha256",
    "request_set_sha256",
    "schema_version",
    "status",
    "tool_git_sha",
}
_EXACT_CASE_KEYS = {
    "base_sha",
    "candidate_profile",
    "case_commitment_sha256",
    "case_id",
    "difficulty",
    "evaluator_commitment_sha256",
    "evaluator_status",
    "generator_projection_sha256",
    "instance_id",
    "issue_url",
    "mapping_selected_hunks_sha256",
    "outbound_request_sha256",
    "rendered_input_sha256",
    "repo",
    "request_envelope_sha256",
    "smoke",
    "source_projection_commitment_sha256",
    "test_command_profile",
}


@dataclass(frozen=True)
class ScoredV02Preregistration:
    path: Path
    raw_sha256: str
    decoded: dict[str, Any]
    cases: tuple[PreregisteredV02Case, ...]
    format: Literal["legacy-v1", "exact-image-v1"]
    request_set_sha256: str | None
    exact_rows: tuple[dict[str, object], ...]

    @property
    def cohort_sha256(self) -> str:
        return cast(str, self.decoded["cohort_sha256"])

    def exact_row(self, case_id: str) -> dict[str, object] | None:
        return next((row for row in self.exact_rows if row["case_id"] == case_id), None)


def load_v02_scored_preregistration(path: Path) -> ScoredV02Preregistration:
    """Load either canonical protocol without treating one schema as the other."""

    source = Path(path)
    with open_regular_file(source) as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise _reject("Scored preregistration exceeds its size limit.")
    try:
        probe = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _reject("Scored preregistration is invalid JSON.") from exc
    if not isinstance(probe, dict):
        raise _reject("Scored preregistration must be an object.")
    if probe.get("algorithm") != EXACT_ALGORITHM:
        legacy = load_v02_preregistration(source)
        return ScoredV02Preregistration(
            path=source,
            raw_sha256=legacy.raw_sha256,
            decoded=cast(dict[str, Any], legacy.decoded),
            cases=legacy.cases,
            format="legacy-v1",
            request_set_sha256=None,
            exact_rows=(),
        )
    canonical = _canonical(probe) + b"\n"
    if raw != canonical:
        raise _reject("Exact scored preregistration is not canonical JSON.")
    if (
        set(probe) != _EXACT_ROOT_KEYS
        or probe.get("benchmark_version") != "0.2"
        or probe.get("schema_version") != "1.0.0"
        or probe.get("status") != "frozen_preinference_exact_image"
        or probe.get("case_count") != 20
        or probe.get("preregistration_sha256") != _self_hash(probe)
    ):
        raise _reject("Exact scored preregistration identity is invalid.")
    cohort = _digest(probe.get("cohort_sha256"), "cohort")
    request_set = _digest(probe.get("request_set_sha256"), "request set")
    values = probe.get("cases")
    if not isinstance(values, list) or len(values) != 20:
        raise _reject("Exact scored preregistration must preserve 20 cases.")
    rows: list[dict[str, object]] = []
    cases: list[PreregisteredV02Case] = []
    for position, value in enumerate(values, start=1):
        if not isinstance(value, dict):
            raise _reject("Exact scored case must be an object.")
        if set(value) != _EXACT_CASE_KEYS:
            raise _reject("Exact scored case fields are invalid.")
        case_id = value.get("case_id")
        if case_id != f"rk-v0.2-{position:03d}" or _CASE_ID.fullmatch(str(case_id)) is None:
            raise _reject("Exact scored cases are incomplete or out of order.")
        profile = value.get("candidate_profile")
        if profile not in {"pytest-v1", "sympy-native-v1"}:
            raise _reject("Exact scored candidate profile is invalid.")
        difficulty = value.get("difficulty")
        expected_smoke = cast(str, case_id) in EXPECTED_SMOKE_CASE_IDS
        expected_status = (
            "runtime_attested_gold_smoke_infrastructure_failure"
            if position == 14
            else "runtime_attested_evaluator_preflight_ready"
        )
        expected_command = "sympy-bin-test-v1" if profile == "sympy-native-v1" else "pytest-v1"
        if (
            difficulty not in {"lt_15m", "15m_to_1h"}
            or type(value.get("smoke")) is not bool
            or value.get("smoke") is not expected_smoke
            or value.get("evaluator_status") != expected_status
            or value.get("test_command_profile") != expected_command
        ):
            raise _reject("Exact scored case policy fields are invalid.")
        repo = _repository(value.get("repo"))
        issue_url = _issue_url(value.get("issue_url"), repo)
        base_sha = _git_sha(value.get("base_sha"))
        _instance_id(value.get("instance_id"))
        for name in (
            "case_commitment_sha256",
            "evaluator_commitment_sha256",
            "generator_projection_sha256",
            "outbound_request_sha256",
            "rendered_input_sha256",
            "source_projection_commitment_sha256",
        ):
            _digest(value.get(name), name)
        unsigned = dict(value)
        commitment = unsigned.pop("case_commitment_sha256")
        if commitment != _json_sha256(unsigned):
            raise _reject("Exact scored case commitment is invalid.")
        case = PreregisteredV02Case(
            id=cast(str, case_id),
            repo=repo,
            issue_url=issue_url,
            base_sha=base_sha,
            difficulty=cast(Any, difficulty),
            smoke=cast(bool, value.get("smoke")),
            generator_projection_sha256=cast(str, value["generator_projection_sha256"]),
            evaluator_commitment_sha256=cast(str, value["evaluator_commitment_sha256"]),
            source_context_sha256=cast(str, value["source_projection_commitment_sha256"]),
        )
        rows.append(cast(dict[str, object], value))
        cases.append(case)
    expected_case_set = _json_sha256(
        {
            "algorithm": "reproassert-v02-exact-preregistered-case-set-v1",
            "case_commitments": [row["case_commitment_sha256"] for row in rows],
        }
    )
    if probe.get("case_set_sha256") != expected_case_set:
        raise _reject("Exact scored case set commitment is invalid.")
    decoded = cast(dict[str, Any], probe)
    decoded["cohort_sha256"] = cohort
    return ScoredV02Preregistration(
        path=source,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        decoded=decoded,
        cases=tuple(cases),
        format="exact-image-v1",
        request_set_sha256=request_set,
        exact_rows=tuple(rows),
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def _self_hash(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned.pop("preregistration_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _json_sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject(f"Exact scored {label} digest is invalid.")
    return value


def _repository(value: object) -> str:
    if not isinstance(value, str) or _REPOSITORY.fullmatch(value) is None:
        raise _reject("Exact scored repository is invalid.")
    return value


def _issue_url(value: object, repository: str) -> str:
    if not isinstance(value, str):
        raise _reject("Exact scored issue URL is invalid.")
    try:
        location = parse_issue_url(value)
    except PolicyRejection as exc:
        raise _reject("Exact scored issue URL is not canonical.") from exc
    if repository != f"{location.owner}/{location.repo}":
        raise _reject("Exact scored repository differs from its issue URL.")
    return value


def _git_sha(value: object) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject("Exact scored base Git SHA is invalid.")
    return value


def _instance_id(value: object) -> str:
    if not isinstance(value, str) or _INSTANCE_ID.fullmatch(value) is None:
        raise _reject("Exact scored instance ID is invalid.")
    return value


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = item
    return value


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("v02_scored_preregistration", message)
