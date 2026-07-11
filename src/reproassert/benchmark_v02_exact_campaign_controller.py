"""Bounded production controller for the exact-image v0.2 scored campaign."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import stat
import uuid
from collections import defaultdict
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, cast

from reproassert import benchmark_v02_runner as runner
from reproassert.benchmark_v02_campaign import verify_v02_campaign_freeze
from reproassert.benchmark_v02_exact_capability import (
    issue_verified_v02_exact_image_evaluator_capability,
    verify_v02_exact_image_capability_index,
)
from reproassert.benchmark_v02_exact_preregistration import (
    verify_v02_exact_preregistration,
)
from reproassert.benchmark_v02_exact_scored import evaluate_v02_exact_frozen_case
from reproassert.benchmark_v02_execution_freeze import (
    verify_v02_exact_image_authorization,
    verify_v02_exact_image_execution_freeze,
)
from reproassert.benchmark_v02_hidden import verify_v02_hidden_gold
from reproassert.benchmark_v02_object_source import issue_v02_source_evidence_from_object_receipt
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory
from reproassert.semantic_issuer import derive_v02_generator_source_context

ALGORITHM = "reproassert-v02-exact-campaign-controller-progress-v1"
MAX_CONFIG_BYTES = 512 * 1024
MAX_PROGRESS_BYTES = 512 * 1024
MAX_IDENTITY_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_CAMPAIGN_MICROUSD = 5_000_000
MAX_CASE_MICROUSD = 250_000


@dataclass(frozen=True)
class ExactCampaignPaths:
    campaign_freeze: Path
    exact_preregistration: Path
    cases_preparation: Path
    cohort_plan: Path
    chronology: Path
    hidden_extraction_receipt: Path
    issue_responses_root: Path
    mapping_preparation: Path
    mapping_consensus: Path
    capability_index: Path
    runtime_manifest: Path
    runtime_manifest_sha256: str
    gold_smoke_receipt: Path
    gold_specs: Path
    execution_freeze: Path
    execution_authorization: Path
    ledger: Path
    attempts_root: Path
    progress: Path


@dataclass(frozen=True)
class ExactCampaignCase:
    case_id: str
    generator_projection: Path
    object_source_receipt: Path
    object_source_plan: Path
    source_evidence_receipt: Path
    object_source_receipt_sha256: str | None


@dataclass(frozen=True)
class ExactCampaignConfig:
    paths: ExactCampaignPaths
    cases: tuple[ExactCampaignCase, ...]
    executed_at: str
    tool_git_sha: str
    prepared_at: str | None = None
    bindings: Mapping[str, object] | None = None
    config_sha256: str | None = None
    raw_sha256: str | None = None


@dataclass(frozen=True)
class _CampaignLock:
    descriptor: int
    path: Path
    identity: Mapping[str, str]


class _Disposition(Protocol):
    @property
    def attempt_id(self) -> str: ...


class _Runtime(Protocol):
    def preflight(
        self, config: ExactCampaignConfig
    ) -> tuple[object, object, object, runner.V02ScoredRunPolicy]: ...
    def source_context(self, case: ExactCampaignCase) -> object: ...
    def generate(
        self,
        config: ExactCampaignConfig,
        case: ExactCampaignCase,
        context: object,
        policy: runner.V02ScoredRunPolicy,
    ) -> _Disposition: ...
    def recover(
        self,
        config: ExactCampaignConfig,
        case: ExactCampaignCase,
        context: object,
        attempt_id: str,
        policy: runner.V02ScoredRunPolicy,
    ) -> object: ...
    def freeze_barrier(
        self, config: ExactCampaignConfig, policy: runner.V02ScoredRunPolicy
    ) -> object: ...
    def evaluation_authorities(
        self, config: ExactCampaignConfig
    ) -> tuple[object, Mapping[str, object]]: ...
    def evaluate(
        self,
        config: ExactCampaignConfig,
        case: ExactCampaignCase,
        context: object,
        preregistration: object,
        barrier: object,
        hidden: object,
        capability: object,
        attempt_id: str,
        policy: runner.V02ScoredRunPolicy,
    ) -> object: ...


class _ProductionRuntime:
    def preflight(
        self, config: ExactCampaignConfig
    ) -> tuple[object, object, object, runner.V02ScoredRunPolicy]:
        paths = config.paths
        exact_preregistration = verify_v02_exact_preregistration(
            paths.exact_preregistration,
            cases_preparation_path=paths.cases_preparation,
            cohort_plan_path=paths.cohort_plan,
            chronology_path=paths.chronology,
            hidden_extraction_receipt=paths.hidden_extraction_receipt,
            issue_responses_root=paths.issue_responses_root,
            mapping_preparation_path=paths.mapping_preparation,
            mapping_consensus_path=paths.mapping_consensus,
            capability_index_path=paths.capability_index,
            runtime_manifest_path=paths.runtime_manifest,
            expected_runtime_manifest_sha256=paths.runtime_manifest_sha256,
            gold_smoke_receipt_path=paths.gold_smoke_receipt,
        )
        freeze = verify_v02_exact_image_execution_freeze(
            paths.execution_freeze,
            campaign_freeze_path=paths.campaign_freeze,
            preregistration_path=paths.exact_preregistration,
            cases_preparation_receipt=paths.cases_preparation,
            instance_runtime_manifest_path=paths.runtime_manifest,
            gold_smoke_receipt_path=paths.gold_smoke_receipt,
        )
        authorization = verify_v02_exact_image_authorization(
            paths.execution_authorization,
            execution_freeze_path=paths.execution_freeze,
            campaign_freeze_path=paths.campaign_freeze,
            preregistration_path=paths.exact_preregistration,
            cases_preparation_receipt=paths.cases_preparation,
            instance_runtime_manifest_path=paths.runtime_manifest,
            gold_smoke_receipt_path=paths.gold_smoke_receipt,
        )
        verify_v02_campaign_freeze(paths.campaign_freeze, paths.exact_preregistration)
        verify_v02_exact_image_capability_index(
            paths.capability_index,
            manifest_path=paths.runtime_manifest,
            expected_manifest_sha256=paths.runtime_manifest_sha256,
            gold_smoke_receipt_path=paths.gold_smoke_receipt,
            hidden_extraction_receipt=paths.hidden_extraction_receipt,
        )
        policy = _policy_from_exact_files(config, freeze, authorization)
        policy.require_executable()
        return exact_preregistration, freeze, authorization, policy

    def source_context(self, case: ExactCampaignCase) -> object:
        evidence = issue_v02_source_evidence_from_object_receipt(
            case.object_source_receipt,
            plan_path=case.object_source_plan,
            expected_case_id=case.case_id,
            source_evidence_receipt_path=case.source_evidence_receipt,
            expected_receipt_sha256=case.object_source_receipt_sha256,
        )
        return derive_v02_generator_source_context(evidence, case.generator_projection)

    def generate(
        self,
        config: ExactCampaignConfig,
        case: ExactCampaignCase,
        context: object,
        policy: runner.V02ScoredRunPolicy,
    ) -> _Disposition:
        paths = config.paths
        return runner.generate_v02_scored_case(
            preregistration_path=paths.exact_preregistration,
            campaign_freeze_path=paths.campaign_freeze,
            execution_authorization_path=paths.execution_authorization,
            exact_execution_freeze_path=paths.execution_freeze,
            exact_execution_freeze=self._freeze,
            exact_execution_authorization=self._authorization,
            case_id=case.case_id,
            generator_projection_path=case.generator_projection,
            generator_source_context=cast(Any, context),
            ledger_path=paths.ledger,
            attempt_directory=paths.attempts_root / case.case_id,
            policy=policy,
        )

    def recover(
        self,
        config: ExactCampaignConfig,
        case: ExactCampaignCase,
        context: object,
        attempt_id: str,
        policy: runner.V02ScoredRunPolicy,
    ) -> object:
        paths = config.paths
        return runner.recover_v02_scored_case(
            preregistration_path=paths.exact_preregistration,
            campaign_freeze_path=paths.campaign_freeze,
            execution_authorization_path=paths.execution_authorization,
            exact_execution_freeze_path=paths.execution_freeze,
            exact_execution_freeze=self._freeze,
            exact_execution_authorization=self._authorization,
            case_id=case.case_id,
            generator_projection_path=case.generator_projection,
            generator_source_context=cast(Any, context),
            ledger_path=paths.ledger,
            attempt_directory=paths.attempts_root / case.case_id,
            attempt_id=attempt_id,
            policy=policy,
        )

    def freeze_barrier(
        self, config: ExactCampaignConfig, policy: runner.V02ScoredRunPolicy
    ) -> object:
        return runner.freeze_v02_campaign_generation_barrier(
            preregistration_path=config.paths.exact_preregistration,
            ledger_path=config.paths.ledger,
            policy=policy,
        )

    def evaluation_authorities(
        self, config: ExactCampaignConfig
    ) -> tuple[object, Mapping[str, object]]:
        paths = config.paths
        hidden = verify_v02_hidden_gold(paths.hidden_extraction_receipt)
        capabilities = {
            case.case_id: issue_verified_v02_exact_image_evaluator_capability(
                manifest_path=paths.runtime_manifest,
                expected_manifest_sha256=paths.runtime_manifest_sha256,
                gold_smoke_receipt_path=paths.gold_smoke_receipt,
                verified_hidden=hidden,
                case_id=case.case_id,
            )
            for case in config.cases
        }
        return hidden, capabilities

    def evaluate(
        self,
        config: ExactCampaignConfig,
        case: ExactCampaignCase,
        context: object,
        preregistration: object,
        barrier: object,
        hidden: object,
        capability: object,
        attempt_id: str,
        policy: runner.V02ScoredRunPolicy,
    ) -> object:
        paths = config.paths
        return evaluate_v02_exact_frozen_case(
            preregistration_path=paths.exact_preregistration,
            exact_preregistration=cast(Any, preregistration),
            case_id=case.case_id,
            generator_projection_path=case.generator_projection,
            generator_source_context=cast(Any, context),
            campaign_barrier=cast(Any, barrier),
            evaluator_capability=cast(Any, capability),
            verified_hidden=cast(Any, hidden),
            manifest_path=paths.runtime_manifest,
            expected_manifest_sha256=paths.runtime_manifest_sha256,
            gold_smoke_receipt_path=paths.gold_smoke_receipt,
            gold_specs_path=paths.gold_specs,
            ledger_path=paths.ledger,
            attempt_directory=paths.attempts_root / case.case_id,
            attempt_id=attempt_id,
            executed_at=config.executed_at,
            tool_git_sha=config.tool_git_sha,
            policy=policy,
        )

    def bind(self, freeze: object, authorization: object) -> None:
        self._freeze = freeze
        self._authorization = authorization


def run_v02_exact_campaign(config_path: Path) -> dict[str, object]:
    """Run or safely resume the exact 20-case campaign from one strict private config."""

    from reproassert.benchmark_v02_exact_campaign_config import (
        require_v02_exact_campaign_config,
        verify_v02_exact_campaign_config,
    )

    authority = require_v02_exact_campaign_config(verify_v02_exact_campaign_config(config_path))
    config = load_v02_exact_campaign_config(config_path, expected_sha256=authority.sha256)
    if (
        config.config_sha256 != authority.config_sha256
        or config.tool_git_sha != authority.tool_git_sha
        or config.bindings is None
        or config.bindings.get("campaign_id") != authority.campaign_id
    ):
        raise _reject("Fresh config authority differs from the exact controller config.")
    runtime = _ProductionRuntime()
    return _run_with_runtime(config, runtime)


def _run_with_runtime(config: ExactCampaignConfig, runtime: _Runtime) -> dict[str, object]:
    paths = config.paths
    require_private_directory(paths.attempts_root)
    require_private_directory(paths.progress.parent)
    identity = _controller_identity(config)
    lock = _acquire_campaign_lock(config, identity)
    try:
        state = _load_or_initialize_progress(config, identity)
        try:
            preregistration, freeze, authorization, policy = runtime.preflight(config)
            _cross_bind_verified_campaign(identity, preregistration, freeze, authorization, policy)
            if isinstance(runtime, _ProductionRuntime):
                runtime.bind(freeze, authorization)
            _audit_caps(paths.ledger, allow_missing=True)
            state["status"] = "running"
            state.pop("error", None)
            state["phase"] = "generation"
            _write_progress(paths.progress, state)
            contexts: dict[str, object] = {}
            for case in config.cases:
                contexts[case.case_id] = runtime.source_context(case)
                attempts = _attempts(paths.ledger)
                attempt = attempts.get(case.case_id)
                if attempt is None:
                    _audit_caps(paths.ledger, allow_missing=True)
                    disposition = runtime.generate(config, case, contexts[case.case_id], policy)
                    attempt_id = disposition.attempt_id
                elif attempt["disposition"]:
                    attempt_id = cast(str, attempt["attempt_id"])
                else:
                    attempt_id = cast(str, attempt["attempt_id"])
                    runtime.recover(config, case, contexts[case.case_id], attempt_id, policy)
                _audit_caps(paths.ledger)
                _mark_case(state, case.case_id, "generation_frozen", attempt_id)
                _write_progress(paths.progress, state)

            barrier = runtime.freeze_barrier(config, policy)
            state["phase"] = "evaluation"
            state["generation_barrier_sha256"] = getattr(barrier, "sha256", None)
            _write_progress(paths.progress, state)
            hidden, capabilities = runtime.evaluation_authorities(config)
            for case in config.cases:
                attempt = _attempts(paths.ledger)[case.case_id]
                attempt_id = cast(str, attempt["attempt_id"])
                runtime.evaluate(
                    config,
                    case,
                    contexts[case.case_id],
                    preregistration,
                    barrier,
                    hidden,
                    capabilities[case.case_id],
                    attempt_id,
                    policy,
                )
                _audit_caps(paths.ledger)
                _mark_case(state, case.case_id, "evaluated", attempt_id)
                _write_progress(paths.progress, state)
            state["phase"] = "complete"
            state["status"] = "complete"
            state["spend"] = _audit_caps(paths.ledger)
            _write_progress(paths.progress, state)
            return state
        except BaseException as exc:
            state["status"] = "halted"
            state["error"] = {"type": type(exc).__name__, "message": str(exc)[:1000]}
            _write_progress(paths.progress, state)
            raise
    finally:
        _release_campaign_lock(lock)


def load_v02_exact_campaign_config(
    path: Path, *, expected_sha256: str | None = None
) -> ExactCampaignConfig:
    with open_regular_file(Path(path)) as stream:
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and raw_sha256 != _sha256(expected_sha256, "expected config"):
        raise _reject("Exact campaign config changed after fresh verification.")
    if len(raw) > MAX_CONFIG_BYTES:
        raise _reject("Exact campaign config exceeds its size limit.")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _reject("Exact campaign config is invalid JSON.") from exc
    if not isinstance(value, dict) or set(value) != {
        "algorithm",
        "bindings",
        "cases",
        "claims",
        "config_sha256",
        "executed_at",
        "paths",
        "prepared_at",
        "schema_version",
        "tool_git_sha",
    }:
        raise _reject("Exact campaign config fields are invalid.")
    from reproassert.benchmark_v02_exact_campaign_config import (
        CONFIG_ALGORITHM,
        CONFIG_SCHEMA_VERSION,
        config_self_hash,
        validate_config_bindings,
    )

    if (
        value.get("algorithm") != CONFIG_ALGORITHM
        or value.get("schema_version") != CONFIG_SCHEMA_VERSION
        or value.get("claims")
        != {
            "credentials_read": False,
            "provider_calls": 0,
            "provider_invoked_by_this_command": False,
        }
        or value.get("config_sha256") != config_self_hash(value)
    ):
        raise _reject("Exact campaign config identity is invalid.")
    bindings = validate_config_bindings(value.get("bindings"))
    path_values = _mapping(value["paths"], "paths")
    expected_paths = set(ExactCampaignPaths.__dataclass_fields__)
    if set(path_values) != expected_paths:
        raise _reject("Exact campaign path fields are invalid.")
    paths = ExactCampaignPaths(
        campaign_freeze=_absolute_path(path_values["campaign_freeze"], "campaign_freeze"),
        exact_preregistration=_absolute_path(
            path_values["exact_preregistration"], "exact_preregistration"
        ),
        cases_preparation=_absolute_path(path_values["cases_preparation"], "cases_preparation"),
        cohort_plan=_absolute_path(path_values["cohort_plan"], "cohort_plan"),
        chronology=_absolute_path(path_values["chronology"], "chronology"),
        hidden_extraction_receipt=_absolute_path(
            path_values["hidden_extraction_receipt"], "hidden_extraction_receipt"
        ),
        issue_responses_root=_absolute_path(
            path_values["issue_responses_root"], "issue_responses_root"
        ),
        mapping_preparation=_absolute_path(
            path_values["mapping_preparation"], "mapping_preparation"
        ),
        mapping_consensus=_absolute_path(path_values["mapping_consensus"], "mapping_consensus"),
        capability_index=_absolute_path(path_values["capability_index"], "capability_index"),
        runtime_manifest=_absolute_path(path_values["runtime_manifest"], "runtime_manifest"),
        runtime_manifest_sha256=_sha256(
            path_values["runtime_manifest_sha256"], "runtime_manifest_sha256"
        ),
        gold_smoke_receipt=_absolute_path(path_values["gold_smoke_receipt"], "gold_smoke_receipt"),
        gold_specs=_absolute_path(path_values["gold_specs"], "gold_specs"),
        execution_freeze=_absolute_path(path_values["execution_freeze"], "execution_freeze"),
        execution_authorization=_absolute_path(
            path_values["execution_authorization"], "execution_authorization"
        ),
        ledger=_absolute_path(path_values["ledger"], "ledger"),
        attempts_root=_absolute_path(path_values["attempts_root"], "attempts_root"),
        progress=_absolute_path(path_values["progress"], "progress"),
    )
    rows = value["cases"]
    if not isinstance(rows, list) or len(rows) != 20:
        raise _reject("Exact campaign config requires exactly 20 cases.")
    cases: list[ExactCampaignCase] = []
    expected_case_fields = set(ExactCampaignCase.__dataclass_fields__)
    for index, item in enumerate(rows, 1):
        row = _mapping(item, "case")
        if set(row) != expected_case_fields or row.get("case_id") != f"rk-v0.2-{index:03d}":
            raise _reject("Exact campaign cases must be complete and canonically ordered.")
        cases.append(
            ExactCampaignCase(
                case_id=cast(str, row["case_id"]),
                generator_projection=_absolute_path(row["generator_projection"], "projection"),
                object_source_receipt=_absolute_path(
                    row["object_source_receipt"], "object receipt"
                ),
                object_source_plan=_absolute_path(row["object_source_plan"], "object plan"),
                source_evidence_receipt=_absolute_path(
                    row["source_evidence_receipt"], "source evidence"
                ),
                object_source_receipt_sha256=(
                    None
                    if row["object_source_receipt_sha256"] is None
                    else _sha256(row["object_source_receipt_sha256"], "object receipt")
                ),
            )
        )
    return ExactCampaignConfig(
        paths=paths,
        cases=tuple(cases),
        executed_at=_timestamp(value["executed_at"], "executed_at"),
        tool_git_sha=_git_sha(value["tool_git_sha"], "tool_git_sha"),
        prepared_at=_timestamp(value["prepared_at"], "prepared_at"),
        bindings=bindings,
        config_sha256=cast(str, value["config_sha256"]),
        raw_sha256=raw_sha256,
    )


def _policy_from_exact_files(
    config: ExactCampaignConfig, freeze_authority: object, authorization_authority: object
) -> runner.V02ScoredRunPolicy:
    freeze = _load_object(config.paths.execution_freeze)
    authorization = _load_object(config.paths.execution_authorization)
    if (
        getattr(freeze_authority, "max_campaign_microusd", None) != MAX_CAMPAIGN_MICROUSD
        or getattr(freeze_authority, "max_case_microusd", None) != MAX_CASE_MICROUSD
        or getattr(authorization_authority, "execution_freeze_sha256", None)
        != getattr(freeze_authority, "sha256", None)
    ):
        raise _reject("Exact verifier authorities do not preserve the hard caps.")
    execution = _mapping(freeze["execution"], "execution")
    pricing = runner._pricing_from_record(_mapping(freeze["pricing_snapshot"], "pricing"))
    approval = _mapping(authorization["authorization"], "authorization")
    reservations = cast(list[Mapping[str, object]], execution["reservations"])
    if freeze.get("controller_git_sha") != config.tool_git_sha:
        raise _reject("Controller config differs from the exact frozen tool Git SHA.")
    executed = datetime.fromisoformat(config.executed_at[:-1] + "+00:00")
    authorized = datetime.fromisoformat(cast(str, approval["authorized_at"])[:-1] + "+00:00")
    if executed < authorized or executed > datetime.now(timezone.utc):
        raise _reject("Controller execution timestamp must be post-authorization and not future.")
    return runner.V02ScoredRunPolicy(
        campaign_id=cast(str, authorization["campaign_id"]),
        campaign_freeze_sha256=cast(
            str, _mapping(freeze["campaign"], "campaign")["campaign_freeze_sha256"]
        ),
        execution_authorization_sha256=cast(Any, authorization_authority).sha256,
        authorization_text_sha256=cast(str, approval["approval_statement_sha256"]),
        authorized_at=cast(str, approval["authorized_at"]),
        request_set_sha256=cast(str, authorization["request_set_sha256"]),
        tool_git_sha=cast(str, freeze["controller_git_sha"]),
        authorization_status="explicit_user_approval",
        authorization_ref=cast(str, approval["approval_ref"]),
        generator_mode="trusted_builtin_provider_adapter",
        provider=cast(str, authorization["provider"]),
        requested_model=cast(str, authorization["requested_model"]),
        pricing=pricing,
        reserved_worst_case_microusd=max(
            cast(int, row["worst_case_microusd"]) for row in reservations
        ),
        max_case_attributable_microusd=MAX_CASE_MICROUSD,
        max_campaign_attributable_microusd=MAX_CAMPAIGN_MICROUSD,
        max_case_wall_ms=cast(int, execution["max_case_wall_ms"]),
        provider_timeout_seconds=cast(int, execution["provider_timeout_ms"]) / 1000,
    )


def _attempts(ledger: Path) -> dict[str, dict[str, object]]:
    if not ledger.exists():
        return {}
    snapshot = runner.read_v02_scored_ledger(ledger)
    attempts: dict[str, dict[str, object]] = {}
    for event in snapshot.events:
        if event["event_type"] == "attempt_started":
            case_id = cast(
                str, _mapping(_mapping(event["payload"], "payload")["case"], "case")["id"]
            )
            if case_id in attempts:
                raise _reject(f"Multiple attempts exist for {case_id}; refusing unsafe resume.")
            attempts[case_id] = {"attempt_id": event["attempt_id"], "disposition": False}
        elif event["event_type"] == "generation_disposition_frozen":
            match = next(
                (row for row in attempts.values() if row["attempt_id"] == event["attempt_id"]), None
            )
            if match is None or match["disposition"]:
                raise _reject("Generation disposition has no unique attempt.")
            match["disposition"] = True
    return attempts


def _audit_caps(ledger: Path, *, allow_missing: bool = False) -> dict[str, object]:
    if not ledger.exists():
        if allow_missing:
            return {"campaign_microusd": 0, "case_microusd": {}}
        raise _reject("Campaign ledger is missing.")
    snapshot = runner.read_v02_scored_ledger(ledger)
    attempt_cases = {
        cast(str, event["attempt_id"]): cast(
            str, _mapping(_mapping(event["payload"], "payload")["case"], "case")["id"]
        )
        for event in snapshot.events
        if event["event_type"] == "attempt_started"
    }
    totals: defaultdict[str, int] = defaultdict(int)
    for event in snapshot.events:
        if event["event_type"] != "cost_recorded":
            continue
        amount = _mapping(event["payload"], "cost").get("amount_microusd")
        if type(amount) is not int or amount < 0:
            raise _reject("Unknown or invalid campaign cost; execution is halted.")
        case_id = attempt_cases.get(cast(str, event["attempt_id"]))
        if case_id is None:
            raise _reject("Campaign cost is not bound to a known case.")
        totals[case_id] += amount
    if any(total > MAX_CASE_MICROUSD for total in totals.values()):
        raise _reject("Observed case spend exceeds the hard USD 0.25 cap.")
    campaign_total = sum(totals.values())
    if campaign_total > MAX_CAMPAIGN_MICROUSD:
        raise _reject("Observed campaign spend exceeds the hard USD 5.00 cap.")
    return {"campaign_microusd": campaign_total, "case_microusd": dict(sorted(totals.items()))}


def _controller_identity(config: ExactCampaignConfig) -> dict[str, str]:
    authorization = _load_object(config.paths.execution_authorization)
    campaign_id = authorization.get("campaign_id")
    if (
        not isinstance(campaign_id, str)
        or not 3 <= len(campaign_id) <= 200
        or not campaign_id.isprintable()
    ):
        raise _reject("Exact execution authorization campaign identity is invalid.")
    config_record = {
        "paths": {
            name: (value if name == "runtime_manifest_sha256" else os.fspath(cast(Path, value)))
            for name, value in vars(config.paths).items()
        },
        "cases": [
            {
                "case_id": case.case_id,
                "generator_projection": os.fspath(case.generator_projection),
                "object_source_receipt": os.fspath(case.object_source_receipt),
                "object_source_plan": os.fspath(case.object_source_plan),
                "source_evidence_receipt": os.fspath(case.source_evidence_receipt),
                "object_source_receipt_sha256": case.object_source_receipt_sha256,
            }
            for case in config.cases
        ],
        "executed_at": config.executed_at,
        "tool_git_sha": config.tool_git_sha,
        "prepared_at": config.prepared_at,
        "bindings": config.bindings,
        "config_sha256": config.config_sha256,
        "raw_sha256": config.raw_sha256,
    }
    return {
        "campaign_id": campaign_id,
        "config_sha256": hashlib.sha256(_canonical(config_record)).hexdigest(),
        "execution_authorization_sha256": _file_sha256(config.paths.execution_authorization),
        "exact_preregistration_sha256": _file_sha256(config.paths.exact_preregistration),
    }


def _acquire_campaign_lock(
    config: ExactCampaignConfig, identity: Mapping[str, str]
) -> _CampaignLock:
    lock_path = config.paths.progress.parent / ".reproassert-v02-exact-campaign-controller.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise _reject("Cannot safely open the exact campaign controller lock.") from exc
    try:
        metadata = os.fstat(descriptor)
        owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not owner_ok
        ):
            raise _reject("Exact campaign controller lock metadata is unsafe.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise _reject(
                    "Another exact campaign controller invocation owns the lock."
                ) from exc
            raise
        raw = _read_fd(descriptor, MAX_PROGRESS_BYTES)
        expected = {
            "algorithm": "reproassert-v02-exact-campaign-controller-lock-v1",
            "identity": dict(identity),
        }
        if raw:
            if _decode_canonical(raw, "campaign controller lock") != expected:
                raise _reject("Campaign controller lock identity differs from this config.")
        else:
            os.lseek(descriptor, 0, os.SEEK_SET)
            _write_fd(descriptor, _canonical(expected) + b"\n")
            os.fsync(descriptor)
            _fsync_directory(lock_path.parent)
        return _CampaignLock(descriptor=descriptor, path=lock_path, identity=dict(identity))
    except BaseException:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        raise


def _release_campaign_lock(lock: _CampaignLock) -> None:
    try:
        fcntl.flock(lock.descriptor, fcntl.LOCK_UN)
    finally:
        os.close(lock.descriptor)


def _cross_bind_verified_campaign(
    identity: Mapping[str, str],
    preregistration: object,
    freeze: object,
    authorization: object,
    policy: runner.V02ScoredRunPolicy,
) -> None:
    campaign_id = getattr(freeze, "campaign_id", None)
    if campaign_id is None:
        campaign_id = getattr(policy, "campaign_id", None)
    if (
        campaign_id != identity["campaign_id"]
        or getattr(preregistration, "sha256", None) != identity["exact_preregistration_sha256"]
        or getattr(authorization, "sha256", None) != identity["execution_authorization_sha256"]
    ):
        raise _reject("Freshly verified evidence differs from the controller lock identity.")


def _load_or_initialize_progress(
    config: ExactCampaignConfig, identity: Mapping[str, str]
) -> dict[str, object]:
    path = config.paths.progress
    if not path.exists():
        if path.is_symlink():
            raise _reject("Exact campaign progress path is an unsafe symlink.")
        return _initial_progress(config, identity)
    with open_regular_file(path) as stream:
        raw = stream.read(MAX_PROGRESS_BYTES + 1)
    if len(raw) > MAX_PROGRESS_BYTES:
        raise _reject("Exact campaign progress exceeds its size limit.")
    observed = _decode_canonical(raw, "campaign progress")
    if observed.get("algorithm") != ALGORITHM or observed.get("identity") != dict(identity):
        raise _reject("Existing campaign progress identity differs from this exact config.")
    limits = {
        "max_campaign_microusd": MAX_CAMPAIGN_MICROUSD,
        "max_case_microusd": MAX_CASE_MICROUSD,
        "overage_permitted": False,
    }
    if observed.get("limits") != limits:
        raise _reject("Existing campaign progress limits are invalid.")
    cases = observed.get("cases")
    expected_ids = [case.case_id for case in config.cases]
    if not isinstance(cases, dict) or list(cases) != expected_ids:
        raise _reject("Existing campaign progress denominator is invalid.")
    for case_id, row in cases.items():
        if (
            not isinstance(row, dict)
            or set(row) != {"attempt_id", "status"}
            or row.get("status") not in {"pending", "generation_frozen", "evaluated"}
            or (
                row.get("attempt_id") is not None
                and (not isinstance(row.get("attempt_id"), str) or not row["attempt_id"])
            )
        ):
            raise _reject(f"Existing campaign progress row for {case_id} is invalid.")
    if observed.get("status") not in {"running", "halted", "complete"}:
        raise _reject("Existing campaign progress status is invalid.")
    return dict(observed)


def _initial_progress(
    config: ExactCampaignConfig, identity: Mapping[str, str]
) -> dict[str, object]:
    return {
        "algorithm": ALGORITHM,
        "identity": dict(identity),
        "status": "running",
        "phase": "preflight",
        "cases": {case.case_id: {"status": "pending", "attempt_id": None} for case in config.cases},
        "limits": {
            "max_campaign_microusd": MAX_CAMPAIGN_MICROUSD,
            "max_case_microusd": MAX_CASE_MICROUSD,
            "overage_permitted": False,
        },
    }


def _mark_case(state: dict[str, object], case_id: str, status: str, attempt_id: str) -> None:
    cases = cast(dict[str, dict[str, object]], state["cases"])
    cases[case_id] = {"status": status, "attempt_id": attempt_id}


def _write_progress(path: Path, value: Mapping[str, object]) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(encoded) > MAX_PROGRESS_BYTES:
        raise _reject("Exact campaign progress exceeds its size limit.")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        _write_fd(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise


def _write_fd(descriptor: int, encoded: bytes) -> None:
    view = memoryview(encoded)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("Unable to persist exact campaign controller state.")
        view = view[written:]


def _read_fd(descriptor: int, limit: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, limit + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise _reject("Exact campaign controller state exceeds its size limit.")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _load_object(path: Path) -> dict[str, object]:
    with open_regular_file(path) as stream:
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise _reject("Exact campaign artifact exceeds its size limit.")
    return _decode_canonical(raw, "artifact")


def _file_sha256(path: Path) -> str:
    with open_regular_file(path) as stream:
        raw = stream.read(MAX_IDENTITY_ARTIFACT_BYTES + 1)
    if len(raw) > MAX_IDENTITY_ARTIFACT_BYTES:
        raise _reject("Exact campaign identity artifact exceeds its size limit.")
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _decode_canonical(raw: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _reject(f"Exact campaign {label} is invalid JSON.") from exc
    if not isinstance(value, dict) or raw != _canonical(value) + b"\n":
        raise _reject(f"Exact campaign {label} is not canonical JSON.")
    return cast(dict[str, object], value)


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise _reject(f"Exact campaign {label} must be an object.")
    return cast(Mapping[str, object], value)


def _absolute_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise _reject(f"Exact campaign {label} must be an absolute path.")
    return Path(value)


def _sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise _reject(f"Exact campaign {label} SHA-256 is invalid.")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 200 or not value.isprintable():
        raise _reject(f"Exact campaign {label} is invalid.")
    return value


def _git_sha(value: object, label: str) -> str:
    text = _text(value, label)
    if len(text) != 40 or any(character not in "0123456789abcdef" for character in text):
        raise _reject(f"Exact campaign {label} Git SHA is invalid.")
    return text


def _timestamp(value: object, label: str) -> str:
    text = _text(value, label)
    if not text.endswith("Z"):
        raise _reject(f"Exact campaign {label} timestamp is invalid.")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise _reject(f"Exact campaign {label} timestamp is invalid.") from exc
    if parsed.tzinfo != timezone.utc:
        raise _reject(f"Exact campaign {label} timestamp is invalid.")
    return text


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("v02_exact_campaign_controller", message)
