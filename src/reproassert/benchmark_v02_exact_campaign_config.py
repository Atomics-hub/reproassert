"""Provider-free builder and verifier for the exact v0.2 campaign config."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from reproassert.benchmark_v02_campaign import verify_v02_campaign_freeze
from reproassert.benchmark_v02_cases import verify_v02_cases
from reproassert.benchmark_v02_exact_campaign_controller import (
    ExactCampaignCase,
    ExactCampaignConfig,
    load_v02_exact_campaign_config,
)
from reproassert.benchmark_v02_exact_capability import (
    verify_v02_exact_image_capability_index,
)
from reproassert.benchmark_v02_exact_preregistration import (
    verify_v02_exact_preregistration,
)
from reproassert.benchmark_v02_execution_freeze import (
    MAX_CAMPAIGN_MICROUSD,
    MAX_CASE_MICROUSD,
    verify_v02_exact_image_authorization,
    verify_v02_exact_image_execution_freeze,
)
from reproassert.benchmark_v02_object_source import (
    issue_v02_source_evidence_from_object_receipt,
)
from reproassert.benchmark_v02_package import _require_outside_source_checkout
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

CONFIG_ALGORITHM = "reproassert-v02-exact-campaign-config-v1"
CONFIG_SCHEMA_VERSION = "1.0.0"
CONFIG_FILENAME = "config.json"
MAX_CONFIG_BYTES = 512 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_ISSUER = object()


@dataclass(frozen=True)
class ExactCampaignConfigInputs:
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


@dataclass(frozen=True, init=False)
class VerifiedExactCampaignConfig:
    path: Path
    sha256: str
    config_sha256: str
    campaign_id: str
    case_count: int
    requested_model: str
    tool_git_sha: str
    max_campaign_microusd: int
    max_case_microusd: int
    provider_calls: int
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedExactCampaignConfig is verifier-issued only")

    def summary(self) -> dict[str, object]:
        return {
            "campaign_id": self.campaign_id,
            "case_count": self.case_count,
            "config": str(self.path),
            "config_sha256": self.config_sha256,
            "credentials_read": False,
            "max_campaign_microusd": self.max_campaign_microusd,
            "max_case_microusd": self.max_case_microusd,
            "provider_calls": self.provider_calls,
            "provider_execution_enabled": False,
            "requested_model": self.requested_model,
            "status": "verified_ready_for_explicit_campaign_execution",
            "tool_git_sha": self.tool_git_sha,
        }


def prepare_v02_exact_campaign_config(
    *,
    inputs: ExactCampaignConfigInputs,
    output_root: Path,
    prepared_at: str,
    executed_at: str,
    tool_git_sha: str,
) -> VerifiedExactCampaignConfig:
    """Atomically create one private, provider-disabled exact campaign workspace."""

    destination = _output_root(output_root)
    prepared = _timestamp(prepared_at, "config preparation time")
    executed = _timestamp(executed_at, "campaign execution time")
    tool_sha = _git_sha(tool_git_sha, "tool Git SHA")
    if _timestamp_value(prepared) > _timestamp_value(executed):
        raise _reject("Config preparation time cannot follow campaign execution time.")

    parent = destination.parent
    require_private_directory(parent)
    _require_outside_source_checkout(parent)
    config_destination = destination / "controller" / CONFIG_FILENAME
    if destination.exists() or destination.is_symlink():
        verified = verify_v02_exact_campaign_config(config_destination)
        existing = load_v02_exact_campaign_config(
            config_destination, expected_sha256=verified.sha256
        )
        if (
            existing.prepared_at != prepared
            or existing.executed_at != executed
            or existing.tool_git_sha != tool_sha
            or existing.config_sha256 != verified.config_sha256
            or existing.bindings is None
            or existing.bindings.get("campaign_id") != verified.campaign_id
            or _inputs_from_paths(existing) != _resolved_inputs(inputs)
        ):
            raise _reject(
                "Existing exact campaign workspace differs; mutable run state is never overwritten."
            )
        return verified
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=parent))
    os.chmod(staging, 0o700, follow_symlinks=False)
    try:
        for name in ("attempts", "controller", "ledger", "source-evidence"):
            child = staging / name
            child.mkdir(mode=0o700)
            os.chmod(child, 0o700, follow_symlinks=False)

        final_source_root = destination / "source-evidence"
        staged_source_root = staging / "source-evidence"
        paths, cases, bindings = _derive(
            inputs=_resolved_inputs(inputs),
            campaign_root=destination,
            source_evidence_write_root=staged_source_root,
            source_evidence_config_root=final_source_root,
            prepared_at=prepared,
            executed_at=executed,
            tool_git_sha=tool_sha,
        )
        record = _record(paths, cases, bindings, prepared, executed, tool_sha)
        record["config_sha256"] = config_self_hash(record)
        encoded = _canonical(record) + b"\n"
        if len(encoded) > MAX_CONFIG_BYTES:
            raise _reject("Exact campaign config exceeds its size limit.")
        write_bytes_exclusive(staging / "controller" / CONFIG_FILENAME, encoded)
        for name in ("attempts", "controller", "ledger", "source-evidence"):
            _fsync_directory(staging / name)
        _fsync_directory(staging)
        os.replace(staging, destination)
        _fsync_directory(parent)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return verify_v02_exact_campaign_config(config_destination)


def verify_v02_exact_campaign_config(path: Path) -> VerifiedExactCampaignConfig:
    """Freshly rederive all exact authorities, paths, case bindings, and hard caps."""

    requested_path = Path(path)
    if requested_path.is_symlink():
        raise _reject("Exact campaign config cannot be a symlink.")
    config_path = requested_path.resolve(strict=True)
    require_private_directory(config_path.parent)
    run_root = config_path.parent.parent
    require_private_directory(run_root)
    for name in ("attempts", "controller", "ledger", "source-evidence"):
        require_private_directory(run_root / name)
    config = load_v02_exact_campaign_config(config_path)
    if config.prepared_at is None or config.bindings is None or config.config_sha256 is None:
        raise _reject("Exact campaign config lacks preparation bindings.")
    inputs = ExactCampaignConfigInputs(
        campaign_freeze=config.paths.campaign_freeze,
        exact_preregistration=config.paths.exact_preregistration,
        cases_preparation=config.paths.cases_preparation,
        cohort_plan=config.paths.cohort_plan,
        chronology=config.paths.chronology,
        hidden_extraction_receipt=config.paths.hidden_extraction_receipt,
        issue_responses_root=config.paths.issue_responses_root,
        mapping_preparation=config.paths.mapping_preparation,
        mapping_consensus=config.paths.mapping_consensus,
        capability_index=config.paths.capability_index,
        runtime_manifest=config.paths.runtime_manifest,
        runtime_manifest_sha256=config.paths.runtime_manifest_sha256,
        gold_smoke_receipt=config.paths.gold_smoke_receipt,
        gold_specs=config.paths.gold_specs,
        execution_freeze=config.paths.execution_freeze,
        execution_authorization=config.paths.execution_authorization,
    )
    expected_paths, expected_cases, expected_bindings = _derive(
        inputs=_resolved_inputs(inputs),
        campaign_root=run_root,
        source_evidence_write_root=None,
        source_evidence_config_root=config_path.parent.parent / "source-evidence",
        prepared_at=config.prepared_at,
        executed_at=config.executed_at,
        tool_git_sha=config.tool_git_sha,
    )
    if config.paths != expected_paths or config.cases != expected_cases:
        raise _reject("Exact campaign config paths differ from canonical verified artifacts.")
    if dict(config.bindings) != expected_bindings:
        raise _reject("Exact campaign config bindings differ from fresh verifier authorities.")
    if config.raw_sha256 is None:
        raise _reject("Exact campaign config lacks its raw-byte binding.")
    return _issue_verified(
        {
            "path": config_path,
            "sha256": config.raw_sha256,
            "config_sha256": config.config_sha256,
            "campaign_id": cast(str, expected_bindings["campaign_id"]),
            "case_count": 20,
            "requested_model": cast(str, expected_bindings["requested_model"]),
            "tool_git_sha": config.tool_git_sha,
            "max_campaign_microusd": MAX_CAMPAIGN_MICROUSD,
            "max_case_microusd": MAX_CASE_MICROUSD,
            "provider_calls": 0,
            "_issuer": _ISSUER,
        }
    )


def config_self_hash(value: Mapping[str, object]) -> str:
    unsigned = dict(value)
    unsigned.pop("config_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def require_v02_exact_campaign_config(value: object) -> VerifiedExactCampaignConfig:
    """Require a fresh verifier-issued exact campaign-config authority."""

    if type(value) is not VerifiedExactCampaignConfig or value._issuer is not _ISSUER:
        raise _reject("Fresh verifier-issued exact campaign config is required.")
    return value


def validate_config_bindings(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "artifact_sha256",
        "authorization_at",
        "campaign_id",
        "case_binding_set_sha256",
        "execution_freeze_sha256",
        "max_campaign_microusd",
        "max_case_microusd",
        "overage_permitted",
        "provider",
        "requested_model",
        "request_set_sha256",
    }:
        raise _reject("Exact campaign config binding fields are invalid.")
    artifacts = value.get("artifact_sha256")
    if (
        not isinstance(artifacts, dict)
        or not artifacts
        or any(
            not isinstance(name, str) or _SHA256.fullmatch(str(digest)) is None
            for name, digest in artifacts.items()
        )
    ):
        raise _reject("Exact campaign artifact bindings are invalid.")
    if (
        not isinstance(value.get("campaign_id"), str)
        or _SHA256.fullmatch(str(value.get("case_binding_set_sha256"))) is None
        or _SHA256.fullmatch(str(value.get("execution_freeze_sha256"))) is None
        or _SHA256.fullmatch(str(value.get("request_set_sha256"))) is None
        or value.get("max_campaign_microusd") != MAX_CAMPAIGN_MICROUSD
        or value.get("max_case_microusd") != MAX_CASE_MICROUSD
        or value.get("overage_permitted") is not False
        or value.get("provider") != "openai"
        or not isinstance(value.get("requested_model"), str)
    ):
        raise _reject("Exact campaign authority bindings are invalid.")
    _timestamp(value.get("authorization_at"), "authorization time")
    return cast(Mapping[str, object], value)


def _derive(
    *,
    inputs: ExactCampaignConfigInputs,
    campaign_root: Path,
    source_evidence_write_root: Path | None,
    source_evidence_config_root: Path,
    prepared_at: str,
    executed_at: str,
    tool_git_sha: str,
) -> tuple[Any, tuple[ExactCampaignCase, ...], dict[str, object]]:
    from reproassert.benchmark_v02_exact_campaign_controller import ExactCampaignPaths

    prepared = verify_v02_cases(inputs.cases_preparation)
    preregistration = verify_v02_exact_preregistration(
        inputs.exact_preregistration,
        cases_preparation_path=inputs.cases_preparation,
        cohort_plan_path=inputs.cohort_plan,
        chronology_path=inputs.chronology,
        hidden_extraction_receipt=inputs.hidden_extraction_receipt,
        issue_responses_root=inputs.issue_responses_root,
        mapping_preparation_path=inputs.mapping_preparation,
        mapping_consensus_path=inputs.mapping_consensus,
        capability_index_path=inputs.capability_index,
        runtime_manifest_path=inputs.runtime_manifest,
        expected_runtime_manifest_sha256=inputs.runtime_manifest_sha256,
        gold_smoke_receipt_path=inputs.gold_smoke_receipt,
    )
    campaign = verify_v02_campaign_freeze(inputs.campaign_freeze, inputs.exact_preregistration)
    capability = verify_v02_exact_image_capability_index(
        inputs.capability_index,
        manifest_path=inputs.runtime_manifest,
        expected_manifest_sha256=inputs.runtime_manifest_sha256,
        gold_smoke_receipt_path=inputs.gold_smoke_receipt,
        hidden_extraction_receipt=inputs.hidden_extraction_receipt,
    )
    freeze = verify_v02_exact_image_execution_freeze(
        inputs.execution_freeze,
        campaign_freeze_path=inputs.campaign_freeze,
        preregistration_path=inputs.exact_preregistration,
        cases_preparation_receipt=inputs.cases_preparation,
        instance_runtime_manifest_path=inputs.runtime_manifest,
        gold_smoke_receipt_path=inputs.gold_smoke_receipt,
    )
    authorization = verify_v02_exact_image_authorization(
        inputs.execution_authorization,
        execution_freeze_path=inputs.execution_freeze,
        campaign_freeze_path=inputs.campaign_freeze,
        preregistration_path=inputs.exact_preregistration,
        cases_preparation_receipt=inputs.cases_preparation,
        instance_runtime_manifest_path=inputs.runtime_manifest,
        gold_smoke_receipt_path=inputs.gold_smoke_receipt,
    )
    if (
        prepared.case_count != 20
        or preregistration.case_count != 20
        or len(campaign.case_ids) != 20
        or capability.case_count != 20
        or freeze.campaign_id != campaign.campaign_id
        or authorization.campaign_id != campaign.campaign_id
        or freeze.max_campaign_microusd != MAX_CAMPAIGN_MICROUSD
        or freeze.max_case_microusd != MAX_CASE_MICROUSD
        or any(
            authority.provider_calls != 0
            for authority in (prepared, preregistration, capability, freeze, authorization)
        )
    ):
        raise _reject("Exact authorities do not preserve the provider-free 20-case contract.")
    authorization_at = _timestamp(authorization.authorized_at, "authorization time")
    if not (
        _timestamp_value(authorization_at)
        <= _timestamp_value(prepared_at)
        <= _timestamp_value(executed_at)
        <= datetime.now(timezone.utc)
    ):
        raise _reject("Config timestamps must follow authorization and cannot be future-dated.")

    freeze_record = _json_object(inputs.execution_freeze, "execution freeze")
    if freeze_record.get("controller_git_sha") != tool_git_sha:
        raise _reject("Configured tool Git SHA differs from the exact execution freeze.")
    gold_smoke = _json_object(inputs.gold_smoke_receipt, "gold smoke receipt")
    gold_inputs = _mapping(gold_smoke.get("inputs"), "gold smoke inputs")
    if _file_sha256(inputs.gold_specs) != gold_inputs.get("gold_specs_sha256"):
        raise _reject("Gold specs differ from the freshly verified gold-smoke input binding.")
    _require_final_tool_sha(inputs, tool_git_sha)
    cases = _derive_cases(
        preparation_root=prepared.root,
        preparation_receipt=inputs.cases_preparation,
        cohort_plan=inputs.cohort_plan,
        source_evidence_write_root=source_evidence_write_root,
        source_evidence_config_root=source_evidence_config_root,
    )
    paths = ExactCampaignPaths(
        campaign_freeze=inputs.campaign_freeze,
        exact_preregistration=inputs.exact_preregistration,
        cases_preparation=inputs.cases_preparation,
        cohort_plan=inputs.cohort_plan,
        chronology=inputs.chronology,
        hidden_extraction_receipt=inputs.hidden_extraction_receipt,
        issue_responses_root=inputs.issue_responses_root,
        mapping_preparation=inputs.mapping_preparation,
        mapping_consensus=inputs.mapping_consensus,
        capability_index=inputs.capability_index,
        runtime_manifest=inputs.runtime_manifest,
        runtime_manifest_sha256=inputs.runtime_manifest_sha256,
        gold_smoke_receipt=inputs.gold_smoke_receipt,
        gold_specs=inputs.gold_specs,
        execution_freeze=inputs.execution_freeze,
        execution_authorization=inputs.execution_authorization,
        ledger=campaign_root / "ledger" / "scored-events.jsonl",
        attempts_root=campaign_root / "attempts",
        progress=campaign_root / "controller" / "progress.json",
    )
    case_bindings = [
        {
            "case_id": case.case_id,
            "generator_projection_sha256": _file_sha256(case.generator_projection),
            "object_source_receipt_sha256": case.object_source_receipt_sha256,
            "source_evidence_receipt_sha256": _file_sha256(
                (source_evidence_write_root or source_evidence_config_root) / f"{case.case_id}.json"
            ),
        }
        for case in cases
    ]
    artifacts = {
        name: _file_sha256(cast(Path, value))
        for name, value in vars(inputs).items()
        if name not in {"issue_responses_root", "runtime_manifest_sha256"}
    }
    bindings: dict[str, object] = {
        "artifact_sha256": dict(sorted(artifacts.items())),
        "authorization_at": authorization_at,
        "campaign_id": campaign.campaign_id,
        "case_binding_set_sha256": hashlib.sha256(
            _canonical(
                {
                    "algorithm": "reproassert-v02-exact-campaign-case-bindings-v1",
                    "cases": case_bindings,
                }
            )
        ).hexdigest(),
        "execution_freeze_sha256": freeze.sha256,
        "max_campaign_microusd": MAX_CAMPAIGN_MICROUSD,
        "max_case_microusd": MAX_CASE_MICROUSD,
        "overage_permitted": False,
        "provider": "openai",
        "requested_model": freeze.requested_model,
        "request_set_sha256": freeze.request_set_sha256,
    }
    return paths, cases, bindings


def _derive_cases(
    *,
    preparation_root: Path,
    preparation_receipt: Path,
    cohort_plan: Path,
    source_evidence_write_root: Path | None,
    source_evidence_config_root: Path,
) -> tuple[ExactCampaignCase, ...]:
    record = _json_object(preparation_receipt, "case preparation")
    inputs = _mapping(record.get("inputs"), "case preparation inputs")
    cohort_ref = _mapping(inputs.get("cohort_plan"), "copied cohort plan")
    canonical_plan = _beneath(preparation_root, cohort_ref.get("path"), "copied cohort plan")
    if _file_sha256(canonical_plan) != cohort_ref.get("sha256"):
        raise _reject("Copied cohort plan differs from its verified preparation binding.")
    object_source_ref = _mapping(inputs.get("object_sources_root"), "object sources root")
    object_source_root = Path(cast(str, object_source_ref.get("path"))).resolve(strict=True)
    if not object_source_root.is_dir():
        raise _reject("Verified object sources root is not a directory.")
    rows = record.get("packages")
    if not isinstance(rows, list) or len(rows) != 20:
        raise _reject("Case preparation does not preserve the 20-case denominator.")
    cases: list[ExactCampaignCase] = []
    for index, row_value in enumerate(rows, 1):
        row = _mapping(row_value, "case package reference")
        case_id = f"rk-v0.2-{index:03d}"
        if row.get("case_id") != case_id:
            raise _reject("Case preparation packages are incomplete or out of order.")
        package_path = _beneath(preparation_root, row.get("path"), "case package")
        if _file_sha256(package_path) != row.get("sha256"):
            raise _reject(f"Case package digest differs for {case_id}.")
        package = _json_object(package_path, f"package {case_id}")
        projection_ref = _mapping(package.get("generator_projection"), "generator projection")
        projection = (preparation_root / "cases" / case_id / "generator-projection.json").resolve(
            strict=True
        )
        if projection != _beneath(preparation_root, projection_ref.get("path"), "projection"):
            raise _reject(f"Generator projection path is noncanonical for {case_id}.")
        if _file_sha256(projection) != projection_ref.get("sha256"):
            raise _reject(f"Generator projection digest differs for {case_id}.")
        source = _mapping(package.get("source"), "object source")
        receipt = (
            object_source_root / f"{case_id}-object-v2" / "benchmark-object-source-receipt.json"
        ).resolve(strict=True)
        if receipt != _absolute_existing_file(source.get("receipt_path"), "object source receipt"):
            raise _reject(f"Object source receipt path is noncanonical for {case_id}.")
        receipt_sha = _sha256(source.get("receipt_sha256"), "object source receipt")
        evidence_config = source_evidence_config_root / f"{case_id}.json"
        evidence_write = (
            evidence_config
            if source_evidence_write_root is None
            else source_evidence_write_root / f"{case_id}.json"
        )
        if source_evidence_write_root is None and not evidence_write.is_file():
            raise _reject(f"Source evidence receipt is missing for {case_id}.")
        issue_v02_source_evidence_from_object_receipt(
            receipt,
            plan_path=canonical_plan,
            expected_case_id=case_id,
            source_evidence_receipt_path=evidence_write,
            expected_receipt_sha256=receipt_sha,
        )
        cases.append(
            ExactCampaignCase(
                case_id=case_id,
                generator_projection=projection,
                object_source_receipt=receipt,
                object_source_plan=canonical_plan,
                source_evidence_receipt=evidence_config,
                object_source_receipt_sha256=receipt_sha,
            )
        )
    return tuple(cases)


def _record(
    paths: object,
    cases: tuple[ExactCampaignCase, ...],
    bindings: Mapping[str, object],
    prepared_at: str,
    executed_at: str,
    tool_git_sha: str,
) -> dict[str, object]:
    return {
        "algorithm": CONFIG_ALGORITHM,
        "bindings": dict(bindings),
        "cases": [
            {
                "case_id": case.case_id,
                "generator_projection": str(case.generator_projection),
                "object_source_plan": str(case.object_source_plan),
                "object_source_receipt": str(case.object_source_receipt),
                "object_source_receipt_sha256": case.object_source_receipt_sha256,
                "source_evidence_receipt": str(case.source_evidence_receipt),
            }
            for case in cases
        ],
        "claims": {
            "credentials_read": False,
            "provider_calls": 0,
            "provider_invoked_by_this_command": False,
        },
        "executed_at": executed_at,
        "paths": {
            name: value if name == "runtime_manifest_sha256" else str(value)
            for name, value in vars(paths).items()
        },
        "prepared_at": prepared_at,
        "schema_version": CONFIG_SCHEMA_VERSION,
        "tool_git_sha": tool_git_sha,
    }


def _resolved_inputs(value: ExactCampaignConfigInputs) -> ExactCampaignConfigInputs:
    fields: dict[str, object] = {}
    for name, item in vars(value).items():
        if name == "runtime_manifest_sha256":
            fields[name] = _sha256(item, "runtime manifest")
        elif name in {"issue_responses_root", "gold_specs"}:
            if not isinstance(item, Path):
                raise _reject(f"{name} path is invalid.")
            fields[name] = item.resolve(strict=True)
        else:
            fields[name] = Path(cast(Path, item)).resolve(strict=True)
    return ExactCampaignConfigInputs(**cast(Any, fields))


def _output_root(value: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise _reject("Exact campaign output root must be absolute.")
    if path.is_symlink():
        raise _reject("Exact campaign output root cannot be a symlink.")
    if any(part in {"", ".", ".."} for part in path.parts[1:]):
        raise _reject("Exact campaign output root must be lexically canonical.")
    parent = path.parent.resolve(strict=True)
    return parent / path.name


def _require_final_tool_sha(inputs: ExactCampaignConfigInputs, expected: str) -> None:
    records = {
        "case preparation": _mapping(
            _json_object(inputs.cases_preparation, "case preparation").get("tool"),
            "case preparation tool",
        ).get("git_sha"),
        "chronology": _json_object(inputs.chronology, "chronology").get("tool_git_sha"),
        "mapping preparation": _mapping(
            _json_object(inputs.mapping_preparation, "mapping preparation").get("tool"),
            "mapping preparation tool",
        ).get("git_sha"),
        "capability index": _json_object(inputs.capability_index, "capability index").get(
            "tool_git_sha"
        ),
        "exact preregistration": _json_object(
            inputs.exact_preregistration, "exact preregistration"
        ).get("tool_git_sha"),
        "campaign freeze": _mapping(
            _json_object(inputs.campaign_freeze, "campaign freeze").get("tool"),
            "campaign freeze tool",
        ).get("git_sha"),
        "execution freeze": _json_object(inputs.execution_freeze, "execution freeze").get(
            "controller_git_sha"
        ),
        "gold smoke": _json_object(inputs.gold_smoke_receipt, "gold smoke").get("tool_git_sha"),
    }
    mismatches = [name for name, value in records.items() if value != expected]
    if mismatches:
        raise _reject(
            "Final tool Git SHA differs across exact authorities: " + ", ".join(mismatches) + "."
        )


def _inputs_from_paths(config: ExactCampaignConfig) -> ExactCampaignConfigInputs:
    paths = config.paths
    return ExactCampaignConfigInputs(
        campaign_freeze=paths.campaign_freeze,
        exact_preregistration=paths.exact_preregistration,
        cases_preparation=paths.cases_preparation,
        cohort_plan=paths.cohort_plan,
        chronology=paths.chronology,
        hidden_extraction_receipt=paths.hidden_extraction_receipt,
        issue_responses_root=paths.issue_responses_root,
        mapping_preparation=paths.mapping_preparation,
        mapping_consensus=paths.mapping_consensus,
        capability_index=paths.capability_index,
        runtime_manifest=paths.runtime_manifest,
        runtime_manifest_sha256=paths.runtime_manifest_sha256,
        gold_smoke_receipt=paths.gold_smoke_receipt,
        gold_specs=paths.gold_specs,
        execution_freeze=paths.execution_freeze,
        execution_authorization=paths.execution_authorization,
    )


def _json_object(path: Path, label: str) -> dict[str, object]:
    with open_regular_file(Path(path)) as stream:
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise _reject(f"{label.capitalize()} exceeds its size limit.")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _reject(f"{label.capitalize()} is invalid JSON.") from exc
    if not isinstance(value, dict):
        raise _reject(f"{label.capitalize()} must be a JSON object.")
    return cast(dict[str, object], value)


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise _reject(f"{label.capitalize()} is invalid.")
    return cast(Mapping[str, object], value)


def _beneath(root: Path, relative: object, label: str) -> Path:
    if not isinstance(relative, str) or relative.startswith("/"):
        raise _reject(f"{label.capitalize()} path is invalid.")
    parts = relative.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise _reject(f"{label.capitalize()} path traversal is forbidden.")
    base = root.resolve(strict=True)
    path = base.joinpath(*parts).resolve(strict=True)
    if path == base or base not in path.parents or not path.is_file():
        raise _reject(f"{label.capitalize()} escapes its verified preparation root.")
    return path


def _absolute_existing_file(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value.startswith("/"):
        raise _reject(f"{label.capitalize()} path must be absolute.")
    path = Path(value).resolve(strict=True)
    if not path.is_file():
        raise _reject(f"{label.capitalize()} is not a regular file.")
    return path


def _file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open_regular_file(Path(path)) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} SHA-256 is invalid.")
    return value


def _git_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} is invalid.")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject(f"{label.capitalize()} is invalid.")
    try:
        _timestamp_value(value)
    except ValueError as exc:
        raise _reject(f"{label.capitalize()} is invalid.") from exc
    return value


def _timestamp_value(value: str) -> datetime:
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if parsed.tzinfo != timezone.utc:
        raise ValueError("timestamp must use UTC")
    return parsed


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _issue_verified(values: Mapping[str, object]) -> VerifiedExactCampaignConfig:
    result = object.__new__(VerifiedExactCampaignConfig)
    for name, value in values.items():
        object.__setattr__(result, name, value)
    return result


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_exact_campaign_config", message)
