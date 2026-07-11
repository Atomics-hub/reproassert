"""Strict loader for the append-only v0.2.1 parser-image successor freeze."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file

PREPARATION_FREEZE_ALGORITHM = "reproassert-v021-preparation-freeze-v1"
PREPARATION_FREEZE_SCHEMA_VERSION = "1.0.0"
PREPARATION_FREEZE_STATUS = "successor_image_frozen_preparation_unrun"
SUCCESSOR_IMAGE_ID = "sha256:fea2f964d148f59c18662a802a0ffa27aff9be5475d8111291ef4c94f9b48cdf"
LEGACY_IMAGE_ID = "sha256:0bf07669fd085b608e6859b90a486b3ede52d8cc409309410181ab32fbe1118f"
PARSER_RECEIPT_SHA256 = "67f337d762536333e06821e91cc1a85dc37ae2b86c14af26057cd090685f96ae"
COHORT_PLAN_SHA256 = "bc948ca82d260da9fb2678032f2172d6f2d1b43fe6df438b1d8d380a1a45818f"
MAX_FREEZE_BYTES = 32 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ROOT_KEYS = {
    "algorithm",
    "benchmark_protocol",
    "claims",
    "cohort",
    "freeze_revision",
    "freeze_sha256",
    "frozen_at",
    "parser",
    "schema_version",
    "status",
    "supersedes",
}


@dataclass(frozen=True)
class V021PreparationFreeze:
    path: Path
    freeze_sha256: str
    image_id: str
    parser_receipt_sha256: str
    case_count: int


def load_v021_preparation_freeze(
    path: Path, *, repository_root: Path | None = None
) -> V021PreparationFreeze:
    """Validate the successor freeze and, when requested, its immutable public predecessors."""

    freeze_path = Path(path)
    raw = _read(freeze_path, MAX_FREEZE_BYTES)
    try:
        decoded = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _reject("Successor preparation freeze is invalid JSON.") from exc
    if not isinstance(decoded, dict) or raw != _canonical(decoded) + b"\n":
        raise _reject("Successor preparation freeze is not exact canonical JSON.")
    root = cast(dict[str, object], decoded)
    if set(root) != _ROOT_KEYS:
        raise _reject("Successor preparation freeze fields are not exact.")
    if (
        root.get("algorithm") != PREPARATION_FREEZE_ALGORITHM
        or root.get("schema_version") != PREPARATION_FREEZE_SCHEMA_VERSION
        or root.get("benchmark_protocol") != "0.2"
        or root.get("freeze_revision") != "0.2.1"
        or root.get("status") != PREPARATION_FREEZE_STATUS
        or root.get("freeze_sha256") != _self_hash(root)
    ):
        raise _reject("Successor preparation freeze identity is invalid.")
    if root.get("claims") != {
        "campaign_readiness_changed": False,
        "historical_artifacts_rewritten": False,
        "model_or_provider_invoked": False,
        "provider_calls": 0,
        "results_changed": False,
    }:
        raise _reject("Successor preparation freeze claims are invalid.")
    cohort = root.get("cohort")
    parser = root.get("parser")
    supersedes = root.get("supersedes")
    if cohort != {
        "case_count": 20,
        "cohort_plan_path": "benchmarks/v0.2-draft/leak-audited-cohort-plan.json",
        "cohort_plan_sha256": COHORT_PLAN_SHA256,
        "selection_changed": False,
    }:
        raise _reject("Successor preparation freeze cohort binding is invalid.")
    if parser != {
        "archive_bytes": 92300454,
        "archive_name": "reproassert-dataset-parser-0.2.1-linux-arm64.tar.gz",
        "archive_sha256": "7dc1c4e4d6bae1c57ba3dba65f29600437eac37e1f5a26f75e08c7867ede44fd",
        "boundary_attestation": {
            "path": "benchmarks/v0.2-draft/dataset-parser-boundary-attestation-v0.2.1.json",
            "sha256": "19bdf12320fff2a7f40835afa75384558c97b263b66df87e684d915a6c0adf05",
        },
        "boundary_attestation_status": "fresh_private_rederivation_verified",
        "image_id": SUCCESSOR_IMAGE_ID,
        "parser_receipt_sha256": PARSER_RECEIPT_SHA256,
        "platform": "linux/arm64",
        "replaces_unrecoverable_image_id": LEGACY_IMAGE_ID,
    }:
        raise _reject("Successor preparation freeze parser binding is invalid.")
    if not isinstance(supersedes, dict) or set(supersedes) != {
        "dataset_parser_boundary_attestation",
        "selection_freeze",
    }:
        raise _reject("Successor preparation freeze predecessor bindings are invalid.")
    if repository_root is not None:
        repo = Path(repository_root)
        _verify_reference(repo, cast(dict[str, object], supersedes["selection_freeze"]))
        _verify_reference(
            repo, cast(dict[str, object], supersedes["dataset_parser_boundary_attestation"])
        )
        cohort_path = cast(str, cast(dict[str, object], cohort)["cohort_plan_path"])
        _verify_exact(repo / cohort_path, COHORT_PLAN_SHA256)
        _verify_reference(
            repo, cast(dict[str, object], cast(dict[str, object], parser)["boundary_attestation"])
        )
    return V021PreparationFreeze(
        path=freeze_path,
        freeze_sha256=cast(str, root["freeze_sha256"]),
        image_id=SUCCESSOR_IMAGE_ID,
        parser_receipt_sha256=PARSER_RECEIPT_SHA256,
        case_count=20,
    )


def _verify_reference(root: Path, reference: dict[str, object]) -> None:
    if set(reference) != {"path", "sha256"}:
        raise _reject("Successor predecessor reference fields are invalid.")
    relative = reference.get("path")
    digest = reference.get("sha256")
    if (
        not isinstance(relative, str)
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
        or not isinstance(digest, str)
        or _SHA256.fullmatch(digest) is None
    ):
        raise _reject("Successor predecessor reference is invalid.")
    _verify_exact(root / relative, digest)


def _verify_exact(path: Path, expected_sha256: str) -> None:
    if hashlib.sha256(_read(path, 512 * 1024)).hexdigest() != expected_sha256:
        raise _reject("A successor freeze predecessor differs from its commitment.")


def _read(path: Path, limit: int) -> bytes:
    try:
        with open_regular_file(path) as stream:
            content = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject("A successor freeze artifact could not be read safely.") from exc
    if len(content) > limit:
        raise _reject("A successor freeze artifact exceeds its size bound.")
    return content


def _self_hash(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned.pop("freeze_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v021_preparation_freeze", message)
