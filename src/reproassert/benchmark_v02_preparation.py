"""Provider-free materialization and rederivation of frozen v0.2 dataset inputs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from reproassert.benchmark_v02_cohort import (
    load_v02_leak_audited_cohort_plan,
    render_prepared_v02_issue_snapshot_projection,
)
from reproassert.benchmark_v02_dataset import load_prepared_v02_dataset_receipt
from reproassert.benchmark_v02_dataset_sandbox import (
    AttestedV02DatasetParse,
    DatasetParserContainerPolicy,
    _decode_attestation,
    run_attested_v02_dataset_parser,
)
from reproassert.benchmark_v02_package import _require_outside_source_checkout
from reproassert.errors import PolicyRejection
from reproassert.safeio import (
    open_regular_file,
    require_private_directory,
    write_bytes_exclusive,
)

if TYPE_CHECKING:
    from reproassert.semantic_issuer import VerifiedV02DatasetEvidence

DATASET_PREPARATION_ALGORITHM = "reproassert-v02-private-dataset-preparation-v1"
DATASET_PREPARATION_SCHEMA_VERSION = "1.0.0"
DATASET_PREPARATION_DIRECTORY = "v02-dataset-preparation"
DATASET_PREPARATION_FILENAME = "benchmark-v02-dataset-preparation.json"
FROZEN_V02_DATASET_PARSER_IMAGE_ID = (
    "sha256:0bf07669fd085b608e6859b90a486b3ede52d8cc409309410181ab32fbe1118f"
)
MAX_PREPARATION_BYTES = 256 * 1024
_MAX_PLAN_BYTES = 256 * 1024
_MAX_WITNESS_BYTES = 256 * 1024
_MAX_ATTESTATION_BYTES = 64 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")

_ROOT_KEYS = {
    "algorithm",
    "case_count",
    "claims",
    "inputs",
    "outputs",
    "prepared_at",
    "preparation_sha256",
    "schema_version",
    "status",
}


@dataclass(frozen=True)
class V02DatasetPreparation:
    root: Path
    receipt_path: Path
    receipt_sha256: str
    parser_receipt_sha256: str
    case_count: int
    provider_calls: int


def issue_v02_dataset_evidence_from_preparation(
    receipt_path: Path, *, case_id: str
) -> VerifiedV02DatasetEvidence:
    """Freshly rederive a private preparation and issue one nominal dataset authority.

    The returned value is intentionally process-local and must be consumed by the trusted package
    orchestrator. It is never serialized by the CLI.
    """

    from reproassert.benchmark_v02_package import V02CaseIdentity
    from reproassert.semantic_issuer import issue_v02_dataset_evidence_from_attested_parse

    prepared, parsed, cases = _verify_v02_dataset_preparation(receipt_path)
    del prepared
    selected = next((case for case in cases if case.get("case_id") == case_id), None)
    if selected is None:
        raise _reject("Requested dataset evidence case is absent from the frozen preparation.")
    case = V02CaseIdentity(
        id=cast(str, selected["case_id"]),
        repo=cast(str, selected["repo"]),
        issue_url=cast(str, selected["issue_url"]),
        base_sha=cast(str, selected["base_sha"]),
    )
    return issue_v02_dataset_evidence_from_attested_parse(
        attested_parse=parsed,
        case=case,
        instance_id=cast(str, selected["instance_id"]),
    )


def prepare_v02_dataset_inputs(
    *,
    output_root: Path,
    tdd_id_list_path: Path,
    source_dataset_path: Path,
    upstream_object_witness_path: Path,
    cohort_plan_path: Path,
    image_digest: str,
    prepared_at: str,
) -> V02DatasetPreparation:
    """Run the fixed parser and persist all 20 safe projections without a provider path."""

    parent = Path(output_root)
    require_private_directory(parent)
    image = _image_id(image_digest)
    timestamp = _timestamp(prepared_at)
    destination = parent / DATASET_PREPARATION_DIRECTORY
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite an existing v0.2 dataset preparation.")

    created = False
    try:
        destination.mkdir(mode=0o700)
        created = True
        os.chmod(destination, 0o700, follow_symlinks=False)
        require_private_directory(destination)
        _require_outside_source_checkout(destination)
        upstream = destination / "upstream"
        attested = destination / "attested"
        projections = destination / "generator-projections"
        for directory in (upstream, attested, projections):
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700, follow_symlinks=False)

        copied = {
            "tdd_id_list": _copy_regular(
                Path(tdd_id_list_path), upstream / "tdd-id-list.txt", 64 * 1024
            ),
            "source_dataset": _copy_regular(
                Path(source_dataset_path),
                upstream / "swe-bench-verified-test.parquet",
                4 * 1024 * 1024,
            ),
            "upstream_object_witness": _copy_regular(
                Path(upstream_object_witness_path),
                upstream / "upstream-object-witness.json",
                _MAX_WITNESS_BYTES,
            ),
            "cohort_plan": _copy_regular(
                Path(cohort_plan_path), upstream / "leak-audited-cohort-plan.json", _MAX_PLAN_BYTES
            ),
        }
        stored_inputs = {
            name: destination / cast(str, reference["path"]) for name, reference in copied.items()
        }
        plan = load_v02_leak_audited_cohort_plan(stored_inputs["cohort_plan"])
        cases = _ordered_cases(plan)
        parsed = run_attested_v02_dataset_parser(
            tdd_id_list_path=stored_inputs["tdd_id_list"],
            source_dataset_path=stored_inputs["source_dataset"],
            upstream_object_witness_path=stored_inputs["upstream_object_witness"],
            policy=DatasetParserContainerPolicy(image_digest=image),
            projection_instance_ids=tuple(cast(str, case["instance_id"]) for case in cases),
        )
        if parsed.production_eligible is not True:
            raise _reject("The attested dataset parser did not issue production-eligible evidence.")
        parser_ref = _write_artifact(
            destination,
            "attested/dataset-parser-receipt.json",
            parsed.parser_receipt,
        )
        attestation_ref = _write_artifact(
            destination,
            "attested/dataset-parser-boundary-attestation.json",
            parsed.boundary_attestation,
        )
        projection_rows: list[dict[str, object]] = []
        stored_plan = stored_inputs["cohort_plan"]
        stored_receipt = destination / cast(str, parser_ref["path"])
        for case in cases:
            case_id = cast(str, case["case_id"])
            content = render_prepared_v02_issue_snapshot_projection(
                stored_receipt,
                stored_plan,
                case_id=case_id,
            )
            projection = json.loads(content)
            if projection.get("issue_text_chronology") != "chronology_unproven":
                raise _reject("A generator projection changed the frozen chronology claim.")
            reference = _write_artifact(
                destination,
                f"generator-projections/{case_id}.json",
                content,
            )
            projection_rows.append({"case_id": case_id, **reference})

        record: dict[str, object] = {
            "algorithm": DATASET_PREPARATION_ALGORITHM,
            "case_count": len(projection_rows),
            "claims": {
                "campaign_readiness_changed": False,
                "issue_text_chronology": "chronology_unproven",
                "model_or_provider_invoked": False,
                "provider_calls": 0,
            },
            "inputs": {**copied, "dataset_parser_image_id": image},
            "outputs": {
                "boundary_attestation": attestation_ref,
                "parser_receipt": parser_ref,
                "projections": projection_rows,
            },
            "prepared_at": timestamp,
            "schema_version": DATASET_PREPARATION_SCHEMA_VERSION,
            "status": "prepared_no_provider_invoked",
        }
        record["preparation_sha256"] = _self_hash(record)
        encoded = _canonical(record) + b"\n"
        if len(encoded) > MAX_PREPARATION_BYTES:
            raise _reject("Dataset preparation receipt exceeds its size limit.")
        receipt_path = destination / DATASET_PREPARATION_FILENAME
        write_bytes_exclusive(receipt_path, encoded)
        return load_v02_dataset_preparation(receipt_path)
    except BaseException:
        if created:
            shutil.rmtree(destination, ignore_errors=True)
        raise


def verify_v02_dataset_preparation(receipt_path: Path) -> V02DatasetPreparation:
    """Freshly rerun the no-network parser and compare every stored safe projection."""

    prepared, _, _ = _verify_v02_dataset_preparation(receipt_path)
    return prepared


def _verify_v02_dataset_preparation(
    receipt_path: Path,
) -> tuple[V02DatasetPreparation, AttestedV02DatasetParse, list[dict[str, object]]]:
    """Return the durable receipt plus the fresh nominal handoff inside the trusted process."""

    prepared = load_v02_dataset_preparation(receipt_path)
    record = _load_record(prepared.receipt_path)
    root = prepared.root
    inputs = cast(dict[str, object], record["inputs"])
    outputs = cast(dict[str, object], record["outputs"])
    paths = {
        name: root / cast(str, cast(dict[str, object], inputs[name])["path"])
        for name in (
            "tdd_id_list",
            "source_dataset",
            "upstream_object_witness",
            "cohort_plan",
        )
    }
    for name, path in paths.items():
        _verify_reference(root, path, cast(dict[str, object], inputs[name]), name)
    parser_ref = cast(dict[str, object], outputs["parser_receipt"])
    attestation_ref = cast(dict[str, object], outputs["boundary_attestation"])
    parser_path = root / cast(str, parser_ref["path"])
    _verify_reference(root, parser_path, parser_ref, "parser receipt")
    _verify_reference(
        root,
        root / cast(str, attestation_ref["path"]),
        attestation_ref,
        "boundary attestation",
    )
    plan = load_v02_leak_audited_cohort_plan(paths["cohort_plan"])
    cases = _ordered_cases(plan)
    parsed = run_attested_v02_dataset_parser(
        tdd_id_list_path=paths["tdd_id_list"],
        source_dataset_path=paths["source_dataset"],
        upstream_object_witness_path=paths["upstream_object_witness"],
        policy=DatasetParserContainerPolicy(
            image_digest=_image_id(inputs["dataset_parser_image_id"])
        ),
        projection_instance_ids=tuple(cast(str, case["instance_id"]) for case in cases),
    )
    stored_parser = _read_regular(parser_path, 2 * 1024 * 1024)
    if parsed.parser_receipt != stored_parser:
        raise _reject("Stored parser receipt differs from fresh container rederivation.")
    stored_attestation = _read_regular(
        root / cast(str, attestation_ref["path"]), _MAX_ATTESTATION_BYTES
    )
    _require_equivalent_boundary_attestation(stored_attestation, parsed.boundary_attestation)
    load_prepared_v02_dataset_receipt(parser_path)
    projections = outputs["projections"]
    if not isinstance(projections, list) or len(projections) != 20:
        raise _reject("Dataset preparation does not contain exactly 20 projections.")
    by_id = {
        cast(str, cast(dict[str, object], item)["case_id"]): cast(dict[str, object], item)
        for item in projections
        if isinstance(item, dict)
    }
    if set(by_id) != {cast(str, case["case_id"]) for case in cases}:
        raise _reject("Dataset preparation projection identities differ from the cohort.")
    for case in cases:
        case_id = cast(str, case["case_id"])
        reference = by_id[case_id]
        path = root / cast(str, reference["path"])
        _verify_reference(root, path, reference, f"projection {case_id}", allow_case_id=True)
        expected = render_prepared_v02_issue_snapshot_projection(
            parser_path,
            paths["cohort_plan"],
            case_id=case_id,
        )
        if _read_regular(path, 128 * 1024) != expected:
            raise _reject(f"Projection {case_id} differs from fresh derivation.")
    return prepared, parsed, cases


def load_v02_dataset_preparation(receipt_path: Path) -> V02DatasetPreparation:
    path = Path(receipt_path)
    root = path.parent
    require_private_directory(root)
    _require_outside_source_checkout(root)
    record = _load_record(path)
    outputs = cast(dict[str, object], record["outputs"])
    parser = cast(dict[str, object], outputs["parser_receipt"])
    raw = _read_regular(path, MAX_PREPARATION_BYTES)
    return V02DatasetPreparation(
        root=root,
        receipt_path=path,
        receipt_sha256=hashlib.sha256(raw).hexdigest(),
        parser_receipt_sha256=cast(str, parser["sha256"]),
        case_count=cast(int, record["case_count"]),
        provider_calls=0,
    )


def _load_record(path: Path) -> dict[str, object]:
    raw = _read_regular(path, MAX_PREPARATION_BYTES)
    try:
        decoded = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _reject("Dataset preparation receipt is invalid JSON.") from exc
    if not isinstance(decoded, dict) or raw != _canonical(decoded) + b"\n":
        raise _reject("Dataset preparation receipt is not canonical JSON.")
    if set(decoded) != _ROOT_KEYS:
        raise _reject("Dataset preparation receipt fields are not exact.")
    if (
        decoded.get("schema_version") != DATASET_PREPARATION_SCHEMA_VERSION
        or decoded.get("algorithm") != DATASET_PREPARATION_ALGORITHM
        or decoded.get("status") != "prepared_no_provider_invoked"
        or decoded.get("case_count") != 20
        or decoded.get("preparation_sha256") != _self_hash(decoded)
    ):
        raise _reject("Dataset preparation receipt identity is invalid.")
    _timestamp(decoded.get("prepared_at"))
    claims = decoded.get("claims")
    if claims != {
        "campaign_readiness_changed": False,
        "issue_text_chronology": "chronology_unproven",
        "model_or_provider_invoked": False,
        "provider_calls": 0,
    }:
        raise _reject("Dataset preparation claims are invalid.")
    inputs = decoded.get("inputs")
    outputs = decoded.get("outputs")
    if not isinstance(inputs, dict) or set(inputs) != {
        "cohort_plan",
        "dataset_parser_image_id",
        "source_dataset",
        "tdd_id_list",
        "upstream_object_witness",
    }:
        raise _reject("Dataset preparation inputs are invalid.")
    _image_id(inputs.get("dataset_parser_image_id"))
    if not isinstance(outputs, dict) or set(outputs) != {
        "boundary_attestation",
        "parser_receipt",
        "projections",
    }:
        raise _reject("Dataset preparation outputs are invalid.")
    return cast(dict[str, object], decoded)


def _ordered_cases(plan: dict[str, object]) -> list[dict[str, object]]:
    cases = plan.get("cases")
    if not isinstance(cases, list) or len(cases) != 20:
        raise _reject("The frozen cohort must contain exactly 20 cases.")
    normalized = [cast(dict[str, object], case) for case in cases if isinstance(case, dict)]
    if len(normalized) != 20:
        raise _reject("The frozen cohort contains an invalid case.")
    expected = [f"rk-v0.2-{position:03d}" for position in range(1, 21)]
    if [case.get("case_id") for case in normalized] != expected:
        raise _reject("The frozen cohort case order is invalid.")
    return normalized


def _copy_regular(source: Path, destination: Path, limit: int) -> dict[str, object]:
    return _write_artifact(
        destination.parents[1],
        destination.relative_to(destination.parents[1]).as_posix(),
        _read_regular(source, limit),
    )


def _write_artifact(root: Path, relative: str, content: bytes) -> dict[str, object]:
    path = root / relative
    write_bytes_exclusive(path, content)
    return {"bytes": len(content), "path": relative, "sha256": hashlib.sha256(content).hexdigest()}


def _verify_reference(
    root: Path,
    path: Path,
    reference: dict[str, object],
    label: str,
    *,
    allow_case_id: bool = False,
) -> None:
    expected_keys = {"bytes", "path", "sha256"} | ({"case_id"} if allow_case_id else set())
    if set(reference) != expected_keys:
        raise _reject(f"{label.capitalize()} reference fields are invalid.")
    relative = reference.get("path")
    if (
        not isinstance(relative, str)
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
    ):
        raise _reject(f"{label.capitalize()} path is unsafe.")
    if path != root / relative:
        raise _reject(f"{label.capitalize()} path differs from its reference.")
    content = _read_regular(path, 4 * 1024 * 1024)
    if (
        reference.get("bytes") != len(content)
        or reference.get("sha256") != hashlib.sha256(content).hexdigest()
    ):
        raise _reject(f"{label.capitalize()} differs from its commitment.")
    if allow_case_id and _CASE_ID.fullmatch(cast(str, reference.get("case_id"))) is None:
        raise _reject(f"{label.capitalize()} case ID is invalid.")


def _read_regular(path: Path, limit: int) -> bytes:
    try:
        with open_regular_file(path) as stream:
            content = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject("A preparation artifact could not be read safely.") from exc
    if len(content) > limit:
        raise _reject("A preparation artifact exceeds its size limit.")
    return content


def _self_hash(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned.pop("preparation_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _require_equivalent_boundary_attestation(stored: bytes, fresh: bytes) -> None:
    stored_record = _decode_attestation(stored)
    fresh_record = _decode_attestation(fresh)
    for record in (stored_record, fresh_record):
        inspection = record.get("container_inspection_sha256")
        if not isinstance(inspection, str) or _SHA256.fullmatch(inspection) is None:
            raise _reject("Dataset boundary inspection commitment is invalid.")
    stored_semantics = dict(stored_record)
    fresh_semantics = dict(fresh_record)
    stored_semantics.pop("container_inspection_sha256")
    fresh_semantics.pop("container_inspection_sha256")
    if stored_semantics != fresh_semantics:
        raise _reject("Stored dataset boundary attestation differs from fresh rederivation.")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _image_id(value: object) -> str:
    if not isinstance(value, str) or _IMAGE_ID.fullmatch(value) is None:
        raise _reject("Dataset parser image ID is invalid.")
    if value != FROZEN_V02_DATASET_PARSER_IMAGE_ID:
        raise _reject("Dataset parser image differs from the frozen v0.2 trusted image.")
    return value


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Dataset preparation timestamp is invalid.")
    return value


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_dataset_preparation", message)
