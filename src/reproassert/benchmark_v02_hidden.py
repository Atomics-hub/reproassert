"""Evaluator-private, Docker-attested extraction of frozen v0.2 hidden gold artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from reproassert.benchmark_v02_cohort import load_v02_leak_audited_cohort_plan
from reproassert.benchmark_v02_dataset_sandbox import (
    DatasetParserContainerPolicy,
    _DockerEngine,
)
from reproassert.benchmark_v02_object_source import FROZEN_V02_COHORT_PLAN_SHA256
from reproassert.benchmark_v02_package import _require_outside_source_checkout
from reproassert.benchmark_v02_preparation import FROZEN_V02_DATASET_PARSER_IMAGE_ID
from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file, require_private_directory, write_bytes_exclusive

HIDDEN_EXTRACTION_ALGORITHM = "reproassert-v02-private-hidden-extraction-v1"
HIDDEN_ATTESTATION_ALGORITHM = "reproassert-v02-hidden-container-attestation-v1"
HIDDEN_REQUEST_PROTOCOL = "reproassert-v02-hidden-extraction-request-v1"
HIDDEN_WORKER_PROTOCOL = "reproassert-v02-hidden-extraction-worker-v1"
HIDDEN_DIRECTORY = "v02-hidden-gold"
HIDDEN_RECEIPT_FILENAME = "benchmark-v02-hidden-extraction.json"
HIDDEN_SCHEMA_VERSION = "1.0.0"
SOURCE_DATASET_SHA256 = "a45b1fe4e2f0c8390b2b2938ac83e92ed5979000856808f3679c07812e9e6dcd"
SOURCE_DATASET_BYTES = 2_096_679
MAX_RECEIPT_BYTES = 256 * 1024
_MAX_PLAN_BYTES = 256 * 1024
_MAX_REQUEST_BYTES = 32 * 1024
_MAX_WORKER_BYTES = 128 * 1024
_MAX_PATCH_BYTES = 1024 * 1024
_MAX_METADATA_BYTES = 8 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_CONTAINER_TMP = "/tmp"  # noqa: S108 -- isolated, size-bounded container tmpfs
_VERIFIED_ISSUER = object()


@dataclass(frozen=True)
class V02HiddenExtraction:
    """Non-secret summary of an evaluator-private extraction."""

    root: Path
    receipt_path: Path
    receipt_sha256: str
    artifacts_sha256: str
    case_count: int
    provider_calls: int = 0


@dataclass(frozen=True, init=False)
class VerifiedV02HiddenExtraction:
    """Nominal process-local authority issued only after fresh Docker verification."""

    prepared: V02HiddenExtraction
    _issuer: object

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV02HiddenExtraction is verifier-issued only")


def prepare_v02_hidden_gold(
    *,
    output_root: Path,
    source_dataset_path: Path,
    cohort_plan_path: Path,
    image_digest: str,
    prepared_at: str,
) -> V02HiddenExtraction:
    """Extract 20 hidden records inside the frozen, no-network parser image."""

    parent = Path(output_root)
    require_private_directory(parent)
    _require_outside_source_checkout(parent)
    if image_digest != FROZEN_V02_DATASET_PARSER_IMAGE_ID:
        raise _reject("Hidden extraction requires the exact frozen parser image.")
    _timestamp(prepared_at)
    destination = parent / HIDDEN_DIRECTORY
    if destination.exists() or destination.is_symlink():
        raise _reject("Refusing to overwrite an existing hidden extraction.")
    created = False
    try:
        destination.mkdir(mode=0o700)
        created = True
        os.chmod(destination, 0o700, follow_symlinks=False)
        require_private_directory(destination)
        inputs = destination / "inputs"
        artifacts = destination / "artifacts"
        inputs.mkdir(mode=0o700)
        artifacts.mkdir(mode=0o700)
        dataset = _copy_private(
            Path(source_dataset_path),
            inputs / "swe-bench-verified-test.parquet",
            SOURCE_DATASET_BYTES,
        )
        if dataset["sha256"] != SOURCE_DATASET_SHA256 or dataset["bytes"] != SOURCE_DATASET_BYTES:
            raise _reject("Source dataset differs from the frozen v0.2 artifact.")
        plan = _copy_private(Path(cohort_plan_path), inputs / "cohort-plan.json", _MAX_PLAN_BYTES)
        plan_record = load_v02_leak_audited_cohort_plan(inputs / "cohort-plan.json")
        _require_frozen_plan(plan_record)
        request_bytes = _request(plan_record)
        request = _write_ref(destination, "inputs/request.json", request_bytes)
        worker_bytes = _read_regular(
            Path(__file__).with_name("_benchmark_v02_hidden_worker.py"), _MAX_WORKER_BYTES
        )
        worker = _write_ref(destination, "inputs/worker.py", worker_bytes)
        extracted, inspection_sha256 = _run_hidden_container(
            dataset_path=inputs / "swe-bench-verified-test.parquet",
            request_path=inputs / "request.json",
            worker_path=inputs / "worker.py",
            image_digest=image_digest,
        )
        try:
            _validate_metadata_against_plan(extracted, plan_record)
            artifact_rows = _persist_extracted(extracted, destination, artifacts, request_bytes)
        finally:
            shutil.rmtree(extracted, ignore_errors=True)
        artifacts_sha256 = _artifact_set_sha256(artifact_rows)
        attestation_record = {
            "algorithm": HIDDEN_ATTESTATION_ALGORITHM,
            "artifacts_sha256": artifacts_sha256,
            "container_inspection_sha256": inspection_sha256,
            "image_digest": image_digest,
            "inputs": {
                "cohort_plan_sha256": plan["sha256"],
                "request_sha256": request["sha256"],
                "source_dataset_sha256": dataset["sha256"],
                "worker_sha256": worker["sha256"],
            },
            "policy": _policy_record(),
        }
        attestation = _write_ref(
            destination,
            "container-attestation.json",
            _canonical(attestation_record) + b"\n",
        )
        record: dict[str, object] = {
            "algorithm": HIDDEN_EXTRACTION_ALGORITHM,
            "artifacts": artifact_rows,
            "artifacts_sha256": artifacts_sha256,
            "benchmark_version": "0.2",
            "case_count": 20,
            "claims": {
                "generator_visible": False,
                "hidden_bytes_emitted_to_stdout": False,
                "model_or_provider_invoked": False,
                "provider_calls": 0,
            },
            "container_attestation": attestation,
            "inputs": {
                "cohort_plan": plan,
                "request": request,
                "source_dataset": dataset,
                "worker": worker,
            },
            "prepared_at": prepared_at,
            "schema_version": HIDDEN_SCHEMA_VERSION,
            "status": "evaluator_private_prepared_no_provider",
        }
        record["receipt_sha256"] = _self_hash(record)
        encoded = _canonical(record) + b"\n"
        if len(encoded) > MAX_RECEIPT_BYTES:
            raise _reject("Hidden extraction receipt exceeds its bound.")
        write_bytes_exclusive(destination / HIDDEN_RECEIPT_FILENAME, encoded)
        return load_v02_hidden_extraction(destination / HIDDEN_RECEIPT_FILENAME)
    except BaseException:
        if created:
            shutil.rmtree(destination, ignore_errors=True)
        raise


def verify_v02_hidden_gold(receipt_path: Path) -> VerifiedV02HiddenExtraction:
    """Rerun extraction from staged inputs and byte-compare every hidden output."""

    prepared = load_v02_hidden_extraction(receipt_path)
    record = _load_receipt(prepared.receipt_path)
    inputs = cast(dict[str, dict[str, object]], record["inputs"])
    for name, reference in inputs.items():
        _verify_ref(prepared.root, reference, name)
    dataset_path = prepared.root / cast(str, inputs["source_dataset"]["path"])
    dataset_bytes = _read_regular(dataset_path, SOURCE_DATASET_BYTES)
    if (
        len(dataset_bytes) != SOURCE_DATASET_BYTES
        or hashlib.sha256(dataset_bytes).hexdigest() != SOURCE_DATASET_SHA256
    ):
        raise _reject("Stored dataset differs from the frozen v0.2 artifact.")
    installed_worker = _read_regular(
        Path(__file__).with_name("_benchmark_v02_hidden_worker.py"), _MAX_WORKER_BYTES
    )
    worker_path = prepared.root / cast(str, inputs["worker"]["path"])
    if _read_regular(worker_path, _MAX_WORKER_BYTES) != installed_worker:
        raise _reject("Stored hidden worker differs from the installed trusted worker.")
    plan_path = prepared.root / cast(str, inputs["cohort_plan"]["path"])
    plan = load_v02_leak_audited_cohort_plan(plan_path)
    _require_frozen_plan(plan)
    request_path = prepared.root / cast(str, inputs["request"]["path"])
    request_bytes = _read_regular(request_path, _MAX_REQUEST_BYTES)
    if request_bytes != _request(plan):
        raise _reject("Stored hidden request differs from the frozen cohort plan.")
    stored_rows = cast(list[dict[str, object]], record["artifacts"])
    attestation_ref = cast(dict[str, object], record["container_attestation"])
    _verify_ref(prepared.root, attestation_ref, "container_attestation")
    attestation = _load_json(prepared.root / cast(str, attestation_ref["path"]), 64 * 1024)
    _validate_attestation(attestation, record)
    _verify_artifacts(prepared.root, stored_rows)
    fresh, inspection_sha256 = _run_hidden_container(
        dataset_path=dataset_path,
        request_path=request_path,
        worker_path=worker_path,
        image_digest=FROZEN_V02_DATASET_PARSER_IMAGE_ID,
    )
    try:
        del inspection_sha256
        _validate_metadata_against_plan(fresh, plan)
        fresh_rows = _describe_extracted(fresh, request_bytes)
        if fresh_rows != stored_rows:
            raise _reject("Stored hidden artifacts differ from fresh container extraction.")
        for row in stored_rows:
            case_id = cast(str, row["case_id"])
            for filename in ("production.patch", "developer-tests.patch", "metadata.json"):
                if _read_regular(fresh / case_id / filename, _limit(filename)) != _read_regular(
                    prepared.root / "artifacts" / case_id / filename, _limit(filename)
                ):
                    raise _reject("Stored hidden bytes differ from fresh container extraction.")
    finally:
        shutil.rmtree(fresh, ignore_errors=True)
    verified = object.__new__(VerifiedV02HiddenExtraction)
    object.__setattr__(verified, "prepared", prepared)
    object.__setattr__(verified, "_issuer", _VERIFIED_ISSUER)
    return verified


def load_v02_hidden_extraction(receipt_path: Path) -> V02HiddenExtraction:
    path = Path(receipt_path)
    root = path.parent
    require_private_directory(root)
    _require_outside_source_checkout(root)
    record = _load_receipt(path)
    raw = _read_regular(path, MAX_RECEIPT_BYTES)
    return V02HiddenExtraction(
        root=root,
        receipt_path=path,
        receipt_sha256=hashlib.sha256(raw).hexdigest(),
        artifacts_sha256=cast(str, record["artifacts_sha256"]),
        case_count=20,
    )


def hidden_case_artifacts(
    verified: VerifiedV02HiddenExtraction, case_id: str
) -> dict[str, dict[str, object]]:
    """Return private paths and commitments for one case without returning hidden bytes."""

    if (
        type(verified) is not VerifiedV02HiddenExtraction
        or verified._issuer is not _VERIFIED_ISSUER
    ):
        raise _reject("Freshly verified hidden extraction authority is required.")
    if re.fullmatch(r"rk-v0\.2-[0-9]{3}", case_id) is None:
        raise _reject("Hidden artifact case ID is invalid.")
    prepared = verified.prepared
    receipt_bytes = _read_regular(prepared.receipt_path, MAX_RECEIPT_BYTES)
    if hashlib.sha256(receipt_bytes).hexdigest() != prepared.receipt_sha256:
        raise _reject("Verified hidden receipt changed after verification.")
    record = _load_receipt(prepared.receipt_path)
    if record.get("artifacts_sha256") != prepared.artifacts_sha256:
        raise _reject("Verified hidden artifact set changed after verification.")
    rows = cast(list[dict[str, object]], record["artifacts"])
    row = next((item for item in rows if item.get("case_id") == case_id), None)
    if row is None:
        raise _reject("Hidden artifact case is absent.")
    _verify_artifacts(prepared.root, [row])
    return {
        "developer_tests": {
            "bytes": row["developer_tests_bytes"],
            "path": prepared.root / "artifacts" / case_id / "developer-tests.patch",
            "sha256": row["developer_tests_sha256"],
        },
        "metadata": {
            "bytes": row["metadata_bytes"],
            "path": prepared.root / "artifacts" / case_id / "metadata.json",
            "sha256": row["metadata_sha256"],
        },
        "production_patch": {
            "bytes": row["production_patch_bytes"],
            "path": prepared.root / "artifacts" / case_id / "production.patch",
            "sha256": row["production_patch_sha256"],
        },
    }


def _run_hidden_container(
    *, dataset_path: Path, request_path: Path, worker_path: Path, image_digest: str
) -> tuple[Path, str]:
    """Run worker with empty stdout and return a private copied-output temp directory.

    The caller owns the returned directory's parent and must eventually remove it. This function
    deliberately uses mkdtemp rather than TemporaryDirectory because verification needs the bytes
    after the container has been destroyed.
    """

    engine = _DockerEngine()
    engine.require_exact_image(image_digest)
    input_root = dataset_path.parent.resolve(strict=True)
    if request_path.parent != dataset_path.parent or worker_path.parent != dataset_path.parent:
        raise _reject("Hidden extraction inputs must share one private staged directory.")
    policy = DatasetParserContainerPolicy(image_digest=image_digest, max_output_bytes=64 * 1024)
    name = f"reproassert-hidden-{uuid.uuid4().hex[:16]}"
    command = (
        "-i",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "PYTHONHASHSEED=0",
        "PYTHONNOUSERSITE=1",
        "REPROASSERT_HIDDEN_CONTAINER=attested-v1",
        "/usr/local/bin/python",
        "-I",
        "-B",
        "/input/worker.py",
        "/input/swe-bench-verified-test.parquet",
        "/input/request.json",
        "/output",
    )
    output_root = Path(tempfile.mkdtemp(prefix="reproassert-v02-hidden-output-")).resolve(
        strict=True
    )
    os.chmod(output_root, 0o700)
    if any(output_root.iterdir()):
        raise _reject("Hidden extraction staging directory is not fresh and empty.")
    args = _hidden_create_args(name, input_root, output_root, policy, command)
    created = False
    try:
        engine.create(args)
        created = True
        before = engine.inspect(name)
        _verify_hidden_inspection(before, name, input_root, output_root, policy, command)
        inspection_sha256 = hashlib.sha256(_canonical(before)).hexdigest()
        result = engine.start(name, policy.timeout_seconds, policy.max_output_bytes)
        if result.returncode != 0 or result.timed_out or result.output_truncated:
            raise _reject("Hidden extraction container failed within its bounded policy.")
        if result.output:
            raise _reject("Hidden extraction worker violated its silent-output contract.")
        after = engine.inspect(name)
        state = after.get("State")
        if (
            not isinstance(state, dict)
            or state.get("Status") != "exited"
            or state.get("ExitCode") != 0
            or state.get("OOMKilled") is not False
        ):
            raise _reject("Hidden extraction container exit state is invalid.")
        _require_private_tree(output_root)
        return output_root, inspection_sha256
    except BaseException:
        shutil.rmtree(output_root, ignore_errors=True)
        raise
    finally:
        if created:
            engine.remove(name)


def _hidden_create_args(
    name: str,
    input_root: Path,
    output_root: Path,
    policy: DatasetParserContainerPolicy,
    command: tuple[str, ...],
) -> list[str]:
    return [
        "create",
        "--name",
        name,
        "--label",
        "io.reproassert.owner=controller-v1",
        "--label",
        "io.reproassert.role=hidden-extractor-v1",
        "--pull",
        "never",
        "--no-healthcheck",
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges=true",
        "--cgroupns",
        "private",
        "--ipc",
        "private",
        "--pids-limit",
        str(policy.pids),
        "--memory",
        str(policy.memory_bytes),
        "--memory-swap",
        str(policy.memory_bytes),
        "--cpus",
        str(policy.cpus),
        "--ulimit",
        "cpu=60:60",
        "--ulimit",
        "nofile=64:64",
        "--tmpfs",
        f"{_CONTAINER_TMP}:rw,noexec,nosuid,nodev,size={policy.tmpfs_bytes},mode=700",
        "--mount",
        f"type=bind,src={input_root},dst=/input,readonly",
        "--mount",
        f"type=bind,src={output_root},dst=/output",
        "--workdir",
        _CONTAINER_TMP,
        "--entrypoint",
        "/usr/bin/env",
        policy.image_digest,
        *command,
    ]


def _verify_hidden_inspection(
    raw: dict[str, Any],
    name: str,
    input_root: Path,
    output_root: Path,
    policy: DatasetParserContainerPolicy,
    command: tuple[str, ...],
) -> None:
    config, host, state = raw.get("Config"), raw.get("HostConfig"), raw.get("State")
    mounts = raw.get("Mounts")
    if not all(isinstance(v, dict) for v in (config, host, state)) or not isinstance(mounts, list):
        raise _reject("Docker returned incomplete hidden extractor inspection evidence.")
    config, host, state = (
        cast(dict[str, Any], config),
        cast(dict[str, Any], host),
        cast(dict[str, Any], state),
    )
    labels, tmpfs = config.get("Labels"), host.get("Tmpfs")
    mount_ok = len(mounts) == 2 and all(isinstance(item, dict) for item in mounts)
    if mount_ok:
        try:
            observed = {
                cast(str, cast(dict[str, Any], item).get("Destination")): (
                    cast(dict[str, Any], item).get("Type"),
                    Path(cast(str, cast(dict[str, Any], item).get("Source"))).resolve(strict=True),
                    cast(dict[str, Any], item).get("RW"),
                )
                for item in mounts
            }
            mount_ok = observed == {
                "/input": ("bind", input_root, False),
                "/output": ("bind", output_root, True),
            }
        except (OSError, TypeError):
            mount_ok = False
    checks = {
        "name": raw.get("Name") == f"/{name}",
        "created": state.get("Status") == "created",
        "image": raw.get("Image") == policy.image_digest,
        "config_image": config.get("Image") == policy.image_digest,
        "network": host.get("NetworkMode") == "none",
        "readonly": host.get("ReadonlyRootfs") is True,
        "user": config.get("User") == "65532:65532",
        "caps": "ALL" in (host.get("CapDrop") or []),
        "nnp": "no-new-privileges=true" in (host.get("SecurityOpt") or []),
        "privileged": host.get("Privileged") is False,
        "ipc": host.get("IpcMode") == "private",
        "cgroup": host.get("CgroupnsMode") == "private",
        "pids": host.get("PidsLimit") == policy.pids,
        "memory": host.get("Memory") == policy.memory_bytes
        and host.get("MemorySwap") == policy.memory_bytes,
        "cpus": host.get("NanoCpus") == int(policy.cpus * 1_000_000_000),
        "devices": not host.get("Devices"),
        "command": config.get("Entrypoint") == ["/usr/bin/env"]
        and config.get("Cmd") == list(command),
        "labels": isinstance(labels, dict)
        and labels.get("io.reproassert.role") == "hidden-extractor-v1",
        "mount": mount_ok,
        "tmpfs": isinstance(tmpfs, dict) and set(tmpfs) == {_CONTAINER_TMP},
    }
    failed = sorted(key for key, ok in checks.items() if not ok)
    if failed:
        raise _reject("Docker did not apply hidden extraction controls: " + ", ".join(failed))


def _persist_extracted(
    source: Path, root: Path, destination: Path, request: bytes
) -> list[dict[str, object]]:
    rows = _describe_extracted(source, request)
    for row in rows:
        case_id = cast(str, row["case_id"])
        case_root = destination / case_id
        case_root.mkdir(mode=0o700)
        for filename in ("production.patch", "developer-tests.patch", "metadata.json"):
            write_bytes_exclusive(
                case_root / filename, _read_regular(source / case_id / filename, _limit(filename))
            )
    return rows


def _describe_extracted(source: Path, request: bytes) -> list[dict[str, object]]:
    manifest = _load_json(source / "manifest.json", 64 * 1024)
    if (
        set(manifest) != {"artifacts", "case_count", "protocol", "request_sha256"}
        or manifest.get("protocol") != HIDDEN_WORKER_PROTOCOL
        or manifest.get("case_count") != 20
        or manifest.get("request_sha256") != hashlib.sha256(request).hexdigest()
    ):
        raise _reject("Hidden worker manifest identity is invalid.")
    rows = manifest.get("artifacts")
    if not isinstance(rows, list) or len(rows) != 20:
        raise _reject("Hidden worker manifest case count is invalid.")
    normalized: list[dict[str, object]] = []
    row_keys = {
        "case_id",
        "developer_tests_bytes",
        "developer_tests_sha256",
        "metadata_bytes",
        "metadata_sha256",
        "production_patch_bytes",
        "production_patch_sha256",
    }
    for ordinal, raw in enumerate(rows, 1):
        if (
            not isinstance(raw, dict)
            or set(raw) != row_keys
            or raw.get("case_id") != f"rk-v0.2-{ordinal:03d}"
        ):
            raise _reject("Hidden worker artifact order is invalid.")
        case_id = cast(str, raw["case_id"])
        expected = dict(raw)
        for filename, prefix in (
            ("production.patch", "production_patch"),
            ("developer-tests.patch", "developer_tests"),
            ("metadata.json", "metadata"),
        ):
            content = _read_regular(source / case_id / filename, _limit(filename))
            if (
                raw.get(f"{prefix}_bytes") != len(content)
                or raw.get(f"{prefix}_sha256") != hashlib.sha256(content).hexdigest()
            ):
                raise _reject("Hidden worker artifact differs from its commitment.")
        normalized.append(expected)
    return normalized


def _validate_metadata_against_plan(source: Path, plan: dict[str, object]) -> None:
    cases = cast(list[dict[str, object]], plan["cases"])
    expected_keys = {
        "base_commit",
        "case_id",
        "created_at",
        "difficulty",
        "environment_setup_commit",
        "instance_id",
        "repo",
        "source_dataset_row_ordinal",
        "source_row_sha256",
        "version",
    }
    for case in cases:
        case_id = cast(str, case["case_id"])
        metadata = _load_json(source / case_id / "metadata.json", _MAX_METADATA_BYTES)
        environment = metadata.get("environment_setup_commit")
        row_sha256 = metadata.get("source_row_sha256")
        if (
            set(metadata) != expected_keys
            or metadata.get("case_id") != case_id
            or metadata.get("instance_id") != case.get("instance_id")
            or metadata.get("repo") != case.get("repo")
            or metadata.get("base_commit") != case.get("base_sha")
            or metadata.get("source_dataset_row_ordinal") != case.get("source_dataset_row_ordinal")
            or not isinstance(environment, str)
            or re.fullmatch(r"[0-9a-f]{40}", environment) is None
            or not isinstance(metadata.get("created_at"), str)
            or not isinstance(metadata.get("difficulty"), str)
            or not isinstance(metadata.get("version"), str)
            or not isinstance(row_sha256, str)
            or _SHA256.fullmatch(row_sha256) is None
        ):
            raise _reject("Hidden row metadata differs from the frozen cohort.")


def _validate_attestation(attestation: dict[str, object], receipt: dict[str, object]) -> None:
    inputs = cast(dict[str, dict[str, object]], receipt["inputs"])
    inspection = attestation.get("container_inspection_sha256")
    if (
        set(attestation)
        != {
            "algorithm",
            "artifacts_sha256",
            "container_inspection_sha256",
            "image_digest",
            "inputs",
            "policy",
        }
        or attestation.get("algorithm") != HIDDEN_ATTESTATION_ALGORITHM
        or attestation.get("artifacts_sha256") != receipt.get("artifacts_sha256")
        or attestation.get("image_digest") != FROZEN_V02_DATASET_PARSER_IMAGE_ID
        or attestation.get("inputs")
        != {
            "cohort_plan_sha256": inputs["cohort_plan"]["sha256"],
            "request_sha256": inputs["request"]["sha256"],
            "source_dataset_sha256": SOURCE_DATASET_SHA256,
            "worker_sha256": inputs["worker"]["sha256"],
        }
        or attestation.get("policy") != _policy_record()
        or not isinstance(inspection, str)
        or _SHA256.fullmatch(inspection) is None
    ):
        raise _reject("Hidden container attestation semantics are invalid.")


def _verify_artifacts(root: Path, rows: list[dict[str, object]]) -> None:
    if _artifact_set_sha256(rows) is None:  # pragma: no cover - typing sentinel
        raise AssertionError
    for row in rows:
        case_id = cast(str, row["case_id"])
        for filename, prefix in (
            ("production.patch", "production_patch"),
            ("developer-tests.patch", "developer_tests"),
            ("metadata.json", "metadata"),
        ):
            content = _read_regular(root / "artifacts" / case_id / filename, _limit(filename))
            if (
                row.get(f"{prefix}_bytes") != len(content)
                or row.get(f"{prefix}_sha256") != hashlib.sha256(content).hexdigest()
            ):
                raise _reject("Stored hidden artifact differs from its commitment.")


def _artifact_set_sha256(rows: list[dict[str, object]]) -> str:
    return hashlib.sha256(_canonical(rows)).hexdigest()


def _request(plan: dict[str, object]) -> bytes:
    cases = cast(list[dict[str, object]], plan["cases"])
    return (
        _canonical(
            {
                "cases": [
                    {"case_id": item["case_id"], "instance_id": item["instance_id"]}
                    for item in cases
                ],
                "protocol": HIDDEN_REQUEST_PROTOCOL,
            }
        )
        + b"\n"
    )


def _require_frozen_plan(plan: dict[str, object]) -> None:
    if plan.get("cohort_plan_sha256") != FROZEN_V02_COHORT_PLAN_SHA256:
        raise _reject("Hidden extraction requires the exact frozen v0.2 cohort plan.")


def _copy_private(source: Path, destination: Path, limit: int) -> dict[str, object]:
    return _write_ref(
        destination.parents[1],
        destination.relative_to(destination.parents[1]).as_posix(),
        _read_regular(source, limit),
    )


def _write_ref(root: Path, relative: str, content: bytes) -> dict[str, object]:
    write_bytes_exclusive(root / relative, content)
    return {"bytes": len(content), "path": relative, "sha256": hashlib.sha256(content).hexdigest()}


def _verify_ref(root: Path, reference: dict[str, object], label: str) -> None:
    if set(reference) != {"bytes", "path", "sha256"}:
        raise _reject(f"{label} reference is invalid.")
    relative = reference.get("path")
    if (
        not isinstance(relative, str)
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
    ):
        raise _reject(f"{label} path is unsafe.")
    content = _read_regular(
        root / relative, SOURCE_DATASET_BYTES if label == "source_dataset" else _MAX_PLAN_BYTES
    )
    if (
        reference.get("bytes") != len(content)
        or reference.get("sha256") != hashlib.sha256(content).hexdigest()
    ):
        raise _reject(f"{label} differs from its commitment.")


def _load_receipt(path: Path) -> dict[str, object]:
    root = _load_json(path, MAX_RECEIPT_BYTES)
    expected = {
        "algorithm",
        "artifacts",
        "artifacts_sha256",
        "benchmark_version",
        "case_count",
        "claims",
        "container_attestation",
        "inputs",
        "prepared_at",
        "receipt_sha256",
        "schema_version",
        "status",
    }
    if (
        set(root) != expected
        or root.get("algorithm") != HIDDEN_EXTRACTION_ALGORITHM
        or root.get("status") != "evaluator_private_prepared_no_provider"
        or root.get("schema_version") != HIDDEN_SCHEMA_VERSION
        or root.get("benchmark_version") != "0.2"
        or root.get("case_count") != 20
        or root.get("receipt_sha256") != _self_hash(root)
    ):
        raise _reject("Hidden extraction receipt identity is invalid.")
    _timestamp(root.get("prepared_at"))
    if root.get("claims") != {
        "generator_visible": False,
        "hidden_bytes_emitted_to_stdout": False,
        "model_or_provider_invoked": False,
        "provider_calls": 0,
    }:
        raise _reject("Hidden extraction claims are invalid.")
    rows = root.get("artifacts")
    if not isinstance(rows, list) or root.get("artifacts_sha256") != _artifact_set_sha256(
        cast(list[dict[str, object]], rows)
    ):
        raise _reject("Hidden artifact set commitment is invalid.")
    return root


def _load_json(path: Path, limit: int) -> dict[str, object]:
    content = _read_regular(path, limit)
    try:
        decoded = json.loads(content, object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _reject("Evaluator-private artifact is invalid JSON.") from exc
    if not isinstance(decoded, dict) or content != _canonical(decoded) + b"\n":
        raise _reject("Evaluator-private artifact is not canonical JSON.")
    return cast(dict[str, object], decoded)


def _read_regular(path: Path, limit: int) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise _reject("Evaluator-private artifact must be a single-link regular file.")
        with open_regular_file(path) as stream:
            content = stream.read(limit + 1)
    except OSError as exc:
        raise _reject("Evaluator-private artifact could not be read safely.") from exc
    if len(content) > limit:
        raise _reject("Evaluator-private artifact exceeds its size limit.")
    return content


def _require_private_tree(root: Path) -> None:
    expected_cases = {f"rk-v0.2-{ordinal:03d}" for ordinal in range(1, 21)}
    if {path.name for path in root.iterdir()} != {"manifest.json", *expected_cases}:
        raise _reject("Container output tree has unexpected entries.")
    for case_id in expected_cases:
        case_root = root / case_id
        if not case_root.is_dir() or {path.name for path in case_root.iterdir()} != {
            "developer-tests.patch",
            "metadata.json",
            "production.patch",
        }:
            raise _reject("Container case output tree has unexpected entries.")
    for path in (root, *root.rglob("*")):
        metadata = path.lstat()
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise _reject("Container output contains a special file.")
        if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
            raise _reject("Container output contains an unsafe link.")
        os.chmod(path, 0o700 if stat.S_ISDIR(metadata.st_mode) else 0o600, follow_symlinks=False)


def _policy_record() -> dict[str, object]:
    return {
        "capabilities_dropped": "ALL",
        "environment_cleared_with_env_i": True,
        "host_credentials_forwarded": False,
        "input_mount_read_only": True,
        "network_mode": "none",
        "no_new_privileges": True,
        "output_private_bind": True,
        "read_only_root": True,
        "resource_limits": True,
        "user": "65532:65532",
    }


def _self_hash(record: dict[str, object]) -> str:
    unsigned = dict(record)
    unsigned.pop("receipt_sha256", None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject("Hidden extraction timestamp is invalid.")
    return value


def _limit(filename: str) -> int:
    return _MAX_METADATA_BYTES if filename == "metadata.json" else _MAX_PATCH_BYTES


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_hidden", message)
