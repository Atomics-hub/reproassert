from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast

import reproassert.benchmark_v02_package as package_module
from reproassert.benchmark_v02_package import (
    BENCHMARK_VERSION,
    SEMANTIC_VERIFICATION_ALGORITHM,
    SOURCE_DATASET_TRANSFORM,
    ArtifactReference,
    FixMappingReceipt,
    V02CaseIdentity,
    V02SemanticVerification,
    V02SemanticVerificationContext,
    VerifiedV02CasePackage,
    VerifiedV02EvaluatorCapability,
    load_v02_preregistration,
    require_v02_evaluator_capability,
    verify_v02_case_package,
)
from reproassert.candidate import ValidatedCandidate, validate_candidate_payload
from reproassert.context import (
    V02_SOURCE_CONTEXT_ALGORITHM,
    V02_SOURCE_CONTEXT_POLICY_SHA256,
    SourceContext,
    build_source_context,
)
from reproassert.dependency_execution_receipt import (
    VerifiedDependencyExecutionReceipt,
    load_dependency_execution_receipt,
)
from reproassert.errors import PolicyRejection
from reproassert.git_objects import (
    GIT_OBJECT_CONTENT_TREE_ALGORITHM,
    VerifiedGitObjectPlan,
    materialize_git_workspace,
    verify_git_object_blobs,
)
from reproassert.isolation_canary import (
    CANARY_VERSION,
    EVALUATOR_DESTINATION,
    GENERATOR_DESTINATION,
    IsolationCanaryResult,
)
from reproassert.safeio import open_regular_file, require_private_directory
from reproassert.source_attestation import SourceTreeAttestation, attest_source_tree

V02_SOURCE_EVIDENCE_ALGORITHM = "reproassert-v02-exact-object-source-v1"
V02_REVIEWER_ROLE_SEAL_ALGORITHM = "reproassert-v02-reviewer-role-seal-v1"
V02_DATASET_EVIDENCE_ALGORITHM = "reproassert-v02-upstream-dataset-evidence-v1"

OFFICIAL_TDD_BENCH_GIT_SHA = "e88abaa3fa6db0a5cb0f92909a2b5fa9e9ff2e2d"
OFFICIAL_TDD_BENCH_ROOT_TREE_OID = "72cc5b2800552461a0ca234e75c6c89f7c87a3ed"
OFFICIAL_TDD_ID_LIST_PATH = "id_list.txt"
OFFICIAL_TDD_ID_LIST_BLOB_OID = "fd0fb7a892b9e9be724937dab535b98bafeb4c64"
OFFICIAL_TDD_ID_LIST_BYTES = 10_510
OFFICIAL_TDD_ID_LIST_SHA256 = "d4a725758956230f4cf24e1adc2d01eeb18d6a04d726ae4bb2a73204bea33ec1"

OFFICIAL_SOURCE_DATASET_GIT_SHA = "7f1793642f5ab809c0bce2e343b902247954170e"
OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID = "2bc6938414d14885cd77d89e4a66f7aecbcc7147"
OFFICIAL_SOURCE_DATASET_PATH = "default/test/0000.parquet"
OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID = "99d737164b1df31cc8dcc963b94c7b7a9e5f15da"
OFFICIAL_SOURCE_DATASET_LFS_SHA256 = (
    "a45b1fe4e2f0c8390b2b2938ac83e92ed5979000856808f3679c07812e9e6dcd"
)
OFFICIAL_SOURCE_DATASET_XET_SHA256 = (
    "928ff5796c01f0fccf70d199d8b6318427eb1c181fa43666fdb81d4cce2872f3"
)
OFFICIAL_SOURCE_DATASET_BYTES = 2_096_679

_SOURCE_EVIDENCE_ISSUER = object()
_CONTEXT_ISSUER = object()
_DATASET_EVIDENCE_ISSUER = object()
_SESSION_ISSUER = object()
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}\Z")
_CASE_ID = re.compile(r"rk-v0\.2-[0-9]{3}\Z")
_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z\Z")
_RUN_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}\Z")
_MAX_RECEIPT_BYTES = 32 * 1024 * 1024
_MAX_PACKAGE_FILES = 20_000
_MAX_PACKAGE_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True, init=False)
class VerifiedV02SourceEvidence:
    """Nominal result of exact-object source rederivation.

    This object is an application TCB composition guard, not a same-process sandbox. Repository,
    package, plugin, issue, and model-controlled Python must never run in the controller process.
    """

    case: V02CaseIdentity
    receipt_sha256: str
    base_root_tree_oid: str
    source_tree_sha256: str
    exact_object_manifest_sha256: str
    exact_object_tree_sha256: str
    evidence_sha256: str
    _plan: VerifiedGitObjectPlan = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV02SourceEvidence is issued only by exact-object verification")


@dataclass(frozen=True, init=False)
class VerifiedV02GeneratorSourceContext:
    """Generator-safe context with no evaluator, hidden-fixed, package, or gold material."""

    case: V02CaseIdentity
    source_evidence_sha256: str
    source_tree_sha256: str
    snapshot_sha256: str
    algorithm: str
    policy_sha256: str
    context_sha256: str
    source_context: SourceContext
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV02GeneratorSourceContext is application-derived only")


@dataclass(frozen=True, init=False)
class VerifiedV02DatasetEvidence:
    """Nominal result of the pinned upstream-object and Parquet-row rederiver.

    No public constructor is provided yet: issuance remains fail-closed until the application ships
    the hash-locked offline Parquet parser. Package-local JSON rows and semantic booleans are never
    accepted as substitutes for that parser result.
    """

    case: V02CaseIdentity
    tdd_bench_git_sha: str
    tdd_bench_root_tree_oid: str
    tdd_id_list_blob_oid: str
    tdd_id_list_sha256: str
    tdd_membership_ordinal: int
    source_dataset_git_sha: str
    source_dataset_root_tree_oid: str
    source_dataset_artifact_git_blob_oid: str
    source_dataset_artifact_lfs_sha256: str
    source_dataset_artifact_lfs_bytes: int
    source_dataset_artifact_xet_sha256: str
    source_dataset_row_ordinal: int
    source_dataset_row_sha256: str
    source_dataset_transform: str
    parser_receipt_sha256: str
    dataset_parser_image_digest: str
    boundary_attestation_sha256: str
    upstream_evidence_sha256: str
    evidence_sha256: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV02DatasetEvidence requires the trusted pinned parser")


class _V02EvaluationSessionState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.consumed = False


@dataclass(frozen=True, init=False)
class V02EvaluationSession:
    """One-use production lease binding one frozen candidate to one evaluator authority."""

    campaign_id: str
    attempt_id: str
    case: V02CaseIdentity
    candidate_sha256: str
    candidate_path: str
    candidate_nodeid: str
    capability_sha256: str
    dependency_receipt_sha256: str | None
    session_sha256: str
    _capability: VerifiedV02EvaluatorCapability = field(repr=False, compare=False)
    _state: _V02EvaluationSessionState = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("V02EvaluationSession instances are application-issued only")


_SESSION_REGISTRY: dict[int, _V02EvaluationSessionState] = {}
_SESSION_REGISTRY_LOCK = threading.Lock()


@dataclass(frozen=True)
class _DerivedSemanticEvidence:
    context: V02SemanticVerificationContext
    verification: V02SemanticVerification
    dependency: VerifiedDependencyExecutionReceipt
    source_context: VerifiedV02GeneratorSourceContext
    artifact_snapshots: tuple[tuple[Path, str], ...]


def render_v02_source_evidence_receipt(
    case: V02CaseIdentity, exact_object_plan: VerifiedGitObjectPlan
) -> bytes:
    """Render inert v0.2 source evidence after locally revalidating exact Git objects."""

    case = _validated_case(case)
    plan, attestation = _materialize_and_attest(exact_object_plan)
    return _canonical_json(_source_receipt_record(case, plan, attestation)) + b"\n"


def verify_v02_source_evidence(
    receipt_path: Path,
    *,
    case: V02CaseIdentity,
    exact_object_plan: VerifiedGitObjectPlan,
) -> VerifiedV02SourceEvidence:
    """Revalidate exact objects and issue a nominal v0.2 source-evidence result."""

    case = _validated_case(case)
    before, _ = _load_canonical_json(receipt_path, "v0.2 source evidence receipt")
    plan, attestation = _materialize_and_attest(exact_object_plan)
    expected = _canonical_json(_source_receipt_record(case, plan, attestation)) + b"\n"
    if before != expected:
        raise _reject("Source receipt differs from the freshly rederived exact-object source.")
    after = _read_regular(receipt_path, _MAX_RECEIPT_BYTES, "v0.2 source evidence receipt")
    if after != before:
        raise _reject("Source evidence receipt changed during verification.")
    receipt_sha256 = hashlib.sha256(before).hexdigest()
    record = {
        "algorithm": V02_SOURCE_EVIDENCE_ALGORITHM,
        "case": asdict(case),
        "receipt_sha256": receipt_sha256,
        "base_root_tree_oid": plan.snapshot.root_tree_oid,
        "source_tree_sha256": attestation.tree_sha256,
        "exact_object_manifest_sha256": plan.snapshot.manifest_sha256,
        "exact_object_tree_sha256": plan.tree_sha256,
    }
    value = object.__new__(VerifiedV02SourceEvidence)
    for name, item in record.items():
        object.__setattr__(value, name, case if name == "case" else item)
    object.__setattr__(value, "evidence_sha256", _json_sha256(record))
    object.__setattr__(value, "_plan", plan)
    object.__setattr__(value, "_issuer", _SOURCE_EVIDENCE_ISSUER)
    return value


def require_v02_source_evidence(value: object) -> VerifiedV02SourceEvidence:
    if type(value) is not VerifiedV02SourceEvidence:
        raise _reject("Source evidence type is invalid.")
    try:
        if value._issuer is not _SOURCE_EVIDENCE_ISSUER:
            raise _reject("Source evidence issuer is invalid.")
        case = _validated_case(value.case)
        plan = verify_git_object_blobs(
            value._plan.snapshot, lambda entry: value._plan.blob_bytes(entry.oid)
        )
        if plan != value._plan:
            raise _reject("Source exact-object plan is inconsistent.")
        record = {
            "algorithm": V02_SOURCE_EVIDENCE_ALGORITHM,
            "case": asdict(case),
            "receipt_sha256": _sha256(value.receipt_sha256, "source receipt"),
            "base_root_tree_oid": _git_oid(value.base_root_tree_oid, "source root tree"),
            "source_tree_sha256": _sha256(value.source_tree_sha256, "source tree"),
            "exact_object_manifest_sha256": _sha256(
                value.exact_object_manifest_sha256, "source object manifest"
            ),
            "exact_object_tree_sha256": _sha256(
                value.exact_object_tree_sha256, "source object tree"
            ),
        }
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise _reject("Source evidence fields are invalid.") from exc
    if (
        record["base_root_tree_oid"] != plan.snapshot.root_tree_oid
        or record["exact_object_manifest_sha256"] != plan.snapshot.manifest_sha256
        or record["exact_object_tree_sha256"] != plan.tree_sha256
        or value.evidence_sha256 != _json_sha256(record)
    ):
        raise _reject("Source evidence identity is inconsistent.")
    return value


def derive_v02_generator_source_context(
    source_evidence: VerifiedV02SourceEvidence,
    generator_projection_path: Path,
) -> VerifiedV02GeneratorSourceContext:
    """Derive the pre-generation context from base source plus the safe public projection only."""

    source = require_v02_source_evidence(source_evidence)
    projection = _load_generator_projection(generator_projection_path, expected_case=source.case)
    with tempfile.TemporaryDirectory(prefix="reproassert-v02-context-") as temporary:
        parent = Path(temporary).resolve(strict=True)
        os.chmod(parent, 0o700)
        workspace = materialize_git_workspace(source._plan, parent / "base")
        attestation = attest_source_tree(
            workspace.path, expected_git_tree_oid=source.base_root_tree_oid
        )
        if attestation.tree_sha256 != source.source_tree_sha256:
            raise _reject("Source tree changed before generator context derivation.")
        issue = cast(Mapping[str, object], projection["issue_snapshot"])
        context = build_source_context(
            workspace.path,
            issue_title=cast(str, issue["title"]),
            issue_body=cast(str, issue["body"]),
        )
    record = _source_context_record(source, projection, context)
    value = object.__new__(VerifiedV02GeneratorSourceContext)
    fields = {
        "case": source.case,
        "source_evidence_sha256": source.evidence_sha256,
        "source_tree_sha256": source.source_tree_sha256,
        "snapshot_sha256": cast(str, issue["snapshot_sha256"]),
        "algorithm": V02_SOURCE_CONTEXT_ALGORITHM,
        "policy_sha256": V02_SOURCE_CONTEXT_POLICY_SHA256,
        "context_sha256": _json_sha256(record),
        "source_context": context,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    object.__setattr__(value, "_issuer", _CONTEXT_ISSUER)
    return value


def require_v02_generator_source_context(value: object) -> VerifiedV02GeneratorSourceContext:
    if type(value) is not VerifiedV02GeneratorSourceContext:
        raise _reject("Generator source context type is invalid.")
    try:
        if value._issuer is not _CONTEXT_ISSUER:
            raise _reject("Generator source context issuer is invalid.")
        case = _validated_case(value.case)
        _sha256(value.source_evidence_sha256, "context source evidence")
        _sha256(value.source_tree_sha256, "context source tree")
        _sha256(value.snapshot_sha256, "context snapshot")
        if value.algorithm != V02_SOURCE_CONTEXT_ALGORITHM:
            raise _reject("Generator source context algorithm is invalid.")
        if value.policy_sha256 != V02_SOURCE_CONTEXT_POLICY_SHA256:
            raise _reject("Generator source context policy is invalid.")
        if type(value.source_context) is not SourceContext:
            raise _reject("Generator source context payload type is invalid.")
        record = {
            "algorithm": value.algorithm,
            "policy_sha256": value.policy_sha256,
            "case": asdict(case),
            "source_evidence_sha256": value.source_evidence_sha256,
            "source_tree_sha256": value.source_tree_sha256,
            "snapshot_sha256": value.snapshot_sha256,
            "context": value.source_context.to_dict(),
        }
    except (AttributeError, TypeError, ValueError) as exc:
        raise _reject("Generator source context fields are invalid.") from exc
    if value.context_sha256 != _json_sha256(record):
        raise _reject("Generator source context digest is invalid.")
    return value


def require_v02_dataset_evidence(value: object) -> VerifiedV02DatasetEvidence:
    """Require dataset evidence issued from the attested production parser boundary."""

    if type(value) is not VerifiedV02DatasetEvidence:
        raise _reject("Pinned upstream dataset evidence is required.")
    try:
        if value._issuer is not _DATASET_EVIDENCE_ISSUER:
            raise _reject("Dataset evidence issuer is invalid.")
        case = _validated_case(value.case)
        record = _dataset_evidence_record(value, case)
    except (AttributeError, TypeError, ValueError) as exc:
        raise _reject("Dataset evidence fields are invalid.") from exc
    if value.evidence_sha256 != _json_sha256(record):
        raise _reject("Dataset evidence digest is invalid.")
    _require_official_dataset_constants(value)
    return value


def issue_v02_dataset_evidence_from_attested_parse(
    *,
    attested_parse: object,
    case: V02CaseIdentity,
    instance_id: str,
) -> VerifiedV02DatasetEvidence:
    """Promote one case only from a revalidated Docker-bound parser handoff.

    Raw parser receipts and host-native ``PreparedV02DatasetEvidence`` values are deliberately not
    accepted. The nominal capability binds the immutable parser image, boundary attestation,
    private receipt, and independently verified upstream graph before selecting the requested row.
    """

    from reproassert import benchmark_v02_dataset as dataset_module
    from reproassert.benchmark_v02_dataset_sandbox import require_attested_v02_dataset_parse

    case = _validated_case(case)
    if (
        not isinstance(instance_id, str)
        or re.fullmatch(r"[A-Za-z0-9_.-]+__[A-Za-z0-9_.-]+-[1-9][0-9]*", instance_id) is None
    ):
        raise _reject("Dataset instance ID is invalid.")
    attested = require_attested_v02_dataset_parse(attested_parse)
    receipt = dataset_module._validate_private_receipt(attested.parser_receipt)
    dataset = cast(Mapping[str, object], receipt["dataset"])
    rows = cast(Sequence[object], dataset["joined_tdd_rows"])
    selected = next(
        (
            cast(Mapping[str, object], row)
            for row in rows
            if isinstance(row, Mapping) and row.get("instance_id") == instance_id
        ),
        None,
    )
    if selected is None:
        raise _reject("Dataset instance is not a member of the exact TDD-Bench cohort.")
    identity = {"base_commit": case.base_sha, "instance_id": instance_id, "repo": case.repo}
    if selected["identity_sha256"] != _json_sha256(identity):
        raise _reject("Dataset row identity differs from the requested benchmark case.")
    upstream = cast(Mapping[str, object], receipt["upstream"])
    source = cast(Mapping[str, object], upstream["source_dataset"])
    tdd = cast(Mapping[str, object], upstream["tdd_bench"])
    verification = cast(Mapping[str, object], upstream["verification"])
    if verification["upstream_evidence_sha256"] != attested.upstream_evidence_sha256:
        raise _reject("Attested parser and private receipt bind different upstream evidence.")

    value = object.__new__(VerifiedV02DatasetEvidence)
    fields: dict[str, object] = {
        "case": case,
        "tdd_bench_git_sha": tdd["git_sha"],
        "tdd_bench_root_tree_oid": tdd["root_tree_oid"],
        "tdd_id_list_blob_oid": tdd["id_list_blob_oid"],
        "tdd_id_list_sha256": tdd["id_list_sha256"],
        "tdd_membership_ordinal": selected["tdd_membership_ordinal"],
        "source_dataset_git_sha": source["git_sha"],
        "source_dataset_root_tree_oid": source["root_tree_oid"],
        "source_dataset_artifact_git_blob_oid": source["artifact_git_blob_oid"],
        "source_dataset_artifact_lfs_sha256": source["artifact_lfs_sha256"],
        "source_dataset_artifact_lfs_bytes": source["artifact_bytes"],
        "source_dataset_artifact_xet_sha256": source["artifact_xet_sha256"],
        "source_dataset_row_ordinal": selected["source_dataset_row_ordinal"],
        "source_dataset_row_sha256": selected["source_dataset_row_sha256"],
        "source_dataset_transform": dataset["source_dataset_transform"],
        "parser_receipt_sha256": attested.parser_receipt_sha256,
        "dataset_parser_image_digest": attested.image_digest,
        "boundary_attestation_sha256": attested.boundary_attestation_sha256,
        "upstream_evidence_sha256": attested.upstream_evidence_sha256,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    object.__setattr__(value, "_issuer", _DATASET_EVIDENCE_ISSUER)
    record = _dataset_evidence_record(value, value.case)
    object.__setattr__(value, "evidence_sha256", _json_sha256(record))
    return require_v02_dataset_evidence(value)


def acquire_v02_evaluation_session(
    evaluator_capability: VerifiedV02EvaluatorCapability,
    *,
    campaign_id: str,
    attempt_id: str,
    candidate: ValidatedCandidate,
    candidate_path: str,
) -> V02EvaluationSession:
    """Mint one in-memory lease after generation has terminated and the candidate is frozen."""

    capability = require_v02_evaluator_capability(evaluator_capability)
    campaign = _run_identifier(campaign_id, "campaign ID")
    attempt = _run_identifier(attempt_id, "attempt ID")
    candidate_value = _revalidated_candidate(candidate)
    relative_path = _validated_candidate_path(candidate_path, candidate_value.test_function)
    record = {
        "algorithm": "reproassert-v02-evaluation-session-v1",
        "campaign_id": campaign,
        "attempt_id": attempt,
        "case": asdict(capability.case),
        "candidate_sha256": candidate_value.sha256,
        "candidate_path": relative_path,
        "candidate_nodeid": f"{relative_path}::{candidate_value.test_function}",
        "capability_sha256": capability.capability_sha256,
        "dependency_receipt_sha256": capability.dependency_receipt_sha256,
    }
    state = _V02EvaluationSessionState()
    value = object.__new__(V02EvaluationSession)
    for name, item in record.items():
        if name != "algorithm":
            object.__setattr__(
                value,
                name,
                capability.case if name == "case" else item,
            )
    object.__setattr__(value, "session_sha256", _json_sha256(record))
    object.__setattr__(value, "_capability", capability)
    object.__setattr__(value, "_state", state)
    object.__setattr__(value, "_issuer", _SESSION_ISSUER)
    with _SESSION_REGISTRY_LOCK:
        if id(value) in _SESSION_REGISTRY:
            raise _reject("Evaluation session object identity was unexpectedly reused.")
        _SESSION_REGISTRY[id(value)] = state
    return value


def require_v02_evaluation_session(value: object) -> V02EvaluationSession:
    if type(value) is not V02EvaluationSession:
        raise _reject("Evaluation session type is invalid.")
    try:
        if (
            value._issuer is not _SESSION_ISSUER
            or type(value._state) is not _V02EvaluationSessionState
        ):
            raise _reject("Evaluation session issuer is invalid.")
        capability = require_v02_evaluator_capability(value._capability)
        record = {
            "algorithm": "reproassert-v02-evaluation-session-v1",
            "campaign_id": _run_identifier(value.campaign_id, "campaign ID"),
            "attempt_id": _run_identifier(value.attempt_id, "attempt ID"),
            "case": asdict(_validated_case(value.case)),
            "candidate_sha256": _sha256(value.candidate_sha256, "session candidate"),
            "candidate_path": _validated_candidate_path(
                value.candidate_path, value.candidate_nodeid.rpartition("::")[2]
            ),
            "candidate_nodeid": value.candidate_nodeid,
            "capability_sha256": _sha256(value.capability_sha256, "session capability"),
            "dependency_receipt_sha256": value.dependency_receipt_sha256,
        }
        if value.dependency_receipt_sha256 is not None:
            _sha256(value.dependency_receipt_sha256, "session dependency receipt")
    except (AttributeError, TypeError, ValueError) as exc:
        raise _reject("Evaluation session fields are invalid.") from exc
    if (
        value.case != capability.case
        or value.capability_sha256 != capability.capability_sha256
        or value.dependency_receipt_sha256 != capability.dependency_receipt_sha256
        or value.candidate_nodeid
        != (f"{value.candidate_path}::{value.candidate_nodeid.rpartition('::')[2]}")
        or value.session_sha256 != _json_sha256(record)
    ):
        raise _reject("Evaluation session identity is inconsistent.")
    with _SESSION_REGISTRY_LOCK:
        if _SESSION_REGISTRY.get(id(value)) is not value._state:
            raise _reject("Evaluation session is unknown, consumed, or expired.")
    return value


def consume_v02_evaluation_session(
    session: V02EvaluationSession,
    *,
    campaign_id: str,
    attempt_id: str,
    candidate: ValidatedCandidate,
    candidate_path: str,
) -> VerifiedV02EvaluatorCapability:
    """Atomically consume a lease immediately before the first hidden-fixed observation."""

    value = require_v02_evaluation_session(session)
    candidate_value = _revalidated_candidate(candidate)
    relative_path = _validated_candidate_path(candidate_path, candidate_value.test_function)
    if (
        value.campaign_id != _run_identifier(campaign_id, "campaign ID")
        or value.attempt_id != _run_identifier(attempt_id, "attempt ID")
        or value.candidate_sha256 != candidate_value.sha256
        or value.candidate_path != relative_path
        or value.candidate_nodeid != f"{relative_path}::{candidate_value.test_function}"
    ):
        raise _reject("Evaluation session does not authorize this exact attempt and candidate.")
    state = value._state
    with state.lock, _SESSION_REGISTRY_LOCK:
        if state.consumed or _SESSION_REGISTRY.get(id(value)) is not state:
            raise _reject("Evaluation session was already consumed or expired.")
        state.consumed = True
        del _SESSION_REGISTRY[id(value)]
    return require_v02_evaluator_capability(value._capability)


def verify_v02_case_package_for_evaluation(
    package_path: Path,
    *,
    preregistration_path: Path,
    source_evidence: VerifiedV02SourceEvidence,
    dataset_evidence: VerifiedV02DatasetEvidence,
    dependency_plan_path: Path,
    isolation_result: IsolationCanaryResult,
    semantic_reviewer_ids: Sequence[str],
    completed_at: str,
    scored_generator_mode: str,
) -> VerifiedV02CasePackage:
    """Application-owned capability issuer; never call from a generator/plugin process.

    Python cannot protect an internal token from hostile code already executing in this process.
    Therefore the entire call is trusted computing base: only fixed application code may call it,
    and all repository/model/package-controlled execution must already have terminated.
    """

    source = require_v02_source_evidence(source_evidence)
    dataset = require_v02_dataset_evidence(dataset_evidence)
    preregistration = load_v02_preregistration(preregistration_path)
    frozen = _require_frozen_case(preregistration.cases, source.case)
    if dataset.case != source.case:
        raise _reject("Dataset and source evidence cases differ.")
    with tempfile.TemporaryDirectory(prefix="reproassert-v02-sealed-package-") as temporary:
        sealed_root = Path(temporary).resolve(strict=True) / "package"
        sealed_path = _seal_private_package(Path(package_path), sealed_root)
        issuer = _ApplicationSemanticIssuer(
            source=source,
            dataset=dataset,
            dependency_plan_path=Path(dependency_plan_path),
            isolation_result=isolation_result,
            semantic_reviewer_ids=tuple(semantic_reviewer_ids),
            completed_at=completed_at,
            scored_generator_mode=scored_generator_mode,
        )
        package = verify_v02_case_package(sealed_path, trusted_semantic_verifier=issuer)
        if (
            package.case != source.case
            or package.generator_projection_sha256 != frozen.generator_projection_sha256
            or package.evaluator_commitment_sha256 != frozen.evaluator_commitment_sha256
        ):
            raise _reject("Private package differs from the frozen preregistration case.")
        capability = issuer.issue_capability(
            package,
            preregistration_sha256=preregistration.raw_sha256,
            cohort_sha256=cast(str, preregistration.decoded["cohort_sha256"]),
            preregistered_case_sha256=_json_sha256(asdict(frozen)),
        )
        if capability.source_context_sha256 != frozen.source_context_sha256:
            raise _reject("Derived source context differs from the frozen preregistration case.")
    return replace(package, evaluator_capability=capability)


class _ApplicationSemanticIssuer:
    """Exact concrete TCB implementation; no callback, protocol, plugin, or dynamic import."""

    def __init__(
        self,
        *,
        source: VerifiedV02SourceEvidence,
        dataset: VerifiedV02DatasetEvidence,
        dependency_plan_path: Path,
        isolation_result: IsolationCanaryResult,
        semantic_reviewer_ids: tuple[str, ...],
        completed_at: str,
        scored_generator_mode: str,
    ) -> None:
        self._source = source
        self._dataset = dataset
        self._dependency_plan_path = dependency_plan_path
        self._isolation_result = isolation_result
        self._semantic_reviewer_ids = _reviewer_ids(semantic_reviewer_ids)
        self._completed_at = _timestamp(completed_at, "semantic completion")
        if scored_generator_mode not in {
            "trusted_builtin_provider_adapter",
            "sandboxed_generator_process",
        }:
            raise _reject("Scored generator mode is not application-approved.")
        self._scored_generator_mode = scored_generator_mode
        self._derived: _DerivedSemanticEvidence | None = None

    def verify(self, context: V02SemanticVerificationContext) -> V02SemanticVerification:
        if type(context) is not V02SemanticVerificationContext or self._derived is not None:
            raise _reject("Semantic issuer context or lifecycle is invalid.")
        source = require_v02_source_evidence(self._source)
        dataset = require_v02_dataset_evidence(self._dataset)
        if context.case != source.case or dataset.case != source.case:
            raise _reject("Semantic evidence cases differ.")
        mapping = context.mapping
        _bind_source_to_mapping(source, mapping)
        _bind_dataset_to_mapping(dataset, mapping)
        source_ref = context.supporting_inputs["source_receipt"]
        if source_ref.sha256 != source.receipt_sha256:
            raise _reject("Package source receipt differs from exact-object evidence.")

        projection_path = context.package_root / context.generator_projection.path
        source_context = derive_v02_generator_source_context(source, projection_path)
        dependency_ref = context.supporting_inputs["dependency_receipt"]
        dependency_path = context.package_root / dependency_ref.path
        dependency = load_dependency_execution_receipt(
            dependency_path,
            expected_receipt_sha256=dependency_ref.sha256,
            expected_plan_path=self._dependency_plan_path,
            expected_case_id=context.case.id,
            expected_base_sha=context.case.base_sha,
            expected_source_tree_sha256=source.source_tree_sha256,
        )
        isolation_ref = context.supporting_inputs["isolation_canary_receipt"]
        _verify_isolation_receipt(
            context.package_root / isolation_ref.path,
            isolation_ref,
            self._isolation_result,
            expected_policy_sha256=context.isolation_policy_sha256,
            expected_image_id=dependency.image_id,
        )
        role_ref = context.supporting_inputs["reviewer_role_seal"]
        _verify_reviewer_role_seal(
            context.package_root / role_ref.path,
            role_ref,
            mapping=mapping,
            case=context.case,
            semantic_reviewer_ids=self._semantic_reviewer_ids,
            completed_at=self._completed_at,
        )
        hidden_fixed_oid, head_oid, patch_paths = _rederive_patch_causality(
            source, context.package_root, mapping
        )
        verification = _semantic_verification(
            context,
            source=source,
            dataset=dataset,
            source_context=source_context,
            dependency=dependency,
            isolation_result=self._isolation_result,
            semantic_reviewer_ids=self._semantic_reviewer_ids,
            completed_at=self._completed_at,
            scored_generator_mode=self._scored_generator_mode,
            hidden_fixed_oid=hidden_fixed_oid,
            head_oid=head_oid,
        )
        snapshots = tuple(
            (path, _file_sha256(path))
            for path in (
                context.package_root / source_ref.path,
                dependency_path,
                context.package_root / isolation_ref.path,
                context.package_root / role_ref.path,
                projection_path,
                *patch_paths,
            )
        )
        self._derived = _DerivedSemanticEvidence(
            context=context,
            verification=verification,
            dependency=dependency,
            source_context=source_context,
            artifact_snapshots=snapshots,
        )
        return verification

    def issue_capability(
        self,
        package: VerifiedV02CasePackage,
        *,
        preregistration_sha256: str,
        cohort_sha256: str,
        preregistered_case_sha256: str,
    ) -> VerifiedV02EvaluatorCapability:
        derived = self._derived
        if derived is None or package.case != derived.context.case:
            raise _reject("Semantic issuer has no matching completed derivation.")
        for path, expected_sha256 in derived.artifact_snapshots:
            if _file_sha256(path) != expected_sha256:
                raise _reject("Evaluator artifact changed before capability issuance.")
        verification = derived.verification
        semantic_ref = derived.context.supporting_inputs["semantic_verification_receipt"]
        semantic_path = derived.context.package_root / semantic_ref.path
        expected_semantic = _canonical_json(asdict(verification)) + b"\n"
        observed_semantic = _read_regular(semantic_path, _MAX_RECEIPT_BYTES, "semantic receipt")
        if observed_semantic != expected_semantic:
            raise _reject("Semantic receipt changed before capability issuance.")
        dependency = load_dependency_execution_receipt(
            derived.context.package_root
            / derived.context.supporting_inputs["dependency_receipt"].path,
            expected_receipt_sha256=derived.dependency.receipt_sha256,
            expected_plan_path=self._dependency_plan_path,
            expected_case_id=package.case.id,
            expected_base_sha=package.case.base_sha,
            expected_source_tree_sha256=self._source.source_tree_sha256,
        )
        return package_module.VerifiedV02EvaluatorCapability(
            package_module._CAPABILITY_ISSUER,  # TCB nominal token
            case=package.case,
            preregistration_sha256=_sha256(preregistration_sha256, "preregistration"),
            cohort_sha256=_sha256(cohort_sha256, "cohort"),
            preregistered_case_sha256=_sha256(preregistered_case_sha256, "preregistered case"),
            package_identity_sha256=package.evaluator_package_sha256,
            public_commitment_sha256=package.evaluator_commitment_sha256,
            generator_projection_sha256=package.generator_projection_sha256,
            dataset_evidence_sha256=self._dataset.evidence_sha256,
            difficulty=package.difficulty,
            upstream_instance_id=package.upstream_instance_id,
            fixing_pr_number=package.fixing_pr_number,
            evaluator_commitment_nonce=package.evaluator_commitment_nonce,
            verification_completed_at=package.verification_completed_at,
            base_commit_sha=package.case.base_sha,
            base_root_tree_oid=self._source.base_root_tree_oid,
            source_receipt_sha256=self._source.receipt_sha256,
            source_tree_sha256=self._source.source_tree_sha256,
            source_context_algorithm=derived.source_context.algorithm,
            source_context_policy_sha256=derived.source_context.policy_sha256,
            source_context_sha256=derived.source_context.context_sha256,
            hidden_fixed_root_tree_oid=verification.hidden_fixed_root_tree_oid,
            fixing_head_commit_sha=verification.fixing_head_commit_sha,
            fixing_head_root_tree_oid=verification.fixing_head_root_tree_oid,
            production_patch_sha256=verification.production_patch_sha256,
            developer_tests_sha256=verification.developer_tests_sha256,
            dependencies_required=True,
            dependency_receipt_sha256=dependency.receipt_sha256,
            dependency_plan_sha256=dependency.plan_sha256,
            dependency_tree_sha256=dependency.dependency_tree_sha256,
            dependency_runner_image_id=dependency.image_id,
            isolation_receipt_sha256=verification.isolation_receipt_sha256,
            isolation_policy_sha256=verification.isolation_policy_sha256,
            reviewer_role_seal_sha256=verification.reviewer_role_seal_sha256,
            semantic_verification_receipt_sha256=semantic_ref.sha256,
        )


def render_v02_reviewer_role_seal(
    *,
    case: V02CaseIdentity,
    mapping_receipt_sha256: str,
    mapping_reviewer_ids: Sequence[str],
    semantic_reviewer_ids: Sequence[str],
    sealed_at: str,
) -> bytes:
    """Render the inert canonical role-separation record used by the application reviewer UI."""

    case = _validated_case(case)
    mapping_ids = _reviewer_ids(tuple(mapping_reviewer_ids))
    semantic_ids = _reviewer_ids(tuple(semantic_reviewer_ids))
    if set(mapping_ids) & set(semantic_ids):
        raise _reject("Mapping and semantic reviewer roles overlap.")
    record = {
        "algorithm": V02_REVIEWER_ROLE_SEAL_ALGORITHM,
        "case": asdict(case),
        "mapping_receipt_sha256": _sha256(mapping_receipt_sha256, "mapping receipt"),
        "mapping_reviewer_ids": list(mapping_ids),
        "semantic_reviewer_ids": list(semantic_ids),
        "gold_hidden_until_verdict": True,
        "sealed_at": _timestamp(sealed_at, "reviewer role seal"),
    }
    return _canonical_json(record) + b"\n"


def _materialize_and_attest(
    exact_object_plan: VerifiedGitObjectPlan,
) -> tuple[VerifiedGitObjectPlan, SourceTreeAttestation]:
    try:
        plan = verify_git_object_blobs(
            exact_object_plan.snapshot,
            lambda entry: exact_object_plan.blob_bytes(entry.oid),
        )
    except (AttributeError, KeyError, TypeError) as exc:
        raise _reject("Exact-object source plan is invalid.") from exc
    if plan != exact_object_plan:
        raise _reject("Exact-object source plan fields are inconsistent.")
    if plan.snapshot.symlink_count or plan.snapshot.gitlink_count:
        raise _reject("The v0.2 source profile rejects symlinks and Gitlinks.")
    with tempfile.TemporaryDirectory(prefix="reproassert-v02-source-verify-") as temporary:
        parent = Path(temporary).resolve(strict=True)
        os.chmod(parent, 0o700)
        workspace = materialize_git_workspace(plan, parent / "source")
        attestation = attest_source_tree(
            workspace.path, expected_git_tree_oid=plan.snapshot.root_tree_oid
        )
        if workspace.tree_sha256 != plan.tree_sha256:
            raise _reject("Materialized exact-object source identity is inconsistent.")
    return plan, attestation


def _source_receipt_record(
    case: V02CaseIdentity,
    plan: VerifiedGitObjectPlan,
    attestation: SourceTreeAttestation,
) -> dict[str, object]:
    return {
        "algorithm": V02_SOURCE_EVIDENCE_ALGORITHM,
        "benchmark_version": BENCHMARK_VERSION,
        "case": asdict(case),
        "exact_objects": {
            "algorithm": GIT_OBJECT_CONTENT_TREE_ALGORITHM,
            "root_tree_oid": plan.snapshot.root_tree_oid,
            "manifest_sha256": plan.snapshot.manifest_sha256,
            "tree_sha256": plan.tree_sha256,
            "entry_count": plan.snapshot.entry_count,
            "regular_file_count": plan.snapshot.regular_file_count,
            "directory_count": plan.snapshot.directory_count,
            "symlink_count": 0,
            "gitlink_count": 0,
        },
        "source_attestation": asdict(attestation),
    }


def _load_generator_projection(
    path: Path, *, expected_case: V02CaseIdentity
) -> Mapping[str, object]:
    _, decoded = _load_canonical_json(path, "generator projection")
    if set(decoded) != {
        "schema_version",
        "benchmark_version",
        "case_id",
        "repo",
        "issue_url",
        "base_sha",
        "issue_snapshot",
    }:
        raise _reject("Generator projection fields are invalid.")
    expected = {
        "benchmark_version": BENCHMARK_VERSION,
        "case_id": expected_case.id,
        "repo": expected_case.repo,
        "issue_url": expected_case.issue_url,
        "base_sha": expected_case.base_sha,
    }
    for name, value in expected.items():
        if decoded.get(name) != value:
            raise _reject("Generator projection identity differs from source evidence.")
    issue = decoded.get("issue_snapshot")
    if not isinstance(issue, dict) or set(issue) != {"title", "body", "snapshot_sha256"}:
        raise _reject("Generator projection snapshot fields are invalid.")
    title = issue.get("title")
    body = issue.get("body")
    snapshot_sha256 = issue.get("snapshot_sha256")
    if not isinstance(title, str) or not isinstance(body, str):
        raise _reject("Generator projection snapshot text is invalid.")
    _sha256(snapshot_sha256, "generator snapshot")
    return decoded


def _source_context_record(
    source: VerifiedV02SourceEvidence,
    projection: Mapping[str, object],
    context: SourceContext,
) -> dict[str, object]:
    issue = cast(Mapping[str, object], projection["issue_snapshot"])
    return {
        "algorithm": V02_SOURCE_CONTEXT_ALGORITHM,
        "policy_sha256": V02_SOURCE_CONTEXT_POLICY_SHA256,
        "case": asdict(source.case),
        "source_evidence_sha256": source.evidence_sha256,
        "source_tree_sha256": source.source_tree_sha256,
        "snapshot_sha256": issue["snapshot_sha256"],
        "context": context.to_dict(),
    }


def _dataset_evidence_record(
    value: VerifiedV02DatasetEvidence, case: V02CaseIdentity
) -> dict[str, object]:
    values: dict[str, object] = {
        "algorithm": V02_DATASET_EVIDENCE_ALGORITHM,
        "case": asdict(case),
        "tdd_bench_git_sha": _git_oid(value.tdd_bench_git_sha, "TDD-Bench commit"),
        "tdd_bench_root_tree_oid": _git_oid(value.tdd_bench_root_tree_oid, "TDD-Bench root"),
        "tdd_id_list_blob_oid": _git_oid(value.tdd_id_list_blob_oid, "TDD id-list blob"),
        "tdd_id_list_sha256": _sha256(value.tdd_id_list_sha256, "TDD id-list"),
        "tdd_membership_ordinal": _positive_int(
            value.tdd_membership_ordinal, "TDD membership ordinal"
        ),
        "source_dataset_git_sha": _git_oid(value.source_dataset_git_sha, "source dataset commit"),
        "source_dataset_root_tree_oid": _git_oid(
            value.source_dataset_root_tree_oid, "source dataset root"
        ),
        "source_dataset_artifact_git_blob_oid": _git_oid(
            value.source_dataset_artifact_git_blob_oid, "source dataset pointer blob"
        ),
        "source_dataset_artifact_lfs_sha256": _sha256(
            value.source_dataset_artifact_lfs_sha256, "source dataset LFS object"
        ),
        "source_dataset_artifact_lfs_bytes": _positive_int(
            value.source_dataset_artifact_lfs_bytes, "source dataset LFS bytes"
        ),
        "source_dataset_artifact_xet_sha256": _sha256(
            value.source_dataset_artifact_xet_sha256, "source dataset Xet object"
        ),
        "source_dataset_row_ordinal": _nonnegative_int(
            value.source_dataset_row_ordinal, "source dataset row ordinal"
        ),
        "source_dataset_row_sha256": _sha256(value.source_dataset_row_sha256, "source dataset row"),
        "source_dataset_transform": value.source_dataset_transform,
        "parser_receipt_sha256": _sha256(value.parser_receipt_sha256, "parser receipt"),
        "dataset_parser_image_digest": value.dataset_parser_image_digest,
        "boundary_attestation_sha256": _sha256(
            value.boundary_attestation_sha256, "dataset parser boundary attestation"
        ),
        "upstream_evidence_sha256": _sha256(
            value.upstream_evidence_sha256, "dataset upstream evidence"
        ),
    }
    if (
        not isinstance(value.dataset_parser_image_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", value.dataset_parser_image_digest) is None
    ):
        raise _reject("Dataset parser image identity is invalid.")
    if value.source_dataset_transform != SOURCE_DATASET_TRANSFORM:
        raise _reject("Dataset evidence transform is invalid.")
    return values


def _require_official_dataset_constants(value: VerifiedV02DatasetEvidence) -> None:
    expected: tuple[tuple[object, object], ...] = (
        (value.tdd_bench_git_sha, OFFICIAL_TDD_BENCH_GIT_SHA),
        (value.tdd_bench_root_tree_oid, OFFICIAL_TDD_BENCH_ROOT_TREE_OID),
        (value.tdd_id_list_blob_oid, OFFICIAL_TDD_ID_LIST_BLOB_OID),
        (value.tdd_id_list_sha256, OFFICIAL_TDD_ID_LIST_SHA256),
        (value.source_dataset_git_sha, OFFICIAL_SOURCE_DATASET_GIT_SHA),
        (value.source_dataset_root_tree_oid, OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID),
        (value.source_dataset_artifact_git_blob_oid, OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID),
        (value.source_dataset_artifact_lfs_sha256, OFFICIAL_SOURCE_DATASET_LFS_SHA256),
        (value.source_dataset_artifact_lfs_bytes, OFFICIAL_SOURCE_DATASET_BYTES),
        (value.source_dataset_artifact_xet_sha256, OFFICIAL_SOURCE_DATASET_XET_SHA256),
    )
    if any(observed != required for observed, required in expected):
        raise _reject("Dataset evidence is not bound to the frozen upstream objects.")


def _bind_source_to_mapping(source: VerifiedV02SourceEvidence, mapping: FixMappingReceipt) -> None:
    if (
        source.case != mapping.case
        or source.case.base_sha != mapping.case.base_sha
        or source.base_root_tree_oid != mapping.base_root_tree_oid
    ):
        raise _reject("Exact-object source evidence differs from the fixing mapping.")


def _bind_dataset_to_mapping(
    dataset: VerifiedV02DatasetEvidence, mapping: FixMappingReceipt
) -> None:
    observed = (
        dataset.tdd_bench_git_sha,
        dataset.tdd_bench_root_tree_oid,
        dataset.tdd_id_list_blob_oid,
        dataset.tdd_id_list_sha256,
        dataset.tdd_membership_ordinal,
        dataset.source_dataset_git_sha,
        dataset.source_dataset_root_tree_oid,
        dataset.source_dataset_artifact_git_blob_oid,
        dataset.source_dataset_artifact_lfs_sha256,
        dataset.source_dataset_artifact_lfs_bytes,
        dataset.source_dataset_artifact_xet_sha256,
        dataset.source_dataset_row_ordinal,
        dataset.source_dataset_row_sha256,
    )
    expected = (
        mapping.tdd_bench_git_sha,
        mapping.tdd_bench_root_tree_oid,
        mapping.tdd_id_list_blob_oid,
        mapping.tdd_id_list_sha256,
        mapping.tdd_membership_ordinal,
        mapping.source_dataset_git_sha,
        mapping.source_dataset_root_tree_oid,
        mapping.source_dataset_artifact_git_blob_oid,
        mapping.source_dataset_artifact_lfs_sha256,
        mapping.source_dataset_artifact_lfs_bytes,
        mapping.source_dataset_artifact_xet_sha256,
        mapping.source_dataset_row_ordinal,
        mapping.upstream_record_sha256,
    )
    if observed != expected:
        raise _reject("Pinned dataset evidence differs from the fixing mapping.")


def _verify_isolation_receipt(
    path: Path,
    reference: ArtifactReference,
    result: IsolationCanaryResult,
    *,
    expected_policy_sha256: str,
    expected_image_id: str,
) -> None:
    if type(result) is not IsolationCanaryResult or not result.accepted:
        raise _reject("Application isolation result is invalid or not accepted.")
    if (
        result.version != CANARY_VERSION
        or result.policy_sha256 != expected_policy_sha256
        or result.image_id != expected_image_id
        or result.positive_mount_destinations != (EVALUATOR_DESTINATION,)
        or result.generator_mount_destinations != (GENERATOR_DESTINATION,)
        or result.tool_git_sha is None
        or _GIT_OID.fullmatch(result.tool_git_sha) is None
    ):
        raise _reject("Isolation result differs from the production policy identities.")
    expected = asdict(result)
    expected["accepted"] = True
    raw = _read_regular(path, _MAX_RECEIPT_BYTES, "isolation receipt")
    if hashlib.sha256(raw).hexdigest() != reference.sha256 or len(raw) != reference.bytes:
        raise _reject("Isolation receipt differs from its package reference.")
    if raw != _canonical_json(expected) + b"\n":
        raise _reject("Isolation receipt is not the exact application canary result.")


def _verify_reviewer_role_seal(
    path: Path,
    reference: ArtifactReference,
    *,
    mapping: FixMappingReceipt,
    case: V02CaseIdentity,
    semantic_reviewer_ids: tuple[str, ...],
    completed_at: str,
) -> None:
    raw, decoded = _load_canonical_json(path, "reviewer role seal")
    if hashlib.sha256(raw).hexdigest() != reference.sha256 or len(raw) != reference.bytes:
        raise _reject("Reviewer role seal differs from its package reference.")
    expected = render_v02_reviewer_role_seal(
        case=case,
        mapping_receipt_sha256=mapping.receipt_sha256,
        mapping_reviewer_ids=mapping.mapping_reviewer_ids,
        semantic_reviewer_ids=semantic_reviewer_ids,
        sealed_at=cast(str, decoded.get("sealed_at")),
    )
    if raw != expected:
        raise _reject("Reviewer role seal differs from application-selected reviewer roles.")
    sealed_at = _timestamp(decoded.get("sealed_at"), "reviewer role seal")
    if not (
        _timestamp_datetime(mapping.reviewed_at)
        <= _timestamp_datetime(sealed_at)
        <= _timestamp_datetime(completed_at)
    ):
        raise _reject("Reviewer role seal time is outside the verified review interval.")


def _rederive_patch_causality(
    source: VerifiedV02SourceEvidence,
    package_root: Path,
    mapping: FixMappingReceipt,
) -> tuple[str, str, tuple[Path, Path]]:
    production_path = package_root / mapping.production_patch.path
    developer_path = package_root / mapping.developer_tests.path
    production = _read_regular(production_path, _MAX_RECEIPT_BYTES, "production patch")
    developer = _read_regular(developer_path, _MAX_RECEIPT_BYTES, "developer tests patch")
    if (
        hashlib.sha256(production).hexdigest() != mapping.production_patch_sha256
        or hashlib.sha256(developer).hexdigest() != mapping.developer_tests_sha256
        or production == developer
    ):
        raise _reject("Production/developer patch identities are invalid.")
    with tempfile.TemporaryDirectory(prefix="reproassert-v02-patch-") as temporary:
        parent = Path(temporary).resolve(strict=True)
        os.chmod(parent, 0o700)
        base = materialize_git_workspace(source._plan, parent / "base").path
        base_attestation = attest_source_tree(base, expected_git_tree_oid=source.base_root_tree_oid)
        if base_attestation.tree_sha256 != source.source_tree_sha256:
            raise _reject("Base source changed before patch reconstruction.")
        fixed = parent / "fixed"
        shutil.copytree(base, fixed, symlinks=True, copy_function=shutil.copy2)
        _apply_patch(fixed, production)
        fixed_attestation = attest_source_tree(fixed)
        if fixed_attestation.reconstructed_git_tree_oid == source.base_root_tree_oid:
            raise _reject("Production patch does not causally change the base tree.")
        hidden_fixed_oid = fixed_attestation.reconstructed_git_tree_oid
        _apply_patch(fixed, developer)
        head_attestation = attest_source_tree(
            fixed, expected_git_tree_oid=mapping.head_root_tree_oid
        )
        if head_attestation.reconstructed_git_tree_oid == hidden_fixed_oid:
            raise _reject("Developer tests patch does not change the production-fixed tree.")
        final_base = attest_source_tree(base, expected_git_tree_oid=source.base_root_tree_oid)
        if final_base.tree_sha256 != source.source_tree_sha256:
            raise _reject("Patch reconstruction mutated the pristine base tree.")
    return (
        hidden_fixed_oid,
        head_attestation.reconstructed_git_tree_oid,
        (
            production_path,
            developer_path,
        ),
    )


def _apply_patch(root: Path, patch: bytes) -> None:
    if re.search(
        rb"(?m)^(?:new file mode|old mode|new mode) (?:120000|160000)$",
        patch,
    ):
        raise _reject("Evaluator patches may not introduce symlinks or Gitlinks.")
    patch = _apply_metadata_only_sections(root, patch)
    if not patch:
        return
    git = Path("/usr/bin/git")
    try:
        metadata = git.stat()
    except OSError as exc:
        raise _reject("Trusted Git patch applicator is unavailable.") from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(git, os.X_OK):
        raise _reject("Trusted Git patch applicator is invalid.")
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "HOME": str(root.parent),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    args = [
        str(git),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.attributesFile=/dev/null",
        "apply",
        "--whitespace=nowarn",
        "--recount",
        "-",
    ]
    try:
        completed = subprocess.run(
            args,
            input=patch,
            cwd=root,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise _reject("Trusted patch application failed or timed out.") from exc
    if completed.returncode != 0:
        raise _reject("Production/developer patch does not apply exactly to the base tree.")


def _apply_metadata_only_sections(root: Path, patch: bytes) -> bytes:
    starts = [match.start() for match in re.finditer(rb"(?m)^diff --git ", patch)]
    if not starts or starts[0] != 0:
        return patch
    starts.append(len(patch))
    retained: list[bytes] = []
    for index in range(len(starts) - 1):
        section = patch[starts[index] : starts[index + 1]]
        if b"\n--- " in section or b"\nGIT binary patch\n" in section:
            retained.append(section)
            continue
        rename_from = _patch_metadata_value(section, b"rename from ")
        rename_to = _patch_metadata_value(section, b"rename to ")
        old_mode = _patch_metadata_value(section, b"old mode ")
        new_mode = _patch_metadata_value(section, b"new mode ")
        if (rename_from is None) != (rename_to is None):
            raise _reject("Evaluator patch contains an incomplete rename.")
        if rename_from is None and new_mode is None:
            retained.append(section)
            continue
        if new_mode not in {None, b"100644", b"100755"} or old_mode not in {
            None,
            b"100644",
            b"100755",
        }:
            raise _reject("Evaluator patch contains an unsupported file mode.")
        destination: Path
        if rename_from is not None and rename_to is not None:
            source = _patch_relative_path(root, rename_from, "rename source")
            destination = _patch_relative_path(root, rename_to, "rename destination")
            try:
                metadata = source.lstat()
            except OSError as exc:
                raise _reject("Evaluator rename source is missing.") from exc
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise _reject("Evaluator rename source is not a single regular file.")
            if destination.exists() or destination.is_symlink():
                raise _reject("Evaluator rename destination already exists.")
            _create_patch_parent(root, destination.parent)
            try:
                source.rename(destination)
            except OSError as exc:
                raise _reject("Evaluator rename could not be applied safely.") from exc
            _remove_empty_patch_parents(root, source.parent)
        else:
            header = section.splitlines()[0]
            parts = header.split(b" ")
            if len(parts) != 4 or not parts[2].startswith(b"a/") or not parts[3].startswith(b"b/"):
                raise _reject("Evaluator mode-only patch header is invalid.")
            if parts[2][2:] != parts[3][2:]:
                raise _reject("Evaluator mode-only patch paths differ.")
            destination = _patch_relative_path(root, parts[2][2:], "mode path")
        if new_mode is not None:
            try:
                metadata = destination.lstat()
            except OSError as exc:
                raise _reject("Evaluator mode target is missing.") from exc
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise _reject("Evaluator mode target is not a single regular file.")
            destination.chmod(0o755 if new_mode == b"100755" else 0o644)
    return b"".join(retained)


def _patch_metadata_value(section: bytes, prefix: bytes) -> bytes | None:
    matches = [line[len(prefix) :] for line in section.splitlines() if line.startswith(prefix)]
    if len(matches) > 1:
        raise _reject("Evaluator patch repeats metadata fields.")
    return matches[0] if matches else None


def _patch_relative_path(root: Path, raw: bytes, label: str) -> Path:
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _reject(f"Evaluator {label} is not UTF-8.") from exc
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", "..", ".git"} for part in path.parts)
        or "\\" in value
    ):
        raise _reject(f"Evaluator {label} escapes the source root.")
    return root.joinpath(*path.parts)


def _create_patch_parent(root: Path, parent: Path) -> None:
    relative = parent.relative_to(root)
    current = root
    for part in relative.parts:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            raise _reject("Evaluator rename parent is not a directory.")


def _remove_empty_patch_parents(root: Path, parent: Path) -> None:
    current = parent
    while current != root:
        try:
            current.rmdir()
        except OSError:
            return
        current = current.parent


def _semantic_verification(
    context: V02SemanticVerificationContext,
    *,
    source: VerifiedV02SourceEvidence,
    dataset: VerifiedV02DatasetEvidence,
    source_context: VerifiedV02GeneratorSourceContext,
    dependency: VerifiedDependencyExecutionReceipt,
    isolation_result: IsolationCanaryResult,
    semantic_reviewer_ids: tuple[str, ...],
    completed_at: str,
    scored_generator_mode: str,
    hidden_fixed_oid: str,
    head_oid: str,
) -> V02SemanticVerification:
    mapping = context.mapping
    supporting = context.supporting_inputs
    return V02SemanticVerification(
        algorithm=SEMANTIC_VERIFICATION_ALGORITHM,
        case=context.case,
        completed_at=completed_at,
        tdd_bench_git_sha=dataset.tdd_bench_git_sha,
        tdd_bench_root_tree_oid=dataset.tdd_bench_root_tree_oid,
        tdd_id_list_path=OFFICIAL_TDD_ID_LIST_PATH,
        tdd_id_list_blob_oid=dataset.tdd_id_list_blob_oid,
        tdd_id_list_sha256=dataset.tdd_id_list_sha256,
        tdd_membership_ordinal=dataset.tdd_membership_ordinal,
        source_dataset_git_sha=dataset.source_dataset_git_sha,
        source_dataset_root_tree_oid=dataset.source_dataset_root_tree_oid,
        source_dataset_split="test",
        source_dataset_artifact_path=OFFICIAL_SOURCE_DATASET_PATH,
        source_dataset_artifact_git_blob_oid=dataset.source_dataset_artifact_git_blob_oid,
        source_dataset_lfs_pointer_sha256=mapping.source_dataset_lfs_pointer_sha256,
        source_dataset_artifact_lfs_sha256=dataset.source_dataset_artifact_lfs_sha256,
        source_dataset_artifact_lfs_bytes=dataset.source_dataset_artifact_lfs_bytes,
        source_dataset_artifact_xet_sha256=dataset.source_dataset_artifact_xet_sha256,
        source_dataset_artifact_sha256=mapping.source_dataset_artifact_sha256,
        source_dataset_row_ordinal=dataset.source_dataset_row_ordinal,
        source_dataset_row_sha256=dataset.source_dataset_row_sha256,
        source_dataset_transform=dataset.source_dataset_transform,
        dataset_evidence_sha256=dataset.evidence_sha256,
        source_receipt_sha256=source.receipt_sha256,
        source_base_commit_sha=context.case.base_sha,
        source_base_root_tree_oid=source.base_root_tree_oid,
        source_tree_sha256=source.source_tree_sha256,
        source_context_algorithm=source_context.algorithm,
        source_context_policy_sha256=source_context.policy_sha256,
        source_context_sha256=source_context.context_sha256,
        production_patch_sha256=mapping.production_patch_sha256,
        developer_tests_sha256=mapping.developer_tests_sha256,
        hidden_fixed_root_tree_oid=hidden_fixed_oid,
        reconstructed_pr_head_root_tree_oid=head_oid,
        fixing_head_commit_sha=mapping.fixed_commit_sha,
        fixing_head_root_tree_oid=mapping.head_root_tree_oid,
        dependency_receipt_sha256=dependency.receipt_sha256,
        dependency_case_id=dependency.case_id,
        dependency_base_sha=dependency.base_sha,
        dependency_source_tree_sha256=dependency.source_tree_sha256,
        dependency_environment_setup_commit=mapping.environment_setup_commit,
        dependency_runner_image_id=dependency.image_id,
        isolation_receipt_sha256=supporting["isolation_canary_receipt"].sha256,
        isolation_policy_sha256=context.isolation_policy_sha256,
        scored_generator_mode=scored_generator_mode,
        arbitrary_host_command_generator_allowed=False,
        evaluator_paths_exposed=False,
        host_credentials_forwarded=False,
        network_after_dependency_prep="disabled",
        production_isolation_accepted=isolation_result.accepted,
        reviewer_role_seal_sha256=supporting["reviewer_role_seal"].sha256,
        reviewer_roles_sealed=True,
        semantic_reviewer_ids=semantic_reviewer_ids,
        gold_hidden_until_verdict=True,
    )


def _seal_private_package(package_path: Path, destination_root: Path) -> Path:
    supplied_path = Path(package_path)
    try:
        supplied_metadata = supplied_path.lstat()
    except OSError as exc:
        raise _reject("Private case-package path is unavailable.") from exc
    if not stat.S_ISREG(supplied_metadata.st_mode) or supplied_metadata.st_nlink != 1:
        raise _reject("Private case-package path must be a regular file with link count one.")
    source_path = supplied_path.resolve(strict=True)
    source_root = source_path.parent
    require_private_directory(source_root)
    _require_outside_checkout(source_root)
    destination_root.mkdir(mode=0o700)
    os.chmod(destination_root, 0o700)
    file_count = 0
    total_bytes = 0
    seen: set[tuple[int, int]] = set()

    def copy_directory(source: Path, destination: Path) -> None:
        nonlocal file_count, total_bytes
        initial = source.stat(follow_symlinks=False)
        if not stat.S_ISDIR(initial.st_mode) or initial.st_uid != os.getuid():
            raise _reject("Private package contains an invalid directory identity.")
        if initial.st_mode & 0o077:
            raise _reject("Private package directories must not grant group/world access.")
        directory_identity = (initial.st_dev, initial.st_ino)
        if directory_identity in seen:
            raise _reject("Private package repeats a filesystem identity.")
        seen.add(directory_identity)
        if not destination.exists():
            destination.mkdir(mode=0o700)
        with os.scandir(source) as entries:
            ordered = sorted(entries, key=lambda item: item.name)
        for entry in ordered:
            source_entry = source / entry.name
            destination_entry = destination / entry.name
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise _reject("Private package contains a symlink.")
            if stat.S_ISDIR(metadata.st_mode):
                copy_directory(source_entry, destination_entry)
                continue
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
            ):
                raise _reject("Private package artifact ownership, mode, or link count is unsafe.")
            entry_identity = (metadata.st_dev, metadata.st_ino)
            if entry_identity in seen:
                raise _reject("Private package repeats an artifact identity.")
            seen.add(entry_identity)
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > _MAX_PACKAGE_FILES or total_bytes > _MAX_PACKAGE_BYTES:
                raise _reject("Private package exceeds its seal bounds.")
            with open_regular_file(source_entry) as stream:
                opened = os.fstat(stream.fileno())
                if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_size,
                    metadata.st_mtime_ns,
                ) or opened.st_nlink != 1:
                    raise _reject("Private package artifact changed before sealing.")
                content = stream.read(_MAX_RECEIPT_BYTES + 1)
            if len(content) > _MAX_RECEIPT_BYTES:
                raise _reject("Private package artifact exceeds its per-file seal bound.")
            descriptor = os.open(destination_entry, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                view = memoryview(content)
                offset = 0
                while offset < len(view):
                    written = os.write(descriptor, view[offset:])
                    if written <= 0:
                        raise _reject("Private package artifact copy made no progress.")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _fsync_directory(destination)
            final = source_entry.stat(follow_symlinks=False)
            if (
                final.st_dev,
                final.st_ino,
                final.st_size,
                final.st_mtime_ns,
                final.st_nlink,
            ) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                1,
            ):
                raise _reject("Private package artifact changed during sealing.")
        final_directory = source.stat(follow_symlinks=False)
        if (final_directory.st_dev, final_directory.st_ino) != directory_identity:
            raise _reject("Private package directory changed during sealing.")

    copy_directory(source_root, destination_root)
    sealed = destination_root / source_path.name
    if not sealed.is_file():
        raise _reject("Sealed package lacks its case package receipt.")
    return sealed


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_outside_checkout(path: Path) -> None:
    resolved = path.resolve(strict=True)
    for ancestor in (resolved, *resolved.parents):
        try:
            os.lstat(ancestor / ".git")
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise _reject("Private package checkout-boundary inspection failed.") from exc
        raise _reject("Private evaluator package must be outside every Git checkout.")


def _require_frozen_case(
    cases: Sequence[package_module.PreregisteredV02Case], case: V02CaseIdentity
) -> package_module.PreregisteredV02Case:
    matches = [item for item in cases if item.id == case.id]
    if len(matches) != 1:
        raise _reject("Frozen preregistration lacks exactly one matching case.")
    frozen = matches[0]
    if (frozen.repo, frozen.issue_url, frozen.base_sha) != (
        case.repo,
        case.issue_url,
        case.base_sha,
    ):
        raise _reject("Frozen preregistration identity differs from source evidence.")
    return frozen


def _validated_case(value: object) -> V02CaseIdentity:
    if type(value) is not V02CaseIdentity:
        raise _reject("v0.2 case identity type is invalid.")
    if (
        _CASE_ID.fullmatch(value.id) is None
        or not value.repo
        or not value.issue_url.startswith(f"https://github.com/{value.repo}/issues/")
        or _GIT_OID.fullmatch(value.base_sha) is None
    ):
        raise _reject("v0.2 case identity fields are invalid.")
    return value


def _reviewer_ids(values: tuple[str, ...]) -> tuple[str, ...]:
    if (
        not 2 <= len(values) <= 3
        or values != tuple(sorted(set(values)))
        or any(_IDENTIFIER.fullmatch(value) is None for value in values)
    ):
        raise _reject("Reviewer IDs must be two or three sorted unique identifiers.")
    return values


def _run_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _RUN_IDENTIFIER.fullmatch(value) is None:
        raise _reject(f"{label} is invalid.")
    return value


def _revalidated_candidate(value: object) -> ValidatedCandidate:
    if type(value) is not ValidatedCandidate:
        raise _reject("Evaluation session candidate type is invalid.")
    revalidated = validate_candidate_payload(
        {
            "test_content": value.test_content,
            "expected_symptom": value.expected_symptom,
            "rationale": value.rationale,
        },
        issue_number=_candidate_issue_number(value.test_function),
    )
    if revalidated != value:
        raise _reject("Evaluation session candidate fields are inconsistent.")
    return revalidated


def _candidate_issue_number(test_function: str) -> int:
    match = re.fullmatch(r"test_issue_([1-9][0-9]*)_reproduction", test_function)
    if match is None:
        raise _reject("Evaluation session candidate function is invalid.")
    return int(match.group(1))


def _validated_candidate_path(value: object, test_function: str) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise _reject("Evaluation session candidate path is invalid.")
    path = PurePosixPath(value)
    issue_number = _candidate_issue_number(test_function)
    expected = f"tests/reproassert/test_issue_{issue_number}.py"
    if path.is_absolute() or path.as_posix() != value or value != expected:
        raise _reject("Evaluation session candidate path is not controller-reserved.")
    return value


def _load_canonical_json(path: Path, label: str) -> tuple[bytes, Mapping[str, object]]:
    raw = _read_regular(path, _MAX_RECEIPT_BYTES, label)
    try:
        decoded = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise _reject(f"{label} is not strict JSON.") from exc
    if not isinstance(decoded, dict) or raw != _canonical_json(decoded) + b"\n":
        raise _reject(f"{label} is not a canonical JSON object.")
    return raw, cast(Mapping[str, object], decoded)


def _read_regular(path: Path, limit: int, label: str) -> bytes:
    try:
        metadata = Path(path).stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise _reject(f"{label} is not one singly-linked regular file.")
        with open_regular_file(Path(path)) as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
            ):
                raise _reject(f"{label} changed before it was read.")
            content = stream.read(limit + 1)
    except OSError as exc:
        raise _reject(f"{label} could not be read safely.") from exc
    if len(content) > limit:
        raise _reject(f"{label} exceeds its byte limit.")
    final = Path(path).stat(follow_symlinks=False)
    if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_nlink) != (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        1,
    ):
        raise _reject(f"{label} changed while it was read.")
    return content


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(_read_regular(path, _MAX_RECEIPT_BYTES, "evaluator artifact")).hexdigest()


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _reject("Value cannot be represented as canonical JSON.") from exc


def _json_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _reject(f"{label} SHA-256 is invalid.")
    return value


def _git_oid(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_OID.fullmatch(value) is None:
        raise _reject(f"{label} Git OID is invalid.")
    return value


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise _reject(f"{label} must be a positive integer.")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _reject(f"{label} must be a non-negative integer.")
    return value


def _timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP.fullmatch(value) is None:
        raise _reject(f"{label} must be an RFC 3339 UTC timestamp.")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise _reject(f"{label} is not a real timestamp.") from exc
    return value


def _timestamp_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_semantic_issuer", message)
