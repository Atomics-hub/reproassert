"""Offline verification of the exact upstream Git object graph used by benchmark v0.2.

The witness is intentionally small: it contains only the commit, tree, and terminal blob objects
needed to prove the two pinned paths.  Verification recomputes every Git object ID, walks each tree
edge, parses the LFS pointer, hashes the reconstructed Parquet bytes, and cross-binds the Xet
resolution metadata captured over HTTPS.  The HTTPS capture is explicitly not represented as a
transferable cryptographic signature.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import cast
from urllib.parse import urlsplit

from reproassert.errors import PolicyRejection
from reproassert.safeio import open_regular_file
from reproassert.semantic_issuer import (
    OFFICIAL_SOURCE_DATASET_BYTES,
    OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID,
    OFFICIAL_SOURCE_DATASET_GIT_SHA,
    OFFICIAL_SOURCE_DATASET_LFS_SHA256,
    OFFICIAL_SOURCE_DATASET_PATH,
    OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID,
    OFFICIAL_SOURCE_DATASET_XET_SHA256,
    OFFICIAL_TDD_BENCH_GIT_SHA,
    OFFICIAL_TDD_BENCH_ROOT_TREE_OID,
    OFFICIAL_TDD_ID_LIST_BLOB_OID,
    OFFICIAL_TDD_ID_LIST_BYTES,
    OFFICIAL_TDD_ID_LIST_PATH,
    OFFICIAL_TDD_ID_LIST_SHA256,
)

UPSTREAM_OBJECT_WITNESS_ALGORITHM = "reproassert-v02-upstream-object-witness-v1"
TDD_BENCH_REPOSITORY_URL = "https://github.com/IBM/TDD-Bench-Verified"
SOURCE_DATASET_REPOSITORY_URL = "https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified"
SOURCE_DATASET_RESOLVE_URL = (
    f"{SOURCE_DATASET_REPOSITORY_URL}/resolve/{OFFICIAL_SOURCE_DATASET_GIT_SHA}/"
    f"{OFFICIAL_SOURCE_DATASET_PATH}"
)
_WITNESS_ISSUER = object()
_MAX_WITNESS_BYTES = 256 * 1024
_MAX_OBJECT_BYTES = 128 * 1024
_GIT_OID = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_TREE_MODES = {b"40000", b"040000"}
_BLOB_MODES = {b"100644", b"100755"}


@dataclass(frozen=True, init=False)
class VerifiedV02UpstreamProvenance:
    """Nominal output of the exact-object graph and artifact verifier."""

    witness_sha256: str
    tdd_bench_git_sha: str
    tdd_bench_root_tree_oid: str
    tdd_id_list_blob_oid: str
    tdd_id_list_sha256: str
    source_dataset_git_sha: str
    source_dataset_root_tree_oid: str
    source_dataset_artifact_git_blob_oid: str
    source_dataset_artifact_lfs_sha256: str
    source_dataset_artifact_lfs_bytes: int
    source_dataset_artifact_xet_sha256: str
    git_graph_verified: bool
    lfs_artifact_verified: bool
    xet_resolution_cross_bound: bool
    xet_resolution_transport: str
    xet_resolution_transferable_cryptographic_proof: bool
    evidence_sha256: str
    _issuer: object = field(repr=False, compare=False)

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("VerifiedV02UpstreamProvenance is verifier-issued only")


@dataclass(frozen=True)
class _GitBinding:
    commit_oid: str
    root_tree_oid: str
    blob_oid: str
    blob: bytes


def verify_v02_upstream_provenance(
    witness_path: Path,
    *,
    tdd_id_list_path: Path,
    source_dataset_path: Path,
) -> VerifiedV02UpstreamProvenance:
    """Verify the complete pinned object paths and their terminal artifact identities."""

    raw = _read_bounded(Path(witness_path), _MAX_WITNESS_BYTES, "upstream object witness")
    root = _load_canonical(raw, "upstream object witness")
    if set(root) != {"algorithm", "source_dataset", "tdd_bench", "xet_resolution"}:
        raise _reject("Upstream object witness fields are invalid.")
    if root.get("algorithm") != UPSTREAM_OBJECT_WITNESS_ALGORITHM:
        raise _reject("Upstream object witness algorithm is invalid.")

    tdd = _verify_repository_binding(
        root.get("tdd_bench"),
        label="TDD-Bench",
        expected_repository_url=TDD_BENCH_REPOSITORY_URL,
        expected_commit_oid=OFFICIAL_TDD_BENCH_GIT_SHA,
        expected_root_tree_oid=OFFICIAL_TDD_BENCH_ROOT_TREE_OID,
        expected_path=OFFICIAL_TDD_ID_LIST_PATH,
        expected_blob_oid=OFFICIAL_TDD_ID_LIST_BLOB_OID,
    )
    source = _verify_repository_binding(
        root.get("source_dataset"),
        label="source dataset",
        expected_repository_url=SOURCE_DATASET_REPOSITORY_URL,
        expected_commit_oid=OFFICIAL_SOURCE_DATASET_GIT_SHA,
        expected_root_tree_oid=OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID,
        expected_path=OFFICIAL_SOURCE_DATASET_PATH,
        expected_blob_oid=OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID,
    )

    id_list = _read_bounded(Path(tdd_id_list_path), OFFICIAL_TDD_ID_LIST_BYTES, "TDD-Bench id list")
    if (
        id_list != tdd.blob
        or len(id_list) != OFFICIAL_TDD_ID_LIST_BYTES
        or hashlib.sha256(id_list).hexdigest() != OFFICIAL_TDD_ID_LIST_SHA256
    ):
        raise _reject("TDD-Bench terminal blob does not match the exact id-list artifact.")

    lfs_oid, lfs_size = _parse_lfs_pointer(source.blob)
    artifact = _read_bounded(
        Path(source_dataset_path), OFFICIAL_SOURCE_DATASET_BYTES, "source dataset artifact"
    )
    artifact_sha256 = hashlib.sha256(artifact).hexdigest()
    if (
        lfs_oid != OFFICIAL_SOURCE_DATASET_LFS_SHA256
        or lfs_size != OFFICIAL_SOURCE_DATASET_BYTES
        or len(artifact) != lfs_size
        or artifact_sha256 != lfs_oid
    ):
        raise _reject(
            "Source dataset artifact is not the object named by the verified LFS pointer."
        )
    xet_hash = _verify_xet_resolution(root.get("xet_resolution"), artifact_sha256, len(artifact))

    fields: dict[str, object] = {
        "witness_sha256": hashlib.sha256(raw).hexdigest(),
        "tdd_bench_git_sha": tdd.commit_oid,
        "tdd_bench_root_tree_oid": tdd.root_tree_oid,
        "tdd_id_list_blob_oid": tdd.blob_oid,
        "tdd_id_list_sha256": hashlib.sha256(id_list).hexdigest(),
        "source_dataset_git_sha": source.commit_oid,
        "source_dataset_root_tree_oid": source.root_tree_oid,
        "source_dataset_artifact_git_blob_oid": source.blob_oid,
        "source_dataset_artifact_lfs_sha256": artifact_sha256,
        "source_dataset_artifact_lfs_bytes": len(artifact),
        "source_dataset_artifact_xet_sha256": xet_hash,
        "git_graph_verified": True,
        "lfs_artifact_verified": True,
        "xet_resolution_cross_bound": True,
        "xet_resolution_transport": "https_tls_at_collection",
        "xet_resolution_transferable_cryptographic_proof": False,
    }
    value = object.__new__(VerifiedV02UpstreamProvenance)
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    object.__setattr__(value, "_issuer", _WITNESS_ISSUER)
    object.__setattr__(value, "evidence_sha256", _record_sha256(fields))
    return require_v02_upstream_provenance(value)


def require_v02_upstream_provenance(value: object) -> VerifiedV02UpstreamProvenance:
    """Revalidate an exact nominal upstream graph-verification result."""

    if type(value) is not VerifiedV02UpstreamProvenance:
        raise _reject("Verified upstream object provenance is required.")
    if value._issuer is not _WITNESS_ISSUER:
        raise _reject("Upstream object provenance issuer is invalid.")
    record = asdict(value)
    record.pop("_issuer")
    evidence_sha256 = cast(str, record.pop("evidence_sha256"))
    if evidence_sha256 != _record_sha256(record):
        raise _reject("Upstream object provenance digest is invalid.")
    expected = {
        "tdd_bench_git_sha": OFFICIAL_TDD_BENCH_GIT_SHA,
        "tdd_bench_root_tree_oid": OFFICIAL_TDD_BENCH_ROOT_TREE_OID,
        "tdd_id_list_blob_oid": OFFICIAL_TDD_ID_LIST_BLOB_OID,
        "tdd_id_list_sha256": OFFICIAL_TDD_ID_LIST_SHA256,
        "source_dataset_git_sha": OFFICIAL_SOURCE_DATASET_GIT_SHA,
        "source_dataset_root_tree_oid": OFFICIAL_SOURCE_DATASET_ROOT_TREE_OID,
        "source_dataset_artifact_git_blob_oid": OFFICIAL_SOURCE_DATASET_GIT_BLOB_OID,
        "source_dataset_artifact_lfs_sha256": OFFICIAL_SOURCE_DATASET_LFS_SHA256,
        "source_dataset_artifact_lfs_bytes": OFFICIAL_SOURCE_DATASET_BYTES,
        "source_dataset_artifact_xet_sha256": OFFICIAL_SOURCE_DATASET_XET_SHA256,
        "git_graph_verified": True,
        "lfs_artifact_verified": True,
        "xet_resolution_cross_bound": True,
        "xet_resolution_transport": "https_tls_at_collection",
        "xet_resolution_transferable_cryptographic_proof": False,
    }
    if any(record.get(name) != item for name, item in expected.items()):
        raise _reject("Upstream object provenance is not bound to the official pinned objects.")
    witness_sha = record.get("witness_sha256")
    if not isinstance(witness_sha, str) or _SHA256.fullmatch(witness_sha) is None:
        raise _reject("Upstream object witness digest is invalid.")
    return value


def _verify_repository_binding(
    raw: object,
    *,
    label: str,
    expected_repository_url: str,
    expected_commit_oid: str,
    expected_root_tree_oid: str,
    expected_path: str,
    expected_blob_oid: str,
) -> _GitBinding:
    if not isinstance(raw, dict) or set(raw) != {
        "commit_oid",
        "objects",
        "path",
        "repository_url",
        "root_tree_oid",
    }:
        raise _reject(f"{label} object witness fields are invalid.")
    if (
        raw.get("repository_url") != expected_repository_url
        or raw.get("commit_oid") != expected_commit_oid
        or raw.get("root_tree_oid") != expected_root_tree_oid
        or raw.get("path") != expected_path
    ):
        raise _reject(f"{label} object witness names a different pinned source.")
    objects = _decode_git_objects(raw.get("objects"), label)
    commit = objects.get(expected_commit_oid)
    if commit is None or commit[0] != "commit":
        raise _reject(f"{label} commit object is absent.")
    root_oid = _commit_tree_oid(commit[1], label)
    if root_oid != expected_root_tree_oid:
        raise _reject(f"{label} commit does not name the pinned root tree.")
    blob_oid = _walk_tree(objects, root_oid, expected_path, label)
    if blob_oid != expected_blob_oid:
        raise _reject(f"{label} path does not name the pinned terminal blob.")
    terminal = objects.get(blob_oid)
    if terminal is None or terminal[0] != "blob":
        raise _reject(f"{label} terminal blob object is absent.")
    return _GitBinding(expected_commit_oid, root_oid, blob_oid, terminal[1])


def _decode_git_objects(raw: object, label: str) -> dict[str, tuple[str, bytes]]:
    if not isinstance(raw, list) or not 2 <= len(raw) <= 16:
        raise _reject(f"{label} Git object list is invalid.")
    result: dict[str, tuple[str, bytes]] = {}
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"oid", "payload_base64", "type"}:
            raise _reject(f"{label} Git object fields are invalid.")
        oid = item.get("oid")
        kind = item.get("type")
        encoded = item.get("payload_base64")
        if (
            not isinstance(oid, str)
            or _GIT_OID.fullmatch(oid) is None
            or kind not in {"blob", "commit", "tree"}
            or not isinstance(encoded, str)
            or oid in result
        ):
            raise _reject(f"{label} Git object identity is invalid.")
        try:
            payload = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise _reject(f"{label} Git object payload is not canonical base64.") from exc
        if len(payload) > _MAX_OBJECT_BYTES or base64.b64encode(payload).decode("ascii") != encoded:
            raise _reject(f"{label} Git object payload is invalid or oversized.")
        calculated = hashlib.sha1(
            f"{kind} {len(payload)}\0".encode("ascii") + payload,
            usedforsecurity=False,
        ).hexdigest()
        if calculated != oid:
            raise _reject(f"{label} Git object hash is invalid.")
        result[oid] = (cast(str, kind), payload)
    return result


def _commit_tree_oid(payload: bytes, label: str) -> str:
    try:
        header = payload.split(b"\n\n", 1)[0]
        tree_lines = [line for line in header.splitlines() if line.startswith(b"tree ")]
        oid = tree_lines[0][5:].decode("ascii")
    except (IndexError, UnicodeDecodeError) as exc:
        raise _reject(f"{label} commit object has no valid root tree header.") from exc
    if len(tree_lines) != 1 or _GIT_OID.fullmatch(oid) is None:
        raise _reject(f"{label} commit root tree header is ambiguous.")
    return oid


def _walk_tree(objects: dict[str, tuple[str, bytes]], root_oid: str, path: str, label: str) -> str:
    pure = PurePosixPath(path)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise _reject(f"{label} pinned path is invalid.")
    current = root_oid
    for index, component in enumerate(pure.parts):
        item = objects.get(current)
        if item is None or item[0] != "tree":
            raise _reject(f"{label} tree object needed for the pinned path is absent.")
        entries = _parse_tree(item[1], label)
        selected = entries.get(component)
        if selected is None:
            raise _reject(f"{label} pinned path is absent from its verified tree.")
        mode, oid = selected
        final = index == len(pure.parts) - 1
        if (final and mode not in _BLOB_MODES) or (not final and mode not in _TREE_MODES):
            raise _reject(f"{label} pinned path has an invalid Git mode transition.")
        current = oid
    return current


def _parse_tree(payload: bytes, label: str) -> dict[str, tuple[bytes, str]]:
    entries: dict[str, tuple[bytes, str]] = {}
    offset = 0
    while offset < len(payload):
        space = payload.find(b" ", offset)
        nul = payload.find(b"\0", space + 1)
        if space <= offset or nul <= space or nul + 21 > len(payload):
            raise _reject(f"{label} tree object encoding is invalid.")
        mode = payload[offset:space]
        raw_name = payload[space + 1 : nul]
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _reject(f"{label} tree entry name is not UTF-8.") from exc
        if not name or "/" in name or name in {".", ".."} or name in entries:
            raise _reject(f"{label} tree entry name is invalid or duplicated.")
        oid = payload[nul + 1 : nul + 21].hex()
        entries[name] = (mode, oid)
        offset = nul + 21
    if offset != len(payload):  # pragma: no cover - loop invariant
        raise _reject(f"{label} tree object has trailing bytes.")
    return entries


def _parse_lfs_pointer(payload: bytes) -> tuple[str, int]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise _reject("Source dataset terminal blob is not an ASCII LFS pointer.") from exc
    lines = text.splitlines(keepends=True)
    if len(lines) != 3 or any(not line.endswith("\n") for line in lines):
        raise _reject("Source dataset LFS pointer shape is invalid.")
    if lines[0] != "version https://git-lfs.github.com/spec/v1\n":
        raise _reject("Source dataset LFS pointer version is invalid.")
    oid_prefix = "oid sha256:"
    if not lines[1].startswith(oid_prefix):
        raise _reject("Source dataset LFS pointer object ID is absent.")
    oid = lines[1][len(oid_prefix) : -1]
    try:
        size = int(lines[2][len("size ") : -1]) if lines[2].startswith("size ") else -1
    except ValueError as exc:
        raise _reject("Source dataset LFS pointer size is invalid.") from exc
    if _SHA256.fullmatch(oid) is None or size < 1:
        raise _reject("Source dataset LFS pointer values are invalid.")
    return oid, size


def _verify_xet_resolution(raw: object, artifact_sha256: str, artifact_bytes: int) -> str:
    keys = {
        "artifact_bytes",
        "artifact_etag",
        "artifact_sha256",
        "redirect_url_without_query",
        "request_url",
        "resolved_commit",
        "transferable_cryptographic_proof",
        "transport_authentication",
        "xet_hash",
    }
    if not isinstance(raw, dict) or set(raw) != keys:
        raise _reject("Xet resolution witness fields are invalid.")
    xet_hash = raw.get("xet_hash")
    if (
        raw.get("request_url") != SOURCE_DATASET_RESOLVE_URL
        or raw.get("resolved_commit") != OFFICIAL_SOURCE_DATASET_GIT_SHA
        or raw.get("artifact_sha256") != artifact_sha256
        or raw.get("artifact_bytes") != artifact_bytes
        or raw.get("transport_authentication") != "https_tls_at_collection"
        or raw.get("transferable_cryptographic_proof") is not False
        or not isinstance(xet_hash, str)
        or _SHA256.fullmatch(xet_hash) is None
        or raw.get("artifact_etag") != xet_hash
        or xet_hash != OFFICIAL_SOURCE_DATASET_XET_SHA256
    ):
        raise _reject("Xet resolution witness is not cross-bound to the pinned artifact.")
    redirect = raw.get("redirect_url_without_query")
    if not isinstance(redirect, str):
        raise _reject("Xet resolution redirect is invalid.")
    parsed = urlsplit(redirect)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "us.aws.cdn.hf.co"
        or parsed.query
        or parsed.fragment
        or parsed.path.rsplit("/", 1)[-1] != xet_hash
    ):
        raise _reject("Xet resolution redirect does not name the verified Xet object.")
    return xet_hash


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    try:
        with open_regular_file(path) as stream:
            content = stream.read(limit + 1)
    except (OSError, PolicyRejection) as exc:
        raise _reject(f"{label} could not be read safely.") from exc
    if len(content) > limit:
        raise _reject(f"{label} exceeds its byte limit.")
    return content


def _load_canonical(content: bytes, label: str) -> dict[str, object]:
    try:
        decoded = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _reject(f"{label} is invalid JSON.") from exc
    if not isinstance(decoded, dict) or content != _canonical(decoded) + b"\n":
        raise _reject(f"{label} is not canonical JSON.")
    return cast(dict[str, object], decoded)


def _record_sha256(record: dict[str, object]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise _reject("Upstream provenance cannot be encoded as canonical JSON.") from exc


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("benchmark_v02_upstream", message)
