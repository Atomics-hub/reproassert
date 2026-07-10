from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import stat
import unicodedata
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from reproassert.errors import PolicyRejection
from reproassert.intake import GITHUB_API_HOST, _fetch_json
from reproassert.safeio import open_exclusive_file, require_private_directory

GIT_OBJECT_SNAPSHOT_ALGORITHM = "reproassert-git-object-snapshot-v1"
GIT_OBJECT_CONTENT_TREE_ALGORITHM = "reproassert-git-object-content-tree-v1"
MAX_GIT_TREE_JSON_BYTES = 8 * 1024 * 1024

_GIT_OID_RE = re.compile(r"[0-9a-f]{40}")
_OWNER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_BLOB_MODES = frozenset({"100644", "100755", "120000"})
_ENTRY_TYPES = {
    "040000": "tree",
    "100644": "blob",
    "100755": "blob",
    "120000": "blob",
    "160000": "commit",
}
_MAX_LIMIT = 2**63 - 1


@dataclass(frozen=True)
class GitObjectLimits:
    """Bounds for one recursive Git tree response and its referenced blobs."""

    max_entries: int = 20_000
    max_blobs: int = 20_000
    max_blob_bytes: int = 64 * 1024 * 1024
    max_total_blob_bytes: int = 256 * 1024 * 1024
    max_path_bytes: int = 4096
    max_component_bytes: int = 255
    max_symlink_target_bytes: int = 4096

    def __post_init__(self) -> None:
        for field_name in (
            "max_entries",
            "max_blobs",
            "max_blob_bytes",
            "max_total_blob_bytes",
            "max_path_bytes",
            "max_component_bytes",
            "max_symlink_target_bytes",
        ):
            value = getattr(self, field_name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= _MAX_LIMIT
            ):
                raise ValueError(f"{field_name} must be an integer between 1 and {_MAX_LIMIT}")


@dataclass(frozen=True)
class GitObjectEntry:
    path: str
    path_bytes: bytes
    parts: tuple[str, ...]
    encoded_parts: tuple[bytes, ...]
    mode: str
    object_type: str
    oid: str
    size: int | None

    @property
    def is_tree(self) -> bool:
        return self.mode == "040000"

    @property
    def is_regular(self) -> bool:
        return self.mode in {"100644", "100755"}

    @property
    def is_symlink(self) -> bool:
        return self.mode == "120000"

    @property
    def is_gitlink(self) -> bool:
        return self.mode == "160000"


@dataclass(frozen=True)
class GitObjectSnapshot:
    algorithm: str
    root_tree_oid: str
    manifest_sha256: str
    entries: tuple[GitObjectEntry, ...]
    entry_count: int
    blob_count: int
    regular_file_count: int
    directory_count: int
    symlink_count: int
    gitlink_count: int
    total_blob_bytes: int


@dataclass(frozen=True)
class VerifiedGitObjectPlan:
    snapshot: GitObjectSnapshot
    tree_sha256: str
    blobs: tuple[tuple[str, bytes], ...]
    symlink_targets: tuple[tuple[str, str], ...]

    def blob_bytes(self, oid: str) -> bytes:
        for observed_oid, content in self.blobs:
            if observed_oid == oid:
                return content
        raise KeyError(oid)

    def symlink_target(self, path: str) -> str:
        for observed_path, target in self.symlink_targets:
            if observed_path == path:
                return target
        raise KeyError(path)


@dataclass(frozen=True)
class MaterializedGitWorkspace:
    path: Path
    root_tree_oid: str
    manifest_sha256: str
    tree_sha256: str
    regular_file_count: int
    directory_count: int
    symlink_count: int
    gitlink_count: int


def fetch_recursive_git_tree(
    owner: str,
    repo: str,
    root_tree_oid: str,
    *,
    timeout_seconds: float = 15.0,
    limits: GitObjectLimits | None = None,
) -> GitObjectSnapshot:
    """Fetch and validate one unauthenticated recursive Git Trees API response.

    This endpoint supplies object metadata only. Call ``verify_git_object_blobs``
    with independently acquired blob bytes before materializing a workspace.
    A truncated response always fails closed; this function never silently
    treats a partial tree as the exact commit tree.
    """

    _validate_repository(owner, repo)
    expected_root = _validate_oid(root_tree_oid, "root tree OID")
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool):
        raise ValueError("timeout_seconds must be a positive finite number")
    if not math.isfinite(float(timeout_seconds)) or not 0 < float(timeout_seconds) <= 300:
        raise ValueError("timeout_seconds must be between 0 and 300 seconds")
    url = f"https://{GITHUB_API_HOST}/repos/{owner}/{repo}/git/trees/{expected_root}?recursive=1"
    payload = _fetch_json(
        url,
        expected_host=GITHUB_API_HOST,
        max_bytes=MAX_GIT_TREE_JSON_BYTES,
        timeout_seconds=float(timeout_seconds),
    )
    return parse_recursive_git_tree(payload, expected_root_tree_oid=expected_root, limits=limits)


def parse_recursive_git_tree(
    payload: Mapping[str, object],
    *,
    expected_root_tree_oid: str,
    limits: GitObjectLimits | None = None,
) -> GitObjectSnapshot:
    """Validate recursive Git Trees API data and reconstruct every tree OID."""

    active_limits = limits or GitObjectLimits()
    expected_root = _validate_oid(expected_root_tree_oid, "root tree OID")
    if not isinstance(payload, Mapping):
        raise _reject("Git tree response root is not an object.")
    returned_root = _validate_oid(payload.get("sha"), "returned root tree OID")
    if returned_root != expected_root:
        raise PolicyRejection(
            "git_object_root_mismatch",
            "Git Trees API returned a different root tree object.",
        )
    if payload.get("truncated") is not False:
        raise PolicyRejection(
            "git_object_tree_truncated",
            "Git Trees API response is truncated or lacks an explicit complete marker.",
        )
    values = payload.get("tree")
    if not isinstance(values, list):
        raise _reject("Git tree response does not contain an entry array.")
    if len(values) > active_limits.max_entries:
        raise PolicyRejection(
            "git_object_entry_limit", "Git tree exceeds the exact-object entry limit."
        )

    entries: list[GitObjectEntry] = []
    by_path: dict[str, GitObjectEntry] = {}
    canonical_paths: dict[str, str] = {}
    blob_count = 0
    total_blob_bytes = 0
    for index, raw in enumerate(values):
        if not isinstance(raw, Mapping):
            raise _reject(f"Git tree entry {index} is not an object.")
        entry = _parse_entry(raw, active_limits)
        if entry.path in by_path:
            raise PolicyRejection(
                "git_object_path_collision", "Git tree contains a duplicate path."
            )
        canonical_path = "/".join(
            unicodedata.normalize("NFC", part).casefold() for part in entry.parts
        )
        prior = canonical_paths.get(canonical_path)
        if prior is not None and prior != entry.path:
            raise PolicyRejection(
                "git_object_path_collision",
                "Git tree paths collide by case or Unicode normalization.",
            )
        canonical_paths[canonical_path] = entry.path
        by_path[entry.path] = entry
        entries.append(entry)
        if entry.mode in _BLOB_MODES:
            blob_count += 1
            if blob_count > active_limits.max_blobs:
                raise PolicyRejection(
                    "git_object_blob_limit", "Git tree exceeds the exact-object blob limit."
                )
            if entry.size is None:  # defensive if a snapshot instance is forged
                raise _reject("Git blob entry is missing its declared size.")
            total_blob_bytes += entry.size
            if total_blob_bytes > active_limits.max_total_blob_bytes:
                raise PolicyRejection(
                    "git_object_total_bytes",
                    "Git tree exceeds the exact-object total blob-byte limit.",
                )

    for entry in entries:
        for depth in range(1, len(entry.parts)):
            ancestor_path = "/".join(entry.parts[:depth])
            ancestor = by_path.get(ancestor_path)
            if ancestor is None or not ancestor.is_tree:
                raise PolicyRejection(
                    "git_object_invalid_hierarchy",
                    "Git tree entry lacks an explicit tree ancestor.",
                )

    calculated_root = _reconstruct_tree(entries, expected_root)
    if calculated_root != expected_root:
        raise PolicyRejection(
            "git_object_root_mismatch",
            "Git tree entries do not reconstruct the expected root tree object.",
        )
    ordered = tuple(sorted(entries, key=lambda item: item.path_bytes))
    regular_count = sum(entry.is_regular for entry in ordered)
    directory_count = sum(entry.is_tree for entry in ordered)
    symlink_count = sum(entry.is_symlink for entry in ordered)
    gitlink_count = sum(entry.is_gitlink for entry in ordered)
    return GitObjectSnapshot(
        algorithm=GIT_OBJECT_SNAPSHOT_ALGORITHM,
        root_tree_oid=expected_root,
        manifest_sha256=_manifest_sha256(ordered),
        entries=ordered,
        entry_count=len(ordered),
        blob_count=blob_count,
        regular_file_count=regular_count,
        directory_count=directory_count,
        symlink_count=symlink_count,
        gitlink_count=gitlink_count,
        total_blob_bytes=total_blob_bytes,
    )


def verify_git_object_blobs(
    snapshot: GitObjectSnapshot,
    load_blob: Callable[[GitObjectEntry], bytes],
    *,
    limits: GitObjectLimits | None = None,
) -> VerifiedGitObjectPlan:
    """Verify every referenced blob and reject symlinks that could escape the workspace."""

    active_limits = limits or GitObjectLimits()
    snapshot = _validated_snapshot(snapshot, active_limits)
    if not callable(load_blob):
        raise TypeError("load_blob must be callable")
    blobs: dict[str, bytes] = {}
    representative: dict[str, GitObjectEntry] = {}
    declared_sizes: dict[str, int] = {}
    for entry in sorted(snapshot.entries, key=lambda item: item.path_bytes):
        if entry.mode not in _BLOB_MODES:
            continue
        if entry.size is None:  # defensive if a snapshot instance is forged
            raise _reject("Git blob entry is missing its declared size.")
        previous_size = declared_sizes.setdefault(entry.oid, entry.size)
        if previous_size != entry.size:
            raise _reject("One Git blob OID has conflicting declared sizes.")
        representative.setdefault(entry.oid, entry)

    observed_total = 0
    for oid in sorted(representative):
        entry = representative[oid]
        content = load_blob(entry)
        if not isinstance(content, bytes):
            raise PolicyRejection(
                "git_object_invalid_blob", "Git blob loader returned a non-byte value."
            )
        if len(content) > active_limits.max_blob_bytes:
            raise PolicyRejection(
                "git_object_blob_too_large", "Git blob exceeds the exact-object byte limit."
            )
        if len(content) != declared_sizes[oid]:
            raise PolicyRejection(
                "git_object_blob_size_mismatch", "Git blob size differs from tree metadata."
            )
        observed_total += len(content)
        if observed_total > active_limits.max_total_blob_bytes:
            raise PolicyRejection(
                "git_object_total_bytes",
                "Verified Git blobs exceed the exact-object total byte limit.",
            )
        if _git_blob_oid(content) != oid:
            raise PolicyRejection(
                "git_object_blob_mismatch", "Git blob bytes do not match the declared object ID."
            )
        blobs[oid] = content

    raw_symlink_targets: dict[str, str] = {}
    for entry in snapshot.entries:
        if not entry.is_symlink:
            continue
        target = _validate_symlink_target_syntax(
            entry,
            blobs[entry.oid],
            max_bytes=active_limits.max_symlink_target_bytes,
        )
        raw_symlink_targets[entry.path] = target
    canonical_entries = {_canonical_path(entry.parts): entry for entry in snapshot.entries}
    for entry in snapshot.entries:
        if entry.is_symlink:
            _validate_symlink_resolution(
                entry,
                raw_symlink_targets[entry.path],
                symlink_targets=raw_symlink_targets,
                canonical_entries=canonical_entries,
            )
    return VerifiedGitObjectPlan(
        snapshot=snapshot,
        tree_sha256=_verified_content_tree_sha256(snapshot, blobs),
        blobs=tuple(sorted(blobs.items())),
        symlink_targets=tuple(sorted(raw_symlink_targets.items())),
    )


def materialize_git_workspace(
    plan: VerifiedGitObjectPlan,
    destination: Path,
) -> MaterializedGitWorkspace:
    """Materialize a metadata-free checkout from a verified exact-object plan.

    Gitlinks are intentionally represented as empty directories, matching an
    uninitialized superproject checkout. Their repository URLs and commit
    objects are never followed or fetched. Root-confined tracked symlinks are
    preserved; all other non-regular filesystem types remain unsupported.
    """

    try:
        validated_plan = verify_git_object_blobs(
            plan.snapshot,
            lambda entry: plan.blob_bytes(entry.oid),
        )
    except KeyError as exc:
        raise _reject("Verified Git object plan is missing a blob.") from exc
    if validated_plan != plan:
        raise _reject("Verified Git object plan fields are inconsistent.")
    plan = validated_plan
    target = Path(destination)
    require_private_directory(target.parent)
    created = False
    try:
        try:
            target.mkdir(mode=0o700)
            created = True
        except FileExistsError as exc:
            raise PolicyRejection(
                "output_exists", f"Refusing to overwrite Git workspace: {target}"
            ) from exc
        os.chmod(target, 0o700, follow_symlinks=False)

        directories = [
            entry for entry in plan.snapshot.entries if entry.is_tree or entry.is_gitlink
        ]
        for entry in sorted(directories, key=lambda item: (len(item.parts), item.path_bytes)):
            path = target.joinpath(*entry.parts)
            path.mkdir(mode=0o700)
            os.chmod(path, 0o700, follow_symlinks=False)

        regular_files = [entry for entry in plan.snapshot.entries if entry.is_regular]
        for entry in regular_files:
            path = target.joinpath(*entry.parts)
            with open_exclusive_file(path) as stream:
                stream.write(plan.blob_bytes(entry.oid))
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(path, 0o700 if entry.mode == "100755" else 0o600, follow_symlinks=False)

        symlinks = [entry for entry in plan.snapshot.entries if entry.is_symlink]
        for entry in symlinks:
            path = target.joinpath(*entry.parts)
            os.symlink(plan.symlink_target(entry.path), path)

        _verify_materialized(plan, target)
    except BaseException:
        if created:
            shutil.rmtree(target, ignore_errors=True)
        raise

    snapshot = plan.snapshot
    return MaterializedGitWorkspace(
        path=target,
        root_tree_oid=snapshot.root_tree_oid,
        manifest_sha256=snapshot.manifest_sha256,
        tree_sha256=plan.tree_sha256,
        regular_file_count=snapshot.regular_file_count,
        directory_count=snapshot.directory_count,
        symlink_count=snapshot.symlink_count,
        gitlink_count=snapshot.gitlink_count,
    )


def _parse_entry(raw: Mapping[str, object], limits: GitObjectLimits) -> GitObjectEntry:
    path_value = raw.get("path")
    if not isinstance(path_value, str):
        raise _reject("Git tree entry path is not text.")
    parts, encoded_parts, path_bytes = _validate_path(path_value, limits)
    mode = raw.get("mode")
    object_type = raw.get("type")
    if not isinstance(mode, str) or mode not in _ENTRY_TYPES:
        raise PolicyRejection("git_object_mode", "Git tree entry mode is unsupported.")
    if object_type != _ENTRY_TYPES[mode]:
        raise PolicyRejection("git_object_type", "Git tree entry type does not match its mode.")
    oid = _validate_oid(raw.get("sha"), "entry object ID")
    size_value = raw.get("size")
    if mode in _BLOB_MODES:
        if not isinstance(size_value, int) or isinstance(size_value, bool) or size_value < 0:
            raise PolicyRejection(
                "git_object_size", "Git blob entry lacks a valid non-negative size."
            )
        if size_value > limits.max_blob_bytes:
            raise PolicyRejection(
                "git_object_blob_too_large", "Git blob exceeds the exact-object byte limit."
            )
        size: int | None = size_value
    else:
        if size_value is not None:
            raise PolicyRejection(
                "git_object_size", "Git tree or gitlink entry unexpectedly declares a size."
            )
        size = None
    return GitObjectEntry(
        path=path_value,
        path_bytes=path_bytes,
        parts=parts,
        encoded_parts=encoded_parts,
        mode=mode,
        object_type=object_type,
        oid=oid,
        size=size,
    )


def _validated_snapshot(snapshot: GitObjectSnapshot, limits: GitObjectLimits) -> GitObjectSnapshot:
    if not isinstance(snapshot, GitObjectSnapshot):
        raise _reject("Git object snapshot has an invalid type.")
    if snapshot.algorithm != GIT_OBJECT_SNAPSHOT_ALGORITHM:
        raise _reject("Git object snapshot algorithm is unsupported.")
    raw_entries: list[dict[str, object]] = []
    for entry in snapshot.entries:
        raw: dict[str, object] = {
            "path": entry.path,
            "mode": entry.mode,
            "type": entry.object_type,
            "sha": entry.oid,
        }
        if entry.size is not None:
            raw["size"] = entry.size
        raw_entries.append(raw)
    validated = parse_recursive_git_tree(
        {
            "sha": snapshot.root_tree_oid,
            "tree": raw_entries,
            "truncated": False,
        },
        expected_root_tree_oid=snapshot.root_tree_oid,
        limits=limits,
    )
    if validated != snapshot:
        raise _reject("Git object snapshot fields are inconsistent.")
    return validated


def _validate_path(
    path: str, limits: GitObjectLimits
) -> tuple[tuple[str, ...], tuple[bytes, ...], bytes]:
    if not path or path.startswith("/") or path.endswith("/") or "\\" in path:
        raise PolicyRejection("git_object_unsafe_path", "Git tree path is unsafe.")
    parts = tuple(path.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise PolicyRejection("git_object_unsafe_path", "Git tree path is unsafe.")
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        for component in parts
        for character in component
    ):
        raise PolicyRejection(
            "git_object_unsafe_path", "Git tree path contains control characters."
        )
    if any(_is_git_metadata_component(part) for part in parts):
        raise PolicyRejection("git_object_git_metadata", "Git tree contains Git metadata.")
    try:
        encoded_parts = tuple(part.encode("utf-8") for part in parts)
    except UnicodeError as exc:
        raise PolicyRejection(
            "git_object_unsafe_path", "Git tree path is not valid UTF-8."
        ) from exc
    path_bytes = b"/".join(encoded_parts)
    if len(path_bytes) > limits.max_path_bytes:
        raise PolicyRejection("git_object_path_too_long", "Git tree path exceeds the byte limit.")
    if any(len(part) > limits.max_component_bytes for part in encoded_parts):
        raise PolicyRejection(
            "git_object_component_too_long", "Git tree path component exceeds the byte limit."
        )
    return parts, encoded_parts, path_bytes


def _reconstruct_tree(entries: list[GitObjectEntry], expected_root: str) -> str:
    by_directory: dict[tuple[bytes, ...], list[GitObjectEntry]] = {(): []}
    tree_entries: dict[tuple[bytes, ...], GitObjectEntry] = {}
    for entry in entries:
        if entry.is_tree:
            tree_entries[entry.encoded_parts] = entry
            by_directory.setdefault(entry.encoded_parts, [])
        by_directory.setdefault(entry.encoded_parts[:-1], []).append(entry)

    calculated: dict[tuple[bytes, ...], str] = {}
    for directory in sorted(by_directory, key=lambda value: (len(value), value), reverse=True):
        children = by_directory[directory]
        encoded: list[tuple[bytes, bytes]] = []
        for child in children:
            oid = calculated[child.encoded_parts] if child.is_tree else child.oid
            sort_key = child.encoded_parts[-1] + (b"/" if child.is_tree else b"")
            git_mode = b"40000" if child.is_tree else child.mode.encode("ascii")
            record = git_mode + b" " + child.encoded_parts[-1] + b"\0"
            record += bytes.fromhex(oid)
            encoded.append((sort_key, record))
        body = b"".join(record for _, record in sorted(encoded, key=lambda item: item[0]))
        digest = hashlib.sha1(f"tree {len(body)}\0".encode("ascii"), usedforsecurity=False)
        digest.update(body)
        observed = digest.hexdigest()
        calculated[directory] = observed
        if directory:
            declared = tree_entries[directory].oid
            if observed != declared:
                raise PolicyRejection(
                    "git_object_subtree_mismatch",
                    "Git tree entries do not reconstruct a declared subtree object.",
                )
    return calculated.get((), expected_root)


def _manifest_sha256(entries: tuple[GitObjectEntry, ...]) -> str:
    digest = hashlib.sha256(GIT_OBJECT_SNAPSHOT_ALGORITHM.encode("ascii") + b"\0")
    for entry in entries:
        digest.update(entry.mode.encode("ascii"))
        digest.update(len(entry.path_bytes).to_bytes(8, "big"))
        digest.update(entry.path_bytes)
        digest.update(bytes.fromhex(entry.oid))
        digest.update((entry.size if entry.size is not None else 2**64 - 1).to_bytes(8, "big"))
    return digest.hexdigest()


def _verified_content_tree_sha256(snapshot: GitObjectSnapshot, blobs: Mapping[str, bytes]) -> str:
    """Commit with SHA-256 to verified bytes, paths, modes, sizes, and gitlinks."""

    digest = hashlib.sha256(GIT_OBJECT_CONTENT_TREE_ALGORITHM.encode("ascii") + b"\0")
    for entry in sorted(snapshot.entries, key=lambda item: item.path_bytes):
        if entry.is_tree:
            kind = b"D"
            size = 0
            identity = hashlib.sha256(b"").digest()
        elif entry.is_gitlink:
            kind = b"G"
            size = 0
            identity = hashlib.sha256(b"gitlink\0" + bytes.fromhex(entry.oid)).digest()
        else:
            kind = b"L" if entry.is_symlink else b"F"
            content = blobs[entry.oid]
            size = len(content)
            identity = hashlib.sha256(content).digest()
        digest.update(kind)
        digest.update(entry.mode.encode("ascii"))
        digest.update(len(entry.path_bytes).to_bytes(8, "big"))
        digest.update(entry.path_bytes)
        digest.update(size.to_bytes(8, "big"))
        digest.update(identity)
    return digest.hexdigest()


def _validate_symlink_target_syntax(
    entry: GitObjectEntry, content: bytes, *, max_bytes: int
) -> str:
    if not content or len(content) > max_bytes or b"\0" in content:
        raise PolicyRejection(
            "git_object_unsafe_symlink", "Tracked symlink target is empty or exceeds its limit."
        )
    try:
        target = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyRejection(
            "git_object_unsafe_symlink", "Tracked symlink target is not valid UTF-8."
        ) from exc
    if target.startswith("/") or target.endswith("/") or "\\" in target:
        raise PolicyRejection(
            "git_object_unsafe_symlink", "Tracked symlink target is not root-confined."
        )
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in target):
        raise PolicyRejection(
            "git_object_unsafe_symlink", "Tracked symlink target contains control characters."
        )
    components = target.split("/")
    if any(component == "" for component in components):
        raise PolicyRejection(
            "git_object_unsafe_symlink", "Tracked symlink target is not canonical."
        )
    for component in components:
        if component == ".":
            continue
        if component != ".." and _is_git_metadata_component(component):
            raise PolicyRejection(
                "git_object_unsafe_symlink", "Tracked symlink targets Git metadata."
            )
        if len(component.encode("utf-8")) > 255:
            raise PolicyRejection(
                "git_object_unsafe_symlink", "Tracked symlink component exceeds the byte limit."
            )
    PurePosixPath(target)  # documents POSIX target semantics; no host resolution occurs here
    return target


def _validate_symlink_resolution(
    entry: GitObjectEntry,
    target: str,
    *,
    symlink_targets: Mapping[str, str],
    canonical_entries: Mapping[str, GitObjectEntry],
) -> None:
    """Resolve tracked symlink chains logically, including links in intermediate components."""

    resolved = list(entry.parts[:-1])
    pending = deque(target.split("/"))
    expansions = 0
    while pending:
        component = pending.popleft()
        if component == ".":
            continue
        if component == "..":
            if not resolved:
                raise PolicyRejection(
                    "git_object_unsafe_symlink", "Tracked symlink escapes the source root."
                )
            resolved.pop()
            continue
        resolved.append(component)
        candidate = canonical_entries.get(_canonical_path(tuple(resolved)))
        if candidate is None or not candidate.is_symlink:
            continue
        expansions += 1
        if expansions > 40:
            raise PolicyRejection(
                "git_object_unsafe_symlink", "Tracked symlink chain is cyclic or too deep."
            )
        resolved.pop()
        nested_target = symlink_targets[candidate.path]
        pending.extendleft(reversed(nested_target.split("/")))
    if not resolved:
        raise PolicyRejection(
            "git_object_unsafe_symlink", "Tracked symlink aliases the source root."
        )


def _verify_materialized(plan: VerifiedGitObjectPlan, root: Path) -> None:
    require_private_directory(root)
    expected = {entry.path: entry for entry in plan.snapshot.entries}
    observed: dict[str, os.stat_result] = {}
    queue: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    while queue:
        directory, prefix = queue.pop()
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: item.name.encode("utf-8"))
        for child in children:
            parts = (*prefix, child.name)
            relative = "/".join(parts)
            if relative in observed:
                raise PolicyRejection(
                    "git_workspace_changed", "Materialized workspace repeats a path."
                )
            metadata = child.stat(follow_symlinks=False)
            observed[relative] = metadata
            entry = expected.get(relative)
            if entry is None:
                raise PolicyRejection(
                    "git_workspace_changed", "Materialized workspace contains an extra path."
                )
            if entry.is_tree or entry.is_gitlink:
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
                    raise PolicyRejection(
                        "git_workspace_changed", "Materialized directory changed type or mode."
                    )
                queue.append((Path(child.path), parts))
            elif entry.is_symlink:
                if not stat.S_ISLNK(metadata.st_mode):
                    raise PolicyRejection(
                        "git_workspace_changed", "Materialized symlink changed type."
                    )
                if os.readlink(child.path) != plan.symlink_target(entry.path):
                    raise PolicyRejection(
                        "git_workspace_changed", "Materialized symlink target changed."
                    )
            else:
                expected_mode = 0o700 if entry.mode == "100755" else 0o600
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != expected_mode
                ):
                    raise PolicyRejection(
                        "git_workspace_changed", "Materialized regular file changed type or mode."
                    )
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                descriptor = os.open(child.path, flags)
                try:
                    content = bytearray()
                    while chunk := os.read(descriptor, 64 * 1024):
                        content.extend(chunk)
                        if len(content) > (entry.size or 0):
                            raise PolicyRejection(
                                "git_workspace_changed", "Materialized regular file grew."
                            )
                finally:
                    os.close(descriptor)
                if bytes(content) != plan.blob_bytes(entry.oid):
                    raise PolicyRejection(
                        "git_workspace_changed", "Materialized regular file bytes changed."
                    )
    if set(observed) != set(expected):
        raise PolicyRejection(
            "git_workspace_changed", "Materialized workspace is missing expected paths."
        )
    for entry in plan.snapshot.entries:
        if entry.is_gitlink:
            path = root.joinpath(*entry.parts)
            if any(path.iterdir()):
                raise PolicyRejection(
                    "git_workspace_changed", "Materialized gitlink directory is not empty."
                )


def _git_blob_oid(content: bytes) -> str:
    digest = hashlib.sha1(f"blob {len(content)}\0".encode("ascii"), usedforsecurity=False)
    digest.update(content)
    return digest.hexdigest()


def _validate_repository(owner: str, repo: str) -> None:
    if (
        not isinstance(owner, str)
        or not isinstance(repo, str)
        or _OWNER_RE.fullmatch(owner) is None
        or _REPOSITORY_RE.fullmatch(repo) is None
        or repo in {".", ".."}
        or not owner.isascii()
        or not repo.isascii()
    ):
        raise PolicyRejection("invalid_repository", "GitHub owner or repository name is invalid")


def _validate_oid(value: object, label: str) -> str:
    if not isinstance(value, str) or _GIT_OID_RE.fullmatch(value) is None:
        raise PolicyRejection(
            "git_object_invalid_oid", f"{label} must be 40 lowercase hexadecimal digits."
        )
    return value


def _is_git_metadata_component(name: str) -> bool:
    canonical = unicodedata.normalize("NFKC", name).casefold().rstrip(" .")
    return canonical == ".git"


def _canonical_path(parts: tuple[str, ...]) -> str:
    return "/".join(unicodedata.normalize("NFC", part).casefold() for part in parts)


def _reject(message: str) -> PolicyRejection:
    return PolicyRejection("invalid_git_object_tree", message)
