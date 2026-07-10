from __future__ import annotations

import gzip
import hashlib
import os
import stat
import tarfile
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import IO, BinaryIO, cast

from reproassert.errors import PolicyRejection
from reproassert.git_objects import (
    GitObjectLimits,
    GitObjectSnapshot,
    VerifiedGitObjectPlan,
    verify_git_object_blobs,
)
from reproassert.intake import MAX_ARCHIVE_BYTES
from reproassert.safeio import open_regular_file

_READ_CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True)
class CodeloadRepair:
    path: str
    expected_oid: str
    reason: str
    observed_oid: str | None


@dataclass(frozen=True)
class CodeloadRepairPlan:
    archive_sha256: str
    archive_bytes: int
    root_tree_oid: str
    object_manifest_sha256: str
    archive_member_count: int
    archive_regular_count: int
    archive_symlink_count: int
    archive_directory_count: int
    exact_blobs: tuple[tuple[str, bytes], ...]
    repairs: tuple[CodeloadRepair, ...]
    repair_oids: tuple[str, ...]

    def exact_blob_bytes(self, oid: str) -> bytes:
        for observed_oid, content in self.exact_blobs:
            if observed_oid == oid:
                return content
        raise KeyError(oid)


@dataclass(frozen=True)
class CodeloadAcquisition:
    repair_plan: CodeloadRepairPlan
    verified_plan: VerifiedGitObjectPlan
    fallback_blob_count: int


def plan_codeload_repairs(
    snapshot: GitObjectSnapshot,
    archive_path: Path,
    *,
    limits: GitObjectLimits | None = None,
) -> CodeloadRepairPlan:
    """Treat codeload as bounded bulk transport, never as exact Git identity.

    Regular-file bytes and symlink linknames are accepted only when their Git
    blob OID matches the independently validated Git Trees API snapshot. Missing
    or ``export-subst``-mutated blobs become explicit repairs. A present gitlink
    must be an empty directory marker; an absent marker is materialized later from
    the authoritative tree. Gitlinks are never recursively fetched. No archive
    member is extracted or executed.
    """

    active_limits = limits or GitObjectLimits()
    expected = {entry.path: entry for entry in snapshot.entries}
    archive = Path(archive_path)
    exact_blobs: dict[str, bytes] = {}
    observed_blob_oids: dict[str, str] = {}
    observed_paths: set[str] = set()
    canonical_paths: dict[str, str] = {}
    archive_member_count = 0
    archive_regular_count = 0
    archive_symlink_count = 0
    archive_directory_count = 0
    unpacked_bytes = 0
    archive_sha256 = ""
    archive_bytes = 0

    try:
        with open_regular_file(archive) as compressed:
            initial = os.fstat(compressed.fileno())
            if initial.st_size > MAX_ARCHIVE_BYTES:
                raise PolicyRejection(
                    "archive_too_large", "Codeload archive exceeds the compressed-byte limit."
                )
            archive_sha256, archive_bytes = _hash_open_file(compressed, MAX_ARCHIVE_BYTES)
            os.lseek(compressed.fileno(), 0, os.SEEK_SET)
            max_tar_bytes = (
                active_limits.max_total_blob_bytes + active_limits.max_entries * 4096 + 1024 * 1024
            )
            with gzip.GzipFile(fileobj=compressed, mode="rb") as expanded:
                bounded = _BoundedReader(cast(IO[bytes], expanded), max_bytes=max_tar_bytes)
                with tarfile.open(fileobj=cast(BinaryIO, bounded), mode="r|") as source:
                    top_level: str | None = None
                    root_seen = False
                    for member in source:
                        archive_member_count += 1
                        if archive_member_count > active_limits.max_entries + 1:
                            raise PolicyRejection(
                                "codeload_member_limit",
                                "Codeload archive exceeds the member limit.",
                            )
                        parts = _validate_archive_path(member.name, active_limits)
                        if top_level is None:
                            if len(parts) != 1 or not member.isdir():
                                raise PolicyRejection(
                                    "codeload_unsafe_root",
                                    "Codeload archive must begin with one directory root.",
                                )
                            top_level = parts[0]
                            root_seen = True
                            continue
                        if parts[0] != top_level or len(parts) == 1:
                            raise PolicyRejection(
                                "codeload_unsafe_root",
                                "Codeload archive escaped or repeated its directory root.",
                            )
                        relative_parts = parts[1:]
                        relative = "/".join(relative_parts)
                        _register_path(relative_parts, observed_paths, canonical_paths)
                        expected_entry = expected.get(relative)
                        if expected_entry is None:
                            raise PolicyRejection(
                                "codeload_extra_path",
                                "Codeload archive contains a path absent from the exact Git tree.",
                            )

                        if member.isdir():
                            archive_directory_count += 1
                            if not (expected_entry.is_tree or expected_entry.is_gitlink):
                                raise PolicyRejection(
                                    "codeload_type_mismatch",
                                    "Codeload directory does not match the exact Git entry mode.",
                                )
                            continue
                        if member.isreg():
                            archive_regular_count += 1
                            if not expected_entry.is_regular:
                                raise PolicyRejection(
                                    "codeload_type_mismatch",
                                    "Codeload regular file does not match the exact "
                                    "Git entry mode.",
                                )
                            if member.size < 0 or member.size > active_limits.max_blob_bytes:
                                raise PolicyRejection(
                                    "codeload_file_too_large",
                                    "Codeload member exceeds the per-blob byte limit.",
                                )
                            unpacked_bytes += member.size
                            if unpacked_bytes > active_limits.max_total_blob_bytes:
                                raise PolicyRejection(
                                    "codeload_total_bytes",
                                    "Codeload members exceed the total byte limit.",
                                )
                            member_stream = source.extractfile(member)
                            if member_stream is None:
                                raise PolicyRejection(
                                    "invalid_codeload_archive",
                                    "Codeload regular member cannot be read.",
                                )
                            with member_stream:
                                content = _read_exact(member_stream, member.size)
                            observed_oid = _git_blob_oid(content)
                            observed_blob_oids[relative] = observed_oid
                            if observed_oid == expected_entry.oid:
                                exact_blobs.setdefault(observed_oid, content)
                            continue
                        if member.issym():
                            archive_symlink_count += 1
                            if not expected_entry.is_symlink:
                                raise PolicyRejection(
                                    "codeload_type_mismatch",
                                    "Codeload symlink does not match the exact Git entry mode.",
                                )
                            try:
                                content = member.linkname.encode("utf-8", "surrogateescape")
                            except UnicodeError as exc:
                                raise PolicyRejection(
                                    "invalid_codeload_archive",
                                    "Codeload symlink target cannot be represented exactly.",
                                ) from exc
                            if len(content) > active_limits.max_symlink_target_bytes:
                                raise PolicyRejection(
                                    "codeload_file_too_large",
                                    "Codeload symlink target exceeds the byte limit.",
                                )
                            unpacked_bytes += len(content)
                            if unpacked_bytes > active_limits.max_total_blob_bytes:
                                raise PolicyRejection(
                                    "codeload_total_bytes",
                                    "Codeload members exceed the total byte limit.",
                                )
                            observed_oid = _git_blob_oid(content)
                            observed_blob_oids[relative] = observed_oid
                            if observed_oid == expected_entry.oid:
                                exact_blobs.setdefault(observed_oid, content)
                            continue
                        raise PolicyRejection(
                            "codeload_special_member",
                            "Codeload archive contains a hardlink or special member.",
                        )
                    if not root_seen:
                        raise PolicyRejection(
                            "codeload_unsafe_root", "Codeload archive has no directory root."
                        )
            final = os.fstat(compressed.fileno())
            if not _same_snapshot(initial, final):
                raise PolicyRejection(
                    "codeload_archive_changed", "Codeload archive changed while it was inspected."
                )
    except PolicyRejection:
        raise
    except (gzip.BadGzipFile, tarfile.TarError, EOFError, UnicodeError, OSError) as exc:
        raise PolicyRejection(
            "invalid_codeload_archive", "Codeload archive is malformed or unreadable."
        ) from exc

    repairs: list[CodeloadRepair] = []
    for entry in snapshot.entries:
        if not (entry.is_regular or entry.is_symlink):
            continue
        if entry.path not in observed_paths:
            repairs.append(CodeloadRepair(entry.path, entry.oid, "missing", None))
            continue
        planned_observed_oid = observed_blob_oids.get(entry.path)
        if planned_observed_oid != entry.oid:
            repairs.append(
                CodeloadRepair(
                    entry.path,
                    entry.oid,
                    "blob_oid_mismatch",
                    planned_observed_oid,
                )
            )
    repair_oids = tuple(sorted({repair.expected_oid for repair in repairs} - set(exact_blobs)))
    return CodeloadRepairPlan(
        archive_sha256=archive_sha256,
        archive_bytes=archive_bytes,
        root_tree_oid=snapshot.root_tree_oid,
        object_manifest_sha256=snapshot.manifest_sha256,
        archive_member_count=archive_member_count,
        archive_regular_count=archive_regular_count,
        archive_symlink_count=archive_symlink_count,
        archive_directory_count=archive_directory_count,
        exact_blobs=tuple(sorted(exact_blobs.items())),
        repairs=tuple(sorted(repairs, key=lambda item: item.path.encode("utf-8"))),
        repair_oids=repair_oids,
    )


def complete_codeload_repairs(
    snapshot: GitObjectSnapshot,
    repair_plan: CodeloadRepairPlan,
    fallback_loader: Callable[[str], bytes],
    *,
    limits: GitObjectLimits | None = None,
) -> CodeloadAcquisition:
    """Fetch only planned exact OIDs, then verify the complete object set."""

    if (
        repair_plan.root_tree_oid != snapshot.root_tree_oid
        or repair_plan.object_manifest_sha256 != snapshot.manifest_sha256
    ):
        raise PolicyRejection(
            "codeload_plan_mismatch", "Codeload repair plan is bound to another Git tree."
        )
    if not callable(fallback_loader):
        raise TypeError("fallback_loader must be callable")
    expected_oids = {
        entry.oid for entry in snapshot.entries if entry.is_regular or entry.is_symlink
    }
    exact_oids = tuple(oid for oid, _ in repair_plan.exact_blobs)
    if (
        exact_oids != tuple(sorted(set(exact_oids)))
        or not set(exact_oids) <= expected_oids
        or repair_plan.repair_oids != tuple(sorted(expected_oids - set(exact_oids)))
    ):
        raise PolicyRejection(
            "codeload_plan_mismatch",
            "Codeload repair plan does not request exactly the missing tree blobs.",
        )
    blobs = dict(repair_plan.exact_blobs)
    for oid in repair_plan.repair_oids:
        content = fallback_loader(oid)
        if not isinstance(content, bytes):
            raise PolicyRejection(
                "git_object_invalid_blob", "Fallback blob loader returned a non-byte value."
            )
        blobs[oid] = content
    verified = verify_git_object_blobs(
        snapshot,
        lambda entry: blobs[entry.oid],
        limits=limits,
    )
    return CodeloadAcquisition(
        repair_plan=repair_plan,
        verified_plan=verified,
        fallback_blob_count=len(repair_plan.repair_oids),
    )


def _validate_archive_path(name: str, limits: GitObjectLimits) -> tuple[str, ...]:
    if not isinstance(name, str) or not name or name.startswith("/") or "\\" in name:
        raise PolicyRejection("codeload_unsafe_path", "Codeload archive path is unsafe.")
    normalized = name[:-1] if name.endswith("/") else name
    if not normalized or normalized.endswith("/"):
        raise PolicyRejection("codeload_unsafe_path", "Codeload archive path is unsafe.")
    parts = tuple(normalized.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise PolicyRejection("codeload_unsafe_path", "Codeload archive path is unsafe.")
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        for component in parts
        for character in component
    ):
        raise PolicyRejection(
            "codeload_unsafe_path", "Codeload archive path contains control characters."
        )
    if any(_canonical_component(part) == ".git" for part in parts):
        raise PolicyRejection("codeload_git_metadata", "Codeload archive contains Git metadata.")
    try:
        encoded = tuple(part.encode("utf-8") for part in parts)
    except UnicodeError as exc:
        raise PolicyRejection(
            "codeload_unsafe_path", "Codeload archive path is not valid UTF-8."
        ) from exc
    relative_bytes = b"/".join(encoded[1:]) if len(encoded) > 1 else b""
    if len(relative_bytes) > limits.max_path_bytes:
        raise PolicyRejection("codeload_path_too_long", "Codeload archive path is too long.")
    if any(len(component) > limits.max_component_bytes for component in encoded):
        raise PolicyRejection(
            "codeload_path_too_long", "Codeload archive path component is too long."
        )
    return parts


def _register_path(
    parts: tuple[str, ...],
    observed: set[str],
    canonical_paths: dict[str, str],
) -> None:
    path = "/".join(parts)
    if path in observed:
        raise PolicyRejection("codeload_path_collision", "Codeload path is duplicated.")
    canonical = "/".join(unicodedata.normalize("NFC", part).casefold() for part in parts)
    prior = canonical_paths.get(canonical)
    if prior is not None and prior != path:
        raise PolicyRejection(
            "codeload_path_collision",
            "Codeload paths collide by case or Unicode normalization.",
        )
    canonical_paths[canonical] = path
    observed.add(path)


def _hash_open_file(stream: BinaryIO, max_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while chunk := stream.read(_READ_CHUNK_SIZE):
        total += len(chunk)
        if total > max_bytes:
            raise PolicyRejection(
                "archive_too_large", "Codeload archive exceeds the compressed-byte limit."
            )
        digest.update(chunk)
    return digest.hexdigest(), total


def _read_exact(stream: IO[bytes], size: int) -> bytes:
    remaining = size
    content = bytearray()
    while remaining:
        chunk = stream.read(min(_READ_CHUNK_SIZE, remaining))
        if not chunk:
            raise PolicyRejection(
                "invalid_codeload_archive", "Codeload member ended before its declared size."
            )
        content.extend(chunk)
        remaining -= len(chunk)
    return bytes(content)


def _git_blob_oid(content: bytes) -> str:
    digest = hashlib.sha1(f"blob {len(content)}\0".encode("ascii"), usedforsecurity=False)
    digest.update(content)
    return digest.hexdigest()


def _canonical_component(component: str) -> str:
    return unicodedata.normalize("NFKC", component).casefold().rstrip(". ")


def _same_snapshot(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and first.st_mode == second.st_mode
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
        and first.st_nlink == second.st_nlink
        and stat.S_ISREG(second.st_mode)
    )


class _BoundedReader:
    def __init__(self, stream: IO[bytes], *, max_bytes: int) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self._bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self._max_bytes - self._bytes_read
        if remaining < 0:
            raise PolicyRejection(
                "codeload_total_bytes", "Codeload stream exceeds the decompressed-byte limit."
            )
        requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self._stream.read(requested)
        self._bytes_read += len(data)
        if self._bytes_read > self._max_bytes:
            raise PolicyRejection(
                "codeload_total_bytes", "Codeload stream exceeds the decompressed-byte limit."
            )
        return data
