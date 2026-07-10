from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from reproassert.errors import PolicyRejection

SOURCE_TREE_ALGORITHM = "reproassert-source-tree-v1"

_READ_CHUNK_SIZE = 64 * 1024
_EMPTY_CONTENT_SHA256 = hashlib.sha256(b"").digest()
_GIT_OID_RE = re.compile(r"[0-9a-f]{40}")
_MAX_LIMIT = 2**63 - 1


@dataclass(frozen=True)
class SourceAttestationLimits:
    """Hard limits for one extracted source-tree attestation.

    Counts exclude the supplied root itself. ``max_members`` covers every file
    and directory below it; the other count limits are independent.
    """

    max_members: int = 20_000
    max_files: int = 20_000
    max_directories: int = 20_000
    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_path_bytes: int = 4096
    max_component_bytes: int = 255

    def __post_init__(self) -> None:
        for field_name in (
            "max_members",
            "max_files",
            "max_directories",
            "max_file_bytes",
            "max_total_bytes",
            "max_path_bytes",
            "max_component_bytes",
        ):
            value = getattr(self, field_name)
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not 1 <= value <= _MAX_LIMIT
            ):
                raise ValueError(f"{field_name} must be an integer between 1 and {_MAX_LIMIT}")


@dataclass(frozen=True)
class SourceTreeAttestation:
    algorithm: str
    tree_sha256: str
    reconstructed_git_tree_oid: str
    expected_git_tree_oid: str | None
    member_count: int
    file_count: int
    directory_count: int
    total_bytes: int
    executable_count: int
    git_metadata_absent: bool


@dataclass(frozen=True)
class _PendingDirectory:
    parts: tuple[str, ...]
    encoded_parts: tuple[bytes, ...]
    device: int
    inode: int


@dataclass(frozen=True)
class _PathSnapshot:
    parts: tuple[str, ...]
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    links: int


@dataclass(frozen=True)
class _CanonicalEntry:
    kind: bytes
    path: bytes
    mode: bytes
    size: int
    content_sha256: bytes


@dataclass(frozen=True)
class _GitEntry:
    name: bytes
    mode: bytes
    oid: bytes
    is_directory: bool


def attest_source_tree(
    root: Path,
    *,
    limits: SourceAttestationLimits | None = None,
    expected_git_tree_oid: str | None = None,
) -> SourceTreeAttestation:
    """Attest an inert extracted tree without following any filesystem link.

    The returned SHA-256 commits to a versioned, length-framed sequence of
    canonical directory and file records. Git blob and tree object IDs are
    reconstructed from the same file descriptors and canonical executable
    modes, allowing a caller to bind the extraction to an expected Git tree.
    """

    active_limits = limits or SourceAttestationLimits()
    expected_oid = _validate_expected_oid(expected_git_tree_oid)
    root_path = Path(root)
    if _is_git_metadata_component(root_path.name):
        raise PolicyRejection(
            "source_git_metadata", "Source root canonicalizes to forbidden Git metadata."
        )

    root_fd = _open_root_directory_nofollow(root_path)
    try:
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise PolicyRejection("source_not_directory", "Source root is not a directory.")

        result = _attest_open_tree(root_fd, root_stat, active_limits)
    finally:
        os.close(root_fd)

    if expected_oid is not None and result.reconstructed_git_tree_oid != expected_oid:
        raise PolicyRejection(
            "source_git_tree_mismatch",
            "Reconstructed Git tree does not match the expected root tree object.",
        )
    return SourceTreeAttestation(
        algorithm=SOURCE_TREE_ALGORITHM,
        tree_sha256=result.tree_sha256,
        reconstructed_git_tree_oid=result.reconstructed_git_tree_oid,
        expected_git_tree_oid=expected_oid,
        member_count=result.member_count,
        file_count=result.file_count,
        directory_count=result.directory_count,
        total_bytes=result.total_bytes,
        executable_count=result.executable_count,
        git_metadata_absent=True,
    )


@dataclass(frozen=True)
class _AttestationResult:
    tree_sha256: str
    reconstructed_git_tree_oid: str
    member_count: int
    file_count: int
    directory_count: int
    total_bytes: int
    executable_count: int


def _attest_open_tree(
    root_fd: int, root_stat: os.stat_result, limits: SourceAttestationLimits
) -> _AttestationResult:
    queue = deque([_PendingDirectory((), (), root_stat.st_dev, root_stat.st_ino)])
    canonical_entries: list[_CanonicalEntry] = []
    git_children: dict[tuple[bytes, ...], list[_GitEntry]] = {(): []}
    directory_snapshots: list[_PathSnapshot] = []
    file_snapshots: list[_PathSnapshot] = []
    seen_directories: set[tuple[int, int]] = set()

    member_count = 0
    file_count = 0
    directory_count = 0
    total_bytes = 0
    executable_count = 0

    while queue:
        pending = queue.popleft()
        directory_fd = _open_relative_directory(root_fd, pending.parts)
        try:
            directory_stat = os.fstat(directory_fd)
            if (
                directory_stat.st_dev != pending.device
                or directory_stat.st_ino != pending.inode
                or not stat.S_ISDIR(directory_stat.st_mode)
            ):
                raise PolicyRejection(
                    "source_tree_changed", "Source directory changed during attestation."
                )
            if directory_stat.st_dev != root_stat.st_dev:
                raise PolicyRejection(
                    "source_mount_boundary", "Source tree crosses a filesystem boundary."
                )
            identity = (directory_stat.st_dev, directory_stat.st_ino)
            if identity in seen_directories:
                raise PolicyRejection(
                    "source_directory_cycle", "Source tree repeats a directory identity."
                )
            seen_directories.add(identity)
            directory_snapshots.append(_snapshot(pending.parts, directory_stat))

            try:
                names = os.listdir(directory_fd)
            except OSError as exc:
                raise PolicyRejection(
                    "source_unreadable", "Unable to enumerate the source tree."
                ) from exc

            validated_names = sorted(
                ((_validate_component(name, limits), name) for name in names),
                key=lambda item: item[0],
            )
            canonical_names: dict[str, str] = {}
            for encoded_name, name in validated_names:
                canonical_name = unicodedata.normalize("NFC", name).casefold()
                previous_name = canonical_names.get(canonical_name)
                if previous_name is not None and previous_name != name:
                    raise PolicyRejection(
                        "source_path_collision",
                        "Source paths collide by case or Unicode normalization.",
                    )
                canonical_names[canonical_name] = name
                parts = (*pending.parts, name)
                encoded_parts = (*pending.encoded_parts, encoded_name)
                relative_path = b"/".join(encoded_parts)
                if len(relative_path) > limits.max_path_bytes:
                    raise PolicyRejection(
                        "source_path_too_long", "Source path exceeds the byte limit."
                    )

                try:
                    entry_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError as exc:
                    raise PolicyRejection(
                        "source_tree_changed", "Source entry changed during attestation."
                    ) from exc

                member_count += 1
                if member_count > limits.max_members:
                    raise PolicyRejection(
                        "source_member_limit", "Source tree exceeds the member limit."
                    )

                if stat.S_ISDIR(entry_stat.st_mode):
                    directory_count += 1
                    if directory_count > limits.max_directories:
                        raise PolicyRejection(
                            "source_directory_limit", "Source tree exceeds the directory limit."
                        )
                    canonical_entries.append(
                        _CanonicalEntry(
                            kind=b"D",
                            path=relative_path,
                            mode=b"40000",
                            size=0,
                            content_sha256=_EMPTY_CONTENT_SHA256,
                        )
                    )
                    git_children.setdefault(encoded_parts, [])
                    queue.append(
                        _PendingDirectory(
                            parts,
                            encoded_parts,
                            entry_stat.st_dev,
                            entry_stat.st_ino,
                        )
                    )
                    continue

                if stat.S_ISLNK(entry_stat.st_mode):
                    raise PolicyRejection("source_symlink", "Source tree contains a symlink.")
                if not stat.S_ISREG(entry_stat.st_mode):
                    raise PolicyRejection(
                        "source_special_file", "Source tree contains a non-regular entry."
                    )
                if entry_stat.st_nlink != 1:
                    raise PolicyRejection(
                        "source_hardlink", "Source tree contains a hard-linked file."
                    )
                if entry_stat.st_dev != root_stat.st_dev:
                    raise PolicyRejection(
                        "source_mount_boundary", "Source tree crosses a filesystem boundary."
                    )

                file_count += 1
                if file_count > limits.max_files:
                    raise PolicyRejection(
                        "source_file_limit", "Source tree exceeds the file limit."
                    )
                if entry_stat.st_size > limits.max_file_bytes:
                    raise PolicyRejection(
                        "source_file_too_large", "Source file exceeds the per-file byte limit."
                    )
                if total_bytes + entry_stat.st_size > limits.max_total_bytes:
                    raise PolicyRejection(
                        "source_total_bytes", "Source tree exceeds the total byte limit."
                    )

                file_digest, blob_oid, observed_size, final_stat = _hash_regular_file(
                    directory_fd,
                    name,
                    entry_stat,
                    total_bytes=total_bytes,
                    limits=limits,
                )
                total_bytes += observed_size
                executable = bool(final_stat.st_mode & 0o111)
                canonical_mode = b"100755" if executable else b"100644"
                executable_count += int(executable)
                canonical_entries.append(
                    _CanonicalEntry(
                        kind=b"F",
                        path=relative_path,
                        mode=canonical_mode,
                        size=observed_size,
                        content_sha256=file_digest,
                    )
                )
                git_children[pending.encoded_parts].append(
                    _GitEntry(
                        name=encoded_name,
                        mode=canonical_mode,
                        oid=blob_oid,
                        is_directory=False,
                    )
                )
                file_snapshots.append(_snapshot(parts, final_stat))
        finally:
            os.close(directory_fd)

    _revalidate_snapshots(root_fd, root_stat, directory_snapshots, file_snapshots)
    tree_oid = _reconstruct_git_tree(git_children)
    tree_sha256 = _canonical_tree_sha256(canonical_entries)
    return _AttestationResult(
        tree_sha256=tree_sha256,
        reconstructed_git_tree_oid=tree_oid,
        member_count=member_count,
        file_count=file_count,
        directory_count=directory_count,
        total_bytes=total_bytes,
        executable_count=executable_count,
    )


def _hash_regular_file(
    directory_fd: int,
    name: str,
    initial_stat: os.stat_result,
    *,
    total_bytes: int,
    limits: SourceAttestationLimits,
) -> tuple[bytes, bytes, int, os.stat_result]:
    flags = os.O_RDONLY | _required_flag("O_NOFOLLOW") | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as exc:
        raise PolicyRejection(
            "source_tree_changed", "Unable to open a source file safely."
        ) from exc

    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode) or not _same_snapshot(initial_stat, opened_stat):
            raise PolicyRejection("source_tree_changed", "Source file changed before it was read.")
        if opened_stat.st_nlink != 1:
            raise PolicyRejection("source_hardlink", "Source tree contains a hard-linked file.")

        content_sha256 = hashlib.sha256()
        blob_sha1 = hashlib.sha1(
            f"blob {opened_stat.st_size}\0".encode("ascii"), usedforsecurity=False
        )
        observed_size = 0
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_SIZE)
            if not chunk:
                break
            observed_size += len(chunk)
            if observed_size > limits.max_file_bytes:
                raise PolicyRejection(
                    "source_file_too_large", "Source file exceeds the per-file byte limit."
                )
            if total_bytes + observed_size > limits.max_total_bytes:
                raise PolicyRejection(
                    "source_total_bytes", "Source tree exceeds the total byte limit."
                )
            content_sha256.update(chunk)
            blob_sha1.update(chunk)

        final_stat = os.fstat(descriptor)
        if observed_size != opened_stat.st_size or not _same_snapshot(opened_stat, final_stat):
            raise PolicyRejection("source_tree_changed", "Source file changed while it was read.")
        return content_sha256.digest(), blob_sha1.digest(), observed_size, final_stat
    finally:
        os.close(descriptor)


def _reconstruct_git_tree(
    children: dict[tuple[bytes, ...], list[_GitEntry]],
) -> str:
    tree_oids: dict[tuple[bytes, ...], bytes] = {}
    for directory in sorted(children, key=lambda parts: (len(parts), parts), reverse=True):
        entries = list(children[directory])
        entries.sort(key=lambda entry: entry.name + (b"/" if entry.is_directory else b""))
        encoded_entries = [entry.mode + b" " + entry.name + b"\0" + entry.oid for entry in entries]
        body_size = sum(len(entry) for entry in encoded_entries)
        digest = hashlib.sha1(f"tree {body_size}\0".encode("ascii"), usedforsecurity=False)
        for encoded_entry in encoded_entries:
            digest.update(encoded_entry)
        tree_oids[directory] = digest.digest()
        if directory:
            children[directory[:-1]].append(
                _GitEntry(
                    name=directory[-1],
                    mode=b"40000",
                    oid=tree_oids[directory],
                    is_directory=True,
                )
            )
    return tree_oids[()].hex()


def _canonical_tree_sha256(entries: list[_CanonicalEntry]) -> str:
    digest = hashlib.sha256(SOURCE_TREE_ALGORITHM.encode("ascii") + b"\0")
    for entry in sorted(entries, key=lambda item: (item.path, item.kind)):
        digest.update(entry.kind)
        digest.update(len(entry.path).to_bytes(8, "big"))
        digest.update(entry.path)
        digest.update(len(entry.mode).to_bytes(1, "big"))
        digest.update(entry.mode)
        digest.update(entry.size.to_bytes(8, "big"))
        digest.update(entry.content_sha256)
    return digest.hexdigest()


def _revalidate_snapshots(
    root_fd: int,
    root_stat: os.stat_result,
    directories: list[_PathSnapshot],
    files: list[_PathSnapshot],
) -> None:
    for expected in directories:
        descriptor = _open_relative_directory(root_fd, expected.parts)
        try:
            observed = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if not _snapshot_matches(expected, observed):
            raise PolicyRejection(
                "source_tree_changed", "Source directory changed during attestation."
            )

    for expected in files:
        parent = expected.parts[:-1]
        directory_fd = _open_relative_directory(root_fd, parent)
        try:
            flags = os.O_RDONLY | _required_flag("O_NOFOLLOW") | getattr(os, "O_CLOEXEC", 0)
            try:
                descriptor = os.open(expected.parts[-1], flags, dir_fd=directory_fd)
            except OSError as exc:
                raise PolicyRejection(
                    "source_tree_changed", "Source file changed during attestation."
                ) from exc
            try:
                observed = os.fstat(descriptor)
            finally:
                os.close(descriptor)
        finally:
            os.close(directory_fd)
        if not _snapshot_matches(expected, observed):
            raise PolicyRejection("source_tree_changed", "Source file changed during attestation.")

    if not _same_snapshot(root_stat, os.fstat(root_fd)):
        raise PolicyRejection("source_tree_changed", "Source root changed during attestation.")


def _open_root_directory_nofollow(path: Path) -> int:
    flags = (
        os.O_RDONLY
        | _required_flag("O_DIRECTORY")
        | _required_flag("O_NOFOLLOW")
        | getattr(os, "O_CLOEXEC", 0)
    )
    if ".." in path.parts:
        raise PolicyRejection(
            "source_unsafe_root", "Source root must not contain parent traversal."
        )
    try:
        # The extraction controller owns the parent. Resolve that trusted path
        # so platform aliases such as macOS /var -> /private/var remain usable,
        # then apply O_NOFOLLOW to the untrusted source-root component itself.
        parent = path.parent.resolve(strict=True)
        target = parent / path.name if path.name else parent
        return os.open(target, flags)
    except OSError as exc:
        raise PolicyRejection(
            "source_unsafe_root", "Source root is not a no-follow directory path."
        ) from exc


def _open_relative_directory(root_fd: int, parts: tuple[str, ...]) -> int:
    flags = (
        os.O_RDONLY
        | _required_flag("O_DIRECTORY")
        | _required_flag("O_NOFOLLOW")
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.dup(root_fd)
    try:
        for component in parts:
            try:
                next_descriptor = os.open(component, flags, dir_fd=descriptor)
            except OSError as exc:
                raise PolicyRejection(
                    "source_tree_changed", "Source directory changed during attestation."
                ) from exc
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_component(name: str, limits: SourceAttestationLimits) -> bytes:
    if not isinstance(name, str) or not name or name in {".", ".."} or "\\" in name:
        raise PolicyRejection("source_unsafe_path", "Source contains an unsafe path component.")
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in name):
        raise PolicyRejection("source_unsafe_path", "Source path contains control characters.")
    if _is_git_metadata_component(name):
        raise PolicyRejection("source_git_metadata", "Source tree contains Git metadata.")
    try:
        encoded = name.encode("utf-8")
    except UnicodeError as exc:
        raise PolicyRejection("source_unsafe_path", "Source path is not valid UTF-8.") from exc
    if len(encoded) > limits.max_component_bytes:
        raise PolicyRejection(
            "source_component_too_long", "Source path component exceeds the byte limit."
        )
    return encoded


def _is_git_metadata_component(name: str) -> bool:
    if not name or name in {".", ".."}:
        return False
    canonical = unicodedata.normalize("NFKC", name).casefold().rstrip(" .")
    return canonical == ".git"


def _validate_expected_oid(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _GIT_OID_RE.fullmatch(value) is None:
        raise PolicyRejection(
            "invalid_git_tree_oid", "Expected Git tree object ID must be 40 lowercase hex digits."
        )
    return value


def _required_flag(name: str) -> int:
    value = getattr(os, name, 0)
    if not value:
        raise PolicyRejection(
            "source_nofollow_unavailable", f"Platform does not provide required {name}."
        )
    return int(value)


def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _same_snapshot(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        _same_identity(first, second)
        and first.st_mode == second.st_mode
        and first.st_size == second.st_size
        and first.st_mtime_ns == second.st_mtime_ns
        and first.st_ctime_ns == second.st_ctime_ns
        and first.st_nlink == second.st_nlink
    )


def _snapshot(parts: tuple[str, ...], value: os.stat_result) -> _PathSnapshot:
    return _PathSnapshot(
        parts=parts,
        device=value.st_dev,
        inode=value.st_ino,
        mode=value.st_mode,
        size=value.st_size,
        mtime_ns=value.st_mtime_ns,
        ctime_ns=value.st_ctime_ns,
        links=value.st_nlink,
    )


def _snapshot_matches(expected: _PathSnapshot, observed: os.stat_result) -> bool:
    return (
        expected.device == observed.st_dev
        and expected.inode == observed.st_ino
        and expected.mode == observed.st_mode
        and expected.size == observed.st_size
        and expected.mtime_ns == observed.st_mtime_ns
        and expected.ctime_ns == observed.st_ctime_ns
        and expected.links == observed.st_nlink
    )
