from __future__ import annotations

import json
import re

from reproassert.errors import ReproAssertError
from reproassert.source_attestation import (
    SOURCE_TREE_ALGORITHM,
    SourceAttestationLimits,
    SourceTreeAttestation,
)

_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_OID = re.compile(r"[0-9a-f]{40}")
MAX_CONTAINER_ATTESTATION_BYTES = 16 * 1024

# This fixed program runs inside the immutable sandbox image. It receives only a
# read-only dependency volume and numeric limits, then emits one bounded JSON object.
# No repository path, host path, credential, network, or generated instruction is used.
DEPENDENCY_TREE_ATTESTOR_SCRIPT = r"""
import hashlib
import json
import os
import stat
import sys
import unicodedata
from collections import deque

ALGORITHM = "reproassert-source-tree-v1"
root = sys.argv[1]
(
    max_members,
    max_files,
    max_directories,
    max_file_bytes,
    max_total_bytes,
    max_path_bytes,
    max_component_bytes,
) = map(int, sys.argv[2:])


def fail(reason):
    raise RuntimeError(reason)


def snapshot(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
        value.st_nlink,
    )


def directory_flags():
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not nofollow or not directory:
        fail("nofollow-unavailable")
    return os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)


def open_directory(root_descriptor, parts):
    descriptor = os.dup(root_descriptor)
    try:
        for component in parts:
            following = os.open(component, directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def canonical_component(name):
    if not name or name in {".", ".."} or "\\" in name:
        fail("unsafe-path")
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in name):
        fail("unsafe-path")
    canonical = unicodedata.normalize("NFKC", name).casefold().rstrip(" .")
    if canonical == ".git":
        fail("git-metadata")
    try:
        encoded = name.encode("utf-8")
    except UnicodeError:
        fail("invalid-utf8")
    if len(encoded) > max_component_bytes:
        fail("component-limit")
    return encoded


root_descriptor = os.open(root, directory_flags())
try:
    root_stat = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root_stat.st_mode):
        fail("root-not-directory")
    root_snapshot = snapshot(root_stat)
    queue = deque([((), (), root_stat.st_dev, root_stat.st_ino)])
    canonical_entries = []
    git_children = {(): []}
    directory_snapshots = []
    file_snapshots = []
    seen_directories = set()
    member_count = 0
    file_count = 0
    directory_count = 0
    total_bytes = 0
    executable_count = 0

    while queue:
        parts, encoded_parts, expected_device, expected_inode = queue.popleft()
        directory_descriptor = open_directory(root_descriptor, parts)
        try:
            directory_stat = os.fstat(directory_descriptor)
            if (
                directory_stat.st_dev != expected_device
                or directory_stat.st_ino != expected_inode
                or not stat.S_ISDIR(directory_stat.st_mode)
            ):
                fail("directory-changed")
            if directory_stat.st_dev != root_stat.st_dev:
                fail("mount-boundary")
            identity = (directory_stat.st_dev, directory_stat.st_ino)
            if identity in seen_directories:
                fail("directory-cycle")
            seen_directories.add(identity)
            directory_snapshots.append((parts, snapshot(directory_stat)))

            names = os.listdir(directory_descriptor)
            validated = sorted(
                ((canonical_component(name), name) for name in names),
                key=lambda item: item[0],
            )
            collisions = {}
            for encoded_name, name in validated:
                collision_key = unicodedata.normalize("NFC", name).casefold()
                if collision_key in collisions and collisions[collision_key] != name:
                    fail("path-collision")
                collisions[collision_key] = name
                child_parts = parts + (name,)
                child_encoded_parts = encoded_parts + (encoded_name,)
                relative_path = b"/".join(child_encoded_parts)
                if len(relative_path) > max_path_bytes:
                    fail("path-limit")
                initial = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
                member_count += 1
                if member_count > max_members:
                    fail("member-limit")

                if stat.S_ISDIR(initial.st_mode):
                    directory_count += 1
                    if directory_count > max_directories:
                        fail("directory-limit")
                    canonical_entries.append(
                        (b"D", relative_path, b"40000", 0, hashlib.sha256(b"").digest())
                    )
                    git_children.setdefault(child_encoded_parts, [])
                    queue.append(
                        (
                            child_parts,
                            child_encoded_parts,
                            initial.st_dev,
                            initial.st_ino,
                        )
                    )
                    continue

                if stat.S_ISLNK(initial.st_mode):
                    fail("symlink")
                if not stat.S_ISREG(initial.st_mode):
                    fail("special-entry")
                if initial.st_nlink != 1:
                    fail("hardlink")
                if initial.st_dev != root_stat.st_dev:
                    fail("mount-boundary")
                file_count += 1
                if file_count > max_files or initial.st_size > max_file_bytes:
                    fail("file-limit")
                if total_bytes + initial.st_size > max_total_bytes:
                    fail("byte-limit")

                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                descriptor = os.open(name, flags, dir_fd=directory_descriptor)
                try:
                    opened = os.fstat(descriptor)
                    if not stat.S_ISREG(opened.st_mode) or snapshot(opened) != snapshot(initial):
                        fail("file-changed")
                    content_digest = hashlib.sha256()
                    blob_digest = hashlib.sha1(
                        f"blob {opened.st_size}\0".encode("ascii"),
                        usedforsecurity=False,
                    )
                    observed_size = 0
                    while True:
                        chunk = os.read(descriptor, 65536)
                        if not chunk:
                            break
                        observed_size += len(chunk)
                        if observed_size > max_file_bytes:
                            fail("file-limit")
                        if total_bytes + observed_size > max_total_bytes:
                            fail("byte-limit")
                        content_digest.update(chunk)
                        blob_digest.update(chunk)
                    final = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                if observed_size != opened.st_size or snapshot(opened) != snapshot(final):
                    fail("file-changed")
                total_bytes += observed_size
                executable = bool(final.st_mode & 0o111)
                mode = b"100755" if executable else b"100644"
                executable_count += int(executable)
                canonical_entries.append(
                    (
                        b"F",
                        relative_path,
                        mode,
                        observed_size,
                        content_digest.digest(),
                    )
                )
                git_children[encoded_parts].append(
                    (encoded_name, mode, blob_digest.digest(), False)
                )
                file_snapshots.append((child_parts, snapshot(final)))
        finally:
            os.close(directory_descriptor)

    for parts, expected in directory_snapshots:
        descriptor = open_directory(root_descriptor, parts)
        try:
            observed = snapshot(os.fstat(descriptor))
        finally:
            os.close(descriptor)
        if observed != expected:
            fail("directory-changed")
    for parts, expected in file_snapshots:
        parent_descriptor = open_directory(root_descriptor, parts[:-1])
        try:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            descriptor = os.open(parts[-1], flags, dir_fd=parent_descriptor)
            try:
                observed = snapshot(os.fstat(descriptor))
            finally:
                os.close(descriptor)
        finally:
            os.close(parent_descriptor)
        if observed != expected:
            fail("file-changed")
    if snapshot(os.fstat(root_descriptor)) != root_snapshot:
        fail("root-changed")

    tree_oids = {}
    directories = sorted(git_children, key=lambda value: (len(value), value), reverse=True)
    for directory in directories:
        entries = list(git_children[directory])
        entries.sort(key=lambda item: item[0] + (b"/" if item[3] else b""))
        encoded_entries = [
            item[1] + b" " + item[0] + b"\0" + item[2] for item in entries
        ]
        body_size = sum(len(item) for item in encoded_entries)
        digest = hashlib.sha1(
            f"tree {body_size}\0".encode("ascii"),
            usedforsecurity=False,
        )
        for encoded_entry in encoded_entries:
            digest.update(encoded_entry)
        tree_oids[directory] = digest.digest()
        if directory:
            git_children[directory[:-1]].append(
                (directory[-1], b"40000", tree_oids[directory], True)
            )

    tree_digest = hashlib.sha256(ALGORITHM.encode("ascii") + b"\0")
    for kind, path, mode, size, content_hash in sorted(
        canonical_entries,
        key=lambda item: (item[1], item[0]),
    ):
        tree_digest.update(kind)
        tree_digest.update(len(path).to_bytes(8, "big"))
        tree_digest.update(path)
        tree_digest.update(len(mode).to_bytes(1, "big"))
        tree_digest.update(mode)
        tree_digest.update(size.to_bytes(8, "big"))
        tree_digest.update(content_hash)

    payload = {
        "algorithm": ALGORITHM,
        "tree_sha256": tree_digest.hexdigest(),
        "reconstructed_git_tree_oid": tree_oids[()].hex(),
        "expected_git_tree_oid": None,
        "member_count": member_count,
        "file_count": file_count,
        "directory_count": directory_count,
        "total_bytes": total_bytes,
        "executable_count": executable_count,
        "git_metadata_absent": True,
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
finally:
    os.close(root_descriptor)
""".strip()


def parse_container_tree_attestation(
    raw: str,
    *,
    limits: SourceAttestationLimits | None = None,
) -> SourceTreeAttestation:
    """Strictly parse bounded JSON emitted by ``DEPENDENCY_TREE_ATTESTOR_SCRIPT``."""

    active_limits = limits or SourceAttestationLimits()
    try:
        encoded = raw.encode("utf-8")
        if len(encoded) > MAX_CONTAINER_ATTESTATION_BYTES:
            raise ValueError("container attestation exceeds byte limit")
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ReproAssertError(
            "dependency_attestation_invalid", "Container tree attestor returned invalid JSON."
        ) from exc
    keys = {
        "algorithm",
        "tree_sha256",
        "reconstructed_git_tree_oid",
        "expected_git_tree_oid",
        "member_count",
        "file_count",
        "directory_count",
        "total_bytes",
        "executable_count",
        "git_metadata_absent",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ReproAssertError(
            "dependency_attestation_invalid", "Container tree attestation fields are invalid."
        )
    canonical = (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )
    if raw != canonical:
        raise ReproAssertError(
            "dependency_attestation_invalid",
            "Container tree attestation is not canonical JSON with one final newline.",
        )
    tree_sha256 = value["tree_sha256"]
    git_oid = value["reconstructed_git_tree_oid"]
    integers = {
        key: _required_int(value[key], f"container tree attestation {key}")
        for key in (
            "member_count",
            "file_count",
            "directory_count",
            "total_bytes",
            "executable_count",
        )
    }
    if (
        value["algorithm"] != SOURCE_TREE_ALGORITHM
        or not isinstance(tree_sha256, str)
        or _SHA256.fullmatch(tree_sha256) is None
        or not isinstance(git_oid, str)
        or _GIT_OID.fullmatch(git_oid) is None
        or value["expected_git_tree_oid"] is not None
        or value["git_metadata_absent"] is not True
        or any(number < 0 for number in integers.values())
        or integers["member_count"] != integers["file_count"] + integers["directory_count"]
        or integers["executable_count"] > integers["file_count"]
        or integers["member_count"] > active_limits.max_members
        or integers["file_count"] > active_limits.max_files
        or integers["directory_count"] > active_limits.max_directories
        or integers["total_bytes"] > active_limits.max_total_bytes
    ):
        raise ReproAssertError(
            "dependency_attestation_invalid",
            "Container tree attestation invariants are invalid.",
        )
    return SourceTreeAttestation(
        algorithm=SOURCE_TREE_ALGORITHM,
        tree_sha256=tree_sha256,
        reconstructed_git_tree_oid=git_oid,
        expected_git_tree_oid=None,
        member_count=integers["member_count"],
        file_count=integers["file_count"],
        directory_count=integers["directory_count"],
        total_bytes=integers["total_bytes"],
        executable_count=integers["executable_count"],
        git_metadata_absent=True,
    )


def _required_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ReproAssertError("dependency_attestation_invalid", f"{label} is not an integer.")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"invalid JSON constant: {value}")
