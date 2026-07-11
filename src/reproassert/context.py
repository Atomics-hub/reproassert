from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from reproassert.errors import PolicyRejection

MAX_MANIFEST_FILES = 5_000
MAX_RENDERED_MANIFEST_BYTES = 128 * 1024
MAX_CONTEXT_BYTES = 96 * 1024
MAX_FILE_BYTES = 16 * 1024
V02_SOURCE_CONTEXT_ALGORITHM = "reproassert-v02-source-context-v1"

_TEXT_SUFFIXES = {".cfg", ".ini", ".md", ".py", ".rst", ".toml", ".txt", ".yaml", ".yml"}
_PRIORITY_NAMES = {
    "conftest.py",
    "pyproject.toml",
    "pytest.ini",
    "setup.cfg",
    "setup.py",
    "tox.ini",
}
_SENSITIVE_COMPONENT = re.compile(
    r"(^|[._-])(credentials?|secrets?|tokens?|private|id_rsa|id_ed25519)([._-]|$)",
    re.I,
)
_WORD = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{2,}")

_V02_SOURCE_CONTEXT_POLICY = {
    "algorithm": V02_SOURCE_CONTEXT_ALGORITHM,
    "builder": "reproassert.context.build_source_context",
    "max_manifest_files": MAX_MANIFEST_FILES,
    "max_rendered_manifest_bytes": MAX_RENDERED_MANIFEST_BYTES,
    "max_context_bytes": MAX_CONTEXT_BYTES,
    "max_file_bytes": MAX_FILE_BYTES,
    "text_suffixes": sorted(_TEXT_SUFFIXES),
    "priority_names": sorted(_PRIORITY_NAMES),
    "ranking": "priority_then_issue_path_terms_then_test_path_then_depth_v1",
    "sensitive_paths": "env_prefix_and_sensitive_component_regex_v1",
    "issue_input": "validated_generator_projection_title_and_body",
    "source_input": "fresh_exact_object_materialization",
}
V02_SOURCE_CONTEXT_POLICY_SHA256 = hashlib.sha256(
    json.dumps(_V02_SOURCE_CONTEXT_POLICY, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()


@dataclass(frozen=True)
class ContextFile:
    path: str
    sha256: str
    content: str
    truncated: bool


@dataclass(frozen=True)
class SourceContext:
    manifest: tuple[str, ...]
    files: tuple[ContextFile, ...]
    context_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "manifest": list(self.manifest),
            "files": [
                {
                    "path": item.path,
                    "sha256": item.sha256,
                    "content": item.content,
                    "truncated": item.truncated,
                }
                for item in self.files
            ],
            "context_bytes": self.context_bytes,
        }


def build_source_context(root: Path, *, issue_title: str, issue_body: str) -> SourceContext:
    root = root.resolve(strict=True)
    manifest: list[str] = []
    candidates: list[tuple[int, str, Path]] = []
    terms = {word.lower() for word in _WORD.findall(f"{issue_title}\n{issue_body}")}

    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in {".git", ".hg", ".svn", ".tox", ".venv", "node_modules"}
            and not (directory_path / name).is_symlink()
        )
        for filename in sorted(filenames):
            path = directory_path / filename
            relative = path.relative_to(root).as_posix()
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            if not stat.S_ISREG(mode):
                continue
            manifest.append(relative)
            if len(manifest) > MAX_MANIFEST_FILES:
                raise PolicyRejection(
                    "source_file_limit", f"Source contains more than {MAX_MANIFEST_FILES} files."
                )
            if path.suffix.lower() not in _TEXT_SUFFIXES or _is_sensitive_path(relative):
                continue
            lowered = relative.lower()
            score = 0
            if filename in _PRIORITY_NAMES:
                score += 80
            if "/test" in f"/{lowered}" or filename.startswith("test_"):
                score += 25
            score += min(60, sum(8 for term in terms if term in lowered))
            score -= min(20, relative.count("/") * 2)
            candidates.append((score, relative, path))

    candidates.sort(key=lambda item: (-item[0], item[1]))
    selected: list[ContextFile] = []
    used = 0
    for _, relative, path in candidates:
        if used >= MAX_CONTEXT_BYTES:
            break
        budget = min(MAX_FILE_BYTES, MAX_CONTEXT_BYTES - used)
        raw = _read_bounded(path, budget + 1)
        truncated = len(raw) > budget
        raw = raw[:budget]
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        used += len(raw)
        selected.append(
            ContextFile(
                path=relative,
                sha256=hashlib.sha256(raw).hexdigest(),
                content=content,
                truncated=truncated,
            )
        )

    rendered_manifest = _bounded_rendered_manifest(
        manifest,
        required_paths={item.path for item in selected},
    )
    return SourceContext(rendered_manifest, tuple(selected), used)


def _bounded_rendered_manifest(manifest: list[str], *, required_paths: set[str]) -> tuple[str, ...]:
    """Keep selected files discoverable while bounding prompt-only path inventory bytes."""

    encoded_paths = {
        path: json.dumps(path, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        for path in manifest
    }
    kept = sorted(required_paths)
    size = 2 + sum(len(encoded_paths[path]) for path in kept) + max(0, len(kept) - 1)
    if size > MAX_RENDERED_MANIFEST_BYTES:
        raise PolicyRejection(
            "source_manifest_budget",
            "Selected source paths exceed the rendered manifest byte budget.",
        )
    kept_set = set(kept)
    for path in sorted(manifest):
        if path in kept_set:
            continue
        added = len(encoded_paths[path]) + (1 if kept else 0)
        if size + added > MAX_RENDERED_MANIFEST_BYTES:
            continue
        kept.append(path)
        kept_set.add(path)
        size += added
    return tuple(sorted(kept))


def _read_bounded(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        return os.read(descriptor, limit)
    finally:
        os.close(descriptor)


def _is_sensitive_path(relative: str) -> bool:
    for component in relative.split("/"):
        if component.lower().startswith(".env") or _SENSITIVE_COMPONENT.search(component):
            return True
    return False
