from __future__ import annotations

import hashlib
import math
import re
import urllib.error
import urllib.request
from typing import Any

from reproassert.errors import PolicyRejection, ReproAssertError
from reproassert.intake import (
    GITHUB_API_HOST,
    MAX_ARCHIVE_BYTES,
    _build_opener,
    _validate_fixed_https_url,
)

_GIT_OID_RE = re.compile(r"[0-9a-f]{40}")
_OWNER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}")


def fetch_raw_git_blob(
    owner: str,
    repo: str,
    oid: str,
    *,
    expected_size: int,
    timeout_seconds: float = 15.0,
) -> bytes:
    """Fetch one exact public Git blob from a fixed unauthenticated API endpoint."""

    _validate_repository(owner, repo)
    if not isinstance(oid, str) or _GIT_OID_RE.fullmatch(oid) is None:
        raise PolicyRejection(
            "invalid_git_blob_oid", "Git blob object ID must be 40 lowercase hex digits."
        )
    if (
        not isinstance(expected_size, int)
        or isinstance(expected_size, bool)
        or not 0 <= expected_size <= MAX_ARCHIVE_BYTES
    ):
        raise ValueError("expected_size must be between 0 and 64 MiB")
    if (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(float(timeout_seconds))
        or not 0 < float(timeout_seconds) <= 300
    ):
        raise ValueError("timeout_seconds must be between 0 and 300 seconds")

    url = f"https://{GITHUB_API_HOST}/repos/{owner}/{repo}/git/blobs/{oid}"
    request = urllib.request.Request(  # noqa: S310 - fixed HTTPS host is checked below
        url,
        headers={
            "Accept": "application/vnd.github.raw+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "reproassert/0.1",
        },
        method="GET",
    )
    try:
        response = _build_opener().open(request, timeout=float(timeout_seconds))
    except PolicyRejection:
        raise
    except urllib.error.HTTPError as exc:
        raise ReproAssertError("github_http_error", f"GitHub returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ReproAssertError(
            "github_unavailable", "Unable to fetch bounded GitHub blob data"
        ) from exc

    try:
        _validate_fixed_https_url(response.geturl(), expected_host=GITHUB_API_HOST)
        if response.geturl() != url:
            raise PolicyRejection("github_redirect_rejected", "GitHub blob response URL changed")
        _validate_content_length(response, expected_size)
        content = _read_exact_bounded(response, expected_size)
    finally:
        response.close()
    if _git_blob_oid(content) != oid:
        raise PolicyRejection(
            "git_object_blob_mismatch", "GitHub blob bytes do not match the requested object ID."
        )
    return content


def _validate_content_length(response: Any, expected_size: int) -> None:
    value = response.headers.get("Content-Length")
    if value is None:
        return
    try:
        observed = int(value)
    except ValueError as exc:
        raise PolicyRejection(
            "invalid_github_response", "GitHub sent an invalid Content-Length"
        ) from exc
    if observed != expected_size:
        raise PolicyRejection(
            "git_object_blob_size_mismatch",
            "GitHub blob response size differs from Git tree metadata.",
        )


def _read_exact_bounded(response: Any, expected_size: int) -> bytes:
    content = bytearray()
    while True:
        chunk = response.read(min(64 * 1024, expected_size - len(content) + 1))
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > expected_size:
            raise PolicyRejection(
                "git_object_blob_size_mismatch",
                "GitHub blob response exceeds the size declared by Git tree metadata.",
            )
    if len(content) != expected_size:
        raise PolicyRejection(
            "git_object_blob_size_mismatch",
            "GitHub blob response ended before the size declared by Git tree metadata.",
        )
    return bytes(content)


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
