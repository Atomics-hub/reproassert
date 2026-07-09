from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import shutil
import ssl
import tarfile
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, BinaryIO, cast

from .errors import PolicyRejection, ReproAssertError
from .models import IssueRef
from .safeio import open_exclusive_file, open_regular_file, require_private_directory, sha256_text

GITHUB_WEB_HOST = "github.com"
GITHUB_API_HOST = "api.github.com"
GITHUB_CODELOAD_HOST = "codeload.github.com"

MAX_ISSUE_JSON_BYTES = 1024 * 1024
MAX_ISSUE_BODY_BYTES = 64 * 1024
MAX_ISSUE_TITLE_BYTES = 4 * 1024
MAX_COMMIT_JSON_BYTES = 512 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
DEFAULT_HTTP_TIMEOUT_SECONDS = 15.0

_OWNER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}")
_ISSUE_PATH_RE = re.compile(
    r"/(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/"
    r"(?P<repo>[A-Za-z0-9_.-]{1,100})/issues/(?P<number>[1-9][0-9]*)"
)
_FULL_SHA_RE = re.compile(r"[0-9a-fA-F]{40}")
_DISALLOWED_REF_CHARACTERS = frozenset(" ~^:?*[\\")


@dataclass(frozen=True)
class GitHubIssueLocation:
    url: str
    owner: str
    repo: str
    number: int

    @property
    def repository_url(self) -> str:
        return f"https://{GITHUB_WEB_HOST}/{self.owner}/{self.repo}"


@dataclass(frozen=True)
class IssueDocument:
    ref: IssueRef
    body: str


@dataclass(frozen=True)
class ArchiveDownload:
    path: Path
    sha256: str
    size_bytes: int


@dataclass(frozen=True)
class ExtractionLimits:
    max_archive_bytes: int = MAX_ARCHIVE_BYTES
    max_files: int = 20_000
    max_unpacked_bytes: int = 256 * 1024 * 1024
    max_path_bytes: int = 4096
    max_component_bytes: int = 255

    def __post_init__(self) -> None:
        for field_name in (
            "max_archive_bytes",
            "max_files",
            "max_unpacked_bytes",
            "max_path_bytes",
            "max_component_bytes",
        ):
            if getattr(self, field_name) < 1:
                raise ValueError(f"{field_name} must be positive")


@dataclass(frozen=True)
class ExtractedArchive:
    destination: Path
    source_root: Path
    member_count: int
    file_count: int
    unpacked_bytes: int


def parse_issue_url(url: str) -> GitHubIssueLocation:
    """Parse only canonical public github.com issue URLs."""

    if not isinstance(url, str) or not url or url != url.strip() or not url.isascii():
        raise PolicyRejection("invalid_issue_url", "Issue URL must be canonical ASCII HTTPS")
    if "\\" in url:
        raise PolicyRejection("invalid_issue_url", "Issue URL contains an invalid separator")

    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise PolicyRejection("invalid_issue_url", "Issue URL is malformed") from exc

    if (
        parsed.scheme != "https"
        or parsed.netloc != GITHUB_WEB_HOST
        or parsed.hostname != GITHUB_WEB_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise PolicyRejection(
            "invalid_issue_url", "Only canonical https://github.com/.../issues/... URLs are allowed"
        )

    match = _ISSUE_PATH_RE.fullmatch(parsed.path)
    if match is None:
        raise PolicyRejection("invalid_issue_url", "Issue URL path is not canonical")

    owner = match.group("owner")
    repo = match.group("repo")
    _validate_repository_parts(owner, repo)
    number = int(match.group("number"))
    if number > 2**63 - 1:
        raise PolicyRejection("invalid_issue_url", "Issue number is outside the supported range")

    canonical = f"https://{GITHUB_WEB_HOST}/{owner}/{repo}/issues/{number}"
    if url != canonical:
        raise PolicyRejection("invalid_issue_url", "Issue URL is not canonical")
    return GitHubIssueLocation(url=canonical, owner=owner, repo=repo, number=number)


def parse_github_issue_url(url: str) -> GitHubIssueLocation:
    return parse_issue_url(url)


def fetch_issue(
    url: str, *, timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS
) -> IssueDocument:
    location = parse_issue_url(url)
    api_url = (
        f"https://{GITHUB_API_HOST}/repos/{location.owner}/{location.repo}/issues/{location.number}"
    )
    payload = _fetch_json(
        api_url,
        expected_host=GITHUB_API_HOST,
        max_bytes=MAX_ISSUE_JSON_BYTES,
        timeout_seconds=timeout_seconds,
    )

    if "pull_request" in payload:
        raise PolicyRejection("not_an_issue", "The supplied URL identifies a pull request")
    if payload.get("number") != location.number:
        raise PolicyRejection(
            "github_response_mismatch", "GitHub returned a different issue number"
        )

    title = payload.get("title")
    body_value = payload.get("body")
    if not isinstance(title, str) or not (isinstance(body_value, str) or body_value is None):
        raise PolicyRejection("invalid_github_response", "GitHub issue fields have invalid types")
    body = body_value or ""
    if len(title.encode("utf-8")) > MAX_ISSUE_TITLE_BYTES:
        raise PolicyRejection(
            "issue_title_too_large", "GitHub issue title exceeds the safety limit"
        )
    if len(body.encode("utf-8")) > MAX_ISSUE_BODY_BYTES:
        raise PolicyRejection("issue_body_too_large", "GitHub issue body exceeds the safety limit")

    return IssueDocument(
        ref=IssueRef(
            url=location.url,
            owner=location.owner,
            repo=location.repo,
            number=location.number,
            title=title,
            body_sha256=sha256_text(body),
        ),
        body=body,
    )


def resolve_commit_sha(
    owner: str,
    repo: str,
    requested_ref: str = "HEAD",
    *,
    timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> str:
    """Resolve a GitHub ref through the fixed API endpoint to a full SHA-1."""

    _validate_repository_parts(owner, repo)
    _validate_requested_ref(requested_ref)
    encoded_ref = urllib.parse.quote(requested_ref, safe="")
    api_url = f"https://{GITHUB_API_HOST}/repos/{owner}/{repo}/commits/{encoded_ref}"
    payload = _fetch_json(
        api_url,
        expected_host=GITHUB_API_HOST,
        max_bytes=MAX_COMMIT_JSON_BYTES,
        timeout_seconds=timeout_seconds,
    )
    sha = payload.get("sha")
    if not isinstance(sha, str) or _FULL_SHA_RE.fullmatch(sha) is None:
        raise PolicyRejection("invalid_commit_sha", "GitHub did not return a full 40-hex SHA")
    return sha.lower()


def resolve_full_commit_sha(
    owner: str,
    repo: str,
    requested_ref: str = "HEAD",
    *,
    timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> str:
    return resolve_commit_sha(owner, repo, requested_ref, timeout_seconds=timeout_seconds)


def download_source_archive(
    owner: str,
    repo: str,
    sha: str,
    run_dir: Path,
    *,
    max_bytes: int = MAX_ARCHIVE_BYTES,
    timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> ArchiveDownload:
    """Stream a pinned GitHub source archive into a new private-run file."""

    _validate_repository_parts(owner, repo)
    normalized_sha = _validate_full_sha(sha)
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    private_dir = Path(run_dir)
    require_private_directory(private_dir)
    destination = private_dir / "source.tar.gz"
    archive_url = f"https://{GITHUB_CODELOAD_HOST}/{owner}/{repo}/tar.gz/{normalized_sha}"

    created = False
    try:
        with _open_https(
            archive_url,
            expected_host=GITHUB_CODELOAD_HOST,
            timeout_seconds=timeout_seconds,
        ) as response:
            _reject_oversized_content_length(response, max_bytes)
            digest = hashlib.sha256()
            total = 0
            magic = b""
            with open_exclusive_file(destination) as output:
                created = True
                while True:
                    chunk = response.read(min(64 * 1024, max_bytes - total + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise PolicyRejection(
                            "archive_too_large", "Source archive exceeds the compressed-byte limit"
                        )
                    if len(magic) < 2:
                        magic = (magic + chunk)[:2]
                    digest.update(chunk)
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())

        if magic != b"\x1f\x8b":
            raise PolicyRejection("invalid_archive", "Source response is not a gzip archive")
        return ArchiveDownload(path=destination, sha256=digest.hexdigest(), size_bytes=total)
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def extract_source_archive(
    archive_path: Path,
    run_dir: Path,
    *,
    limits: ExtractionLimits | None = None,
) -> ExtractedArchive:
    """Manually extract regular files from a bounded tar.gz into a private run directory."""

    active_limits = limits or ExtractionLimits()
    private_dir = Path(run_dir)
    require_private_directory(private_dir)
    destination = private_dir / "source"
    try:
        destination.mkdir(mode=0o700)
        os.chmod(destination, 0o700, follow_symlinks=False)
    except FileExistsError as exc:
        raise PolicyRejection(
            "output_exists", f"Refusing to reuse source extraction directory: {destination}"
        ) from exc

    succeeded = False
    try:
        result = _extract_archive(Path(archive_path), destination, active_limits)
        succeeded = True
        return result
    except PolicyRejection:
        raise
    except (gzip.BadGzipFile, tarfile.TarError, EOFError, UnicodeError, OSError) as exc:
        raise PolicyRejection(
            "invalid_archive", "Source archive is malformed or unreadable"
        ) from exc
    finally:
        if not succeeded:
            shutil.rmtree(destination, ignore_errors=True)


def extract_tar_gz(
    archive_path: Path,
    run_dir: Path,
    *,
    limits: ExtractionLimits | None = None,
) -> ExtractedArchive:
    return extract_source_archive(archive_path, run_dir, limits=limits)


def _extract_archive(
    archive_path: Path, destination: Path, limits: ExtractionLimits
) -> ExtractedArchive:
    member_count = 0
    file_count = 0
    unpacked_bytes = 0
    seen_members: set[str] = set()
    path_kinds: dict[str, str] = {}
    canonical_paths: dict[str, str] = {}
    top_levels: set[str] = set()

    max_tar_bytes = limits.max_unpacked_bytes + limits.max_files * 4096 + 1024 * 1024
    with open_regular_file(archive_path) as compressed_stream:
        if os.fstat(compressed_stream.fileno()).st_size > limits.max_archive_bytes:
            raise PolicyRejection(
                "archive_too_large", "Source archive exceeds the compressed-byte limit"
            )
        with gzip.GzipFile(fileobj=compressed_stream, mode="rb") as gzip_stream:
            bounded_stream = _BoundedReader(cast(IO[bytes], gzip_stream), max_bytes=max_tar_bytes)
            with tarfile.open(fileobj=cast(BinaryIO, bounded_stream), mode="r|") as archive:
                for member in archive:
                    member_count += 1
                    if member_count > limits.max_files:
                        raise PolicyRejection(
                            "archive_too_many_files", "Source archive contains too many members"
                        )

                    is_directory = member.isdir()
                    if not (is_directory or member.isreg()):
                        raise PolicyRejection(
                            "archive_special_file",
                            f"Source archive contains a non-regular member: {member.name!r}",
                        )

                    parts = _validate_member_path(member.name, limits)
                    relative_path = "/".join(parts)
                    top_levels.add(parts[0])
                    _register_member_path(
                        parts,
                        is_directory=is_directory,
                        seen_members=seen_members,
                        path_kinds=path_kinds,
                        canonical_paths=canonical_paths,
                    )

                    target = destination.joinpath(*parts)
                    if is_directory:
                        target.mkdir(mode=0o700, parents=True, exist_ok=True)
                        os.chmod(target, 0o700, follow_symlinks=False)
                        continue

                    if member.size < 0:
                        raise PolicyRejection(
                            "invalid_archive",
                            f"Archive member has a negative size: {relative_path}",
                        )
                    unpacked_bytes += member.size
                    if unpacked_bytes > limits.max_unpacked_bytes:
                        raise PolicyRejection(
                            "archive_too_large", "Source archive exceeds the unpacked-byte limit"
                        )

                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    _chmod_parent_chain(target.parent, destination)
                    source = archive.extractfile(member)
                    if source is None:
                        raise PolicyRejection(
                            "invalid_archive", f"Unable to read archive member: {relative_path}"
                        )
                    with source, open_exclusive_file(target) as output:
                        _copy_exact(cast(BinaryIO, source), output, member.size, relative_path)
                    safe_mode = 0o700 if member.mode & 0o111 else 0o600
                    os.chmod(target, safe_mode, follow_symlinks=False)
                    file_count += 1

    source_root = destination
    if len(top_levels) == 1:
        candidate = destination / next(iter(top_levels))
        if candidate.is_dir() and not candidate.is_symlink():
            source_root = candidate
    return ExtractedArchive(
        destination=destination,
        source_root=source_root,
        member_count=member_count,
        file_count=file_count,
        unpacked_bytes=unpacked_bytes,
    )


def _validate_repository_parts(owner: str, repo: str) -> None:
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


def _validate_requested_ref(requested_ref: str) -> None:
    if not isinstance(requested_ref, str) or not requested_ref or not requested_ref.isascii():
        raise PolicyRejection("invalid_commit_ref", "Commit ref must be non-empty ASCII")
    if len(requested_ref.encode("ascii")) > 256:
        raise PolicyRejection("invalid_commit_ref", "Commit ref exceeds the safety limit")
    if requested_ref == "HEAD":
        return
    if (
        any(
            character in _DISALLOWED_REF_CHARACTERS or ord(character) < 32
            for character in requested_ref
        )
        or ".." in requested_ref
        or "@{" in requested_ref
        or "//" in requested_ref
        or requested_ref.startswith(("/", "."))
        or requested_ref.endswith(("/", ".", ".lock"))
        or any(part in {"", ".", ".."} for part in requested_ref.split("/"))
    ):
        raise PolicyRejection("invalid_commit_ref", "Commit ref is not a safe Git reference")


def _validate_full_sha(sha: str) -> str:
    if not isinstance(sha, str) or _FULL_SHA_RE.fullmatch(sha) is None:
        raise PolicyRejection("invalid_commit_sha", "Commit SHA must contain exactly 40 hex digits")
    return sha.lower()


def _validate_member_path(name: str, limits: ExtractionLimits) -> tuple[str, ...]:
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise PolicyRejection("archive_unsafe_path", f"Archive member path is unsafe: {name!r}")
    normalized_name = name[:-1] if name.endswith("/") else name
    if not normalized_name or normalized_name.endswith("/"):
        raise PolicyRejection("archive_unsafe_path", f"Archive member path is unsafe: {name!r}")
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in normalized_name):
        raise PolicyRejection("archive_unsafe_path", f"Archive member path is unsafe: {name!r}")
    parts = tuple(normalized_name.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise PolicyRejection("archive_unsafe_path", f"Archive member path is unsafe: {name!r}")
    if re.fullmatch(r"[A-Za-z]:.*", parts[0]):
        raise PolicyRejection("archive_unsafe_path", f"Archive member path is unsafe: {name!r}")

    try:
        encoded_path = normalized_name.encode("utf-8")
        encoded_parts = [part.encode("utf-8") for part in parts]
    except UnicodeError as exc:
        raise PolicyRejection("archive_unsafe_path", "Archive path is not valid UTF-8") from exc
    if len(encoded_path) > limits.max_path_bytes or any(
        len(part) > limits.max_component_bytes for part in encoded_parts
    ):
        raise PolicyRejection("archive_path_too_long", f"Archive member path is too long: {name!r}")
    return parts


def _register_member_path(
    parts: tuple[str, ...],
    *,
    is_directory: bool,
    seen_members: set[str],
    path_kinds: dict[str, str],
    canonical_paths: dict[str, str],
) -> None:
    full_path = "/".join(parts)
    if full_path in seen_members:
        raise PolicyRejection("archive_path_collision", f"Duplicate archive path: {full_path}")

    for index in range(1, len(parts) + 1):
        actual = "/".join(parts[:index])
        canonical = "/".join(
            unicodedata.normalize("NFC", part).casefold() for part in parts[:index]
        )
        previous = canonical_paths.get(canonical)
        if previous is not None and previous != actual:
            raise PolicyRejection(
                "archive_case_collision",
                f"Archive paths collide by case or normalization: {actual}",
            )
        canonical_paths.setdefault(canonical, actual)

        if index < len(parts):
            if path_kinds.get(actual) == "file":
                raise PolicyRejection(
                    "archive_path_collision", f"Archive file shadows a directory: {actual}"
                )
            path_kinds.setdefault(actual, "directory")

    existing_kind = path_kinds.get(full_path)
    if is_directory:
        if existing_kind == "file":
            raise PolicyRejection(
                "archive_path_collision", f"Archive path changes type: {full_path}"
            )
        path_kinds[full_path] = "directory"
    else:
        if existing_kind is not None:
            raise PolicyRejection(
                "archive_path_collision", f"Archive file collides with a directory: {full_path}"
            )
        path_kinds[full_path] = "file"
    seen_members.add(full_path)


def _chmod_parent_chain(parent: Path, root: Path) -> None:
    current = parent
    while current != root:
        os.chmod(current, 0o700, follow_symlinks=False)
        current = current.parent


def _copy_exact(source: BinaryIO, output: BinaryIO, size: int, relative_path: str) -> None:
    remaining = size
    while remaining:
        chunk = source.read(min(64 * 1024, remaining))
        if not chunk:
            raise PolicyRejection("invalid_archive", f"Archive member ended early: {relative_path}")
        output.write(chunk)
        remaining -= len(chunk)


class _BoundedReader:
    def __init__(self, stream: IO[bytes], *, max_bytes: int) -> None:
        self._stream = stream
        self._max_bytes = max_bytes
        self._bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self._max_bytes - self._bytes_read
        if remaining < 0:
            raise PolicyRejection("archive_too_large", "Archive stream exceeds its safety limit")
        requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self._stream.read(requested)
        self._bytes_read += len(data)
        if self._bytes_read > self._max_bytes:
            raise PolicyRejection("archive_too_large", "Archive stream exceeds its safety limit")
        return data


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        fp.close()
        raise PolicyRejection("github_redirect_rejected", "GitHub response attempted a redirect")


def _build_opener() -> urllib.request.OpenerDirector:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    verify_paths = ssl.get_default_verify_paths()
    cafile = verify_paths.openssl_cafile if os.path.isfile(verify_paths.openssl_cafile) else None
    capath = verify_paths.openssl_capath if os.path.isdir(verify_paths.openssl_capath) else None
    if cafile is None and capath is None:
        raise ReproAssertError("tls_trust_unavailable", "No system TLS trust store is available")
    context.load_verify_locations(cafile=cafile, capath=capath)
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _RejectRedirectHandler(),
    )


def _open_https(url: str, *, expected_host: str, timeout_seconds: float) -> Any:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    _validate_fixed_https_url(url, expected_host=expected_host)
    request = urllib.request.Request(  # noqa: S310
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "reproassert/0.1",
        },
        method="GET",
    )
    try:
        response = _build_opener().open(request, timeout=timeout_seconds)
    except PolicyRejection:
        raise
    except urllib.error.HTTPError as exc:
        raise ReproAssertError("github_http_error", f"GitHub returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ReproAssertError("github_unavailable", "Unable to fetch bounded GitHub data") from exc

    response_url = response.geturl()
    try:
        _validate_fixed_https_url(response_url, expected_host=expected_host)
        if response_url != url:
            raise PolicyRejection("github_redirect_rejected", "GitHub response URL changed")
    except BaseException:
        response.close()
        raise
    return response


def _fetch_json(
    url: str, *, expected_host: str, max_bytes: int, timeout_seconds: float
) -> dict[str, Any]:
    with _open_https(url, expected_host=expected_host, timeout_seconds=timeout_seconds) as response:
        _reject_oversized_content_length(response, max_bytes)
        content = _read_bounded(response, max_bytes=max_bytes, code="github_json_too_large")
    try:
        payload = json.loads(content, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise PolicyRejection("invalid_github_response", "GitHub returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise PolicyRejection("invalid_github_response", "GitHub JSON root must be an object")
    return payload


def _read_bounded(response: Any, *, max_bytes: int, code: str) -> bytes:
    content = bytearray()
    while True:
        chunk = response.read(min(64 * 1024, max_bytes - len(content) + 1))
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > max_bytes:
            raise PolicyRejection(code, "GitHub response exceeds the byte limit")
    return bytes(content)


def _reject_oversized_content_length(response: Any, max_bytes: int) -> None:
    value = response.headers.get("Content-Length")
    if value is None:
        return
    try:
        length = int(value)
    except ValueError as exc:
        raise PolicyRejection(
            "invalid_github_response", "GitHub sent an invalid Content-Length"
        ) from exc
    if length < 0:
        raise PolicyRejection("invalid_github_response", "GitHub sent a negative Content-Length")
    if length > max_bytes:
        raise PolicyRejection("github_response_too_large", "GitHub response exceeds the byte limit")


def _validate_fixed_https_url(url: str, *, expected_host: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise PolicyRejection("unsafe_github_endpoint", "GitHub endpoint is malformed") from exc
    if (
        parsed.scheme != "https"
        or parsed.netloc != expected_host
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
    ):
        raise PolicyRejection("unsafe_github_endpoint", "GitHub endpoint escaped its fixed host")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"Non-standard JSON constant: {value}")
