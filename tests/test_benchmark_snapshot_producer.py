from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

import pytest

from reproassert import __version__
from reproassert.benchmark_snapshot import canonicalize_snapshot_receipt
from reproassert.benchmark_snapshot_producer import (
    GRAPHQL_API_VERSION,
    GRAPHQL_CAPTURE_FORMAT,
    ISSUE_HISTORY_QUERY_SHA256,
    PRIVATE_CHRONOLOGY_REASON,
    REDACTION_POLICY_SHA256,
    SOLUTION_CUTOFF_QUERY_SHA256,
    SnapshotIdentity,
    SnapshotPrivacyReview,
    SnapshotProducerMetadata,
    derive_snapshot,
    produce_snapshot_receipt,
)
from reproassert.errors import PolicyRejection

REPOSITORY = "owner/repo"
ISSUE_URL = "https://github.com/owner/repo/issues/7"
CASE_ID = "rk-v0.2-004"
BASE_SHA = "a" * 40
FIX_URL = "https://github.com/owner/repo/pull/9"

CREATED_AT = "2024-01-01T00:00:00Z"
PRE_TITLE_AT = "2024-01-15T00:00:00Z"
PRE_BODY_AT = "2024-02-01T00:00:00Z"
CUTOFF_AT = "2024-03-01T00:00:00Z"
POST_AT = "2024-04-01T00:00:00Z"

INITIAL_TITLE = "Initial duplicate separator report"
SELECTED_TITLE = "Duplicate separators survive normalization"
CURRENT_TITLE = "Resolved duplicate separator report"
INITIAL_BODY = "Calling normalize('a--b') keeps two separators."
SELECTED_BODY = (
    "Reproduces with normalize('a--b'). Fix discussion: #9 and "
    "https://github.com/owner/repo/pull/9. "
    "Unrelated context: https://github.com/owner/repo/pull/8.\r\n"
)
CURRENT_BODY = "Post-publication text names implementation details and must stay evaluator-only."


def _page(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "totalCount": len(nodes),
        "pageInfo": {
            "hasNextPage": False,
            "hasPreviousPage": False,
            "startCursor": "start" if nodes else None,
            "endCursor": "end" if nodes else None,
        },
        "nodes": nodes,
    }


def _issue_artifact() -> dict[str, Any]:
    body_nodes = [
        {
            "id": "body-current",
            "createdAt": POST_AT,
            "editedAt": POST_AT,
            "deletedAt": None,
            "diff": CURRENT_BODY,
        },
        {
            "id": "body-pre-cutoff",
            "createdAt": PRE_BODY_AT,
            "editedAt": PRE_BODY_AT,
            "deletedAt": None,
            "diff": SELECTED_BODY,
        },
        {
            # GitHub may materialize the creation-history record at the first later edit.
            "id": "body-creation",
            "createdAt": PRE_BODY_AT,
            "editedAt": CREATED_AT,
            "deletedAt": None,
            "diff": INITIAL_BODY,
        },
    ]
    title_nodes = [
        {
            "__typename": "RenamedTitleEvent",
            "id": "title-current",
            "createdAt": POST_AT,
            "previousTitle": SELECTED_TITLE,
            "currentTitle": CURRENT_TITLE,
        },
        {
            "__typename": "RenamedTitleEvent",
            "id": "title-pre-cutoff",
            "createdAt": PRE_TITLE_AT,
            "previousTitle": INITIAL_TITLE,
            "currentTitle": SELECTED_TITLE,
        },
    ]
    return {
        "format": GRAPHQL_CAPTURE_FORMAT,
        "query_sha256": ISSUE_HISTORY_QUERY_SHA256,
        "response": {
            "data": {
                "repository": {
                    "nameWithOwner": REPOSITORY,
                    "issue": {
                        "number": 7,
                        "url": ISSUE_URL,
                        "title": CURRENT_TITLE,
                        "body": CURRENT_BODY,
                        "createdAt": CREATED_AT,
                        "lastEditedAt": POST_AT,
                        "includesCreatedEdit": True,
                        "userContentEdits": _page(body_nodes),
                        "timelineItems": _page(title_nodes),
                    },
                }
            }
        },
    }


def _cutoff_artifact() -> dict[str, Any]:
    return {
        "format": GRAPHQL_CAPTURE_FORMAT,
        "query_sha256": SOLUTION_CUTOFF_QUERY_SHA256,
        "response": {
            "data": {
                "repository": {
                    "nameWithOwner": REPOSITORY,
                    "pullRequest": {
                        "number": 9,
                        "url": FIX_URL,
                        "createdAt": "2024-02-25T00:00:00Z",
                        "publishedAt": CUTOFF_AT,
                        "mergedAt": "2024-03-02T00:00:00Z",
                        "isDraft": False,
                        "baseRepository": {"nameWithOwner": REPOSITORY},
                    },
                }
            }
        },
    }


def _encoded(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _produce(
    issue_artifact: dict[str, Any] | None = None,
    cutoff_artifact: dict[str, Any] | None = None,
) -> tuple[dict[str, object], bytes, bytes]:
    raw = _encoded(issue_artifact or _issue_artifact())
    cutoff = _encoded(cutoff_artifact or _cutoff_artifact())
    receipt = produce_snapshot_receipt(
        identity=SnapshotIdentity(
            case_id=CASE_ID,
            repository=REPOSITORY,
            issue_url=ISSUE_URL,
            base_sha=BASE_SHA,
        ),
        raw_issue_evidence_bytes=raw,
        cutoff_basis_bytes=cutoff,
        producer=SnapshotProducerMetadata(
            captured_at="2026-07-10T12:00:00Z",
            tool_git_sha="b" * 40,
        ),
        privacy_review=SnapshotPrivacyReview(
            reviewed_at="2026-07-10T13:00:00Z",
            reviewer_id="reviewer-001",
            checklist_sha256="c" * 64,
        ),
    )
    return receipt, raw, cutoff


def _project(receipt: dict[str, object], raw: bytes, cutoff: bytes) -> dict[str, str]:
    return canonicalize_snapshot_receipt(
        receipt,
        raw_receipt_bytes=raw,
        cutoff_basis_bytes=cutoff,
        expected_case_id=CASE_ID,
        expected_repo=REPOSITORY,
        expected_issue_url=ISSUE_URL,
        expected_base_sha=BASE_SHA,
    )


def test_offline_producer_rederives_pre_publication_revision_and_projects_only_safe_fields() -> (
    None
):
    receipt, raw, cutoff = _produce()

    projection = _project(receipt, raw, cutoff)

    expected_body = (
        "Reproduces with normalize('a--b'). Fix discussion: [fix reference removed] and "
        "[fix reference removed]. Unrelated context: "
        "https://github.com/owner/repo/pull/8.\n"
    )
    assert projection == {
        "title": SELECTED_TITLE,
        "body": expected_body,
        "snapshot_sha256": receipt["content"]["snapshot_sha256"],  # type: ignore[index]
    }
    assert CURRENT_TITLE not in json.dumps(projection)
    assert CURRENT_BODY not in json.dumps(projection)
    assert FIX_URL not in json.dumps(projection)
    assert "pull/8" in projection["body"]
    assert set(projection) == {"title", "body", "snapshot_sha256"}


def test_receipt_commits_query_provenance_chronology_redaction_and_human_review() -> None:
    receipt, raw, cutoff = _produce()

    assert receipt["capture"] == {
        "captured_at": "2026-07-10T12:00:00Z",
        "source": "trusted_local_receipt",
        "api": {
            "kind": "github_graphql",
            "version": GRAPHQL_API_VERSION,
            "request_sha256": ISSUE_HISTORY_QUERY_SHA256,
        },
        "tool": {
            "name": "reproassert-snapshot-producer",
            "version": __version__,
            "git_sha": "b" * 40,
        },
        "raw_receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_receipt_bytes": len(raw),
    }
    assert receipt["cutoff"] == {
        "policy": "pre_solution_pr_publication",
        "timestamp": CUTOFF_AT,
        "publication_proven": True,
        "basis_sha256": hashlib.sha256(cutoff).hexdigest(),
        "basis_bytes": len(cutoff),
    }
    assert receipt["temporal_provenance"] == {
        "status": "pre_fix_chronology_unproven",
        "issue_created_at": CREATED_AT,
        "selected_revision_at": PRE_BODY_AT,
        "reason": PRIVATE_CHRONOLOGY_REASON,
    }
    redaction = receipt["redaction"]
    assert isinstance(redaction, dict)
    assert redaction["policy_sha256"] == REDACTION_POLICY_SHA256
    assert redaction["count"] == 2
    assert redaction["pre_redaction_sha256"] != redaction["post_redaction_sha256"]
    assert receipt["privacy_review"] == {
        "status": "approved",
        "reviewed_at": "2026-07-10T13:00:00Z",
        "reviewer_id": "reviewer-001",
        "checklist_sha256": "c" * 64,
        "sensitive_material_excluded": True,
    }


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_query",
        "wrong_repository",
        "wrong_issue",
        "creation_flag_false",
        "body_next_page",
        "body_previous_page",
        "body_count_drift",
        "body_wrong_order",
        "creation_missing",
        "creation_wrong_time",
        "deleted_body_edit",
        "null_body_revision",
        "duplicate_body_id",
        "current_body_mismatch",
        "last_edited_mismatch",
        "title_next_page",
        "title_count_drift",
        "title_ambiguous_timestamp",
        "title_chain_break",
        "duplicate_title_id",
    ],
)
def test_incomplete_or_inconsistent_github_history_fails_closed(mutation: str) -> None:
    artifact = _issue_artifact()
    repository = artifact["response"]["data"]["repository"]
    issue = repository["issue"]
    body = issue["userContentEdits"]
    titles = issue["timelineItems"]
    if mutation == "wrong_query":
        artifact["query_sha256"] = "0" * 64
    elif mutation == "wrong_repository":
        repository["nameWithOwner"] = "other/repo"
    elif mutation == "wrong_issue":
        issue["number"] = 8
    elif mutation == "creation_flag_false":
        issue["includesCreatedEdit"] = False
    elif mutation == "body_next_page":
        body["pageInfo"]["hasNextPage"] = True
    elif mutation == "body_previous_page":
        body["pageInfo"]["hasPreviousPage"] = True
    elif mutation == "body_count_drift":
        body["totalCount"] += 1
    elif mutation == "body_wrong_order":
        body["nodes"][0], body["nodes"][1] = body["nodes"][1], body["nodes"][0]
    elif mutation == "creation_missing":
        body["nodes"].pop()
        body["totalCount"] -= 1
    elif mutation == "creation_wrong_time":
        body["nodes"][-1]["editedAt"] = "2024-01-02T00:00:00Z"
    elif mutation == "deleted_body_edit":
        body["nodes"][1]["deletedAt"] = "2024-02-02T00:00:00Z"
    elif mutation == "null_body_revision":
        body["nodes"][1]["diff"] = None
    elif mutation == "duplicate_body_id":
        body["nodes"][1]["id"] = body["nodes"][0]["id"]
    elif mutation == "current_body_mismatch":
        issue["body"] = "different current body"
    elif mutation == "last_edited_mismatch":
        issue["lastEditedAt"] = PRE_BODY_AT
    elif mutation == "title_next_page":
        titles["pageInfo"]["hasNextPage"] = True
    elif mutation == "title_count_drift":
        titles["totalCount"] += 1
    elif mutation == "title_ambiguous_timestamp":
        titles["nodes"][1]["createdAt"] = titles["nodes"][0]["createdAt"]
    elif mutation == "title_chain_break":
        titles["nodes"][1]["currentTitle"] = "unrelated title"
    else:
        titles["nodes"][1]["id"] = titles["nodes"][0]["id"]

    with pytest.raises(PolicyRejection) as caught:
        _produce(issue_artifact=artifact)
    assert caught.value.code == "benchmark_snapshot_evidence"


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_query",
        "wrong_repository",
        "wrong_url",
        "wrong_base_repository",
        "draft",
        "unpublished",
        "unmerged",
        "merge_before_publication",
        "cutoff_before_issue",
    ],
)
def test_untrusted_or_ambiguous_solution_publication_basis_fails_closed(mutation: str) -> None:
    artifact = _cutoff_artifact()
    repository = artifact["response"]["data"]["repository"]
    pull = repository["pullRequest"]
    if mutation == "wrong_query":
        artifact["query_sha256"] = "0" * 64
    elif mutation == "wrong_repository":
        repository["nameWithOwner"] = "other/repo"
    elif mutation == "wrong_url":
        pull["url"] = "https://github.com/owner/repo/pull/10"
    elif mutation == "wrong_base_repository":
        pull["baseRepository"]["nameWithOwner"] = "other/repo"
    elif mutation == "draft":
        pull["isDraft"] = True
    elif mutation == "unpublished":
        pull["publishedAt"] = None
    elif mutation == "unmerged":
        pull["mergedAt"] = None
    elif mutation == "merge_before_publication":
        pull["mergedAt"] = "2024-02-01T00:00:00Z"
    else:
        pull["createdAt"] = pull["publishedAt"] = "2023-12-31T00:00:00Z"

    with pytest.raises(PolicyRejection) as caught:
        _produce(cutoff_artifact=artifact)
    assert caught.value.code == "benchmark_snapshot_evidence"


def test_coherently_rehashed_receipt_tampering_is_caught_by_independent_rederivation() -> None:
    receipt, raw, cutoff = _produce()
    tampered = copy.deepcopy(receipt)
    content = tampered["content"]
    redaction = tampered["redaction"]
    selected = tampered["selected_revision"]
    assert isinstance(content, dict)
    assert isinstance(redaction, dict)
    assert isinstance(selected, dict)
    body = "A plausible but invented historical issue body."
    title = str(content["title"])
    canonical = json.dumps(
        {"body": body, "title": title}, sort_keys=True, separators=(",", ":")
    ).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    content.update(
        body=body,
        body_bytes=len(body.encode()),
        body_sha256=hashlib.sha256(body.encode()).hexdigest(),
        canonical_bytes=len(canonical),
        snapshot_sha256=digest,
    )
    selected["revision_sha256"] = digest
    redaction.update(
        count=0,
        pre_redaction_sha256=digest,
        post_redaction_sha256=digest,
    )

    with pytest.raises(PolicyRejection) as caught:
        _project(tampered, raw, cutoff)
    assert caught.value.code == "benchmark_snapshot_evidence"


def test_exact_cutoff_excludes_same_timestamp_edits() -> None:
    artifact = _issue_artifact()
    issue = artifact["response"]["data"]["repository"]["issue"]
    issue["userContentEdits"]["nodes"][1]["editedAt"] = CUTOFF_AT
    issue["userContentEdits"]["nodes"][1]["createdAt"] = CUTOFF_AT

    raw = _encoded(artifact)
    cutoff = _encoded(_cutoff_artifact())
    derived = derive_snapshot(
        raw_issue_evidence_bytes=raw,
        cutoff_basis_bytes=cutoff,
        expected_repository=REPOSITORY,
        expected_issue_url=ISSUE_URL,
        expected_issue_number=7,
    )

    assert derived.selected_body == INITIAL_BODY
    assert derived.selected_at == PRE_TITLE_AT


def test_empty_title_history_is_complete_and_uses_current_title_as_creation_title() -> None:
    artifact = _issue_artifact()
    issue = artifact["response"]["data"]["repository"]["issue"]
    issue["title"] = INITIAL_TITLE
    issue["timelineItems"] = _page([])

    receipt, raw, cutoff = _produce(issue_artifact=artifact)

    assert _project(receipt, raw, cutoff)["title"] == INITIAL_TITLE


def test_title_history_order_is_derived_from_timestamps_not_connection_order() -> None:
    newest_first = _issue_artifact()
    oldest_first = copy.deepcopy(newest_first)
    titles = oldest_first["response"]["data"]["repository"]["issue"]["timelineItems"]["nodes"]
    titles.reverse()

    first, _, _ = _produce(issue_artifact=newest_first)
    second, _, _ = _produce(issue_artifact=oldest_first)

    assert first["selected_revision"] == second["selected_revision"]
    assert first["content"] == second["content"]


def test_draft_then_published_solution_uses_publication_not_creation_as_cutoff() -> None:
    artifact = _cutoff_artifact()
    pull = artifact["response"]["data"]["repository"]["pullRequest"]
    pull["createdAt"] = "2024-01-20T00:00:00Z"
    pull["publishedAt"] = CUTOFF_AT

    receipt, _, _ = _produce(cutoff_artifact=artifact)

    assert receipt["cutoff"]["timestamp"] == CUTOFF_AT  # type: ignore[index]


def test_duplicate_json_keys_and_noncanonical_shapes_fail_closed() -> None:
    cutoff = _encoded(_cutoff_artifact())
    with pytest.raises(PolicyRejection) as duplicate:
        derive_snapshot(
            raw_issue_evidence_bytes=b'{"format":"a","format":"b"}',
            cutoff_basis_bytes=cutoff,
            expected_repository=REPOSITORY,
            expected_issue_url=ISSUE_URL,
            expected_issue_number=7,
        )
    assert duplicate.value.code == "benchmark_snapshot_evidence"

    artifact = _issue_artifact()
    artifact["live_fallback"] = True
    with pytest.raises(PolicyRejection) as extra:
        _produce(issue_artifact=artifact)
    assert extra.value.code == "benchmark_snapshot_evidence"
