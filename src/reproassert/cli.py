from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any, TypeVar

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reproassert import __version__
from reproassert.benchmark_object_source import (
    prepare_object_source_case,
    verify_object_source_receipt,
)
from reproassert.benchmark_snapshot_producer import (
    SnapshotIdentity,
    SnapshotPrivacyReview,
    SnapshotProducerMetadata,
    produce_snapshot_receipt_file,
)
from reproassert.benchmark_source import (
    SOURCE_INDEX_FILENAME,
    SOURCE_RECEIPT_FILENAME,
    build_source_index,
    load_frozen_manifest,
    prepare_source_case,
    verify_source_receipt,
)
from reproassert.benchmark_v02_campaign import (
    finalize_v02_campaign,
    prepare_v02_campaign_freeze,
    seal_v02_causal_control_set,
    seal_v02_semantic_review_set,
    verify_v02_campaign_bundle,
    verify_v02_campaign_freeze,
    verify_v02_causal_control_set,
    verify_v02_semantic_review_set,
)
from reproassert.benchmark_v02_candidate_evaluator import CandidateArtifact
from reproassert.benchmark_v02_cases import prepare_v02_cases, verify_v02_cases
from reproassert.benchmark_v02_chronology import (
    capture_v02_public_issue_responses,
    prepare_v02_chronology_evidence,
    verify_v02_chronology_evidence,
)
from reproassert.benchmark_v02_exact_campaign_config import (
    ExactCampaignConfigInputs,
    prepare_v02_exact_campaign_config,
    verify_v02_exact_campaign_config,
)
from reproassert.benchmark_v02_exact_campaign_controller import run_v02_exact_campaign
from reproassert.benchmark_v02_exact_capability import (
    issue_verified_v02_exact_image_evaluator_capability,
    prepare_v02_exact_image_capability_index,
    verify_v02_exact_image_capability_index,
)
from reproassert.benchmark_v02_exact_controls import (
    run_exact_image_causal_controls,
    verify_exact_image_causal_control_receipt,
)
from reproassert.benchmark_v02_exact_preregistration import (
    prepare_v02_exact_preregistration,
    verify_v02_exact_preregistration,
)
from reproassert.benchmark_v02_execution_freeze import (
    authorize_v02_exact_image_execution,
    exact_approval_statement,
    prepare_v02_exact_image_execution_freeze,
    verify_v02_exact_image_execution_freeze,
)
from reproassert.benchmark_v02_hidden import prepare_v02_hidden_gold, verify_v02_hidden_gold
from reproassert.benchmark_v02_instance_controller import (
    run_instance_gold_smoke,
    verify_instance_gold_smoke_receipt,
)
from reproassert.benchmark_v02_mapping_handoff import (
    prepare_v02_mapping_review_handoff,
    verify_v02_mapping_review_handoff,
)
from reproassert.benchmark_v02_mapping_packets import (
    prepare_v02_mapping_packets,
    seal_v02_mapping_consensus,
    verify_v02_mapping_consensus,
    verify_v02_mapping_packets,
)
from reproassert.benchmark_v02_object_source import (
    prepare_v02_object_source_case,
    verify_v02_object_source_receipt,
)
from reproassert.benchmark_v02_parser_image import install_v02_parser_image
from reproassert.benchmark_v02_preparation import (
    FROZEN_V02_DATASET_PARSER_IMAGE_ID,
    prepare_v02_dataset_inputs,
    verify_v02_dataset_preparation,
)
from reproassert.benchmark_v02_replay import run_v02_replay_bundle
from reproassert.dependency_execution_receipt import load_dependency_execution_receipt
from reproassert.errors import ReproAssertError
from reproassert.generator import (
    DEFAULT_OPENAI_MODEL,
    CandidateGenerator,
    CommandGenerator,
    OpenAIResponsesGenerator,
    StaticGenerator,
)
from reproassert.intake import parse_issue_url
from reproassert.isolation_canary import IsolationCanaryResult, run_isolation_canary
from reproassert.safeio import require_private_directory, sanitize_log
from reproassert.sandbox import DEFAULT_IMAGE, DockerSandbox, SandboxPolicy
from reproassert.schema import SCHEMA_FILENAMES, schema_text
from reproassert.workflow import (
    WorkflowResult,
    candidate_from_file,
    run_issue_workflow,
    run_replay_workflow,
)

console = Console()
error_console = Console(stderr=True)
_CommandFunction = TypeVar("_CommandFunction", bound=Callable[..., Any])


def _default_run_base() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "reproassert" / "runs"


def _default_benchmark_source_root() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "reproassert" / "benchmark-sources" / "v0.1"


def _default_v02_benchmark_source_root() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "reproassert" / "benchmark-sources" / "v0.2"


def _default_v02_private_preparation_root() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "reproassert" / "benchmark-private" / "v0.2"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="reproassert")
def main() -> None:
    """The test before the fix: generate and verify failing pytest candidates."""


@main.group("benchmark")
def benchmark_group() -> None:
    """Prepare inert benchmark evidence without running a generator or model."""


@benchmark_group.command("run-v02-exact-campaign")
@click.argument("config", type=click.Path(path_type=Path, exists=True, dir_okay=False))
def benchmark_run_v02_exact_campaign(config: Path) -> None:
    """Run or safely resume the authorized exact 20-case campaign."""

    try:
        result = run_v02_exact_campaign(config)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(json.dumps(result, indent=2, sort_keys=True))


@benchmark_group.command("prepare-v02-exact-campaign-config")
@click.option(
    "--campaign-freeze",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--exact-preregistration",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--cases-preparation",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--cohort-plan", type=click.Path(path_type=Path, exists=True, dir_okay=False), required=True
)
@click.option(
    "--chronology", type=click.Path(path_type=Path, exists=True, dir_okay=False), required=True
)
@click.option(
    "--hidden-extraction-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--issue-responses-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    required=True,
)
@click.option(
    "--mapping-preparation",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--mapping-consensus",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--capability-index",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--runtime-manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--runtime-manifest-sha256", required=True)
@click.option(
    "--gold-smoke-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--gold-specs", type=click.Path(path_type=Path, exists=True, dir_okay=False), required=True
)
@click.option(
    "--execution-freeze",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--execution-authorization",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    required=True,
    help="New private campaign workspace, or an identical workspace to reverify.",
)
@click.option("--prepared-at", required=True, help="RFC 3339 UTC config preparation time.")
@click.option(
    "--executed-at",
    required=True,
    help=(
        "RFC 3339 UTC time persisted on evaluator receipts; run the campaign immediately after "
        "preparation."
    ),
)
@click.option("--tool-git-sha", required=True, help="Exact authorized controller revision.")
def benchmark_prepare_v02_exact_campaign_config(
    campaign_freeze: Path,
    exact_preregistration: Path,
    cases_preparation: Path,
    cohort_plan: Path,
    chronology: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    mapping_preparation: Path,
    mapping_consensus: Path,
    capability_index: Path,
    runtime_manifest: Path,
    runtime_manifest_sha256: str,
    gold_smoke_receipt: Path,
    gold_specs: Path,
    execution_freeze: Path,
    execution_authorization: Path,
    output_root: Path,
    prepared_at: str,
    executed_at: str,
    tool_git_sha: str,
) -> None:
    """Atomically derive the provider-free exact 20-case runner config."""

    try:
        result = prepare_v02_exact_campaign_config(
            inputs=ExactCampaignConfigInputs(
                campaign_freeze=campaign_freeze,
                exact_preregistration=exact_preregistration,
                cases_preparation=cases_preparation,
                cohort_plan=cohort_plan,
                chronology=chronology,
                hidden_extraction_receipt=hidden_extraction_receipt,
                issue_responses_root=issue_responses_root,
                mapping_preparation=mapping_preparation,
                mapping_consensus=mapping_consensus,
                capability_index=capability_index,
                runtime_manifest=runtime_manifest,
                runtime_manifest_sha256=runtime_manifest_sha256,
                gold_smoke_receipt=gold_smoke_receipt,
                gold_specs=gold_specs,
                execution_freeze=execution_freeze,
                execution_authorization=execution_authorization,
            ),
            output_root=output_root,
            prepared_at=prepared_at,
            executed_at=executed_at,
            tool_git_sha=tool_git_sha,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(json.dumps(result.summary(), indent=2, sort_keys=True))


@benchmark_group.command("verify-v02-exact-campaign-config")
@click.argument("config", type=click.Path(path_type=Path, exists=True, dir_okay=False))
def benchmark_verify_v02_exact_campaign_config(config: Path) -> None:
    """Freshly verify one exact config and every upstream authority."""

    try:
        result = verify_v02_exact_campaign_config(config)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(json.dumps(result.summary(), indent=2, sort_keys=True))


@benchmark_group.command("produce-snapshot")
@click.argument("case_id")
@click.option("--repository", required=True, help="Exact owner/repository identity.")
@click.option("--issue-url", required=True, help="Canonical public GitHub issue URL.")
@click.option("--base-sha", required=True, help="Exact lowercase 40-hex buggy commit.")
@click.option(
    "--raw-history",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Offline evaluator-only GraphQL issue-history artifact.",
)
@click.option(
    "--cutoff-basis",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Offline evaluator-selected solution-publication artifact.",
)
@click.option("--captured-at", required=True, help="Evidence capture time in RFC 3339 UTC.")
@click.option("--tool-name", required=True, help="Snapshot producer tool identity.")
@click.option("--tool-version", required=True, help="Snapshot producer version.")
@click.option("--tool-git-sha", required=True, help="Exact 40-hex producer revision.")
@click.option(
    "--privacy-reviewed-at",
    required=True,
    help="Completed human review time in RFC 3339 UTC.",
)
@click.option("--privacy-reviewer-id", required=True, help="Bounded human reviewer identity.")
@click.option(
    "--privacy-checklist-sha256",
    required=True,
    help="Exact lowercase SHA-256 of the completed review checklist.",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="New canonical receipt path inside a private directory.",
)
def benchmark_produce_snapshot(
    case_id: str,
    repository: str,
    issue_url: str,
    base_sha: str,
    raw_history: Path,
    cutoff_basis: Path,
    captured_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
    privacy_reviewed_at: str,
    privacy_reviewer_id: str,
    privacy_checklist_sha256: str,
    output: Path,
) -> None:
    """Produce one strictly rederived snapshot receipt from offline evidence."""

    try:
        _ensure_private_output_root(output.parent)
        result = produce_snapshot_receipt_file(
            identity=SnapshotIdentity(
                case_id=case_id,
                repository=repository,
                issue_url=issue_url,
                base_sha=base_sha,
            ),
            raw_issue_evidence_path=raw_history,
            cutoff_basis_path=cutoff_basis,
            output_path=output,
            producer=SnapshotProducerMetadata(
                captured_at=captured_at,
                tool_name=tool_name,
                tool_version=tool_version,
                tool_git_sha=tool_git_sha,
            ),
            privacy_review=SnapshotPrivacyReview(
                reviewed_at=privacy_reviewed_at,
                reviewer_id=privacy_reviewer_id,
                checklist_sha256=privacy_checklist_sha256,
            ),
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_id": case_id,
                "receipt": str(result.receipt_path),
                "receipt_sha256": result.receipt_sha256,
                "snapshot_sha256": result.snapshot_sha256,
                "offline_only": True,
                "derivation_reverified": True,
                "campaign_readiness_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("prepare-object-source")
@click.argument("case_id")
@click.option(
    "--manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_benchmark_source_root,
    show_default="private user state directory",
)
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
@click.option("--timeout-seconds", type=click.FloatRange(min=0, min_open=True), default=15.0)
def benchmark_prepare_object_source(
    case_id: str,
    manifest: Path,
    output_root: Path,
    tool_git_sha: str,
    timeout_seconds: float,
) -> None:
    """Prepare an exact Git-object workspace receipt without model execution."""

    try:
        _ensure_private_output_root(output_root)
        receipt_path = prepare_object_source_case(
            manifest,
            case_id,
            output_root,
            tool_git_sha=tool_git_sha,
            timeout_seconds=timeout_seconds,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_id": case_id,
                "receipt": str(receipt_path),
                "archive": str(receipt_path.parent / "source.tar.gz"),
                "campaign_readiness_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-object-source")
@click.argument("receipt_path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--case-id", required=True)
@click.option("--expected-receipt-sha256")
@click.option("--timeout-seconds", type=click.FloatRange(min=0, min_open=True), default=15.0)
def benchmark_verify_object_source(
    receipt_path: Path,
    manifest: Path,
    case_id: str,
    expected_receipt_sha256: str | None,
    timeout_seconds: float,
) -> None:
    """Freshly verify an exact-object source receipt and its preserved archive."""

    try:
        receipt = verify_object_source_receipt(
            receipt_path,
            manifest_path=manifest,
            expected_case_id=case_id,
            expected_receipt_sha256=expected_receipt_sha256,
            timeout_seconds=timeout_seconds,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    source = receipt.get("source")
    if not isinstance(source, dict):
        raise ReproAssertError(
            "benchmark_object_source_receipt", "Verified object-source record is invalid."
        )
    workspace = source.get("verified_workspace")
    transport = source.get("transport")
    if not isinstance(workspace, dict) or not isinstance(transport, dict):
        raise ReproAssertError(
            "benchmark_object_source_receipt", "Verified object-source evidence is invalid."
        )
    click.echo(
        json.dumps(
            {
                "case_id": case_id,
                "archive_sha256": transport["sha256"],
                "git_tree_oid": source["github_root_tree_oid"],
                "tree_sha256": workspace["tree_sha256"],
                "verified": True,
                "campaign_readiness_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("install-v02-parser-image")
@click.argument(
    "archive",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
)
@click.option(
    "--archive-sha256",
    required=True,
    help="Exact lowercase SHA-256 published for the Docker archive.",
)
@click.option(
    "--image-id",
    default=FROZEN_V02_DATASET_PARSER_IMAGE_ID,
    show_default=True,
    help="Exact immutable image ID expected after loading.",
)
@click.option(
    "--platform",
    "expected_platform",
    default="linux/arm64",
    show_default=True,
    type=click.Choice(["linux/amd64", "linux/arm64"]),
)
def benchmark_install_v02_parser_image(
    archive: Path,
    archive_sha256: str,
    image_id: str,
    expected_platform: str,
) -> None:
    """Fail closed while loading an exact published dataset-parser image."""

    try:
        installed = install_v02_parser_image(
            archive,
            expected_archive_sha256=archive_sha256,
            expected_image_id=image_id,
            expected_platform=expected_platform,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "archive": str(installed.archive_path),
                "archive_bytes": installed.archive_bytes,
                "archive_sha256": installed.archive_sha256,
                "image_id": installed.image_id,
                "platform": installed.platform,
                "verified": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("prepare-v02-dataset")
@click.option(
    "--tdd-id-list",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--source-dataset",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--upstream-object-witness",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--cohort-plan",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--image-digest",
    default=FROZEN_V02_DATASET_PARSER_IMAGE_ID,
    show_default=True,
    help="Exact frozen local dataset-parser image ID.",
)
@click.option("--prepared-at", required=True, help="UTC preparation timestamp.")
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_v02_private_preparation_root,
    show_default="private user state directory",
)
def benchmark_prepare_v02_dataset(
    tdd_id_list: Path,
    source_dataset: Path,
    upstream_object_witness: Path,
    cohort_plan: Path,
    image_digest: str,
    prepared_at: str,
    output_root: Path,
) -> None:
    """Attest the frozen dataset and write 20 safe projections without a provider."""

    try:
        _ensure_private_output_root(output_root)
        prepared = prepare_v02_dataset_inputs(
            output_root=output_root,
            tdd_id_list_path=tdd_id_list,
            source_dataset_path=source_dataset,
            upstream_object_witness_path=upstream_object_witness,
            cohort_plan_path=cohort_plan,
            image_digest=image_digest,
            prepared_at=prepared_at,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": prepared.case_count,
                "parser_receipt_sha256": prepared.parser_receipt_sha256,
                "preparation_receipt": str(prepared.receipt_path),
                "preparation_receipt_sha256": prepared.receipt_sha256,
                "provider_calls": prepared.provider_calls,
                "status": "prepared_no_provider_invoked",
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-dataset")
@click.argument(
    "preparation_receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
)
def benchmark_verify_v02_dataset(preparation_receipt: Path) -> None:
    """Freshly rerun and verify an exact provider-free v0.2 dataset preparation."""

    try:
        prepared = verify_v02_dataset_preparation(preparation_receipt)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": prepared.case_count,
                "parser_receipt_sha256": prepared.parser_receipt_sha256,
                "preparation_receipt_sha256": prepared.receipt_sha256,
                "provider_calls": prepared.provider_calls,
                "verified": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("prepare-v02-hidden-gold")
@click.option(
    "--source-dataset",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--cohort-plan",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--image-digest",
    default=FROZEN_V02_DATASET_PARSER_IMAGE_ID,
    show_default=True,
)
@click.option("--prepared-at", required=True, help="UTC preparation timestamp.")
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_v02_private_preparation_root,
    show_default="private user state directory",
)
def benchmark_prepare_v02_hidden_gold(
    source_dataset: Path,
    cohort_plan: Path,
    image_digest: str,
    prepared_at: str,
    output_root: Path,
) -> None:
    """Extract evaluator-private hidden gold in the frozen no-network sandbox."""

    try:
        _ensure_private_output_root(output_root)
        prepared = prepare_v02_hidden_gold(
            output_root=output_root,
            source_dataset_path=source_dataset,
            cohort_plan_path=cohort_plan,
            image_digest=image_digest,
            prepared_at=prepared_at,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "artifacts_sha256": prepared.artifacts_sha256,
                "case_count": prepared.case_count,
                "preparation_receipt_sha256": prepared.receipt_sha256,
                "provider_calls": 0,
                "status": "evaluator_private_prepared_no_provider",
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-hidden-gold")
@click.argument(
    "preparation_receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
)
def benchmark_verify_v02_hidden_gold(preparation_receipt: Path) -> None:
    """Freshly rerun hidden extraction and byte-verify all 20 evaluator artifacts."""

    try:
        verified = verify_v02_hidden_gold(preparation_receipt)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    prepared = verified.prepared
    click.echo(
        json.dumps(
            {
                "artifacts_sha256": prepared.artifacts_sha256,
                "case_count": prepared.case_count,
                "preparation_receipt_sha256": prepared.receipt_sha256,
                "provider_calls": 0,
                "verified": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("prepare-v02-exact-capabilities")
@click.option(
    "--instance-runtime-manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--expected-manifest-sha256", required=True)
@click.option(
    "--gold-smoke-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--hidden-extraction-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--prepared-at", required=True)
@click.option("--tool-git-sha", required=True)
@click.option("--output", type=click.Path(path_type=Path, dir_okay=False), required=True)
def benchmark_prepare_v02_exact_capabilities(
    instance_runtime_manifest: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt: Path,
    hidden_extraction_receipt: Path,
    prepared_at: str,
    tool_git_sha: str,
    output: Path,
) -> None:
    """Persist 20 exact-image commitments while keeping authority process-local."""

    try:
        _ensure_private_output_root(output.parent)
        verified = prepare_v02_exact_image_capability_index(
            manifest_path=instance_runtime_manifest,
            expected_manifest_sha256=expected_manifest_sha256,
            gold_smoke_receipt_path=gold_smoke_receipt,
            hidden_extraction_receipt=hidden_extraction_receipt,
            prepared_at=prepared_at,
            tool_git_sha=tool_git_sha,
            output_path=output,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(json.dumps(asdict(verified), indent=2, sort_keys=True, default=str))


@benchmark_group.command("verify-v02-exact-capabilities")
@click.argument("index", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--instance-runtime-manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--expected-manifest-sha256", required=True)
@click.option(
    "--gold-smoke-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--hidden-extraction-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
def benchmark_verify_v02_exact_capabilities(
    index: Path,
    instance_runtime_manifest: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt: Path,
    hidden_extraction_receipt: Path,
) -> None:
    """Rederive a redacted exact-image capability commitment index."""

    try:
        verified = verify_v02_exact_image_capability_index(
            index,
            manifest_path=instance_runtime_manifest,
            expected_manifest_sha256=expected_manifest_sha256,
            gold_smoke_receipt_path=gold_smoke_receipt,
            hidden_extraction_receipt=hidden_extraction_receipt,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    result = asdict(verified)
    result["verified"] = True
    click.echo(json.dumps(result, indent=2, sort_keys=True, default=str))


@benchmark_group.command("execute-v02-exact-causal-controls")
@click.option("--case-id", required=True)
@click.option(
    "--instance-runtime-manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--expected-manifest-sha256", required=True)
@click.option(
    "--gold-smoke-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--gold-specs",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--hidden-extraction-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--mapping-preparation",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--mapping-consensus",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--candidate-evaluation-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--candidate-file",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--candidate-relative-path", required=True)
@click.option("--candidate-test-function", required=True)
@click.option("--executed-at", required=True)
@click.option("--tool-git-sha", required=True)
@click.option("--output", type=click.Path(path_type=Path, dir_okay=False), required=True)
def benchmark_run_v02_exact_causal_controls(
    case_id: str,
    instance_runtime_manifest: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt: Path,
    gold_specs: Path,
    hidden_extraction_receipt: Path,
    mapping_preparation: Path,
    mapping_consensus: Path,
    candidate_evaluation_receipt: Path,
    candidate_file: Path,
    candidate_relative_path: str,
    candidate_test_function: str,
    executed_at: str,
    tool_git_sha: str,
    output: Path,
) -> None:
    """Execute the three exact-image causal controls; never invoke a provider."""

    try:
        _ensure_private_output_root(output.parent)
        hidden = verify_v02_hidden_gold(hidden_extraction_receipt)
        capability = issue_verified_v02_exact_image_evaluator_capability(
            manifest_path=instance_runtime_manifest,
            expected_manifest_sha256=expected_manifest_sha256,
            gold_smoke_receipt_path=gold_smoke_receipt,
            verified_hidden=hidden,
            case_id=case_id,
        )
        verified = run_exact_image_causal_controls(
            evaluator_capability=capability,
            verified_hidden=hidden,
            manifest_path=instance_runtime_manifest,
            expected_manifest_sha256=expected_manifest_sha256,
            gold_smoke_receipt_path=gold_smoke_receipt,
            gold_specs_path=gold_specs,
            mapping_consensus_path=mapping_consensus,
            mapping_preparation_path=mapping_preparation,
            candidate_evaluation_receipt_path=candidate_evaluation_receipt,
            candidate=CandidateArtifact(
                relative_path=candidate_relative_path,
                content=candidate_file.read_bytes(),
                test_function=candidate_test_function,
            ),
            output_path=output,
            executed_at=executed_at,
            tool_git_sha=tool_git_sha,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(json.dumps(verified.public_record(), indent=2, sort_keys=True, default=str))


@benchmark_group.command("verify-v02-exact-causal-controls")
@click.argument("receipt", type=click.Path(path_type=Path, exists=True, dir_okay=False))
def benchmark_verify_v02_exact_causal_controls(receipt: Path) -> None:
    """Structurally inspect one receipt; this does not reissue L2 authority."""

    try:
        verified = verify_exact_image_causal_control_receipt(receipt)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    result = asdict(verified)
    result["structurally_valid"] = True
    result["verified"] = False
    click.echo(json.dumps(result, indent=2, sort_keys=True, default=str))


def _exact_preregistration_evidence_options(function: _CommandFunction) -> _CommandFunction:
    options = (
        click.option(
            "--cases-preparation",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--cohort-plan",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--chronology",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--hidden-extraction-receipt",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--issue-responses-root",
            type=click.Path(path_type=Path, exists=True, file_okay=False),
            required=True,
        ),
        click.option(
            "--mapping-preparation",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--mapping-consensus",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--capability-index",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--instance-runtime-manifest",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option("--expected-manifest-sha256", required=True),
        click.option(
            "--gold-smoke-receipt",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
    )
    decorated = function
    for option in reversed(options):
        decorated = option(decorated)
    return decorated


@benchmark_group.command("prepare-v02-exact-preregistration")
@_exact_preregistration_evidence_options
@click.option("--frozen-at", required=True, help="UTC pre-inference freeze timestamp.")
@click.option("--tool-git-sha", required=True, help="Exact final controller revision.")
@click.option("--output", type=click.Path(path_type=Path, dir_okay=False), required=True)
def benchmark_prepare_v02_exact_preregistration(
    cases_preparation: Path,
    cohort_plan: Path,
    chronology: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    mapping_preparation: Path,
    mapping_consensus: Path,
    capability_index: Path,
    instance_runtime_manifest: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt: Path,
    frozen_at: str,
    tool_git_sha: str,
    output: Path,
) -> None:
    """Freeze exact requests and evaluator commitments after genuine mapping consensus."""

    try:
        _ensure_private_output_root(output.parent)
        verified = prepare_v02_exact_preregistration(
            cases_preparation_path=cases_preparation,
            cohort_plan_path=cohort_plan,
            chronology_path=chronology,
            hidden_extraction_receipt=hidden_extraction_receipt,
            issue_responses_root=issue_responses_root,
            mapping_preparation_path=mapping_preparation,
            mapping_consensus_path=mapping_consensus,
            capability_index_path=capability_index,
            runtime_manifest_path=instance_runtime_manifest,
            expected_runtime_manifest_sha256=expected_manifest_sha256,
            gold_smoke_receipt_path=gold_smoke_receipt,
            frozen_at=frozen_at,
            tool_git_sha=tool_git_sha,
            output_path=output,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(json.dumps(asdict(verified), indent=2, sort_keys=True, default=str))


@benchmark_group.command("verify-v02-exact-preregistration")
@click.argument("preregistration", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@_exact_preregistration_evidence_options
def benchmark_verify_v02_exact_preregistration(
    preregistration: Path,
    cases_preparation: Path,
    cohort_plan: Path,
    chronology: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    mapping_preparation: Path,
    mapping_consensus: Path,
    capability_index: Path,
    instance_runtime_manifest: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt: Path,
) -> None:
    """Freshly verify the exact successor freeze against every bound evidence source."""

    try:
        verified = verify_v02_exact_preregistration(
            preregistration,
            cases_preparation_path=cases_preparation,
            cohort_plan_path=cohort_plan,
            chronology_path=chronology,
            hidden_extraction_receipt=hidden_extraction_receipt,
            issue_responses_root=issue_responses_root,
            mapping_preparation_path=mapping_preparation,
            mapping_consensus_path=mapping_consensus,
            capability_index_path=capability_index,
            runtime_manifest_path=instance_runtime_manifest,
            expected_runtime_manifest_sha256=expected_manifest_sha256,
            gold_smoke_receipt_path=gold_smoke_receipt,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    result = asdict(verified)
    result["verified"] = True
    click.echo(json.dumps(result, indent=2, sort_keys=True, default=str))


@benchmark_group.command("capture-v02-chronology")
@click.option(
    "--cohort-plan",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    required=True,
)
def benchmark_capture_v02_chronology(cohort_plan: Path, output_root: Path) -> None:
    """Capture 20 public issue responses without credentials or model-provider access."""

    try:
        _ensure_private_output_root(output_root)
        captured = capture_v02_public_issue_responses(
            cohort_plan_path=cohort_plan, output_root=output_root
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": 20,
                "credentials_sent": False,
                "issue_responses_root": str(captured),
                "provider_calls": 0,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("prepare-v02-chronology")
@click.option(
    "--cohort-plan",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--hidden-extraction-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--issue-responses-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    required=True,
)
@click.option("--captured-at", required=True, help="UTC evidence capture timestamp.")
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
@click.option("--output", type=click.Path(path_type=Path, dir_okay=False), required=True)
def benchmark_prepare_v02_chronology(
    cohort_plan: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    captured_at: str,
    tool_git_sha: str,
    output: Path,
) -> None:
    """Seal 20 chronology pairs from captured public responses and verified metadata."""

    try:
        _ensure_private_output_root(output.parent)
        verified = prepare_v02_chronology_evidence(
            cohort_plan_path=cohort_plan,
            hidden_extraction_receipt=hidden_extraction_receipt,
            issue_responses_root=issue_responses_root,
            captured_at=captured_at,
            tool_git_sha=tool_git_sha,
            output_path=output,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": verified.case_count,
                "issue_precedes_fix_count": verified.issue_precedes_fix_count,
                "provider_calls": verified.provider_calls,
                "receipt_sha256": verified.sha256,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-chronology")
@click.argument("receipt", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--cohort-plan",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--hidden-extraction-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--issue-responses-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    required=True,
)
def benchmark_verify_v02_chronology(
    receipt: Path,
    cohort_plan: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
) -> None:
    """Rederive one chronology receipt from its exact 20 source pairs."""

    try:
        verified = verify_v02_chronology_evidence(
            receipt,
            cohort_plan_path=cohort_plan,
            hidden_extraction_receipt=hidden_extraction_receipt,
            issue_responses_root=issue_responses_root,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": verified.case_count,
                "issue_precedes_fix_count": verified.issue_precedes_fix_count,
                "provider_calls": verified.provider_calls,
                "receipt_sha256": verified.sha256,
                "verified": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("prepare-v02-mapping-packets")
@click.option(
    "--hidden-extraction-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--prepared-at", required=True, help="UTC packet preparation timestamp.")
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_v02_private_preparation_root,
    show_default="private user state directory",
)
def benchmark_prepare_v02_mapping_packets(
    hidden_extraction_receipt: Path,
    prepared_at: str,
    tool_git_sha: str,
    output_root: Path,
) -> None:
    """Prepare 20 blank hunk-mapping packets; never infer reviewer decisions."""

    try:
        _ensure_private_output_root(output_root)
        verified_hidden = verify_v02_hidden_gold(hidden_extraction_receipt)
        prepared = prepare_v02_mapping_packets(
            verified_hidden=verified_hidden,
            output_root=output_root,
            prepared_at=prepared_at,
            tool_git_sha=tool_git_sha,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": prepared.case_count,
                "preparation_receipt_sha256": prepared.receipt_sha256,
                "provider_calls": 0,
                "status": "prepared_review_required_provider_disabled",
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-mapping-packets")
@click.argument("receipt", type=click.Path(path_type=Path, exists=True, dir_okay=False))
def benchmark_verify_v02_mapping_packets(receipt: Path) -> None:
    """Verify all 20 blank packets and their exact patch-algebra commitments."""

    try:
        prepared = verify_v02_mapping_packets(receipt)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": prepared.case_count,
                "preparation_receipt_sha256": prepared.receipt_sha256,
                "provider_calls": 0,
                "verified": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("prepare-v02-mapping-review-handoff")
@click.option(
    "--mapping-preparation",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--primary-reviewer-id",
    multiple=True,
    required=True,
    help="Exactly two genuine mapping reviewer IDs, in primary order.",
)
@click.option(
    "--semantic-reviewer-id",
    multiple=True,
    required=True,
    help="Two or three genuine future semantic reviewer IDs; must be disjoint.",
)
@click.option(
    "--tiebreak-reviewer-id",
    help="Optional genuine mapping tie-break reviewer; submit only after disagreement.",
)
@click.option("--prepared-at", required=True, help="Caller-supplied UTC handoff time.")
@click.option("--tool-git-sha", required=True)
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_v02_private_preparation_root,
    show_default="private user state directory",
)
def benchmark_prepare_v02_mapping_review_handoff(
    mapping_preparation: Path,
    primary_reviewer_id: tuple[str, ...],
    semantic_reviewer_id: tuple[str, ...],
    tiebreak_reviewer_id: str | None,
    prepared_at: str,
    tool_git_sha: str,
    output_root: Path,
) -> None:
    """Export private human packets and incomplete, source-bound submission templates."""

    if len(primary_reviewer_id) != 2:
        raise click.UsageError("--primary-reviewer-id must be supplied exactly twice.")
    try:
        _ensure_private_output_root(output_root)
        verified = prepare_v02_mapping_review_handoff(
            mapping_preparation_path=mapping_preparation,
            primary_reviewer_ids=(primary_reviewer_id[0], primary_reviewer_id[1]),
            semantic_reviewer_ids=semantic_reviewer_id,
            tiebreak_reviewer_id=tiebreak_reviewer_id,
            output_root=output_root,
            prepared_at=prepared_at,
            tool_git_sha=tool_git_sha,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(json.dumps(asdict(verified), indent=2, sort_keys=True, default=str))


@benchmark_group.command("verify-v02-mapping-review-handoff")
@click.argument("handoff", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--mapping-preparation",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
def benchmark_verify_v02_mapping_review_handoff(handoff: Path, mapping_preparation: Path) -> None:
    """Verify reviewer roles, source patches, redaction, and still-blank submissions."""

    try:
        verified = verify_v02_mapping_review_handoff(
            handoff, mapping_preparation_path=mapping_preparation
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    result = asdict(verified)
    result["verified"] = True
    click.echo(json.dumps(result, indent=2, sort_keys=True, default=str))


@benchmark_group.command("seal-v02-mapping-consensus")
@click.option(
    "--preparation-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--submissions-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    required=True,
)
@click.option("--sealed-at", required=True, help="UTC consensus seal timestamp.")
@click.option("--output", type=click.Path(path_type=Path, dir_okay=False), required=True)
def benchmark_seal_v02_mapping_consensus(
    preparation_receipt: Path, submissions_root: Path, sealed_at: str, output: Path
) -> None:
    """Seal genuine two-reviewer agreement or a valid third-reviewer tie break."""

    try:
        _ensure_private_output_root(output.parent)
        sealed = seal_v02_mapping_consensus(
            preparation_path=preparation_receipt,
            submissions_root=submissions_root,
            output_path=output,
            sealed_at=sealed_at,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": sealed.case_count,
                "provider_calls": 0,
                "seal_sha256": sealed.sha256,
                "status": "sealed_complete",
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-mapping-consensus")
@click.argument("seal", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--preparation-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
def benchmark_verify_v02_mapping_consensus(seal: Path, preparation_receipt: Path) -> None:
    """Verify a sealed mapping set still binds the exact 20-case preparation."""

    try:
        verified = verify_v02_mapping_consensus(seal, preparation_path=preparation_receipt)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": verified.case_count,
                "provider_calls": 0,
                "seal_sha256": verified.sha256,
                "verified": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("prepare-v02-cases")
@click.option(
    "--cohort-plan",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--dataset-preparation-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--hidden-extraction-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--object-sources-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    required=True,
)
@click.option(
    "--pricing-snapshot",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--dependency-plans-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
)
@click.option(
    "--instance-runtime-manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
)
@click.option("--expected-runtime-manifest-sha256")
@click.option(
    "--gold-smoke-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
)
@click.option(
    "--exact-capability-index",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
)
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
@click.option("--prepared-at", required=True, help="UTC preparation timestamp.")
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_v02_private_preparation_root,
    show_default="private user state directory",
)
def benchmark_prepare_v02_cases(
    cohort_plan: Path,
    dataset_preparation_receipt: Path,
    hidden_extraction_receipt: Path,
    object_sources_root: Path,
    pricing_snapshot: Path,
    dependency_plans_root: Path | None,
    instance_runtime_manifest: Path | None,
    expected_runtime_manifest_sha256: str | None,
    gold_smoke_receipt: Path | None,
    exact_capability_index: Path | None,
    tool_git_sha: str,
    prepared_at: str,
    output_root: Path,
) -> None:
    """Prepare the frozen 20-case evaluator set with provider execution disabled."""

    try:
        _ensure_private_output_root(output_root)
        prepared = prepare_v02_cases(
            cohort_plan_path=cohort_plan,
            dataset_preparation_receipt=dataset_preparation_receipt,
            hidden_extraction_receipt=hidden_extraction_receipt,
            object_sources_root=object_sources_root,
            dependency_plans_root=dependency_plans_root,
            instance_runtime_manifest=instance_runtime_manifest,
            expected_runtime_manifest_sha256=expected_runtime_manifest_sha256,
            gold_smoke_receipt=gold_smoke_receipt,
            exact_capability_index=exact_capability_index,
            output_root=output_root,
            pricing_snapshot_path=pricing_snapshot,
            tool_git_sha=tool_git_sha,
            prepared_at=prepared_at,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "campaign_ready_count": prepared.campaign_ready_count,
                "case_count": prepared.case_count,
                "dependency_ready_count": prepared.dependency_ready_count,
                "preparation_receipt_sha256": prepared.receipt_sha256,
                "provider_calls": 0,
                "provider_execution_enabled": False,
                "status": "prepared_review_required_provider_disabled",
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-cases")
@click.argument(
    "preparation_receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
)
def benchmark_verify_v02_cases(preparation_receipt: Path) -> None:
    """Freshly verify the frozen case preparation and its deny-by-default spend gate."""

    try:
        prepared = verify_v02_cases(preparation_receipt)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "campaign_ready_count": prepared.campaign_ready_count,
                "case_count": prepared.case_count,
                "dependency_ready_count": prepared.dependency_ready_count,
                "preparation_receipt_sha256": prepared.receipt_sha256,
                "provider_calls": 0,
                "provider_execution_enabled": False,
                "verified": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("smoke-v02-instance-runtimes")
@click.option(
    "--instance-runtime-manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--expected-manifest-sha256", required=True)
@click.option(
    "--hidden-extraction-receipt",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--gold-specs",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--expected-gold-specs-sha256", required=True)
@click.option("--case-id", help="Run one case while retaining 20 denominator rows.")
@click.option("--executed-at", required=True, help="UTC execution timestamp.")
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="New evaluator-private canonical gold-smoke receipt.",
)
def benchmark_run_v02_instance_gold_smoke(
    instance_runtime_manifest: Path,
    expected_manifest_sha256: str,
    hidden_extraction_receipt: Path,
    gold_specs: Path,
    expected_gold_specs_sha256: str,
    case_id: str | None,
    executed_at: str,
    tool_git_sha: str,
    output: Path,
) -> None:
    """Run exact hidden gold tests in no-network instance sandboxes; never call a provider."""

    try:
        _ensure_private_output_root(output.parent)
        receipt = run_instance_gold_smoke(
            manifest_path=instance_runtime_manifest,
            expected_manifest_sha256=expected_manifest_sha256,
            hidden_extraction_receipt=hidden_extraction_receipt,
            gold_specs_path=gold_specs,
            expected_gold_specs_sha256=expected_gold_specs_sha256,
            output_path=output,
            executed_at=executed_at,
            tool_git_sha=tool_git_sha,
            case_id=case_id,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": 20,
                "infrastructure_failure_count": receipt.infrastructure_failure_count,
                "provider_calls": 0,
                "provider_execution_enabled": False,
                "receipt_sha256": receipt.sha256,
                "selected_case_count": receipt.selected_case_count,
                "semantic_valid_count": receipt.semantic_valid_count,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-instance-gold-smoke")
@click.argument("receipt", type=click.Path(path_type=Path, exists=True, dir_okay=False))
def benchmark_verify_v02_instance_gold_smoke(receipt: Path) -> None:
    """Verify canonical redacted gold-smoke evidence without executing code."""

    try:
        verified = verify_instance_gold_smoke_receipt(receipt)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_count": 20,
                "infrastructure_failure_count": verified.infrastructure_failure_count,
                "provider_calls": 0,
                "receipt_sha256": verified.sha256,
                "selected_case_count": verified.selected_case_count,
                "semantic_valid_count": verified.semantic_valid_count,
                "verified": True,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("prepare-v02-object-source")
@click.argument("case_id")
@click.option(
    "--cohort-plan",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_v02_benchmark_source_root,
    show_default="private user state directory",
)
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
@click.option("--timeout-seconds", type=click.FloatRange(min=0, min_open=True), default=15.0)
def benchmark_prepare_v02_object_source(
    case_id: str,
    cohort_plan: Path,
    output_root: Path,
    tool_git_sha: str,
    timeout_seconds: float,
) -> None:
    """Prepare an exact Git-object source bound to the frozen v0.2 cohort."""

    try:
        _ensure_private_output_root(output_root)
        receipt_path = prepare_v02_object_source_case(
            cohort_plan,
            case_id,
            output_root,
            tool_git_sha=tool_git_sha,
            timeout_seconds=timeout_seconds,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_id": case_id,
                "receipt": str(receipt_path),
                "archive": str(receipt_path.parent / "source.tar.gz"),
                "benchmark_version": "0.2.0",
                "campaign_readiness_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-object-source")
@click.argument("receipt_path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--cohort-plan",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--case-id", required=True)
@click.option("--expected-receipt-sha256")
@click.option("--timeout-seconds", type=click.FloatRange(min=0, min_open=True), default=15.0)
def benchmark_verify_v02_object_source(
    receipt_path: Path,
    cohort_plan: Path,
    case_id: str,
    expected_receipt_sha256: str | None,
    timeout_seconds: float,
) -> None:
    """Freshly verify a v0.2 exact-object source and its preserved archive."""

    try:
        receipt = verify_v02_object_source_receipt(
            receipt_path,
            plan_path=cohort_plan,
            expected_case_id=case_id,
            expected_receipt_sha256=expected_receipt_sha256,
            timeout_seconds=timeout_seconds,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    source = receipt.get("source")
    if not isinstance(source, dict):
        raise ReproAssertError(
            "benchmark_v02_object_source", "Verified v0.2 object-source record is invalid."
        )
    workspace = source.get("verified_workspace")
    transport = source.get("transport")
    if not isinstance(workspace, dict) or not isinstance(transport, dict):
        raise ReproAssertError(
            "benchmark_v02_object_source", "Verified v0.2 object-source evidence is invalid."
        )
    click.echo(
        json.dumps(
            {
                "case_id": case_id,
                "archive_sha256": transport["sha256"],
                "git_tree_oid": source["github_root_tree_oid"],
                "tree_sha256": workspace["tree_sha256"],
                "benchmark_version": "0.2.0",
                "verified": True,
                "campaign_readiness_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("prepare-source")
@click.argument("case_id")
@click.option(
    "--manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_benchmark_source_root,
    show_default="private user state directory",
)
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
@click.option("--timeout-seconds", type=click.FloatRange(min=0, min_open=True), default=15.0)
def benchmark_prepare_source(
    case_id: str,
    manifest: Path,
    output_root: Path,
    tool_git_sha: str,
    timeout_seconds: float,
) -> None:
    """Prepare one exact source archive and deterministic receipt."""

    try:
        _ensure_private_output_root(output_root)
        receipt_path = prepare_source_case(
            manifest,
            case_id,
            output_root,
            tool_git_sha=tool_git_sha,
            timeout_seconds=timeout_seconds,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "case_id": case_id,
                "receipt": str(receipt_path),
                "archive": str(receipt_path.parent / "source.tar.gz"),
                "campaign_readiness_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-source")
@click.argument("receipt_path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--case-id", required=True)
@click.option("--expected-receipt-sha256")
@click.option("--timeout-seconds", type=click.FloatRange(min=0, min_open=True), default=15.0)
def benchmark_verify_source(
    receipt_path: Path,
    manifest: Path,
    case_id: str,
    expected_receipt_sha256: str | None,
    timeout_seconds: float,
) -> None:
    """Re-fetch commit metadata, then rehash, extract, and attest one receipt."""

    try:
        receipt = verify_source_receipt(
            receipt_path,
            manifest_path=manifest,
            expected_case_id=case_id,
            expected_receipt_sha256=expected_receipt_sha256,
            timeout_seconds=timeout_seconds,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    source = receipt["source"]
    if not isinstance(source, dict):
        raise ReproAssertError("benchmark_source_receipt", "Verified source record is invalid.")
    attestation = source["attestation"]
    archive = source["archive"]
    if not isinstance(attestation, dict) or not isinstance(archive, dict):
        raise ReproAssertError("benchmark_source_receipt", "Verified source evidence is invalid.")
    click.echo(
        json.dumps(
            {
                "case_id": case_id,
                "archive_sha256": archive["sha256"],
                "git_tree_oid": source["github_root_tree_oid"],
                "tree_sha256": attestation["tree_sha256"],
                "verified": True,
                "campaign_readiness_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("build-source-index")
@click.option(
    "--manifest",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--receipts-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    required=True,
)
@click.option("--output", type=click.Path(path_type=Path, dir_okay=False))
@click.option("--tool-git-sha", required=True, help="Exact 40-hex index-builder revision.")
@click.option("--timeout-seconds", type=click.FloatRange(min=0, min_open=True), default=15.0)
def benchmark_build_source_index(
    manifest: Path,
    receipts_root: Path,
    output: Path | None,
    tool_git_sha: str,
    timeout_seconds: float,
) -> None:
    """Reverify exactly 20 source receipts and write an inert deterministic index."""

    try:
        frozen = load_frozen_manifest(manifest)
        receipt_paths = [f"{case.id}/{SOURCE_RECEIPT_FILENAME}" for case in frozen.cases]
        destination = output or receipts_root / SOURCE_INDEX_FILENAME
        index_path = build_source_index(
            manifest,
            receipts_root,
            receipt_paths,
            destination,
            tool_git_sha=tool_git_sha,
            timeout_seconds=timeout_seconds,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "index": str(index_path),
                "receipt_count": len(receipt_paths),
                "campaign_readiness_changed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-dependency-receipt")
@click.argument("receipt_path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--plan",
    "plan_path",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Exact reviewed dependency plan bound by the receipt.",
)
@click.option("--expected-receipt-sha256")
def benchmark_verify_dependency_receipt(
    receipt_path: Path,
    plan_path: Path,
    expected_receipt_sha256: str | None,
) -> None:
    """Independently rederive and verify one causal dependency receipt."""

    try:
        verified = load_dependency_execution_receipt(
            receipt_path,
            expected_plan_path=plan_path,
            expected_receipt_sha256=expected_receipt_sha256,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(json.dumps(asdict(verified), indent=2, sort_keys=True))


@benchmark_group.command("prepare-v02-campaign")
@click.option(
    "--preregistration",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Exact frozen 20-case v0.2 preregistration.",
)
@click.option("--campaign-id", required=True, help="Bounded campaign identity.")
@click.option("--prepared-at", required=True, help="Preparation time in RFC 3339 UTC.")
@click.option("--tool-name", default="reproassert", show_default=True)
@click.option("--tool-version", required=True)
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="New canonical preparation-only campaign freeze.",
)
def benchmark_prepare_v02_campaign(
    preregistration: Path,
    campaign_id: str,
    prepared_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
    output: Path,
) -> None:
    """Freeze a v0.2 campaign without authorizing or invoking any provider."""

    try:
        _ensure_private_output_root(output.parent)
        path = prepare_v02_campaign_freeze(
            preregistration,
            output,
            campaign_id=campaign_id,
            prepared_at=prepared_at,
            tool_name=tool_name,
            tool_version=tool_version,
            tool_git_sha=tool_git_sha,
        )
        verified = verify_v02_campaign_freeze(path, preregistration)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "campaign_id": verified.campaign_id,
                "campaign_freeze": str(path),
                "campaign_freeze_sha256": verified.raw_sha256,
                "case_count": len(verified.case_ids),
                "provider_authorized": False,
                "provider_invoked_by_this_command": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-campaign")
@click.argument("campaign_freeze", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--preregistration",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
def benchmark_verify_v02_campaign(campaign_freeze: Path, preregistration: Path) -> None:
    """Verify the exact deny-by-default campaign freeze without executing a case."""

    try:
        verified = verify_v02_campaign_freeze(campaign_freeze, preregistration)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "campaign_id": verified.campaign_id,
                "campaign_freeze_sha256": verified.raw_sha256,
                "case_count": len(verified.case_ids),
                "preparation_only": True,
                "provider_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


def _exact_image_freeze_inputs(function: _CommandFunction) -> _CommandFunction:
    options = (
        click.option(
            "--campaign-freeze",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--preregistration",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--cases-preparation",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--instance-runtime-manifest",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
        click.option(
            "--gold-smoke-receipt",
            type=click.Path(path_type=Path, exists=True, dir_okay=False),
            required=True,
        ),
    )
    for option in reversed(options):
        function = option(function)
    return function


@benchmark_group.command("prepare-v02-execution-freeze")
@_exact_image_freeze_inputs
@click.option("--prepared-at", required=True, help="Freeze time in RFC 3339 UTC.")
@click.option(
    "--controller-git-sha",
    required=True,
    help="Exact merged 40-hex controller revision also bound by every request envelope.",
)
@click.option(
    "--requested-model",
    required=True,
    help="Exact model already bound by the pricing snapshot and requests.",
)
@click.option("--output", type=click.Path(path_type=Path, dir_okay=False), required=True)
def benchmark_freeze_v02_execution(
    campaign_freeze: Path,
    preregistration: Path,
    cases_preparation: Path,
    instance_runtime_manifest: Path,
    gold_smoke_receipt: Path,
    prepared_at: str,
    controller_git_sha: str,
    requested_model: str,
    output: Path,
) -> None:
    """Bind evidence, requests, pricing, and cap audit before final user approval."""

    try:
        _ensure_private_output_root(output.parent)
        verified = prepare_v02_exact_image_execution_freeze(
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
            cases_preparation_receipt=cases_preparation,
            instance_runtime_manifest_path=instance_runtime_manifest,
            gold_smoke_receipt_path=gold_smoke_receipt,
            prepared_at=prepared_at,
            controller_git_sha=controller_git_sha,
            requested_model=requested_model,
            output_path=output,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "campaign_id": verified.campaign_id,
                "execution_freeze": str(verified.path),
                "execution_freeze_sha256": verified.sha256,
                "max_campaign_usd": "5.00",
                "max_case_usd": "0.25",
                "overage_permitted": False,
                "provider_authorized": False,
                "provider_calls": 0,
                "provider_invoked_by_this_command": False,
                "request_set_sha256": verified.request_set_sha256,
                "requested_model": verified.requested_model,
                "required_approval_statement": exact_approval_statement(verified.sha256),
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("authorize-v02-execution")
@click.argument("execution_freeze", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@_exact_image_freeze_inputs
@click.option(
    "--approval-file", type=click.Path(path_type=Path, exists=True, dir_okay=False), required=True
)
@click.option("--approval-ref", required=True)
@click.option("--authorized-at", required=True)
@click.option("--output", type=click.Path(path_type=Path, dir_okay=False), required=True)
def benchmark_authorize_v02_execution(
    execution_freeze: Path,
    campaign_freeze: Path,
    preregistration: Path,
    cases_preparation: Path,
    instance_runtime_manifest: Path,
    gold_smoke_receipt: Path,
    approval_file: Path,
    approval_ref: str,
    authorized_at: str,
    output: Path,
) -> None:
    """Authorize one exact prepared-freeze hash without invoking a provider."""
    try:
        _ensure_private_output_root(output.parent)
        verified = authorize_v02_exact_image_execution(
            execution_freeze_path=execution_freeze,
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
            cases_preparation_receipt=cases_preparation,
            instance_runtime_manifest_path=instance_runtime_manifest,
            gold_smoke_receipt_path=gold_smoke_receipt,
            approval_file=approval_file,
            approval_ref=approval_ref,
            authorized_at=authorized_at,
            output_path=output,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "authorization": str(verified.path),
                "authorization_sha256": verified.sha256,
                "authorized_at": verified.authorized_at,
                "campaign_id": verified.campaign_id,
                "execution_freeze_sha256": verified.execution_freeze_sha256,
                "provider_calls": 0,
                "provider_invoked_by_this_command": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-execution-freeze")
@click.argument("execution_freeze", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@_exact_image_freeze_inputs
def benchmark_verify_v02_execution_freeze(
    execution_freeze: Path,
    campaign_freeze: Path,
    preregistration: Path,
    cases_preparation: Path,
    instance_runtime_manifest: Path,
    gold_smoke_receipt: Path,
) -> None:
    """Reverify an exact-image execution freeze without reading credentials."""

    try:
        verified = verify_v02_exact_image_execution_freeze(
            execution_freeze,
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
            cases_preparation_receipt=cases_preparation,
            instance_runtime_manifest_path=instance_runtime_manifest,
            gold_smoke_receipt_path=gold_smoke_receipt,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "campaign_id": verified.campaign_id,
                "execution_freeze_sha256": verified.sha256,
                "max_campaign_usd": "5.00",
                "max_case_usd": "0.25",
                "provider_calls": 0,
                "request_set_sha256": verified.request_set_sha256,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("seal-v02-causal-controls")
@click.option(
    "--campaign-freeze",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--preregistration",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--controls-draft",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Bounded JSON array of exactly 20 already-executed causal-control cases.",
)
@click.option("--sealed-at", required=True, help="Control-set seal time in RFC 3339 UTC.")
@click.option("--tool-name", default="reproassert", show_default=True)
@click.option("--tool-version", required=True)
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="New canonical private causal-control set.",
)
def benchmark_seal_v02_causal_controls(
    campaign_freeze: Path,
    preregistration: Path,
    controls_draft: Path,
    sealed_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
    output: Path,
) -> None:
    """Seal existing sandbox receipts; this command never runs a control or provider."""

    try:
        _ensure_private_output_root(output.parent)
        path = seal_v02_causal_control_set(
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
            controls_draft_path=controls_draft,
            output_path=output,
            sealed_at=sealed_at,
            tool_name=tool_name,
            tool_version=tool_version,
            tool_git_sha=tool_git_sha,
        )
        digest = verify_v02_causal_control_set(
            path,
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "causal_control_set": str(path),
                "causal_control_set_sha256": digest,
                "case_count": 20,
                "verification_scope": (
                    "structural_receipts_evidence_binding_deferred_to_finalization"
                ),
                "provider_invoked_by_this_command": False,
                "untrusted_code_executed_by_this_command": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-causal-controls")
@click.argument(
    "causal_control_set",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
)
@click.option(
    "--campaign-freeze",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--preregistration",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
def benchmark_verify_v02_causal_controls(
    causal_control_set: Path,
    campaign_freeze: Path,
    preregistration: Path,
) -> None:
    """Verify canonical control receipts without executing code or invoking a provider."""

    try:
        digest = verify_v02_causal_control_set(
            causal_control_set,
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "causal_control_set": str(causal_control_set),
                "causal_control_set_sha256": digest,
                "case_count": 20,
                "verified": True,
                "provider_invoked_by_this_command": False,
                "untrusted_code_executed_by_this_command": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("seal-v02-semantic-reviews")
@click.option(
    "--campaign-freeze",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--preregistration",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--reviews-draft",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Bounded JSON array of exactly 20 blinded multi-reviewer case bundles.",
)
@click.option("--sealed-at", required=True, help="Review-set seal time in RFC 3339 UTC.")
@click.option("--tool-name", default="reproassert", show_default=True)
@click.option("--tool-version", required=True)
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False),
    required=True,
    help="New canonical private semantic review set.",
)
def benchmark_seal_v02_semantic_reviews(
    campaign_freeze: Path,
    preregistration: Path,
    reviews_draft: Path,
    sealed_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
    output: Path,
) -> None:
    """Seal already-completed blinded attestations without opening evaluator results."""

    try:
        _ensure_private_output_root(output.parent)
        path = seal_v02_semantic_review_set(
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
            reviews_draft_path=reviews_draft,
            output_path=output,
            sealed_at=sealed_at,
            tool_name=tool_name,
            tool_version=tool_version,
            tool_git_sha=tool_git_sha,
        )
        digest = verify_v02_semantic_review_set(
            path,
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "semantic_review_set": str(path),
                "semantic_review_set_sha256": digest,
                "review_count": 20,
                "verification_scope": "structural_seals_candidate_binding_deferred_to_finalization",
                "provider_invoked_by_this_command": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("finalize-v02-campaign")
@click.option(
    "--campaign-freeze",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--preregistration",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--ledger",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Private canonical v0.2 event ledger.",
)
@click.option(
    "--attempts-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    required=True,
    help="Private root containing one directory per frozen case ID.",
)
@click.option(
    "--causal-control-set",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Complete sealed executed causal-control set for all 20 cases.",
)
@click.option(
    "--semantic-review-set",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Complete sealed blinded-review set for all 20 cases.",
)
@click.option(
    "--output-root",
    type=click.Path(path_type=Path, file_okay=False),
    required=True,
    help="Private directory for new finalization and releasable aggregate files.",
)
@click.option("--finalized-at", required=True, help="Finalization time in RFC 3339 UTC.")
@click.option("--tool-name", default="reproassert", show_default=True)
@click.option("--tool-version", required=True)
@click.option("--tool-git-sha", required=True, help="Exact 40-hex controller revision.")
def benchmark_finalize_v02_campaign(
    campaign_freeze: Path,
    preregistration: Path,
    ledger: Path,
    attempts_root: Path,
    causal_control_set: Path,
    semantic_review_set: Path,
    output_root: Path,
    finalized_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
) -> None:
    """Offline-finalize only after all candidates, costs, and reviews reconcile."""

    try:
        _ensure_private_output_root(output_root)
        result = finalize_v02_campaign(
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
            ledger_path=ledger,
            attempts_root=attempts_root,
            causal_control_set_path=causal_control_set,
            semantic_review_set_path=semantic_review_set,
            output_root=output_root,
            finalized_at=finalized_at,
            tool_name=tool_name,
            tool_version=tool_version,
            tool_git_sha=tool_git_sha,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "private_finalization": str(result.private_path),
                "public_aggregate": str(result.public_path),
                "public_aggregate_sha256": result.public_sha256,
                "provisional_candidate_count": result.provisional_candidate_count,
                "l2_semantic_valid_count": result.l2_semantic_valid_count,
                "review_semantic_valid_count": result.review_semantic_valid_count,
                "total_attributable_microusd": result.total_attributable_microusd,
                "provider_invoked_by_this_command": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("finalize-v02-exact-campaign")
@click.option(
    "--campaign-freeze",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--preregistration",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--ledger",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--attempts-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    required=True,
)
@click.option(
    "--causal-control-set",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--semantic-review-set",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option("--output-root", type=click.Path(path_type=Path, file_okay=False), required=True)
@click.option("--finalized-at", required=True)
@click.option("--tool-name", default="reproassert", show_default=True)
@click.option("--tool-version", required=True)
@click.option("--tool-git-sha", required=True)
@_exact_preregistration_evidence_options
def benchmark_finalize_v02_exact_campaign(
    campaign_freeze: Path,
    preregistration: Path,
    ledger: Path,
    attempts_root: Path,
    causal_control_set: Path,
    semantic_review_set: Path,
    output_root: Path,
    finalized_at: str,
    tool_name: str,
    tool_version: str,
    tool_git_sha: str,
    cases_preparation: Path,
    cohort_plan: Path,
    chronology: Path,
    hidden_extraction_receipt: Path,
    issue_responses_root: Path,
    mapping_preparation: Path,
    mapping_consensus: Path,
    capability_index: Path,
    instance_runtime_manifest: Path,
    expected_manifest_sha256: str,
    gold_smoke_receipt: Path,
) -> None:
    """Freshly rederive exact preregistration authority, then finalize fail-closed L2."""

    try:
        _ensure_private_output_root(output_root)
        exact = verify_v02_exact_preregistration(
            preregistration,
            cases_preparation_path=cases_preparation,
            cohort_plan_path=cohort_plan,
            chronology_path=chronology,
            hidden_extraction_receipt=hidden_extraction_receipt,
            issue_responses_root=issue_responses_root,
            mapping_preparation_path=mapping_preparation,
            mapping_consensus_path=mapping_consensus,
            capability_index_path=capability_index,
            runtime_manifest_path=instance_runtime_manifest,
            expected_runtime_manifest_sha256=expected_manifest_sha256,
            gold_smoke_receipt_path=gold_smoke_receipt,
        )
        result = finalize_v02_campaign(
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
            ledger_path=ledger,
            attempts_root=attempts_root,
            causal_control_set_path=causal_control_set,
            semantic_review_set_path=semantic_review_set,
            output_root=output_root,
            finalized_at=finalized_at,
            tool_name=tool_name,
            tool_version=tool_version,
            tool_git_sha=tool_git_sha,
            exact_preregistration=exact,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "private_finalization": str(result.private_path),
                "public_aggregate": str(result.public_path),
                "public_aggregate_sha256": result.public_sha256,
                "provisional_candidate_count": result.provisional_candidate_count,
                "l2_semantic_valid_count": result.l2_semantic_valid_count,
                "review_semantic_valid_count": result.review_semantic_valid_count,
                "total_attributable_microusd": result.total_attributable_microusd,
                "exact_preregistration_authority_rederived": True,
                "exact_l2_authority_mode": "fail_closed_without_live_control_authorities",
                "provider_invoked_by_this_command": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("verify-v02-finalization")
@click.option(
    "--campaign-freeze",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--preregistration",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--private-finalization",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--public-aggregate",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--ledger",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
    help="Private canonical v0.2 event ledger.",
)
@click.option(
    "--attempts-root",
    type=click.Path(path_type=Path, exists=True, file_okay=False),
    required=True,
)
@click.option(
    "--causal-control-set",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--semantic-review-set",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    required=True,
)
def benchmark_verify_v02_finalization(
    campaign_freeze: Path,
    preregistration: Path,
    private_finalization: Path,
    public_aggregate: Path,
    ledger: Path,
    attempts_root: Path,
    causal_control_set: Path,
    semantic_review_set: Path,
) -> None:
    """Rederive final artifacts from the complete private evidence bundle offline."""

    try:
        result = verify_v02_campaign_bundle(
            campaign_freeze_path=campaign_freeze,
            preregistration_path=preregistration,
            ledger_path=ledger,
            attempts_root=attempts_root,
            causal_control_set_path=causal_control_set,
            semantic_review_set_path=semantic_review_set,
            private_finalization_path=private_finalization,
            public_aggregate_path=public_aggregate,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "public_aggregate_sha256": result.public_sha256,
                "provisional_candidate_count": result.provisional_candidate_count,
                "l2_semantic_valid_count": result.l2_semantic_valid_count,
                "review_semantic_valid_count": result.review_semantic_valid_count,
                "total_attributable_microusd": result.total_attributable_microusd,
                "verified": True,
                "verification_scope": "full_bundle_rederived",
                "provider_invoked_by_this_command": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@benchmark_group.command("replay-v02-case")
@click.argument("bundle_path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--run-base",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_run_base,
    show_default="user state directory",
)
def benchmark_replay_v02_case(bundle_path: Path, run_base: Path) -> None:
    """Reacquire and replay one published exact-source v0.2 bundle."""

    try:
        result = run_v02_replay_bundle(bundle_path, run_base=run_base)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    click.echo(
        json.dumps(
            {
                "claim_level": result.claim_level,
                "failure_fingerprint": result.fingerprint,
                "model_or_provider_invoked": False,
                "outcome": result.outcome,
                "result_path": str(result.result_path),
                "run_dir": str(result.run_dir),
            },
            indent=2,
            sort_keys=True,
        )
    )


@main.command("schema")
@click.option(
    "name",
    "--name",
    type=click.Choice(sorted(SCHEMA_FILENAMES)),
    default="report",
    show_default=True,
)
def schema_command(name: str) -> None:
    """Print one exact JSON Schema bundled with the installed controller."""

    click.echo(schema_text(name), nl=False)


@main.command()
@click.option("--image", default=DEFAULT_IMAGE, show_default=True)
def doctor(image: str) -> None:
    """Check whether the strict sandbox boundary is ready."""

    status = DockerSandbox(SandboxPolicy(image=image)).doctor()
    table = Table(title="ReproAssert doctor", box=None, show_header=False)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_row("Docker CLI", _status(status.cli_available))
    table.add_row("Docker engine", _status(status.engine_available, status.server_version))
    table.add_row("Sandbox image", _status(status.image_available, status.image_id))
    table.add_row("Native fallback", "[green]disabled[/green]")
    console.print(table)
    if not (status.cli_available and status.engine_available and status.image_available):
        raise click.exceptions.Exit(1)


@main.group("sandbox")
def sandbox_group() -> None:
    """Manage the pinned local verifier image."""


@sandbox_group.command("build")
@click.option("--image", default=DEFAULT_IMAGE, show_default=True)
def sandbox_build(image: str) -> None:
    """Build the trusted pytest runner image from hash-locked inputs."""

    sandbox = DockerSandbox(SandboxPolicy(image=image))
    try:
        image_id = sandbox.build_image()
    except ReproAssertError as exc:
        _fail(exc)
    console.print(f"[green]Built[/green] {image}\n[dim]{image_id}[/dim]")


@sandbox_group.command("isolation-canary")
@click.option("--image", default=DEFAULT_IMAGE, show_default=True)
@click.option(
    "--tool-git-sha",
    help="Optional exact controller revision to bind into the receipt; no Git command is run.",
)
@click.option("--json-output", is_flag=True, help="Print the complete bounded receipt as JSON.")
def sandbox_isolation_canary(image: str, tool_git_sha: str | None, json_output: bool) -> None:
    """Run a standalone synthetic generator/evaluator mount-policy canary."""

    try:
        result = run_isolation_canary(
            DockerSandbox(SandboxPolicy(image=image)), tool_git_sha=tool_git_sha
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    _render_isolation_canary(result, json_output=json_output)
    if not result.accepted:
        raise click.exceptions.Exit(1)


@main.command("issue")
@click.argument("issue_url")
@click.option(
    "requested_ref",
    "--commit",
    default="HEAD",
    show_default=True,
    help="Full commit SHA or ref; ReproAssert records the exact 40-hex SHA.",
)
@click.option(
    "generator_command",
    "--generator-command",
    envvar="REPROASSERT_GENERATOR_COMMAND",
    help="Trusted JSON-protocol adapter command (never sourced from the issue).",
)
@click.option(
    "provider",
    "--provider",
    type=click.Choice(["openai"], case_sensitive=False),
    help="Explicitly use a built-in network provider. No provider is auto-selected.",
)
@click.option(
    "model",
    "--model",
    metavar="MODEL",
    help=f"Model for --provider openai (default: {DEFAULT_OPENAI_MODEL}).",
)
@click.option(
    "pass_env",
    "--pass-env",
    multiple=True,
    help="Explicit host environment name passed only to the trusted generator adapter.",
)
@click.option(
    "candidate_file",
    "--candidate-file",
    type=click.Path(path_type=Path, exists=True, dir_okay=False),
    help="Human-authored test content to verify instead of invoking a generator.",
)
@click.option("--expected-symptom", help="Required with --candidate-file.")
@click.option("--rationale", help="Required with --candidate-file.")
@click.option("--repeats", type=click.IntRange(2, 10), default=3, show_default=True)
@click.option(
    "--run-base",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_run_base,
    show_default="user state directory",
)
@click.option("--sandbox-image", default=DEFAULT_IMAGE, show_default=True)
@click.option("--json-output", is_flag=True, help="Print the final summary as JSON.")
def issue_command(
    issue_url: str,
    requested_ref: str,
    generator_command: str | None,
    provider: str | None,
    model: str | None,
    pass_env: tuple[str, ...],
    candidate_file: Path | None,
    expected_symptom: str | None,
    rationale: str | None,
    repeats: int,
    run_base: Path,
    sandbox_image: str,
    json_output: bool,
) -> None:
    """Generate one candidate test and verify it on an exact buggy commit."""

    try:
        location = parse_issue_url(issue_url)
        generator = _select_generator(
            issue_number=location.number,
            generator_command=generator_command,
            provider=provider,
            model=model,
            pass_env=pass_env,
            candidate_file=candidate_file,
            expected_symptom=expected_symptom,
            rationale=rationale,
        )
        sandbox = DockerSandbox(SandboxPolicy(image=sandbox_image))
        sandbox.require_ready()
        result = run_issue_workflow(
            issue_url,
            requested_ref=requested_ref,
            generator=generator,
            sandbox=sandbox,
            run_base=run_base,
            repeats=repeats,
        )
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    _render_result(result, json_output=json_output)
    if result.outcome != "repeatable_base_failure":
        raise click.exceptions.Exit(2)


@main.command("replay")
@click.argument("report_path", type=click.Path(path_type=Path, exists=True, dir_okay=False))
@click.option(
    "--run-base",
    type=click.Path(path_type=Path, file_okay=False),
    default=_default_run_base,
    show_default="user state directory",
)
@click.option("--sandbox-image", default=DEFAULT_IMAGE, show_default=True)
@click.option("--json-output", is_flag=True)
def replay_command(
    report_path: Path, run_base: Path, sandbox_image: str, json_output: bool
) -> None:
    """Replay bounded report data with controller-owned commands."""

    try:
        sandbox = DockerSandbox(SandboxPolicy(image=sandbox_image))
        sandbox.require_ready()
        result = run_replay_workflow(report_path, sandbox=sandbox, run_base=run_base)
    except (ReproAssertError, OSError, ValueError) as exc:
        _fail(exc)
    _render_result(result, json_output=json_output)
    if result.outcome != "repeatable_base_failure":
        raise click.exceptions.Exit(2)


def _select_generator(
    *,
    issue_number: int,
    generator_command: str | None,
    provider: str | None,
    model: str | None,
    pass_env: tuple[str, ...],
    candidate_file: Path | None,
    expected_symptom: str | None,
    rationale: str | None,
) -> CandidateGenerator:
    if model is not None and provider is None:
        raise ReproAssertError("generator_options", "--model requires --provider openai.")
    selected_sources = sum(
        (bool(generator_command), provider is not None, candidate_file is not None)
    )
    if selected_sources != 1:
        raise ReproAssertError(
            "generator_required",
            "Choose exactly one: --provider, --generator-command, or --candidate-file.",
        )
    if generator_command:
        if model or expected_symptom or rationale:
            raise ReproAssertError(
                "generator_options",
                "--model requires --provider; symptom options belong to --candidate-file.",
            )
        return CommandGenerator(generator_command, pass_env=pass_env)
    if provider:
        if pass_env:
            raise ReproAssertError("generator_options", "--pass-env requires --generator-command.")
        if expected_symptom or rationale:
            raise ReproAssertError(
                "generator_options",
                "--expected-symptom and --rationale belong to --candidate-file.",
            )
        if provider.casefold() != "openai":
            raise ReproAssertError("generator_provider", "Unsupported built-in provider.")
        return OpenAIResponsesGenerator(model=model or DEFAULT_OPENAI_MODEL)
    if pass_env:
        raise ReproAssertError("generator_options", "--pass-env requires --generator-command.")
    if not expected_symptom or not rationale or candidate_file is None:
        raise ReproAssertError(
            "candidate_options",
            "--candidate-file requires --expected-symptom and --rationale.",
        )
    candidate = candidate_from_file(
        candidate_file,
        issue_number=issue_number,
        expected_symptom=expected_symptom,
        rationale=rationale,
    )
    return StaticGenerator(candidate)


def _render_result(result: WorkflowResult, *, json_output: bool) -> None:
    if json_output:
        console.print_json(
            json.dumps(
                {
                    "claim_level": result.claim_level,
                    "outcome": result.outcome,
                    "report": str(result.report_path),
                    "patch": str(result.patch_path),
                    "replay": result.replay_command,
                }
            )
        )
        return
    accepted = result.outcome == "repeatable_base_failure"
    color = "green" if accepted else "yellow"
    title = "REPEATABLE BASE FAILURE" if accepted else "CANDIDATE REJECTED"
    console.print(
        Panel.fit(
            "\n".join(
                [
                    f"claim    {result.claim_level}",
                    f"outcome  {result.outcome}",
                ]
            ),
            title=f"[{color}]{title}[/{color}]",
            border_style=color,
        )
    )
    # Rich intentionally constrains panels to the detected terminal width. Artifact
    # paths are the durable output contract, so emit them through Click unchanged
    # rather than allowing a narrow terminal to replace them with an ellipsis.
    click.echo(f"patch    {result.patch_path}")
    click.echo(f"report   {result.report_path}")
    click.echo(f"replay   {result.replay_command}")


def _render_isolation_canary(result: IsolationCanaryResult, *, json_output: bool) -> None:
    payload = asdict(result)
    payload["accepted"] = result.accepted
    if json_output:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    table = Table(title="Generator / evaluator isolation canary", box=None, show_header=False)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_row("Positive evaluator control", _status(result.positive_control_passed))
    table.add_row("Generator sentinel absence", _status(result.negative_control_passed))
    table.add_row("Cleanup", _status(result.cleanup_succeeded))
    table.add_row("Image", f"[dim]{result.image_id}[/dim]")
    table.add_row("Receipt", f"[dim]{result.config_sha256}[/dim]")
    console.print(table)


def _ensure_private_output_root(path: Path) -> None:
    target = Path(path)
    try:
        target.mkdir(mode=0o700, parents=True)
    except FileExistsError:
        pass
    else:
        os.chmod(target, 0o700, follow_symlinks=False)
    require_private_directory(target)


def _status(ok: bool, detail: str | None = None) -> str:
    label = "[green]ready[/green]" if ok else "[red]not ready[/red]"
    return f"{label} [dim]{sanitize_log(detail or '')}[/dim]"


def _fail(error: BaseException) -> None:
    if isinstance(error, ReproAssertError):
        message = f"[{error.code}] {error.message}"
    else:
        message = str(error)
    raise click.ClickException(sanitize_log(message, max_chars=1_000))
