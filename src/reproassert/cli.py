from __future__ import annotations

import json
import os
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reproassert import __version__
from reproassert.errors import ReproAssertError
from reproassert.generator import (
    DEFAULT_OPENAI_MODEL,
    CandidateGenerator,
    CommandGenerator,
    OpenAIResponsesGenerator,
    StaticGenerator,
)
from reproassert.intake import parse_issue_url
from reproassert.safeio import sanitize_log
from reproassert.sandbox import DEFAULT_IMAGE, DockerSandbox, SandboxPolicy
from reproassert.schema import report_schema_text
from reproassert.workflow import (
    WorkflowResult,
    candidate_from_file,
    run_issue_workflow,
    run_replay_workflow,
)

console = Console()
error_console = Console(stderr=True)


def _default_run_base() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "reproassert" / "runs"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="reproassert")
def main() -> None:
    """The test before the fix: generate and verify failing pytest candidates."""


@main.command("schema")
def schema_command() -> None:
    """Print the bundled ReproAssert report JSON Schema."""

    click.echo(report_schema_text(), nl=False)


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


@main.command("issue")
@click.argument("issue_url")
@click.option(
    "requested_ref",
    "--commit",
    default="HEAD",
    show_default=True,
    help="Commit or ref; GitHub resolves and records the exact 40-hex SHA.",
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
                    f"patch    {result.patch_path}",
                    f"report   {result.report_path}",
                    f"replay   {result.replay_command}",
                ]
            ),
            title=f"[{color}]{title}[/{color}]",
            border_style=color,
        )
    )


def _status(ok: bool, detail: str | None = None) -> str:
    label = "[green]ready[/green]" if ok else "[red]not ready[/red]"
    return f"{label} [dim]{sanitize_log(detail or '')}[/dim]"


def _fail(error: BaseException) -> None:
    if isinstance(error, ReproAssertError):
        message = f"[{error.code}] {error.message}"
    else:
        message = str(error)
    raise click.ClickException(sanitize_log(message, max_chars=1_000))
