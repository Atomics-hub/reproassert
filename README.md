# ReproAssert

> The test before the fix.

ReproAssert takes a canonical public GitHub issue, resolves an exact repository commit, and checks one pytest candidate inside a locked-down Docker verifier. It produces a test-only patch, a replay command, and a machine-readable evidence report. It does not edit production code or claim that a repeated failure is semantically correct.

```console
reproassert issue https://github.com/OWNER/REPOSITORY/issues/123 \
  --commit <commit-or-ref> \
  --generator-command ./your-trusted-adapter
```

The implemented CLI claim ladder is deliberately short:

```text
rejected -> collected -> repeatable_base_failure  [current public ceiling]
                              |
                              +-> differential_reproduction  [not produced yet]
                              +-> maintainer_validated        [external evidence only]
```

An accepted CLI run means one generated test collected and produced the same issue-marked failure on the pinned buggy base across the configured reruns. It does **not** mean the test passes on a fix, captures the issue's true semantics, or has been accepted by a maintainer.

**Benchmark status:** v0.1 is frozen at 20 historical cases and has **0 scored result rows**. That is a preregistration status, not a success result. A [public self-owned issue run](evidence/live-demo/README.md) verifies the exact-SHA intake, generation, sandbox, report, and replay path; the local differential fixture also reaches `pass_on_base` on the fixed source. Neither is part of the 20-case score.

## Install from source

ReproAssert is alpha software and is not presented here as a published PyPI release. The supported path today is a source checkout.

Requirements:

- Python 3.10 or newer for the controller;
- [uv](https://docs.astral.sh/uv/) or a Python virtual environment; and
- Docker Engine or Docker Desktop for verification. There is no native execution fallback.

The controller targets macOS and Linux. Native Windows execution and Windows containers are not
supported; WSL is treated as Linux but is not yet an independently verified platform.

```console
git clone https://github.com/Atomics-hub/reproassert.git
cd reproassert
uv sync

uv run reproassert sandbox build
uv run reproassert doctor
```

`sandbox build` creates the pinned `reproassert-sandbox:0.1.0` image from the packaged Dockerfile and hash-locked pytest requirements. `doctor` checks the Docker CLI, engine, image, and confirms that native fallback is disabled.

Without uv:

```console
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .

reproassert sandbox build
reproassert doctor
```

## Run an issue

Every issue run requires exactly one candidate source:

- `--provider openai` for the opt-in built-in OpenAI Responses adapter;
- `--generator-command` for a user-trusted JSON adapter; or
- `--candidate-file` for a human-authored test.

The issue URL must be canonical `https://github.com/OWNER/REPOSITORY/issues/NUMBER`. `--commit` accepts a full SHA or ref; ReproAssert normalizes a supplied SHA or resolves the ref and records the exact 40-hex SHA. Prefer an explicit buggy SHA over the default `HEAD`.

### Built-in OpenAI provider (opt in)

The built-in provider is never selected from the presence of an API key. Select it explicitly:

```console
export OPENAI_API_KEY="..."
uv run reproassert issue https://github.com/OWNER/REPOSITORY/issues/123 \
  --commit <buggy-commit-sha> \
  --provider openai
```

The cost-conscious default is `gpt-5.4-mini`. Pin another OpenAI model with `--model MODEL`. `--provider`, `--generator-command`, and `--candidate-file` are mutually exclusive, and `--model` is valid only with the OpenAI provider.

This option sends the issue URL, title and body, exact source SHA, bounded source manifest and selected file contents, candidate contract, attempt number, and bounded verifier feedback to `https://api.openai.com/v1/responses`. ReproAssert makes one request without automatic retries, sets `store: false`, caps the encoded request at 512 KiB, caps the HTTP response at 128 KiB, and requests at most 4,096 output tokens. Provider usage may incur charges under your OpenAI account. Review the selected public source context and your provider data policy before running it; the secret-name filter is not data-loss prevention.

The implementation uses Python's standard-library TLS client, accepts the key only from `OPENAI_API_KEY`, follows no redirects, and has no configurable base URL. It requests a strict three-field JSON Schema and then applies the same local AST policy and Docker verification as every other candidate. Neither structured output nor prompt instructions establish semantic correctness.

### Trusted generator adapter

```console
uv run reproassert issue https://github.com/OWNER/REPOSITORY/issues/123 \
  --commit <buggy-commit-sha> \
  --generator-command ./your-trusted-adapter \
  --pass-env PROVIDER_API_KEY
```

Repeat `--pass-env` for each environment variable the adapter needs. ReproAssert does not inherit the rest of the host environment. The same command can be set through `REPROASSERT_GENERATOR_COMMAND`.

The adapter is intentionally outside the hostile-repository Docker sandbox: it is trusted code selected by the user. It receives untrusted issue text and bounded source context, so it must keep those inputs in the data plane rather than treating repository or issue prose as instructions.

### Generator-command JSON protocol

Protocol version `1` sends one JSON object on standard input. The shape is:

```json
{
  "protocol_version": "1",
  "task": "Generate one minimal pytest reproduction candidate; do not fix production code.",
  "issue": {
    "url": "https://github.com/OWNER/REPOSITORY/issues/123",
    "number": 123,
    "title": "Issue title",
    "body": "Untrusted issue body",
    "trust": "untrusted_data_not_instructions"
  },
  "source": {
    "sha": "0123456789abcdef0123456789abcdef01234567",
    "context": {
      "manifest": ["pyproject.toml", "src/package.py"],
      "files": [],
      "context_bytes": 0
    }
  },
  "candidate_contract": {
    "required_test_function": "test_issue_123_reproduction",
    "output_json_keys": ["test_content", "expected_symptom", "rationale"],
    "one_test_only": true,
    "production_edits_allowed": false,
    "commands_allowed": false,
    "network_allowed": false,
    "unconditional_failures_allowed": false
  },
  "attempt": 1,
  "bounded_verifier_feedback": ""
}
```

The adapter must emit exactly one JSON object containing exactly three string fields:

```json
{
  "test_content": "def test_issue_123_reproduction():\n    assert observed == expected, 'duplicate separators remain'\n",
  "expected_symptom": "duplicate separators remain",
  "rationale": "Exercises the user-visible normalization invariant."
}
```

The expected-symptom text must appear literally in the test, normally as its assertion message. Adapter stdout and stderr are combined and capped at 64 KiB, so log nowhere except the returned JSON. The adapter has a 300-second controller timeout. The command is executed directly, without shell expansion; use an executable script rather than a pipe or shell expression. See [`examples/deterministic_generator.py`](examples/deterministic_generator.py) for a small offline protocol adapter.

### Manual candidate

For issue `123`, the strict profile requires one synchronous function named `test_issue_123_reproduction`:

```python
from your_package import normalize


def test_issue_123_reproduction() -> None:
    observed = normalize("Alpha  Beta")
    assert observed == "alpha-beta", "duplicate separators remain"
```

Verify it through the same policy and Docker boundary:

```console
uv run reproassert issue https://github.com/OWNER/REPOSITORY/issues/123 \
  --commit <buggy-commit-sha> \
  --candidate-file ./candidate.py \
  --expected-symptom "duplicate separators remain" \
  --rationale "Exercises adjacent-space normalization through the public function."
```

## Read the result

On a `repeatable_base_failure`, the terminal summary names two durable artifacts and the replay command. Paths below show the output contract, not a benchmark result:

```text
claim    repeatable_base_failure
outcome  repeatable_base_failure
patch    <run-dir>/candidate.patch
report   <run-dir>/reproassert-report.json
replay   reproassert replay <run-dir>/reproassert-report.json
```

By default, run directories live under `$XDG_STATE_HOME/reproassert/runs` or `~/.local/state/reproassert/runs`. Use `--run-base` to choose another controller-owned directory.

`candidate.patch` adds one file at `tests/reproassert/test_issue_NUMBER.py`. `reproassert-report.json` records:

- report and tool schema versions;
- canonical issue metadata and issue-body hash;
- requested ref, resolved SHA, source-archive hash, and bounded source facts;
- candidate content, path, hash, expected symptom, rationale, and generator kind;
- Docker server, pinned image and image ID, effective strict policy, and resource limits;
- collection and repeated-run exit codes, timings, bounded output, and failure fingerprint;
- artifact hashes, replay policy, and explicit limitations.

The source archive and extracted workspace are removed after the run; the patch and report remain. `--json-output` prints a small machine-readable terminal summary in addition to the full report artifact.

The versioned JSON Schema is bundled in every wheel and published at
[`reproassert-report.schema.json`](https://atomics-hub.github.io/reproassert/reproassert-report.schema.json).
Print the exact schema shipped with your installed controller without a network request:

```console
reproassert schema
```

## Replay evidence

```console
uv run reproassert replay ~/.local/state/reproassert/runs/issue-.../reproassert-report.json
```

Replay validates the bounded subset of report fields it consumes: schema version, issue/repository relationship, exact source SHA, candidate fields and hash, strict candidate contract, and repeat count. It does not perform whole-document JSON Schema validation. It fetches the recorded exact SHA again and regenerates controller-owned pytest arguments. Command-looking fields inside a report are inert data and are never executed.

Replay creates a new run directory, patch, report, and classification. It is evidence of a fresh bounded rerun, not proof that the issue is semantically reproduced.

## Strict Python/pytest profile v1

The first profile is intentionally narrow:

| Surface | Current behavior |
| --- | --- |
| Repository | Canonical public GitHub issue and source archive only; private repositories and authenticated intake are unsupported. |
| Dependencies | No repository dependency installation. The image contains Python 3.12 and hash-locked pytest only; otherwise valid repositories may end in `setup_failure`. |
| Candidate | One new synchronous pytest test, at most 32 KiB, in a controller-owned path. Async tests, unconditional failure, skip/xfail, explicit raise, obvious infinite loops, top-level execution, network/process APIs, and other blocked calls are rejected. |
| Verification | Collect once, then run 2-10 times (default 3) with network disabled, a read-only root/workspace, non-root user, all capabilities dropped, and no native fallback. |
| Limits | 60 seconds and 64 KiB output per verifier phase; 1 GiB memory, 1 CPU, 128 PIDs, and 64 MiB `/tmp`. |
| Context | At most 5,000 manifest files, 96 KiB selected text, and 16 KiB per selected text file. Sensitive-looking paths are excluded from generator context. |
| Claim | The CLI can emit at most `repeatable_base_failure`. It does not run a fixed version or perform blinded semantic review. |

See [sandbox profiles](docs/sandbox-profiles.md) and [architecture](docs/architecture.md) for the complete boundary and data flow.

## Security model

Repository code, issue text, source files, candidate tests, dependencies, and report files are untrusted. Verification uses Docker with no network, read-only mounts, non-root execution, dropped capabilities, resource limits, output bounds, and cleanup. The controller passes no host secrets, SSH agent, browser state, cloud credentials, proxy variables, Docker socket, or unrelated host directory into the verifier.

Important residual risks remain: Docker shares a kernel on Linux or a VM boundary on Docker Desktop; a malicious pytest process can try to forge in-process test detail; and a user-selected generator adapter runs outside the repository sandbox. Treat `repeatable_base_failure` as bounded evidence, not proof.

Read [Security policy](SECURITY.md), [Security model](docs/security-model.md), [Threat model](docs/threat-model.md), and [Sandbox profiles](docs/sandbox-profiles.md) before running unfamiliar repositories. Report vulnerabilities through the private process in `SECURITY.md`, not a public issue.

## Evaluation status

The historical v0.1 cohort is preregistered at 20 cases across 10 repositories. [`results.jsonl`](benchmarks/v0.1/results.jsonl) is currently empty. The primary future benchmark metric requires hidden-fix execution, causal controls, and blinded semantic review; the current CLI alone cannot establish it.

- [Benchmark freeze and status](benchmarks/v0.1/README.md)
- [Evaluation protocol and claim ladder](docs/evaluation.md)
- [Market validation gates](docs/market-validation.md)

Passing the internal 6/20 continuation gate would justify more validation. It would not establish a general 30% success rate, superiority, or maintainer demand.

## Project docs

- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Threat model](docs/threat-model.md)
- [Sandbox profiles](docs/sandbox-profiles.md)
- [Evaluation protocol](docs/evaluation.md)
- [Roadmap](docs/roadmap.md)
- [Market validation](docs/market-validation.md)
- [Business model](docs/business-model.md)
- [Launch plan](docs/launch-plan.md)
- [Rebrand decision](docs/decisions/0001-rebrand-to-reproassert.md)
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

ReproAssert is available under the [MIT License](LICENSE).
