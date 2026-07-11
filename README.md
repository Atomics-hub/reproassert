# ReproAssert

> The test before the fix.

ReproAssert takes a canonical public GitHub issue, resolves an exact repository commit, proves the
downloaded files reconstruct that commit's Git root tree, and checks one pytest candidate inside a
locked-down Docker verifier. It produces a test-only patch, a replay command, and a machine-readable
evidence report. It does not edit production code or claim that a repeated failure is semantically
correct.

```console
reproassert issue https://github.com/OWNER/REPOSITORY/issues/123 \
  --commit <commit-or-ref> \
  --generator-command ./your-trusted-adapter
```

The public issue/replay claim ladder is deliberately short:

```text
rejected -> collected -> repeatable_base_failure  [current public ceiling]
                              |
                              +-> differential_reproduction  [capability-gated primitive only]
                              +-> maintainer_validated        [external evidence only]
```

An accepted CLI run means one generated test collected and produced the same issue-marked failure on the pinned buggy base across the configured reruns. It does **not** mean the test passes on a fix, captures the issue's true semantics, or has been accepted by a maintainer.

**Benchmark status:** v0.1 remains immutable at **0/20** because of its
[provenance erratum](benchmarks/v0.1/ERRATA.md). The replacement v0.2 selection is now frozen at 20
leak-audited cases from the pinned upstream dataset. Its exact Git object graph and Parquet parser
boundary are independently attested, but its issue text is honestly labeled
`dataset_snapshot_at_pinned_commit`, `chronology_unproven`, and
`historical_public_contamination_exposed`. The scored runner, pre-inference pricing and
authorization barrier, executed causal controls, two-reviewer/tie-break consensus, and bounded
publication verifier are implemented and default-deny. Authentic model results and maintainer
validations remain **0/20** and **0**, respectively. No scored model spend or outreach has occurred.

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
uv run reproassert sandbox isolation-canary
```

`sandbox build` creates the pinned `reproassert-sandbox:0.1.0` image from the packaged Dockerfile and
hash-locked pytest requirements. The controller resolves that tag once and uses the immutable image
ID for staging and execution; a later tag change is rejected. `doctor` checks the Docker CLI, engine,
image, and confirms that
native fallback is disabled. `sandbox isolation-canary` runs a standalone synthetic mount-policy
check: its positive container reads an evaluator-only sentinel while its separate generator-view
container must not mount or find it. This is not yet the production benchmark generator path and
does not flip campaign readiness. Add `--json-output` for its bounded receipt and optionally
`--tool-git-sha` to bind an exact controller revision without invoking Git.

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

`candidate.patch` adds one file at `tests/reproassert/test_issue_NUMBER.py`. Before execution, the
controller revalidates the candidate, copies the pristine source, requires the reserved candidate
directory to be absent, applies exactly that one test, attests the candidate-applied tree, and then
attests the staged Docker volume against it. `reproassert-report.json` records:

- report and tool schema versions;
- canonical issue metadata and issue-body hash;
- requested ref, resolved SHA, archive hash/size, Git root-tree OID, independent canonical tree
  SHA-256, candidate-applied executed-tree SHA-256, no-Git-metadata result, and bounded source facts;
- candidate content, path, hash, expected symptom, rationale, and generator kind;
- Docker server, pinned image and image ID, effective strict policy, and resource limits;
- collection and repeated-run exit codes, timings, bounded output, and failure fingerprint;
- artifact hashes, replay policy, and explicit limitations.

The source archive and extracted workspace are removed after the run; the patch and report remain. `--json-output` prints a small machine-readable terminal summary in addition to the full report artifact.

The versioned JSON Schema is bundled in every wheel and published at
[`reproassert-report.schema.json`](https://atomics-hub.github.io/reproassert/reproassert-report.schema.json).
New reports use schema 1.1 and require the candidate-applied `executed_tree_sha256`; replay retains
bounded backward support for schema-1.0 reports without inventing that missing historical evidence.
Print the exact schema shipped with your installed controller without a network request:

```console
reproassert schema
```

## Replay evidence

```console
uv run reproassert replay ~/.local/state/reproassert/runs/issue-.../reproassert-report.json
```

Replay validates the bounded subset of report fields it consumes. It fetches the exact commit
metadata and archive again, requires the archive hash to match, reconstructs the Git tree, compares
the recorded canonical tree digest when present, and regenerates controller-owned pytest arguments.
It does not execute command-looking report fields or treat whole-document JSON Schema validation as
an execution boundary.

Replay creates a new run directory, patch, report, and classification. It is evidence of a fresh bounded rerun, not proof that the issue is semantically reproduced.

Published v0.2 cases use a stricter bundle-backed replay path:

```console
uv run reproassert benchmark replay-v02-case path/to/reproassert-v02-replay-bundle.json
```

The bundle self-binds the exact repository SHA, Git root tree, canonical source-tree digest,
candidate bytes, expected failure fingerprint, a publisher-declared controller revision, and—when
required—the complete hash-locked wheel plan, installed dependency-tree digest, and immutable
runner image ID. The declared revision is recorded but is not authenticated against the installed
controller. Replay accepts only ReproAssert's packaged trusted runner tag, reacquires the source,
rebuilds dependencies with network limited to the download phase, disables network for installation
and pytest, and rejects any mismatch. Its self-hashed result records collection plus every repeated
run's bounded argv, duration, exit state, output digest, and JUnit digest. It never invokes a model
provider.

Before a scored campaign, the private preparation lane can materialize and independently rederive
the frozen dataset inputs without making a provider call:

```console
reproassert benchmark prepare-v02-dataset --help
reproassert benchmark verify-v02-dataset --help
reproassert benchmark prepare-v02-object-source --help
reproassert benchmark verify-v02-object-source --help
```

Dataset preparation writes a self-hashed receipt, the attested parser receipt, and exactly 20
generator-safe projections inside a controller-owned `0700` directory outside every Git checkout.
Verification reruns the exact no-network parser and byte-compares every projection. The projections
remain explicitly `chronology_unproven`; none of these commands exposes paid execution or changes
campaign readiness.

The exact bundle and result schemas are published at
[`benchmark-v02-replay-bundle.schema.json`](https://atomics-hub.github.io/reproassert/benchmark-v02-replay-bundle.schema.json)
and
[`benchmark-v02-replay-result.schema.json`](https://atomics-hub.github.io/reproassert/benchmark-v02-replay-result.schema.json).

## Strict Python/pytest profile v1

The first profile is intentionally narrow:

| Surface | Current behavior |
| --- | --- |
| Repository | Canonical public GitHub issue and source archive only; private repositories and authenticated intake are unsupported. |
| Dependencies | Ordinary `issue`/`replay` remains dependency-free. `benchmark replay-v02-case` rebuilds only a published, canonical, hash-locked wheel plan in the causal executor, then mounts the attested installed tree read-only with network disabled. |
| Candidate | One new synchronous pytest test, at most 32 KiB, in a controller-owned path. Async tests, unconditional failure, skip/xfail, explicit raise, obvious infinite loops, top-level execution, network/process APIs, and other blocked calls are rejected. |
| Verification | Collect once, then run 2-10 times (default 3) with network disabled, a read-only root/workspace, non-root user, all capabilities dropped, and no native fallback. |
| Limits | 60 seconds and 64 KiB output per verifier phase; 1 GiB memory, 1 CPU, 128 PIDs, and 64 MiB `/tmp`. |
| Context | At most 5,000 manifest files, 96 KiB selected text, and 16 KiB per selected text file. Sensitive-looking paths are excluded from generator context. |
| Claim | The CLI can emit at most `repeatable_base_failure`. It does not run a fixed version or perform blinded semantic review. |

See [sandbox profiles](docs/sandbox-profiles.md) and [architecture](docs/architecture.md) for the complete boundary and data flow.

## Security model

Repository code, issue text, source files, candidate tests, dependencies, and report files are
untrusted. Archive paths/types are checked twice and the accepted files must reconstruct the exact
commit tree before generation. Verification uses Docker with no network, read-only mounts, non-root
execution, dropped capabilities, resource limits, output bounds, and label-verified cleanup. JUnit is
read through a separate inspected, resource-bounded result-volume anchor; it remains hostile and
forgeable evidence. The controller passes no host secrets, SSH agent, browser state, cloud
credentials, proxy variables, Docker socket, or unrelated host directory into the verifier.

Important residual risks remain: Docker shares a kernel on Linux or a VM boundary on Docker Desktop; a malicious pytest process can try to forge in-process test detail; and a user-selected generator adapter runs outside the repository sandbox. Treat `repeatable_base_failure` as bounded evidence, not proof.

Read [Security policy](SECURITY.md), [Security model](docs/security-model.md), [Threat model](docs/threat-model.md), and [Sandbox profiles](docs/sandbox-profiles.md) before running unfamiliar repositories. Report vulnerabilities through the private process in `SECURITY.md`, not a public issue.

## Evaluation status

The historical v0.1 cohort is preregistered at 20 cases across 10 repositories. [`results.jsonl`](benchmarks/v0.1/results.jsonl) is currently empty. The v0.2 primary metric requires hidden-fix execution, executed causal controls, and blinded semantic review; the ordinary issue CLI alone cannot establish it.

The [v0.2 draft](benchmarks/v0.2-draft/README.md) replaces the unsupported chronology claim with a
frozen dataset-snapshot mode. A network-disabled, resource-bounded parser container derives the
20-case selection from pinned upstream objects; raw host-native preparation cannot mint semantic
evidence. Exact source, dependency, hidden-fix, isolation, reviewer-role, request, pricing, and
authorization commitments are bound before any provider-capable call. The cohort is
selection-frozen but not yet scored: **0/20 runs, 0/20 L1, 0/20 L2, and zero maintainer validations**.

The preparation-only dependency executor now creates fresh labeled tmpfs volumes, runs fixed
networked-download and offline-install phases under the immutable runner image ID, attests the
wheelhouse and installed tree, issues a typed read-only borrow handle, and emits a canonical receipt
that an independent strict verifier recomputes and cross-binds to the plan, tree, image, phase
commands, and cleanup policy. Real local Docker checks passed the pinned PyPI `six==1.17.0` download,
offline install, typed verifier borrow, and inode-quota `ENOSPC` canary. This is execution-boundary
evidence, not a prepared benchmark case: campaign-ready dependency/evaluator packages remain 0/20.

Exact-source preparation is available independently and makes no model call:

```console
reproassert benchmark prepare-source rk-v0.1-018 \
  --manifest benchmarks/v0.1/manifest.json \
  --tool-git-sha <exact-controller-git-sha>
```

See the [benchmark preparation commands](benchmarks/v0.1/README.md#exact-source-preparation-no-model-call).
They preserve archives in private user state, re-fetch commit metadata during verification, and
never change campaign readiness automatically.

The first no-model preparation pass accepted and independently reverified 16/20 frozen sources;
four failed closed on a gitlink, tracked symlinks, or codeload byte substitution. See the
[source-preparation baseline](benchmarks/v0.1/source-preparation-baseline.json). This is preparation
compatibility evidence, not a reproduction score.

The follow-up exact-object path treats codeload only as bulk transport, reconstructs Git trees,
repairs only planned blob OIDs, confines tracked symlinks, and leaves gitlinks uninitialized:

```console
reproassert benchmark prepare-object-source rk-v0.1-018 \
  --manifest benchmarks/v0.1/manifest.json \
  --tool-git-sha <exact-controller-git-sha>
```

Its recorded no-model baseline accepted and freshly reverified all 20/20 sources, including the four
previous compatibility failures; median local preparation was 3.533 seconds. See the
[object-source baseline](benchmarks/v0.1/object-source-preparation-baseline.json). The receipts and
archives remain private, no object-source index exists, and this does not unblock generation,
establish reproduction accuracy, or authorize spend.

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
- [Exact Git-object decision](docs/decisions/0006-repair-codeload-from-git-objects.md)
- [Causal dependency preparation gate](docs/decisions/0007-dependency-preparation-remains-a-gated-prototype.md)
- [Capability-gated differential evaluation](docs/decisions/0008-capability-gated-differential-evaluation.md)
- [Rebrand decision](docs/decisions/0001-rebrand-to-reproassert.md)
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

ReproAssert is available under the [MIT License](LICENSE).
