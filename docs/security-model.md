# Security model

Status: implemented local strict profile, reviewed 2026-07-10.

ReproAssert separates a trusted controller from hostile repository execution. The boundary is a
hardened Docker container; there is deliberately no native execution fallback. Static candidate
screening reduces obvious bad outcomes but is not the security boundary.

See [the threat model](threat-model.md) for adversaries and residual risks and
[the sandbox profiles](sandbox-profiles.md) for exact runtime controls.

## Evidence status

The policy and adversarial behavior are unit-tested. A live local integration run was also recorded
on 2026-07-09 using Docker Desktop 4.68.0, Engine 29.3.1, LinuxKit on arm64:

```text
REPROASSERT_RUN_DOCKER_TESTS=1 uv run --python 3.12 --extra dev \
  pytest tests/integration/test_docker_sandbox.py -q
1 passed in 22.78s
```

That fixture showed three consistent failures on the bundled buggy slug implementation and passes
on the bundled fixed implementation. It also exercised the Docker policy inspection performed
before verification. It does not prove resistance to container escapes, correctness on third-party
repositories, Linux-host parity, CI behavior, semantic validity, or production readiness.

On 2026-07-10, the standalone generator/evaluator canary also passed locally against the packaged
image. Its positive container read an evaluator-only sentinel, its generator-view container had
only `/workspace` and could not find the sentinel, the effective Docker policy matched the frozen
config, and cleanup completed. This is mount-policy evidence, not proof against a Docker or kernel
escape:

```text
reproassert sandbox isolation-canary --json-output
accepted: true
positive_control_passed: true
negative_control_passed: true
cleanup_succeeded: true
```

## Trust boundaries

| Component or data | Trust level | Treatment |
| --- | --- | --- |
| ReproAssert controller, installed package, runner image, Docker CLI and daemon | Trusted | A compromise here can defeat every other control. |
| Built-in OpenAI provider client | Trusted controller path plus remote service | Runs only after explicit selection, sends bounded issue/source context to fixed `api.openai.com`, and reads only `OPENAI_API_KEY`. |
| User-selected generator command | Trusted executable | Runs outside Docker with a cleared environment plus only explicitly passed variables. It receives issue and selected source context. |
| GitHub issue title/body | Hostile data | Size-bounded, labeled as untrusted in the generator protocol, never interpreted as setup or shell instructions. |
| Repository archive and files | Hostile data | Downloaded from a fixed host, manually extracted without links or special files, rewalked without following links, and bound to the commit root tree before generation. |
| Draft historical snapshot receipt and raw evidence | Controller-only producer-development input | Structural fields and byte commitments are checked, but raw-history revision/redaction derivation is not implemented. Default projection fails closed as `benchmark_snapshot_producer_unverified`; the fixture override cannot satisfy a campaign prerequisite. Current live issues are never a historical fallback. |
| Candidate test | Hostile executable code | Schema- and AST-screened, written only to a controller-selected test path, then executed only in Docker. |
| Repository pytest configuration, imports, `sitecustomize`, and `conftest.py` | Hostile executable code | May run inside Docker during collection or verification. |
| Pytest stdout and optional JUnit XML | Hostile evidence | Byte-bounded and terminal-sanitized. Optional XML is element-bounded and parsed with `defusedxml`; both forms are treated as forgeable. |
| Imported replay report | Hostile data | Size-, type-, URL-, SHA-, candidate-, and repeat-count validated. Command-like fields are ignored. |
| Generated report and patch | Controller output | Created exclusively in a private run directory; informative, not signed or remotely attested. |

## End-to-end flow

### 1. Public GitHub intake

The CLI accepts only an exact ASCII URL of the form:

```text
https://github.com/<owner>/<repository>/issues/<positive-integer>
```

It rejects alternate schemes, ports, credentials, queries, fragments, trailing path components,
encoded traversal shapes, and non-GitHub hosts. The controller constructs requests only for
`api.github.com` and `codeload.github.com`. Redirects are rejected. Its urllib opener has no proxy
or authentication handler and uses an explicit user agent. The controller constructs an explicit
TLS client context from Python/OpenSSL's compiled system trust paths, but the host TLS library, CA
store, process environment, resolver, and operating system remain trusted rather than attested.

Current intake limits are:

| Input | Limit |
| --- | ---: |
| Issue JSON | 1 MiB |
| Issue title | 4 KiB UTF-8 |
| Issue body | 64 KiB UTF-8 |
| Commit JSON | 512 KiB |
| Compressed source archive | 64 MiB |

A requested branch, tag, or `HEAD` is resolved through GitHub's commits API to a lowercase 40-hex
commit SHA. An already-full SHA is normalized locally so a large commit's API diff cannot exhaust
the bounded metadata response. The controller then reads the root tree OID from GitHub's bounded
Git-database commit endpoint and builds the codeload URL only from that exact SHA. Public unauthenticated GitHub
repositories are the only implemented source type; private repositories and GitHub Enterprise are
not supported.

### 2. Host-side source handling without execution

The controller creates an unpredictable run directory owned by the current user with mode `0700`.
Artifacts are opened relative to no-follow directory descriptors, created exclusively with mode
`0600`, and never overwrite an existing file or symlink.

The tar.gz archive is processed as a bounded stream. Extraction is manual; `extractall` is not used.
Only directories and regular files are accepted. Absolute paths, empty or dot components, `..`,
backslashes, control characters, symlinks, hardlinks, devices, FIFOs, duplicate paths, file/directory
collisions, case or Unicode-normalization collisions, and canonical `.git` aliases are rejected.
Current extraction limits independently cap 20,000 members, files, and directories, 64 MiB per
file, 256 MiB declared unpacked data, 4,096 path bytes, and 255 bytes per component. File
ownership, setuid, setgid, and archive directory modes are not restored; files become owner-only,
with only the owner executable bit preserved.

Before any source context or generator call, a second no-follow traversal revalidates file types,
paths, link counts, device boundaries, resource limits, and filesystem snapshots. It reconstructs
Git blob/tree object IDs from the accepted bytes and executable bits and requires the root tree to
match the exact commit metadata. It also records a versioned canonical SHA-256 digest that includes
directories, paths, modes, sizes, and content hashes. This still trusts GitHub, DNS/TLS, Git's SHA-1
identity model, the controller host, and the local filesystem implementation.

Source context generation reads regular text files without following final symlinks. It exposes at
most 5,000 manifest names, 96 KiB of selected context, and 16 KiB from any one file. Names matching a
secret-like heuristic remain visible in the manifest but their contents are skipped. This is a
public-repository safeguard, not secret scanning or data-loss prevention.

### 3. Generation outside the repository sandbox

The generator protocol sends bounded issue data, the exact source SHA, and selected source context
as JSON. It labels issue text as `untrusted_data_not_instructions` and states that commands, network,
production edits, and unconditional failures are not allowed in the returned candidate.

The command adapter is controller-side trusted code. Its executable is resolved to an absolute path,
invoked with an argv array rather than a shell, receives only `LANG`, `LC_ALL`, and variables named by
`--pass-env`, has a default 300-second timeout, and can return at most 64 KiB. It is not sandboxed: it
can use its own filesystem and network privileges. Never point `--generator-command` at repository
code or an executable supplied by an issue author.

The built-in OpenAI path is separate and opt in. Merely setting `OPENAI_API_KEY` does not activate it;
the user must select `--provider openai`, which is mutually exclusive with command and manual
candidates. The controller then sends the issue URL/title/body, exact SHA, source manifest and
selected source file contents, candidate contract, attempt, and feedback to the fixed
`api.openai.com/v1/responses` endpoint. It accepts no base URL, proxy, redirect, or key CLI argument.
The standard-library HTTPS request reads the key only from `OPENAI_API_KEY`, sets `store: false`, has
a 120-second timeout and no automatic retry, and bounds the request, response, output tokens, and
extracted output text. These controls limit accidental disclosure and spend; they do not make prompt
instructions a security boundary or replace the user's OpenAI account and data-handling policies.

### 4. Candidate policy

Generator output must contain exactly `test_content`, `expected_symptom`, and `rationale`. The
controller chooses the test filename and function name. It permits one synchronous pytest function,
requires the symptom text in the assertion evidence, caps test content at 32 KiB, and rejects syntax
errors, unconditional false assertions, explicit raises, obvious infinite loops, skip/xfail behavior,
blocked network/process modules and calls, dangerous import aliases, and non-literal top-level
assignments. Literal top-level test data remains allowed.

This is defense in depth, not a proof that code is harmless. Python is dynamic and repository import
hooks run before or alongside the candidate. Every accepted candidate still runs as hostile code in
Docker.

### 5. Verification

The extracted source and candidate are copied into a controller-owned Docker volume. The verification
container receives that volume read-only and no host bind mounts. It first collects the exact
controller-owned pytest node and then executes it two to ten times, three by default. The controller
rejects collection/setup errors, missing tests, passes, inconsistent exit codes or fingerprints,
timeouts, OOM kills, output overflow, non-pytest exits, errors, skips, multiple failures, wrong test
names, and missing symptom evidence.

The runner requests bounded JUnit XML as an optional hostile hint. In the current Docker path that
file is written under `/tmp`; Docker's tmpfs is no longer available to `docker cp` after the stopped
container's mounts are released. When XML is unavailable, the verifier conservatively classifies
bounded pytest stdout: it requires the exact node marker, one failed test, expected symptom text,
and a stable normalized fingerprint across every repeat. Missing XML alone is therefore not a
rejection. Repository code can forge either evidence channel, so neither is an attestation.

Acceptance as `repeatable_base_failure` means only that the recorded candidate collected and produced
one consistent issue-marked failure on every buggy-base run. It is not a hidden-fix differential,
root-cause proof, semantic-validity judgment, or maintainer acceptance.

### 6. Reports and replay

Reports are JSON capped at 1 MiB. They record source and archive hashes, candidate content and hash,
runner image identity, requested policy, bounded sanitized output, phases, repeat outcomes, and
limitations. JUnit XML is not copied into the final report. Reports are not signed; hashes detect
internal mismatch but do not authenticate the author.

Replay treats the report as data. It accepts only a bounded regular non-symlink file, revalidates the
canonical issue URL and repository match, exact source SHA, candidate schema and hash, and repeat
count. It ignores all report command fields, downloads the exact source from fixed GitHub hosts, and
regenerates pytest argv from controller code. Replay does not trust or reuse the report's runner
image, Docker policy, displayed command, result, or claim level.

## Secret handling

The strict Docker environment is constructed with `/usr/bin/env -i`; host variables, proxy settings,
GitHub tokens, SSH agents, cloud credentials, and Docker sockets are not mounted or forwarded. Docker
control commands receive only `LANG`, `LC_ALL`, and a minimal `PATH`. Public intake uses no GitHub
credential.

Exceptions are explicit: the built-in OpenAI path reads `OPENAI_API_KEY` and sends the documented
context to the fixed provider endpoint; a trusted command generator receives variables selected with
`--pass-env`; the Docker CLI/daemon may use host-side configuration to find its engine and images;
and reports contain the issue title, candidate, selected evidence, and paths. Users must review those
surfaces and the residual risks in [the threat model](threat-model.md).
