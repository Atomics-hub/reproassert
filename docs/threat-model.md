# Threat model

Status: current local strict profile, reviewed 2026-07-10.

This model assumes an attacker can fully control a public GitHub issue, the referenced repository at
the selected commit, repository configuration, imports and tests, the generated candidate, or an
imported replay report. It does not assume the ReproAssert controller, installed runner image,
Docker daemon, host kernel, or host administrator is already compromised.

## Assets

- host files, processes, devices, browser state, SSH agents, Docker socket, cloud credentials, API
  keys, GitHub tokens, and model-provider credentials;
- integrity of the source SHA, candidate patch, report, claim level, and replay behavior;
- availability of the host and Docker daemon, including CPU, memory, disk, inodes, PIDs, file
  descriptors, and logs;
- isolation between runs and, in a future hosted system, between tenants;
- privacy of issue/source context sent to a generator or stored in a report; and
- maintainer trust: a wrong-reason failure must not be presented as semantic correctness.

## Adversaries and entry points

| Adversary-controlled surface | Examples |
| --- | --- |
| Issue author | Prompt injection, copied shell commands, huge text, misleading expected behavior, malicious links |
| Repository commit | Import hooks, pytest plugins, `conftest.py`, `sitecustomize.py`, native code, fork bombs, output floods, forged JUnit |
| Candidate generator output | Production edits, unconditional failure, network/process calls, skip/xfail, top-level execution, deceptive assertions |
| Source archive | Traversal, absolute paths, `.git` aliases, links, devices, FIFOs, bombs, duplicate/case-colliding paths, or bytes inconsistent with the declared commit tree |
| Imported report | Command fields, alternate repository, malformed SHA, candidate substitution, huge JSON, symlink path |
| Dependency or runner supply chain | Malicious image layer, base image, Python package, registry, or mutable local tag |
| Local operator configuration | Remote Docker context, untrusted generator command, explicit network provider, passed secrets, compromised daemon |

## Threats and implemented controls

| Threat | Implemented control | Remaining exposure |
| --- | --- | --- |
| URL/parser SSRF | Canonical `https://github.com/.../issues/N`; fixed API and codeload hosts; no redirects, proxies, auth, ports, queries, or fragments | DNS, TLS trust store, OS resolver, and GitHub are trusted; GitHub Enterprise is unsupported |
| Archive traversal, substitution, or host overwrite | Private `0700` run directory; exclusive no-follow `0600` files; manual regular-file extraction; repeated path/type/link/count limits; reconstructed Git root-tree match; independent canonical tree SHA-256 | GitHub, DNS/TLS, Git SHA-1 identity, host tar/gzip/JSON/Python parsers, controller, and local filesystem remain trusted |
| Issue prompt injection | Issue labeled as hostile data; generator returns an exact three-field schema; issue commands never become controller argv | A model can still produce an irrelevant or deceptive test; prompt text is not a security boundary |
| Candidate command/network behavior | AST defense in depth; dangerous imports/calls and aliases rejected; Docker has no network and receives no host secrets | Python static screening is incomplete by nature; loopback and in-container process behavior remain; Docker is the real boundary |
| Shell/option injection | Controller and generator use argv arrays, not a shell; pytest node is controller-selected; leading-dash target rejected; replay ignores command fields | `--generator-command` is deliberately trusted user input; displayed commands should still be reviewed before copying |
| Host filesystem access | No host bind mounts during verification; only a read-only controller-owned volume; read-only root; no devices or Docker/SSH socket | Docker daemon and container runtime are trusted; a container escape can reach their privileges |
| Secret theft | Public unauthenticated intake; Docker env cleared and allowlisted; no token/socket mounts; Docker control env minimized; OpenAI key sent only to a fixed TLS endpoint after explicit provider selection | Built-in provider, DNS/TLS trust, trusted command generators, daemon, and host remain outside the hostile-repository boundary |
| Verification network exfiltration | Docker `--network none`; no dependency setup in strict profile | Loopback remains; runtime/daemon escape bypasses this; trusted image build has network when invoked |
| CPU/RAM/PID/file/output exhaustion | Cgroup CPU/memory/PID limits, ulimits, bounded tmpfs/inodes, outer timeout, controller output cap, bounded Docker logs | Shared daemon/VM storage, staging helpers, kernel bugs, I/O pressure, and crash-left resources can still affect the host |
| Terminal/clipboard injection | CSI, OSC, C1, CR, control, and format characters stripped from captured logs and CLI errors | Arbitrary report fields are data; other renderers must still escape Markdown, HTML, and rich-text markup |
| Forged test result | Bounded stdout and optional defused XML; exact node name, one test/failure, symptom evidence, repeated fingerprint | Repository code runs in-process with pytest and can forge either evidence form; evidence is not attestation |
| Malicious replay report | Regular non-symlink <=1 MiB; canonical URL/repository/SHA; recorded archive hash; fresh commit-tree attestation; optional recorded tree-digest comparison; candidate schema/hash; bounded repeats; command fields ignored | Reports are unsigned; replay does not authenticate author or reuse/verify the original runner policy and result |
| Cross-run contamination | New labeled volume/container per workflow and best-effort cleanup | No crash-recovery janitor; local Docker image/cache and daemon are shared; hosted multi-tenancy is not supported |
| False product claim | Explicit claim levels and report limitations; `repeatable_base_failure` has a narrow definition | Semantic review, hidden-fix differential, benchmark rates, and maintainer acceptance are separate unimplemented evidence gates |

## Important residual risks

### Docker is not a hostile multi-tenant boundary

On Linux, ordinary Docker/runc containers share the host kernel. On macOS, Docker Desktop places the
Linux daemon in a VM, but containers share that VM and Docker Desktop has host integration. Kernel,
runc, containerd, Docker Desktop, or daemon vulnerabilities can invalidate the boundary. The current
profile does not require rootless Docker, user namespaces, gVisor, a custom seccomp profile, or a
dedicated VM, and it does not attest the effective seccomp/LSM policy.

ReproAssert also does not prove that the active Docker context is local. A configured remote context
can send source and execution to another machine. The operator must trust and verify the selected
Docker endpoint.

### Generation happens outside the repository sandbox

The built-in OpenAI adapter activates only with `--provider openai`. It sends the public issue and
selected source context to fixed `api.openai.com` with the user's `OPENAI_API_KEY`, before Docker
verification. It has no configurable endpoint, proxy, redirect, or automatic retry and does not send
the key in the JSON body. `store: false` is requested, but users still need to review their OpenAI
account and data-handling policies. The source-context secret-name heuristic is not data-loss
prevention, and a public repository can still contain accidentally committed sensitive data.

Issue and selected source text are sent to the configured generator command before Docker execution.
That adapter can access the host and network under the invoking user's identity, subject only to its
cleared process environment and explicit `--pass-env` choices. Prompt isolation does not constrain a
malicious adapter. Do not execute an adapter supplied by the target repository, issue, or imported
report.

If a command adapter calls any external model provider, public issue/source context likewise leaves
the machine under that adapter's own policy. Private repositories are not implemented.

### Candidate and pytest evidence can lie

The candidate policy blocks known dangerous patterns, including the fixed top-level-assignment and
import-alias bypass regressions. It is not a complete Python effect system. Repository code can run
from `sitecustomize`, imports, pytest, or `conftest.py`, tamper with its process, and forge JUnit or
stdout evidence. JUnit is optional because Docker tmpfs output may not remain copyable after stop;
the bounded stdout fallback is conservative but equally untrusted. Repetition makes an observation
more stable; it does not make it truthful or issue-causal.

A stronger benchmark must apply the candidate separately to a hidden fixed revision and conduct
blinded semantic review. A live unresolved issue cannot receive that claim automatically.

### Reports are evidence bundles, not attestations

The report records hashes and runner facts but is not signed. A user can edit a report and recompute
internal hashes. Replay deliberately regenerates controller commands and source intake, requires the
new archive bytes to match the recorded archive hash, and freshly binds the extraction to the commit
tree. It still does not authenticate the original runner, policy, outcome, or author. Treat reports
from others as untrusted until independently replayed and reviewed.

### Cleanup and availability are best effort

The controller removes known containers and volumes on ordinary completion and forces removal on
timeout/output overflow. A crash or kill can leave labeled resources. Cgroups reduce a single
container's consumption but do not guarantee availability of the shared Docker daemon, Desktop VM,
host disk, or kernel. tmpfs pages may be swapped by the Docker host/VM.

## Out of scope for the current profile

- private GitHub repositories, GitHub Enterprise, authenticated source intake, and secrets in target
  tests;
- arbitrary dependency installation or networked setup;
- repositories requiring services, databases, browsers, GPUs, privileged syscalls, or writable
  source trees;
- Windows containers or native Windows execution;
- protection from a compromised controller, Python installation, runner image, Docker daemon,
  container runtime, host kernel, host administrator, DNS resolver, CA store, or GitHub itself;
- side-channel resistance, speculative-execution isolation, and forensic-grade secure deletion;
- hosted multi-tenancy, billing abuse, webhook authorization, GitHub App token separation, and
  report signing; and
- automatic proof of semantic correctness, root cause, fix quality, maintainer acceptance, demand,
  benchmark success, speed, or cost.

## Security invariants to keep tested

Changes should preserve adversarial regressions for:

- SSRF-shaped issue URLs and redirect attempts;
- tar traversal, `.git` aliases, links, devices, FIFOs, bombs, path/case/Unicode collisions, and
  archive-to-Git-tree mismatches;
- exclusive no-follow report and artifact I/O;
- inert command fields in reports and generated JSON;
- leading-dash pytest targets and controller-owned paths;
- terminal CSI/OSC/clipboard/control sanitization;
- top-level candidate execution, network/process APIs and aliases, and skip/xfail behavior;
- Docker arguments with no binds, secret/socket/proxy forwarding, or network, plus the positive and
  negative evaluator-isolation canary; and
- bounded report, generator, JUnit, log, and archive parsing.
