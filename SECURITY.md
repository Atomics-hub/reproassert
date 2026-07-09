# Security policy

ReproAssert executes repository code. Treat every GitHub issue, source archive, repository file,
generated test, pytest plugin, test result, and imported report as hostile.

The current code is a pre-1.0 validation build. Its implemented controls and residual risks are
documented in [the security model](docs/security-model.md), [the threat model](docs/threat-model.md),
and [the sandbox profiles](docs/sandbox-profiles.md). Those documents are part of the product
contract; a security claim that is not supported there should not be inferred.

## Reporting a vulnerability

Use GitHub's private
[Report a vulnerability](https://github.com/Atomics-hub/reproassert/security/advisories/new) flow.
Do not file a public issue with exploit details before a fix or mitigation is available.

Include:

- the affected commit or version;
- operating system, architecture, Docker client/engine versions, and Docker context type;
- the smallest fixture or report that demonstrates the problem;
- the expected boundary and the observed impact;
- whether the behavior reaches the host, Docker daemon, another run, credentials, or only the
  hostile container; and
- any temporary mitigation you have confirmed.

Use synthetic credentials and repositories you own. Do not include real tokens, private source,
personal data, or an exploit against an unrelated project. A policy bypass that remains inside the
sandbox is still worth reporting, but distinguish it from a container escape.

If private vulnerability reporting is unavailable, do not post technical details publicly. A
minimal public request to enable private reporting may identify the affected component, but should
not include a proof of concept, payload, or impact details.

## Response targets

These are best-effort targets, not a service-level agreement:

- acknowledge a private report within three business days;
- provide an initial severity and scope assessment within seven business days;
- send an update at least every 14 days while remediation is active; and
- coordinate publication after a fix or documented mitigation is available.

Security fixes should include a regression test whenever the failure can be reproduced safely.
Material changes to the trust boundary should update the three security documents linked above.

## Security-supported scope

During the pre-1.0 phase, security fixes target the current default branch. No older release line is
promised security maintenance until a release policy says otherwise.

Reports are in scope when they show or plausibly enable:

- host file, secret, process, device, or socket access from repository code;
- network access that contradicts the recorded verification policy;
- Docker argument, target, path, archive, report, or shell-command injection;
- a container or Docker Desktop VM escape;
- cross-run data access or executable cache poisoning;
- unsafe archive extraction, symlink following, path traversal, or output overwrite;
- authentication or proxy inheritance in unauthenticated public-GitHub intake;
- the built-in OpenAI key being sent anywhere except the fixed `api.openai.com` endpoint after
  explicit `--provider openai` selection;
- resource controls being absent despite a report claiming they were applied;
- terminal escape, clipboard, or control-sequence injection in trusted output;
- report replay executing data-supplied commands or using an unvalidated source; or
- a repeatable-failure claim being elevated beyond the evidence actually collected.

Examples that are usually not security vulnerabilities by themselves:

- an irrelevant or semantically wrong test that remains contained and is labeled only as a
  repeatable base failure;
- a repository that cannot run because the strict profile performs no dependency installation;
- ordinary Docker or model-provider availability failures;
- the explicitly disclosed public issue and selected source context being sent to OpenAI after the
  user selects `--provider openai`;
- behavior that requires a malicious Docker daemon, runner image, controller installation, or host
  administrator, all of which are currently trusted; and
- a generator adapter reading data or environment variables the user explicitly authorized it to
  receive. Generator adapters run outside the repository sandbox and must be trusted.

The first two cases can still be correctness bugs. Report them publicly only when doing so does not
expose a security weakness.

## Research and disclosure

Good-faith research should minimize access, persistence, and disruption. Stop once impact is
demonstrated; do not retain data that is not yours, attack third-party repositories, contact their
maintainers as part of testing, or spend money on external services. This policy is not legal
authorization and does not override applicable law or third-party terms.

Public disclosure should identify the affected versions, impact, prerequisites, fix, and residual
risk without publishing live secrets or a weaponized container escape before users can update.
