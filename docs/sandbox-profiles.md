# Sandbox profiles

Status: one dependency-free local issue/replay profile and one preparation-only causal wheel
executor are implemented. The wheel path is not wired into a scored campaign, and enhanced/hosted
profiles remain design paths rather than shipped features.

## `strict-python-pytest-v1` — implemented

ReproAssert has no native execution path. `reproassert issue` and `reproassert replay` call
`require_ready()` and stop if the Docker CLI, engine, or configured image is unavailable. The strict
profile performs no target-repository dependency installation and never executes a repository
Dockerfile, setup command, Makefile, tox command, or copied issue instruction.

The packaged image is built from a Python 3.12.13 slim Bookworm base pinned by SHA-256. Runner Python
dependencies are installed from a hash-locked requirements file. `reproassert sandbox build` has
network access to pull/build that trusted image; hostile repository code is not present in the build
context. Verification later uses `--pull never`. The local image tag is mutable, so each sandbox
resolves its actual immutable image ID on first readiness and uses that ID for staging, attestation,
execution, ownership helpers, and facts. A later tag swap is rejected. The controller does not
currently verify an image signature or transparency log.

### Verification container arguments

The controller currently requests:

| Area | Docker arguments or behavior |
| --- | --- |
| Image/network | `--pull never`, `--network none` |
| Filesystem | `--read-only`; controller-owned named volume at `/workspace`, `readonly`; fresh 2 MiB/64-inode local-tmpfs result volume at `/results`; no bind mounts |
| Identity | `--user 65532:65532`, `--cap-drop ALL`, `--security-opt no-new-privileges=true` |
| Processes | private default PID and IPC namespaces, `--pids-limit 128`, `--init` |
| Memory/CPU | `--memory 1073741824`, matching `--memory-swap`, `--cpus 1.0` |
| Ulimits | `nofile=256:256`, `core=0:0`, `fsize=67108864:67108864` |
| Temporary data | 64 MiB `/tmp` tmpfs with `rw,noexec,nosuid,nodev,nr_inodes=4096`; 64 MiB shm |
| Logs | Docker `local` driver, `max-size=128k`, `max-file=1`; controller retains at most 64 KiB |
| Runtime timeout | 60 seconds per collection or verification container by default; removal and kill on timeout or output overflow |
| Environment | `/usr/bin/env -i`, followed only by the allowlist below |

The explicit environment is:

```text
HOME=/tmp/home
LANG=C.UTF-8
LC_ALL=C.UTF-8
PATH=/usr/local/bin:/usr/bin:/bin
PYTHONDONTWRITEBYTECODE=1
PYTHONHASHSEED=0
PYTHONPATH=/workspace:/workspace/src:/workspace/.reproassert-deps
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
TZ=UTC
```

Pytest receives fixed controller argv: the trusted image Python, `-m pytest`, `/dev/null` as config,
an explicit root directory, disabled cache plugin, importlib mode, no color, short tracebacks, a tmpfs
base directory, a random JUnit path, and one controller-selected `tests/reproassert/...` node. Targets
beginning with `-` are rejected. No command from the issue, candidate, repository, or imported report
is placed into Docker argv.

JUnit is hostile evidence, not the sole classifier. Each phase writes it to a fresh quota-bounded
local-tmpfs volume at `/results`. A separate inspected anchor container keeps the tmpfs mount alive
only until a fixed isolated reader returns at most the allowed bytes. The anchor has no network,
read-only root, non-root identity, dropped capabilities, no-new-privileges, private cgroup/IPC,
16 PIDs, 64 MiB memory, 0.1 CPU, no Docker logs, and no workspace/dependency mount. Accepted base and
fixed executions both require strict JUnit for exactly one expected node and the required
failure/pass shape; missing or malformed JUnit fails closed. Bounded stdout is only supplemental
symptom evidence after valid JUnit identifies the target result. Repository code can forge either
channel.

`--network none` leaves the container loopback device. It blocks normal host, LAN, DNS, and internet
connectivity but does not prevent processes inside the same container from communicating over
loopback.

### Policy attestation

The controller creates, then inspects, each verification container before starting it. It refuses to
run if Docker's inspected configuration does not show:

- network mode `none`;
- a read-only root filesystem;
- healthchecks disabled and the immutable image ID selected at readiness;
- user `65532:65532`;
- all capabilities dropped and no-new-privileges requested;
- non-privileged mode and private PID/IPC configuration;
- requested PID, memory, swap, and CPU limits;
- no devices or bind mounts; and
- the expected named volume mounted read-only at `/workspace`.

The code does not currently attest the effective seccomp profile, AppArmor/SELinux policy, user
namespace mode, rootless-engine status, tmpfs flags, ulimits, log driver, or whether the selected
Docker context points to a local engine. Docker and its defaults remain trusted. Do not translate
"policy inspection passed" into "container escape is impossible."

### Staging and cleanup

The controller first creates and attests a private copy containing the exact pristine source plus one
revalidated candidate. Those bytes are copied into a new controller-labeled Docker volume with
`docker cp`; no host directory is bind-mounted. A read-only in-container attestor must reproduce the
candidate-applied tree evidence before pytest can run. The staging container uses `--network none`
and a trusted `/bin/true` entrypoint. A separate short-lived helper runs trusted `/bin/chown` as root
with only `CHOWN` and `DAC_READ_SEARCH` added, no-new-privileges, no network, and a read-only root so
it can make the volume readable by UID 65532. These helpers do not execute repository code, but they
are not attested with the full verification policy.

Normal completion removes containers and volumes in `finally` blocks only after checking the exact
controller label; removal is confirmed by inspect or an exact-name listing. Timeout and output
overflow force-remove the active owned container. The dependency executor similarly retains sole
ownership of borrowed dependency cleanup. There is not yet a startup janitor for resources left
after a controller crash, host kill, daemon failure, or power loss. Stale resources labeled
`io.reproassert.owner=controller-v1` may require operator cleanup.

### Recorded live fixture

On 2026-07-09 the opt-in Docker integration test passed locally on Docker Desktop 4.68.0 / Engine
29.3.1 / LinuxKit arm64. It exercised the strict create/inspect/start path, three repeatable failures
for a bundled buggy slug fixture, cleanup, and three passes for the bundled fixed fixture.

This is one fixture on one machine. It does not establish cross-platform compatibility, production
hardening, escape resistance, benchmark success, or a semantic reproduction rate.

On 2026-07-10, `reproassert sandbox isolation-canary --json-output` also passed locally. The
canary's evaluator-only view read a random sentinel, while the generator view had exactly one
separate read-only `/workspace` volume and could not find it. The canary additionally inspected its
effective image ID, network, mounts, user, capabilities, no-new-privileges flag, resources, tmpfs,
bounded log driver, process-environment clearing, and cleanup. This is a narrow mount-policy control;
it does not strengthen ordinary Docker into a hosted hostile multi-tenant boundary.

The capability-gated differential integration fixture also passed locally on 2026-07-10. It staged
separately attested candidate-applied buggy/fixed trees and executed
`base, fixed, fixed, base, base, fixed`; the three base runs had one repeat-stable intended failure
and the three fixed runs each had one exact JUnit pass. This is a synthetic repository fixture under
a test-only capability, not an authentic historical package or public L1 result.

## `pypi-hash-locked-wheels-v1` — causal executor implemented, campaign-gated

`DependencyExecutor` accepts a strict dependency-plan path, not a caller-constructed plan object. It
resolves the immutable runner image ID once, then creates three distinct local-driver tmpfs volumes:

| Role | Size | Inodes | Runtime access |
| --- | ---: | ---: | --- |
| rendered input | 1 MiB | 64 | read-only in download |
| wheelhouse | 512 MiB | 1,024 | writable only in download; read-only thereafter |
| installed dependencies | 512 MiB | 32,768 | writable only in offline install; read-only borrow thereafter |

Docker inspect must show the exact type, size, inode, UID/GID `65532:65532`, mode `0700`, owner, run,
role, and plan labels. Read-only retention anchors keep each local tmpfs mount alive and prevent
reuse. Newly created volumes are probed empty. The networked phase receives only the rendered
hash-complete requirements and wheelhouse, runs `python -I -m pip --isolated download` under fixed
source-free binary-only argv, and has no source or dependency-output mount. The install phase uses
`--network none`, `--no-index`, `--no-deps`, binary wheels only, and writes the separate dependency
volume.

Before install, the executor individually retrieves only pre-enumerated flat regular wheel files and
checks their hashes; it never recursively exports the hostile wheelhouse or installed tree to the
host. It proves the wheelhouse is unchanged across install, the input is unchanged, and the
dependency tree is stable across an in-container no-follow attestation. A nominal typed handle binds
the exact labels, quota, immutable image ID, tree attestation, receipt digest, and executor-only
cleanup capability. `DockerSandbox.borrow_dependency_volume()` accepts only that exact type,
revalidates it before every `/dependencies` mount, and never takes cleanup ownership.

The canonical execution receipt is below 1 MiB and deliberately records
`campaign_readiness_changed: false`. Its separate strict loader/verifier rejects duplicate keys and
noncanonical JSON, then recomputes the plan, requirements, policy, volume contract, command/config
hashes, phase outcomes, causal sequence, wheelhouse/tree identities, image binding, and cleanup
contract rather than trusting copied booleans. Root and bundled JSON Schemas describe the same
format.

Real local Docker checks passed a pinned `six==1.17.0` PyPI download, offline install, direct import,
typed read-only verifier borrow, checked cleanup, and a separate inode-quota canary that reached
`ENOSPC`. The opt-in network canary requires both `REPROASSERT_RUN_DOCKER_TESTS=1` and
`REPROASSERT_RUN_DEPENDENCY_NETWORK_TESTS=1`, so ordinary CI does not download from PyPI.

This profile is still preparation-only. It is not a general repository installer, does not run
setup.py, build backends, sdists, VCS dependencies, or repository commands, and is not wired into
`reproassert issue`/`replay`. Docker bridge egress constrains the trusted process and inputs, not the
network layer. No authentic v0.2 case package or campaign prerequisite exists merely because the
executor or receipt verifier passes.

## `gvisor-python-pytest` — proposed enhanced Linux profile

An enhanced Linux path may retain the same controller, image, argv, and report contract while using
the gVisor `runsc` OCI runtime. Before it can be called supported it needs:

- explicit runtime selection and post-create attestation;
- pinned runsc installation and version evidence;
- compatibility tests for Python, pytest, native wheels, process behavior, filesystems, and signals;
- the full adversarial suite under runsc, including escape-oriented probes;
- measured cold/warm overhead; and
- an honest fallback policy. A missing or incompatible runsc must stop that profile, not silently
  downgrade to ordinary runc.

gVisor reduces direct exposure to the host Linux kernel by implementing much of the syscall surface
in userspace. It remains software with vulnerabilities and compatibility gaps; it is not equivalent
to a dedicated VM.

## Hosted microVM profile — proposed, required before multi-tenancy

The current Docker profile is not the hosted multi-tenant design. A hosted service should use a
disposable microVM per run, such as Firecracker with its Jailer or an equivalently isolated managed
runtime. The minimum design is:

1. A webhook/control service verifies authorization and holds the narrow GitHub installation token.
2. A fetcher obtains source, validates and hashes it, then destroys the token before execution.
3. Generation occurs in a separate trusted plane; provider credentials never enter the execution VM.
4. Dependency preparation, if introduced, uses a reviewed egress proxy that permits only declared
   registries and blocks host, LAN, metadata, private, link-local, and rebinding destinations.
5. The execution VM receives a read-only base image, unique writable overlay, no credentials, no
   inbound network, offline verification, hard resource limits, and no writable cache shared with
   another tenant.
6. The entire VM and overlay are destroyed after the run. A separate narrow publisher validates a
   bounded report as hostile data before writing a fixed-form GitHub Check.

Firecracker/Kata/microVM support, private repositories, dependency egress, a GitHub App, report
signing, and hosted cleanup are not implemented in this repository today.

## Unsupported substitutes

Running pytest on the host, `python -m` without Docker, a process-only macOS sandbox, bubblewrap with
an ad hoc policy, an uninspected remote Docker daemon, or a privileged container is not an equivalent
ReproAssert profile. The CLI should fail closed rather than advertise those paths as verified.
