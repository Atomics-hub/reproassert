# 0007 — Causal dependency preparation remains campaign-gated

Status: accepted and locally implemented, not campaign-ready, on 2026-07-10

## Context

The strict verifier intentionally installs no target-repository dependencies. That keeps hostile
setup code and network access out of verification, but it also turns otherwise valid historical
cases into setup failures. A useful benchmark needs a bounded dependency path without letting an
issue, repository, or generated command choose what runs with network access.

A requirements filename, a successful `pip install`, or a directory hash alone would not prove
that the installed environment came from the reviewed artifacts under the recorded policy.

## Decision

The preparation contract is deliberately narrow:

- A strict duplicate-free plan binds one case/base/source tree and runner image to a complete,
  sorted closure of normalized package names, exact versions, and reviewed SHA-256 hashes.
- The only networked command is controller-rendered `pip download` for those exact hashes, with
  dependencies and source distributions disabled. Repository source, credentials, proxy variables,
  and the dependency output volume are absent from that phase.
- Wheel files are handled as hostile archives: regular single-link files only, bounded compressed
  and aggregate declared expansion, bounded member counts and metadata, no encrypted members,
  links, special files, or unsafe paths, and identity/hash equality with the reviewed plan.
- Installation is a separate `--network none`, `--no-index`, `--no-deps`, binary-only command into a
  controller-owned dependency volume. Verification may mount that volume read-only at
  `/dependencies`; the ordinary dependency-free command remains byte-for-byte unchanged.
- The policy states plainly that Docker bridge egress is constrained by fixed trusted-process argv
  and post-download hashes, not by a network-layer PyPI allowlist.

One `DependencyExecutor` now causally enforces the contract:

1. it accepts only a strict plan path and resolves one immutable runner image ID before creating
   resources;
2. it creates distinct, fresh, empty, exactly labeled local-tmpfs input, wheelhouse, and dependency
   volumes with fixed byte/inode quotas and read-only retention anchors;
3. it stages only the controller-rendered requirements, runs the fixed networked download and
   network-disabled install commands, inspects the effective container policy, and records bounded
   exit/timeout/OOM/output state;
4. it individually retrieves and validates only pre-enumerated wheel files, proves the input and
   wheelhouse are unchanged, and attests the installed dependency tree in-container without
   following links;
5. it issues a nominal typed read-only handle binding the exact labels, quota, immutable image ID,
   dependency tree, receipt digest, and executor-only cleanup capability; and
6. it performs label-verified cleanup and requires authoritative resource absence.

The verifier accepts only that exact handle type, revalidates it before every `/dependencies` mount,
and never takes cleanup ownership. A separate bounded canonical receipt loader/verifier rejects
duplicate or noncanonical JSON and recomputes the plan, requirements, policy, volume contract,
command/config hashes, phase outcomes, causal sequence, wheelhouse/tree identities, image, and
cleanup semantics. Root and bundled JSON Schemas describe the same receipt. The receipt deliberately
records `campaign_readiness_changed: false`.

## Campaign gate

The executor and strict verifier establish local causal execution proof for one reviewed plan; they
do not select benchmark dependencies, authenticate a historical case, or create a hidden-fix
evaluator package. Real local Docker checks passed a pinned `six==1.17.0` PyPI download, offline
install, direct import, typed read-only verifier borrow, cleanup, and an input-volume inode quota
canary that reached `ENOSPC`.

Campaign readiness remains fail closed until each frozen v0.2 package is authentically bound to its
case/source/environment setup revision, the application-owned semantic issuer verifies the receipt
and private evaluator evidence, and the production scored runner consumes the issued capability.
There are currently **0/20 authentic dependency/evaluator case packages and 0/20 campaign-ready**.

## Consequences

The executor rejects sdists, VCS dependencies, repository builds, editable installs, resolver
output, mutable version ranges, and legacy/native environments that do not have compatible reviewed
wheels. Aggregate declared wheel expansion, volume bytes, and volume inodes are bounded. The Docker
local-driver tmpfs policy is locally checked but still trusts the daemon/host implementation. Hosted
use additionally requires an egress proxy or equivalent network enforcement and a microVM-class
tenant boundary.
