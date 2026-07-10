# 0007 — Dependency preparation remains a gated prototype

Status: accepted design, executor not implemented, on 2026-07-10

## Context

The strict verifier intentionally installs no target-repository dependencies. That keeps hostile
setup code and network access out of verification, but it also turns otherwise valid historical
cases into setup failures. A useful benchmark needs a bounded dependency path without letting an
issue, repository, or generated command choose what runs with network access.

A requirements filename, a successful `pip install`, or a directory hash alone would not prove
that the installed environment came from the reviewed artifacts under the recorded policy.

## Decision

The implemented preparation contract is deliberately narrow:

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

The plan parser, fixed argv builders, wheel attestation, deterministic receipt builder, and
read-only verification mount exist as tested primitives. They are not exposed as a completed
campaign preparation command.

## Campaign gate

No dependency receipt produced by assembling these primitives manually counts as execution proof.
Before campaign readiness can change, one controller must causally enforce and record all of the
following:

1. fresh, empty, exclusively labeled input, wheelhouse, and dependency volumes;
2. constrained ownership setup for the non-root container user;
3. effective container inspection and the exact immutable image ID for download and install;
4. bounded attached execution evidence, including exit, timeout, OOM, and output state;
5. wheelhouse attestation before offline installation;
6. a successful offline install followed by no-follow dependency-tree attestation; and
7. cleanup plus one receipt that binds the inspected phases, reviewed plan, wheel bytes, and final
   read-only tree.

Until that executor exists and passes a real isolation canary, prepared dependency images and
evaluator packages remain **0/20 campaign-ready**.

## Consequences

The prototype rejects sdists, VCS dependencies, repository builds, editable installs, resolver
output, mutable version ranges, and legacy/native environments that do not have compatible reviewed
wheels. Aggregate declared wheel expansion is capped at 512 MiB, but the eventual executor still
needs a daemon/volume storage quota and cleanup policy. Hosted use additionally requires an egress
proxy or equivalent network enforcement and a microVM-class tenant boundary.
