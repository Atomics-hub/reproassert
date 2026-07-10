# 0008 — Differential evaluation requires an application-issued capability

Status: accepted and primitive implemented, production issuer not implemented, on 2026-07-10

## Context

A test that fails on a buggy tree and passes on a fixed tree is stronger evidence than a repeated
base failure, but only when the evaluator has proven the identities and separation of both trees.
Allowing a caller to supply arbitrary paths, hashes, booleans, or a package-controlled verification
plugin would let fixture drift, hidden-test leakage, or a fabricated receipt manufacture an L1 claim.

The v0.2 public package, preregistration, and leak-scanning tooling needs to be independently useful
before the production evaluator exists, without silently turning structural validation into
execution authority.

## Decision

Differential execution accepts only a nominal `VerifiedV02EvaluatorCapability`. The capability is
created with an internal issuer token and its digest binds:

- exact case and base commit identity;
- base content-tree and root-tree identities;
- hidden-fixed, fixing-head, production-patch, and developer-test identities;
- the private evaluator-package identity and public salted commitment; and
- either a complete dependency receipt/plan/tree/image identity set or explicit dependency-free
  mode.

Every consumer revalidates the nominal type, issuer token, field shapes, dependency all-or-none
contract, and capability digest. Filesystem paths are not authority. The differential controller
independently attests freshly supplied base/fixed trees against the capability before execution.
This nominal Python object is an accidental-misuse and API-composition guard, not an adversarial
same-process security boundary: code already executing in the trusted controller process can import
or introspect private module state and forge it. The production boundary must therefore keep
repository, model, plugin, and package-controlled code out of that process; the official issuer and
its caller are trusted computing base.

The public v0.2 case-package verifier is structural. It requires an application-selected trusted
semantic verifier and fails closed without one, but it deliberately returns
`evaluator_capability=None` even after structural checks. The public cohort audit therefore remains
not ready. An official application-owned controller must rederive dataset membership, exact-object
source identity, causal dependency receipt, two-tree patch application, production generator
isolation, and reviewer-role seal in process before issuing a live capability. Repository code,
issue text, model output, plugins, and package-controlled executables must never select or implement
that issuer.

Given a valid capability, the implemented differential primitive:

1. revalidates one candidate and requires the controller-owned issue path;
2. builds and attests `pristine tree + exactly one candidate` separately for base and fixed roles;
3. independently attests the staged Docker volumes;
4. optionally revalidates and borrows the capability-bound typed dependency volume;
5. runs `base, fixed, fixed, base, base, fixed` in fresh no-network containers;
6. requires three matching intended base failures and three exact one-target JUnit passes; and
7. reduces raw fixed stdout and JUnit to digests in its public projection.

The primitive may produce the narrow `differential_reproduction`/L1 meaning only when the official
issuer and authentic package path exist. It does not establish issue semantics, causal controls,
blinded review, maintainer acceptance, or L2/L3.

## Evidence and gate

A real local Docker fixture passed the six-run interleaving with three repeat-stable buggy failures
and three fixed passes. The fixture uses a test-only in-module capability and is not an authentic
v0.2 package or public L1 benchmark result.

Until the official issuer, authentic 20-case packages, and production scored runner exist:

- the public issue/replay ceiling remains `repeatable_base_failure`;
- v0.2 package and cohort audits remain structurally useful but not ready;
- L1, L2, runtime, and cost results remain 0/20 or unmeasured; and
- no model campaign is authorized merely because the differential primitive passes.

## Consequences

This adds an explicit nominal API gate and in-process recomputation instead of a general evaluator
plugin surface. It keeps private paths out of public records and prevents accidental upgrades from
raw caller-supplied paths. It does not protect against code that already controls the trusted Python
process. The cost is that the local primitive cannot be presented as a shipped end-to-end benchmark
until the trusted issuer, process separation, and scored runner are completed and audited.
