# ADR 0012: provider-free v0.2 preparation is a first-class transaction

Status: accepted — 2026-07-11

## Decision

ReproAssert exposes a dedicated offline preparation lane before any scored-provider authorization:

- `benchmark prepare-v02-dataset` runs the pinned parser in the exact inspected no-network image,
  copies the frozen upstream inputs into a private `0700` transaction, and writes all 20
  generator-safe projections plus a canonical self-hashed receipt;
- `benchmark verify-v02-dataset` freshly reruns the parser and byte-compares its receipt and every
  projection;
- `benchmark prepare-v02-object-source` and `verify-v02-object-source` bind exact Git-object source
  evidence to the frozen v0.2 cohort rather than reusing the v0.1 manifest; and
- the cohort audit can consume the 20 nominal, in-memory packages returned by the official semantic
  issuer without attempting to serialize evaluator capabilities.

These commands have no provider adapter. Their receipts fix `provider_calls` to zero and cannot
change campaign readiness.

## Why

The released validators were individually strict, but the operator path was incomplete: v0.2
source preparation was v0.1-only, dataset materialization required an ad hoc Python harness, and the
cohort audit required a capability that the structural package verifier never returns. That made an
authentic 20-case run impossible through supported production APIs even though fixtures passed.

Preparation is now an explicit transaction with a fresh-rederivation verifier. Live capabilities
remain nominal process-local authority; making them JSON would turn an unforgeable application token
into caller-controlled data.

## Consequences

- Dataset, patch, test, and fixing evidence remain evaluator-only and outside Git checkouts.
- Safe projections retain `chronology_unproven`; preparation does not upgrade that claim.
- A complete case package still requires exact source, reviewed dependency evidence, fixing-PR
  capture, privacy and role review, isolation evidence, and application-owned semantic issuance.
- No pricing or spend approval should be requested until all 20 packages and exact rendered requests
  pass the offline readiness gate.
