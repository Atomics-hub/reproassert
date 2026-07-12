# ADR 0019: approved v0.2.1 preregistration remains provider-disabled

## Status

Accepted for the v0.2.1 preparation line.

## Decision

The v0.2.1 amendment can move the exact-image cohort from 19/20 to 20/20 only after the genuine, verifier-issued human consensus introduced by ADR 0018. The old serialized `review_status` field is not sufficient authority.

The new `prepare-v021-preregistration` command freshly verifies:

- the pending amendment and approved amendment consensus;
- 20 pending-consensus case packages;
- the amended all-20 gold smoke and capability-index v2;
- 20 approved, non-empty mapping decisions;
- 20/20 issue-before-fix chronology;
- the cohort, runtime manifest, hidden extraction, and exact pricing snapshot;
- cross-artifact cohort, hidden-extraction, pricing, and mapping-preparation commitments;
- one final controller Git SHA and chronology for every mutable receipt.

The resulting artifact records an effective dependency-ready count of 20 while preserving the pre-consensus count of zero. It commits the exact `$5.00` total, `$0.25` per-case, zero-overage policy and emits the exact statement required for a later authorization artifact.

## Security boundary

This change does not authorize or execute anything. Its status is `execution_disabled_until_v021_runtime_migration`; it contains no secret or API-key field, does not read environment variables, and exposes no `run-v021` command. The approval statement itself has `authorized: false`.

Verifier-issued artifacts are digest-bound when they are reread, so an atomic file swap cannot silently replace the evidence that was actually verified.

The next atomic slice must migrate the runtime, authorization, campaign freeze, evaluator, causal-control, and finalization contracts together. Until that migration passes adversarial review, v0.2.1 execution remains structurally unavailable.

## Compatibility

All v0.2 schemas and commands remain readable and unchanged. Legacy 19/1 evidence is explicitly rejected by the v0.2.1 preregistration verifier rather than reinterpreted.
