# 0018: Require genuine v0.2.1 amendment consensus before runtime migration

## Decision

The all-20 v0.2.1 evaluator amendment remains provider-disabled until two genuine, oracle-aware
human reviewers approve the exact pending amendment. Review identities are reused from the already
frozen mapping-review roster. The first two mapping reviewers are the primaries; a third reviewer
may act only when that identity was declared in the mapping handoff and the primaries disagree.
Future semantic reviewers remain disjoint because they must stay blind to gold evidence.

The review handoff freshly binds the pending amendment's raw and internal receipt hashes, exact
old/new gold-spec and gold-smoke commitments, runtime manifest, hidden extraction, strict-subset
delta, and final tool Git SHA. Submissions bind the raw handoff hash and make an explicit
oracle-review declaration. A sealed consensus is evidence only; verifier-issued in-process
authority is required by downstream code.

## Provider-disabled boundary

This change deliberately exposes no `run-v021` command and no provider-capable config. Approval is
necessary but not sufficient for execution. The next coherent slice must create a v0.2.1
preregistration and authorization-ready freeze/config lineage that freshly requires:

- approved amendment consensus;
- the amended 20 semantic-valid / 0 infrastructure-failure smoke;
- dependency-ready cases at 20/20;
- the v2 hard-cap evidence and exact USD 5.00 total / USD 0.25 per-case / zero-overage statement;
- the existing 20-case mapping consensus, chronology, runtime manifest, and hidden commitments; and
- a versioned runtime migration that cannot enter any v0.2 execution path.

Until that full verifier chain lands, model/provider calls remain disabled even after reviewers
approve the amendment.
