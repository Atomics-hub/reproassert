# ADR 0013: Provider-disabled v0.2 case preparation

- Status: accepted
- Date: 2026-07-10

## Decision

`reproassert benchmark prepare-v02-cases` creates a private, immutable preparation packet for each
of the 20 frozen v0.2 cases. It is a pre-review stage, not a `VerifiedV02CasePackage` and not a
campaign-readiness claim.

Before writing output, the controller reruns the pinned no-network dataset parser, reruns the
evaluator-private hidden extractor, enforces the frozen cohort commitment, independently rederives
each exact Git object source, derives the bounded base-source context, and freezes the exact
provider request envelope. Hidden patches remain behind a verifier-issued process-local capability.
Generator-visible projections and requests reject hidden artifact bytes, digests, and private paths.

Each packet also records:

- a source-bound dependency state and any missing hash-locked plan or execution receipt;
- a two-reviewer mapping rubric, two-reviewer semantic rubric, and deterministic tie-break rule,
  with all genuine reviewer slots empty;
- the captured official model pricing snapshot;
- an unsigned proposal capped at $0.25 per case and $5.00 for the 20-case campaign; and
- `provider_execution_enabled=false`, `authorization_status=not_authorized`, and `provider_calls=0`.

The exact request-set hash binds the full provider-disabled envelopes, including model,
instructions, output schema, selected source context, limits, and rendered input. It cannot be used
as spend authorization. A separate exact approval artifact remains mandatory.

## Claim boundary

Preparation packets always report `campaign_ready_count=0`. They cannot become campaign packages
until dependency execution evidence, fixing/mapping review, preregistration, genuine independent
reviewers, and exact capped authorization exist.

The issue snapshots remain `chronology_unproven` and historically contaminated. The controller
also records a bounded, non-secret count when a hidden patch's added line already occurs in the
independently derived buggy-base request context. This is contamination evidence, not evidence that
hidden bytes crossed the evaluator boundary.

## Operational consequence

Fresh Git-object verification uses unauthenticated public GitHub reads and can fail closed when the
public rate limit is exhausted. Preparation output is transactional and removed on failure. The
tool never reads GitHub or provider credentials to bypass this limit.
