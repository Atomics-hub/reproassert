# 0015: Freeze fix-hunk mappings before generation

Status: accepted

## Decision

The evaluator inventories each hidden production patch before any provider request. The inventory
uses strict unified-diff parsing, ordered atomic hunk IDs, the exact patch SHA-256, and a patch
algebra commitment over the ordered hunk set. Preparation emits blank reviewer packets only. It
does not create identities, reviews, verdicts, or campaign readiness.

Every case requires two chronological, independent mapping-review submissions bound to the exact
packet. A third submission is required only when the first two decisions disagree, and its decision
must match one of them. Each reviewer declares a mapping-only role, no generator access, and no
semantic-review role. The later semantic-review role seal remains responsible for enforcing
campaign-wide separation.

The parser rejects path traversal, binary patches, renames, file-mode changes, create/delete diffs,
overlapping or reordered hunks, inconsistent hunk counts, and degenerate splits. All artifacts stay
evaluator-private. Preparation and sealing are provider-disabled and preserve the full 20-case
denominator.

## Consequences

- Missing or placeholder reviews cannot produce a seal.
- Agreeing first reviewers prohibit an unnecessary tie breaker.
- Review submissions and final consensus remain independently re-verifiable from the sealed set.
- The seal is evidence of recorded consensus, not proof that a named human is who they claim to be;
  operational reviewer identity verification remains a human process.
