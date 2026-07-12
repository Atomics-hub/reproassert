# Benchmark v0.2 draft

> v0.2.1 result: the automated successor evaluated all 20 frozen cases and accepted 0. Seventeen
> candidates failed the frozen contract and three failed deterministic attribution after sandbox
> execution. See the committed public result bundle in `../v0.2-results/`.

This directory preserves the public selection and preparation history. It is not itself the result
bundle. The v0.2.1 campaign made 20 calls for $0.688111, accepted 0/20, made no L2 or human-review
claim, and has zero maintainer validations.

The v0.2 preparation contract replaces v0.1's unsubstantiated `pre_fix_source_snapshot` claim with
the bounded `dataset_snapshot_at_pinned_commit` source. The frozen plan conservatively labels every
case `chronology_unproven`; a later hash-bound receipt now proves the narrower fact that public issue
creation precedes fixing-artifact creation for 20/20. The later title/body snapshot remains
`historical_public_contamination_exposed`. The supported ceiling is “generated against the exact
buggy base with the historical fix hidden,” never “before anyone attempted a fix.” Full historical
body-revision capture remains optional future evidence.

The committed [`upstream-provenance.json`](upstream-provenance.json) is a public, oracle-safe
projection from a real offline parse of the exact 500-row SWE-bench Verified Parquet artifact and
an exact join against all 449 TDD-Bench Verified member IDs. It binds both upstream commits, Git
objects, artifact hashes, parser protocol, PyArrow version, and the shipped worker hash while
excluding instance IDs, row ordinals, row commitments, production patches, and developer tests.
[`upstream-object-witness.json`](upstream-object-witness.json) independently recomputes the commit,
root tree, nested path, terminal blob, LFS pointer, and artifact identities. Host-native parsing is
preparation-only and cannot mint semantic evidence. Production selection was rederived inside the
hash-locked parser image and recorded in
[`dataset-parser-boundary-attestation.json`](dataset-parser-boundary-attestation.json).

[`leak-audited-cohort-plan.json`](leak-audited-cohort-plan.json) fixes the deterministic 20 cases.
The 500-row audit quarantined every direct own-fix reference and every production/test added-line
overlap of at least 40 stripped characters; 64 rows were excluded and the final 20/20 are
mechanically clean. [`selection-freeze.json`](selection-freeze.json) binds that plan to the parser
image, boundary receipt, upstream witness, and explicit 0/20 result state.

### Append-only v0.2.1 preparation successor

The original parser image identity was frozen correctly but its exact image archive was not
retained, so a fresh Docker build cannot reproduce that local image ID even when its parser output
is byte-identical. The original selection freeze and boundary attestation remain immutable.
[`preparation-freeze-v0.2.1.json`](preparation-freeze-v0.2.1.json) is an append-only operational
successor for `linux/arm64`: it preserves the same 20-case cohort and parser-receipt commitment,
binds the replacement exact image ID, and records that no provider call, result, or campaign
readiness changed. New preparation commands default to the successor image; verification continues
to accept the exact legacy image for historical receipts.

The successor freeze binds the fresh public-safe
[`dataset-parser-boundary-attestation-v0.2.1.json`](dataset-parser-boundary-attestation-v0.2.1.json):
the exact replacement image rederived the unchanged parser receipt and output under the frozen
no-network, read-only, capability-dropped policy. Private dataset and hidden-gold receipts must
still freshly verify their exact stored bytes before authorizing case preparation. At the time it
was frozen, this correction did not change the then-unrun 0/20 state. The later v0.2.1 result is
preserved separately in `../v0.2-results/`.

The successor freeze also binds the release archive name, exact 92,300,454-byte size, and SHA-256.
After downloading that asset from the v0.2.1 release, install it without trusting a mutable tag:

```console
reproassert benchmark install-v02-parser-image \
  reproassert-dataset-parser-0.2.1-linux-arm64.tar.gz \
  --archive-sha256 7dc1c4e4d6bae1c57ba3dba65f29600437eac37e1f5a26f75e08c7867ede44fd
```

The installer loads only the verified bytes and then requires the frozen image ID and
`linux/arm64` platform. A different archive, image ID, or architecture fails closed.

The offline producer and validator now parse a frozen GitHub GraphQL capture format, require complete
issue-creation/body and title-rename histories, select the last combined revision strictly before
the fixing pull request's publication, rerun exact fixing-link redaction, and independently rederive
the safe three-field projection. Synthetic adversarial fixtures exercise the contract. This removes
the earlier producer-implementation blocker; it does **not** make a campaign ready.

GitHub's public REST issue endpoints do not expose complete body revision history. The selection
therefore makes no prospective chronology claim. If a future campaign upgrades a case to
`pre_solution_pr_publication`, the evaluator must preserve complete GraphQL history and the fixing-PR
publication basis outside the generator view and pass the existing privacy gate.

The offline command never collects from GitHub or chooses the fixing pull request. An evaluator must
capture the frozen query responses, choose and preserve the publication basis outside the generator
view, complete the privacy checklist, and then provide every identity explicitly:

```console
reproassert benchmark produce-snapshot rk-v0.2-001 \
  --repository OWNER/REPOSITORY \
  --issue-url https://github.com/OWNER/REPOSITORY/issues/NUMBER \
  --base-sha <exact-buggy-sha> \
  --raw-history <private-issue-history.json> \
  --cutoff-basis <private-fixing-pr-publication.json> \
  --captured-at <rfc3339-utc> \
  --tool-name <capture-tool> \
  --tool-version <capture-version> \
  --tool-git-sha <capture-tool-sha> \
  --privacy-reviewed-at <rfc3339-utc> \
  --privacy-reviewer-id <human-reviewer-id> \
  --privacy-checklist-sha256 <completed-checklist-sha256> \
  --output <private-0700-directory>/benchmark-snapshot-receipt.json
```

The command bounds and no-follow reads both evaluator artifacts, derives the receipt, independently
rederives it through the strict default validator, and writes exclusively. Its output contains only
receipt/snapshot digests and paths, not raw history or the fixing-PR basis. A successful derivation is
not proof that the capture is authentic, the selected fixing PR is correct, or the human review was
sound.

A bounded [self-owned fixture record](../../evidence/snapshot-producer-self-fixture.json) documents
one live derivation without committing raw history or manufacturing a privacy-approved receipt. It
is infrastructure proof only and is not a member of a v0.2 cohort.

## Structural package and freeze tooling

The v0.2 draft implementation now strictly parses and cross-binds:

- upstream TDD-Bench membership and source-dataset row provenance;
- fixing-PR identity, publication/merge chronology, base/head trees, production patch, developer
  tests, and the environment setup revision;
- the historical snapshot receipt, raw evidence, privacy checklist, and a generator projection that
  contains only case identity plus the frozen issue title/body commitment;
- exact-object source, causal dependency, production-isolation, reviewer-role, and semantic
  verification receipts; and
- a private salted evaluator-package identity with a public commitment.

The public preregistration encoder fixes 20 cases, five predeclared smoke cases, difficulty mix,
protocol hashes, one candidate per case, and evaluator commitments. The cohort audit rejects
duplicate upstream instances, fixing targets, base/fix pairs, or private nonces. The publication
scanner rejects private evaluator identities, patch bytes, and package paths in a proposed public
tree.

The application-owned issuer now mints nominal dataset evidence only from the revalidated
Docker-bound parser handoff and cross-binds the image, boundary attestation, private receipt, and
upstream evidence. Raw receipts and host-native preparation values are ineligible. The scored runner
then binds that evidence with source, dependency, hidden-fix, isolation, request, pricing,
authorization, and reviewer-role commitments before provider-capable work.

## Implemented local evaluator primitives

### Provider-disabled 20-case preparation

The supported zero-spend path now has two private stages. First, extract hidden evaluator inputs in
the pinned no-network parser image:

```console
reproassert benchmark prepare-v02-hidden-gold \
  --source-dataset <private-swe-bench-verified.parquet> \
  --cohort-plan benchmarks/v0.2-draft/leak-audited-cohort-plan.json \
  --prepared-at <rfc3339-utc> \
  --output-root <private-0700-directory>
```

Then prepare all 20 cases:

```console
reproassert benchmark prepare-v02-cases \
  --cohort-plan benchmarks/v0.2-draft/leak-audited-cohort-plan.json \
  --dataset-preparation-receipt <private-dataset-receipt> \
  --hidden-extraction-receipt <private-hidden-receipt> \
  --object-sources-root <private-exact-object-sources> \
  --pricing-snapshot benchmarks/v0.2-draft/gpt-5.4-mini-pricing-snapshot.json \
  --tool-git-sha <exact-controller-revision> \
  --prepared-at <rfc3339-utc> \
  --output-root <fresh-private-0700-directory>
```

For the amended exact-image dependency evidence path, replace the legacy wheel-plan input with the
complete verifier-bound set:

```console
reproassert benchmark prepare-v02-cases \
  ...the inputs above... \
  --instance-runtime-manifest <private-runtime-manifest> \
  --expected-runtime-manifest-sha256 <sha256> \
  --gold-smoke-receipt <private-all-case-gold-smoke-receipt> \
  --exact-capability-index <private-exact-capability-index>
```

This reruns the dataset and hidden Docker boundaries, freshly rederives every Git source, freezes
the exact provider request envelopes, and writes dependency, review, pricing, and unsigned spend
preflight records. It cannot call a provider and does not read an API key. Its current honest output
is 20/20 pre-review packets, 0/20 campaign-ready, and 0 provider calls. The legacy no-plan mode
remains 0/20 dependency-ready. Exact-image mode derives its dependency-ready count only from fresh
gold-smoke verifier authority; an installed image, tag, digest, or wheel plan alone never counts.
`verify-v02-cases` performs the same fresh checks and can fail closed when GitHub's unauthenticated
public rate limit is exhausted.

The frozen pricing capture records official GPT-5.4 mini rates of $0.75/M input tokens, $0.075/M
cached input tokens, and $4.50/M output tokens as observed on 2026-07-10. It is not authorization.
The packet contains only an unsigned proposal capped at $0.25 per case and $5.00 total.

The preparation-only dependency executor now turns one strict reviewed wheel plan into fresh,
distinct, quota-bounded tmpfs volumes; fixed networked download and network-disabled install phases;
wheelhouse and installed-tree attestations; a typed read-only mount handle; and a canonical bounded
receipt. A separate strict loader/verifier recomputes and cross-binds plan, requirements, image,
volume policy, phase commands/results, causal sequence, tree, and cleanup fields. The receipt always
records that campaign readiness did not change. Real local Docker checks passed a pinned
`six==1.17.0` PyPI download, offline install, verifier borrow, and inode-quota `ENOSPC` canary.

The internal differential primitive accepts only the nominal evaluator capability, revalidates and
applies exactly one candidate to separately attested base/fixed trees, and runs the frozen schedule
`base, fixed, fixed, base, base, fixed`. A real local Docker fixture produced three matching base
failures and three exact fixed passes. Raw fixed stdout/JUnit is reduced to digests before the public
record. This fixture does not come from an authentic v0.2 package and is not an L1 result.

The automated successor campaign executed on 2026-07-12. It reserved spend before each provider
call, wrote durable candidate transactions before evaluation, recovered without duplicate calls,
and emitted the complete 20-case aggregate. No case was accepted. Any future published accepted
case would still require `reproassert benchmark replay-v02-case <bundle>` to reacquire exact source
and rebuild hash-locked dependencies without invoking a model.
