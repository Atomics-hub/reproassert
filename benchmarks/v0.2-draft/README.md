# Benchmark v0.2 draft

This directory is a design marker, not a frozen benchmark and not a scored campaign. It contains no
cohort manifest, model outputs, or results.

The v0.2 preparation contract replaces v0.1's unsubstantiated `pre_fix_source_snapshot` label with
the independently observable `pre_solution_pr_publication` cutoff. Snapshot receipts separately
record whether earlier private fix chronology is proven or unproven. That caveat never enters the
three-field generator projection and must never be turned into a “before anyone attempted a fix”
claim.

The committed [`upstream-provenance.json`](upstream-provenance.json) is a public, oracle-safe
projection from a real offline parse of the exact 500-row SWE-bench Verified Parquet artifact and
an exact join against all 449 TDD-Bench Verified member IDs. It binds both upstream commits, Git
objects, artifact hashes, parser protocol, PyArrow version, and the shipped worker hash while
excluding instance IDs, row ordinals, row commitments, production patches, and developer tests.
This is authentic upstream-input evidence, not a selected 20-case cohort, campaign freeze, model
run, or benchmark result. The host-native PyArrow step remains evidence preparation only; hosted
use requires the same parser in a memory-bounded, no-secret, network-disabled container or microVM.

No v0.2 cohort is frozen yet. Case IDs and receipts used by the draft validator are fixtures until a
new manifest is preregistered. Benchmark v0.1 remains immutable, blocked, and at 0/20.

The offline producer and validator now parse a frozen GitHub GraphQL capture format, require complete
issue-creation/body and title-rename histories, select the last combined revision strictly before
the fixing pull request's publication, rerun exact fixing-link redaction, and independently rederive
the safe three-field projection. Synthetic adversarial fixtures exercise the contract. This removes
the earlier producer-implementation blocker; it does **not** make a campaign ready.

There is no authenticated collector and no v0.2 cohort. GitHub's public REST issue endpoints expose
current issue text and selected events, but not the complete body revision history required by this
contract; the supported history shape comes from authenticated GitHub GraphQL. No third-party
GraphQL capture has been authorized. The evaluator must pre-bind the correct fixing pull request and
preserve the raw issue-history and publication-basis artifacts outside the generator view. Capture
authenticity remains trusted-controller evidence rather than a GitHub-signed attestation, and the
explicit privacy review remains a human semantic gate. The fixture-only override is still not
evidence, and the cutoff will not be weakened to fit unauthenticated REST data.

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

These are structural controls, not evidence producers. Case verification requires an
application-selected trusted semantic verifier and fails closed without one. Even a structurally
valid package deliberately returns no live `VerifiedV02EvaluatorCapability`; the cohort audit
therefore remains `ready: false` until an official application-owned issuer rederives the source,
dependency, two-tree patch causality, production isolation, and reviewer seal in process. Repository
code, issue text, model output, plugins, and package-controlled executables must never supply that
issuer.

## Implemented local evaluator primitives

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

There are still no authentic v0.2 issue-history captures or case packages, no frozen 20-case
cohort, no model campaign, and no public L1/L2 result. The upstream provenance record does not
change those facts or authorize model/provider or GitHub Actions spend.
