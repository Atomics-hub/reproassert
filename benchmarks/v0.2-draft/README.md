# Benchmark v0.2 draft

This directory is a design marker, not a frozen benchmark and not a scored campaign. It contains no
cohort manifest, model outputs, or results.

The v0.2 preparation contract replaces v0.1's unsubstantiated `pre_fix_source_snapshot` label with
the independently observable `pre_solution_pr_publication` cutoff. Snapshot receipts separately
record whether earlier private fix chronology is proven or unproven. That caveat never enters the
three-field generator projection and must never be turned into a “before anyone attempted a fix”
claim.

No v0.2 cohort is frozen yet. Case IDs and receipts used by the draft validator are fixtures until a
new manifest is preregistered. Benchmark v0.1 remains immutable, blocked, and at 0/20.

The offline producer and validator now parse a frozen GitHub GraphQL capture format, require complete
issue-creation/body and title-rename histories, select the last combined revision strictly before
the fixing pull request's publication, rerun exact fixing-link redaction, and independently rederive
the safe three-field projection. Synthetic adversarial fixtures exercise the contract. This removes
the earlier producer-implementation blocker; it does **not** make a campaign ready.

There is no authenticated collector and no v0.2 cohort. The evaluator must pre-bind the correct
fixing pull request and preserve the raw issue-history and publication-basis artifacts outside the
generator view. Capture authenticity remains trusted-controller evidence rather than a GitHub-signed
attestation, and the explicit privacy review remains a human semantic gate. The fixture-only
override is still not evidence.

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
