# ReproAssert evaluation protocol

Version 0.1 evaluates whether ReproAssert can turn a historical GitHub issue into a verified failing pytest reproduction before a fix is attempted. The protocol is frozen before scored runs and separates generation from hidden-fix evaluation.

The primary result is `semantic_valid_success_at_1`: the number of cases for which the single submitted candidate reaches L2, divided by all 20 frozen cases. Raw patch production, collection, base failure, or fail-to-pass are diagnostic milestones, not the headline success metric.

## Claims

| Level | Required evidence | Allowed wording |
| --- | --- | --- |
| L0 — executable candidate | Test-only patch applies, compiles or collects, and produces the same issue-aligned failure on all three base executions. | "Verified failing candidate on the pinned buggy base." |
| L1 — plausible fail-to-pass | L0 plus passes on all three hidden-fixed executions. | "Plausible fail-to-pass reproduction." Do not call it semantically correct. |
| L2 — semantic valid | L1 plus causal controls and blinded review support a faithful trigger and oracle. | "Semantic-valid reproduction under benchmark v0.1." |
| L3 — maintainer validated | A real maintainer independently validates or accepts the artifact. | "Maintainer validated," linked to recorded external evidence. |

Before a fix exists, L0 is the public ceiling. Within this historical benchmark, L2 is the primary success definition. L3 is outside the internal benchmark and cannot be inferred from L2.

## Frozen cohort

[`benchmarks/v0.1/manifest.json`](../benchmarks/v0.1/manifest.json) declares 20 public GitHub issues from 10 Python repositories and pins the exact buggy commit for each. Every case is in the 449-case TDD-Bench-Verified release and has a human fix/test record available to the evaluator.

The cohort was selected for initial feasibility: public GitHub issue, pytest-compatible repository, historically replayable environment, no complete final test in the issue body, and upstream human effort below one hour. This makes the set useful for an early product gate but systematically easier than the full population of maintainer reports.

Five predeclared smoke cases exercise checkout, dependency image, patch application, pytest collection, result capture, and cleanup. Smoke runs may be discarded while fixing the harness only if they never expose evaluator-only material to the generator. Once the scored run begins, every case outcome is retained.

## Generator/evaluator boundary

| Generator may see | Evaluator only |
| --- | --- |
| Repository and canonical issue URL | Fixing pull request URL or number |
| Exact buggy base SHA and checked-out base tree | Fixed commit and production patch |
| Frozen pre-fix issue title and body | Developer-written tests and gold patch |
| Repository-owned documentation and tests present at the base SHA | Oracle symptom rubric, decoys, and alternative-fix controls |
| Declared resource policy and generated-run feedback | Other benchmark cases' hidden artifacts or verdicts |

Issue comments are excluded. Backlinks or automatic references to a fixing pull request are stripped from the issue snapshot. The snapshot hash, capture time, cutoff, included fields, and stripping decision are recorded. Generation has no access to benchmark source records that encode a fix.

Dependency preparation is a separate bounded phase. It may access approved package indexes and the cloned public repository, records the resulting image digest and lock evidence, and exposes no host credentials. Every generation and verification execution starts from a fresh container or equivalent real sandbox. Network access is disabled after dependency preparation. The sandbox receives no SSH agent, cloud credentials, browser state, GitHub token, unrelated host directory, or evaluator artifact.

The model/provider/version, prompt hash, configuration hash, tool commit, image digest, limits, timestamps, token usage, cost, and submitted patch hash are recorded. Exactly one candidate per case is submitted for scoring. Internal attempts may be counted, but no candidate may be selected using the hidden fix, gold tests, or their execution results.

## Candidate policy

A candidate may add or edit only test modules and narrowly scoped test fixtures inside the repository's established test tree. It may not alter production code, dependency declarations or locks, build configuration, CI, pytest configuration, interpreter startup files, or existing assertions merely to manufacture a failure.

The evaluator rejects candidates containing unconditional `assert False`, unconditional raise/exit, skip or xfail used to simulate a result, arbitrary sleeps, wall-clock or randomness dependence, external network access, subprocesses unrelated to the issue, destructive writes outside the sandbox, resource exhaustion, or assertions against implementation details unsupported by the report.

A reported exception can be a valid oracle only when the issue itself identifies that exception and the trigger reaches the relevant product behavior. Syntax errors, import/setup errors, missing dependencies introduced by the candidate, collection errors, timeouts, out-of-memory exits, and generic crashes are never valid reproductions.

Minimality is reviewed, not enforced by an arbitrary line threshold. Fixtures and setup needed to reach the behavior are allowed; unrelated changes are not.

## Scored procedure

1. **Freeze inputs.** Verify the manifest and schemas; snapshot issue title/body at the declared pre-fix cutoff; hash every artifact. Neither cohort nor scoring rules change after generation output is observed.
2. **Prepare dependencies.** Build the case image with bounded network policy, record the digest and cold cost/time, then disable network. A repository that cannot be prepared for benchmark reasons is `benchmark_infrastructure_error`; a setup error caused by the candidate is `setup_failure`.
3. **Generate on base.** Run ReproAssert against the exact base tree with only generator-visible inputs. Preserve logs under output limits and choose one candidate without oracle feedback.
4. **Inspect policy and patch.** Reject empty/unapplicable patches and forbidden file or behavior changes before executing code. Parse the diff; do not rely only on filename conventions or model declarations.
5. **Collect target nodes.** Apply the patch to a clean base tree and collect exactly the declared generated pytest node IDs. Collection must succeed without running unrelated tests.
6. **Run interleaved verification.** In six fresh clean environments execute the schedule `base, fixed, fixed, base, base, fixed`. Each execution uses the same candidate and command. The three base results must share an issue-aligned normalized failure fingerprint; the three fixed results must pass. Interleaving reduces systematic warm-cache and time-order bias.
7. **Apply causal controls.** When production fix hunks can be separated, `fix minus issue-relevant hunks` should continue to fail and `base plus issue-relevant hunks` should pass. Record `not_available` or `inconclusive` with a reason when hunks are inseparable. Repository-appropriate decoy or alternative-fix controls are supporting evidence and must be declared before unblinding the gold tests.
8. **Review semantics while blinded.** Two reviewers inspect the frozen issue, candidate, normalized base failure, fixed pass evidence, and declared causal-control results without seeing developer tests or the human test patch. A third reviewer breaks a disagreement. Reviewer identities, binary rubric answers, confidence, rationale, and agreement are recorded.
9. **Unblind after verdict.** Developer tests and gold artifacts may be inspected only after the semantic verdict is committed. They may explain divergence but cannot retroactively select or rewrite the submitted candidate.
10. **Append the result.** Write one immutable JSON object per case to `benchmarks/v0.1/results.jsonl`, including rejected and infrastructure outcomes. Validate the ledger before calculating aggregate metrics.

## Semantic review rubric

An L2 verdict requires reviewers to answer yes to all of the following:

1. **Trigger faithful:** setup and action represent a state reachable under the issue as written, without smuggling in the hidden implementation.
2. **Oracle supported:** the assertion or expected exception follows from explicit issue evidence, stable public behavior, or a documented invariant—not merely from the human patch.
3. **Failure causal:** the buggy behavior, rather than collection/setup damage or unrelated repository drift, causes the base failure.
4. **Implementation independent:** the test permits reasonable alternative fixes and does not assert a private implementation detail without necessity.
5. **Minimal and readable:** every material fixture/action/assertion contributes to reproducing the symptom and a maintainer could understand the artifact.

Disagreement remains `disagreement` until the blinded tie-break verdict is recorded. A mechanically fail-to-pass test that misses any semantic condition is `plausible_f2p_semantic_invalid`.

## Terminal outcomes

Each case receives exactly one terminal outcome:

| Outcome | Meaning |
| --- | --- |
| `benchmark_infrastructure_error` | Evaluator or historical environment failed independently of the candidate; repair and rerun before reporting a complete scored benchmark. |
| `no_output` | No candidate was produced within budget. |
| `invalid_patch` | Candidate is empty, malformed, or does not apply. |
| `policy_violation` | Candidate edits forbidden files or uses prohibited behavior. |
| `setup_failure` | Candidate-caused dependency, setup, or top-level execution error prevents collection. |
| `collect_failure` | Intended generated test node does not compile or collect. |
| `pass_on_base` | Candidate runs but does not fail on the buggy base. |
| `wrong_failure` | Repeatable base failure is unrelated, generic, or occurs in a disallowed phase. |
| `flaky_base` | Base behavior or fingerprint is inconsistent across required runs. |
| `fail_on_fix` | Candidate still fails after the hidden production fix. |
| `flaky_fix` | Fixed executions do not all pass. |
| `plausible_f2p_semantic_invalid` | Candidate is fail-to-pass but fails semantic review or causal controls. |
| `semantic_valid` | Candidate reaches L2 and counts toward the primary metric. |

An infrastructure error is reported and excluded from no denominator silently: the 20-case aggregate is incomplete until the case is repaired and rerun. Other terminal failures remain in the denominator.

## Metrics and gates

Report at minimum:

- L0, L1, and L2 counts out of 20, with per-case terminal outcomes.
- Primary `semantic_valid_success_at_1 = L2 / 20` and an exact binomial 95% confidence interval.
- Setup, collection, wrong-failure, base-flake, fixed-failure, and semantic-invalid rates.
- Cold-cache and warm-cache p50/p90 dependency, generation, verification, and total wall time.
- Total attributable cost, cost per attempted case, and `total attributable cost / L2 count`; when L2 is zero, cost per success is undefined rather than zero.
- Model input/output tokens and model, sandbox compute, artifact transfer, and cold dependency-prep cost as separate fields.

Attributable cost includes every successful and failed scored attempt. Report one-time dependency image construction and human curation/review labor separately. Median cost among successful cases alone is not a decision metric because it hides spend on failures.

The internal continuation gates are:

- at least 6/20 semantic-valid reproductions;
- median warm total runtime under 600 seconds per case;
- attributable cost per semantic-valid reproduction at or below $1, or a documented measured path to that level.

The external gates are one generated test independently accepted or validated by a real maintainer and three maintainers willing to use ReproAssert again. Maintainers must not be contacted and third-party issues or pull requests must not be opened without Tom's separate exact approval.

Six successes in 20 has wide statistical uncertainty and this sample is selected. Passing the gate justifies continuing the product bet; it does not establish a population rate, superiority over other systems, or state-of-the-art performance.

## Contamination and reproducibility limits

This is a historical public benchmark. A model may have encountered an issue, code, fix, or downstream discussion during pretraining. Generator isolation prevents live lookup and accidental oracle mounting, but it cannot erase memorized data. Every published result must therefore say `historical public, contamination-exposed` and identify the exact model version and run date.

The full manifest, failure rows, environment digests, commands, bounded-log hashes, costs, and aggregate script must be public. Evaluator-only gold artifacts should remain access-controlled until the run is locked, then may be released in a leakage-labeled evaluation bundle if upstream licensing permits. No post-hoc case replacement, silent rerun, or best-of-N selection is allowed. Corrections that could change a score create a new benchmark version.
