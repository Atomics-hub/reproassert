# Market validation

Date: 2026-07-09

Status: test-first validation in progress; no market or performance claim is proven yet.

## Product hypothesis

ReproAssert turns a GitHub issue and an exact repository commit into a candidate Python/pytest reproduction before a human or coding agent attempts a fix. A claimed success must include a test patch, one-command reproduction, and structured evidence showing that the test collects and repeatedly fails on the buggy base for the intended symptom.

The initial paying-user hypothesis is a 5-50 engineer team that:

- maintains Python/pytest repositories on GitHub;
- receives at least 10 actionable bug reports per month;
- already uses coding agents or wants an independent gate before agent-generated fixes; and
- can run its test environment without specialized hardware or unrestricted production access.

Open-source maintainers are an important adoption and trust cohort, but are not assumed to be the primary revenue buyer.

## What public evidence says

| Evidence | Observation | Evidence ceiling |
| --- | --- | --- |
| [GitHub Octoverse 2025](https://github.blog/news-insights/octoverse/octoverse-a-new-developer-joins-github-every-second-as-ai-leads-typescript-to-1/) | GitHub reported more than 180 million developers, a 2025 monthly average of 17.5 million issues created, and Python as its second-most-used language. | This establishes a large distribution surface. It does not estimate the number of eligible issues or paying ReproAssert accounts. |
| [GitHub enterprise AI survey](https://github.blog/news-insights/research/survey-ai-wave-grows/) | In a 2,000-person survey, more than 98% of respondents said their organizations had experimented with AI-generated tests. | Self-reported experimentation is not adoption, repeat use, or willingness to pay. |
| [Stack Overflow 2025 AI survey](https://survey.stackoverflow.co/2025/ai) | 46% distrusted AI-tool accuracy; 87% reported accuracy concerns and 81% reported security/privacy concerns about agents. | This supports a trust problem, not demand for this particular solution. |
| [Issue2Test](https://arxiv.org/abs/2503.16320) | The paper reports 30.4% issue reproduction on SWT-Bench Lite. | Research result on a curated historical benchmark; not ReproAssert performance. |
| [Echo](https://arxiv.org/abs/2603.07326) | The March 2026 preprint reports 66.28% on SWT-Bench Verified. | Preprint result with its own method and evaluation; do not compare as if all benchmark settings were identical. |
| [BRT Agent](https://arxiv.org/abs/2502.01821) | The Google study reports plausible reproduction tests for 28% of 80 internal bugs. | Industrial feasibility evidence, not a public product or external demand result. |
| [BLAST](https://arxiv.org/abs/2509.01616) | BLAST reports 35.4% on 426 issue-patch pairs. In a three-repository Mozilla deployment, maintainers judged 6 of 11 proposed tests valid and integrated 2. | The live sample is small and BLAST receives the patch, unlike the pre-fix ReproAssert wedge. It also shows that fail-to-pass alone is insufficient. |
| [Rethinking the Value of Agent-Generated Tests](https://arxiv.org/abs/2602.07900) | The 2026 preprint found that agent-written tests often acted as observation channels and that changing test-writing volume did not significantly change issue-resolution outcomes. | Counterevidence: ReproAssert must demonstrate useful assertions and independent proof, not merely generate more tests. |

The research category is real and competitive. The unproven opportunity is productizing a secure, provider-neutral, independently verifiable workflow that abstains rather than returning a wrong-reason failure.

## Benchmark protocol

The first benchmark contains approximately 20 historical Python/pytest issues with known human fixes and tests. The generation path receives the issue, repository, and buggy base commit, but cannot inspect the hidden human fix or its test. Evaluation applies the hidden fix only after generation.

A semantically valid reproduction must:

1. install in the declared sandbox environment;
2. compile and collect without setup, import, or syntax failure;
3. fail repeatedly on the buggy base;
4. fail for the issue's intended symptom rather than a generic crash, timeout, or unrelated existing failure;
5. pass after the hidden human fix is applied without production-code changes from ReproAssert; and
6. preserve the base SHA, commands, environment facts, exit codes, bounded logs, patch, and rerun outcomes.

Report every assigned benchmark issue, including abstentions and failures. The denominator is all eligible assigned issues, not only issues for which the system emitted a test.

Track at least:

- semantic success rate;
- wrong-reason and generic-failure rate;
- setup/import/collection failure rate;
- abstention rate;
- flaky-one-off rate and repeated-run consistency;
- wall-clock time per attempt and per success;
- total and median model/compute cost, including failed attempts; and
- results by repository and issue type.

## Decision gates

Continue toward a hosted product only if evidence trends toward all of the following:

- at least 6 of 20 semantically valid reproductions;
- median runtime below 10 minutes;
- median model/compute cost below roughly $1 per successful reproduction, or a documented measured path there;
- at least one generated test accepted or independently validated by a real maintainer; and
- three maintainers willing to use the workflow again.

The cost gate is not a gross-margin result: aggregate cost must include unsuccessful attempts, runner preparation, storage, and support.

No maintainer contact, third-party pull request, issue comment, or outreach is authorized by this plan. Prepare candidate artifacts and an outreach packet; use them only after separate exact approval.

## Current verdict and claim ceiling

Verdict: **go for the narrow validation build; defer the hosted-business bet.**

Allowed now:

- describe the intended issue-to-reproduction contract;
- describe the sandbox and evidence format after they exist and are tested; and
- publish benchmark targets clearly labeled as targets.

Not allowed until measured:

- a ReproAssert success, speed, cost, or false-positive rate;
- claims of state of the art, production safety, or guaranteed semantic correctness;
- claims of maintainer acceptance, repeat demand, or willingness to pay; or
- claims that ReproAssert improves coding-agent fix rates.
