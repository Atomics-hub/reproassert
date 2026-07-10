# Launch plan

Date: 2026-07-09

Status: prepare and verify the public product slice; external outreach remains approval-gated.

## Launch promise

Working headline:

> The test before the fix.

Working description:

> ReproAssert turns a GitHub issue and exact commit into a sandboxed failing pytest patch,
> one-command reproduction, and auditable report without changing production code.

The first viewport should show an actual terminal run, generated patch, repeated failing result, and report excerpt. It should not lead with a generic AI claim.

## Milestone 1: credible open-source slice

Do not call the repository launched until all of these are public and reproducible:

- clean installation in a new environment;
- `reproassert issue <github-issue-url> --commit <commit>` working end to end for a supported fixture;
- a real sandbox/container boundary with secrets, filesystem, network, resource, time, and output controls;
- candidate test patch plus exact reproduction command;
- deterministic `reproassert-report.json` with bounded logs and rerun evidence;
- syntax, import/setup, collection, unrelated-failure, timeout, and flaky-one-off rejection;
- unit, integration, and adversarial security tests in CI;
- three public example runs, including at least one honest abstention or failure;
- the approximately 20-case hidden-fix benchmark with every result recorded; and
- architecture, security, contribution, roadmap, and benchmark-method documentation.

The release page must distinguish fixture success, benchmark results, and unvalidated product goals.

## Milestone 2: repository-native distribution

After Milestone 1:

1. Publish a verified GitHub release and package only after installation from the release artifact succeeds in a clean environment.
2. Provide `uvx`/`pipx` usage and a GitHub Action using the same core and report schema.
3. Make automation opt-in through manual dispatch, an explicit label, or a user command. Do not run or comment on every issue automatically.
4. Attach a GitHub Check and downloadable artifact to the exact commit rather than filling issue threads with repeated bot comments.
5. Require an explicit commit when an issue does not unambiguously identify the buggy base.

The [BLAST field study](https://arxiv.org/abs/2509.01616) found that maintainers preferred bug-only or on-demand triggers, that generated tests could become stale as a pull request changed, and that fail-to-pass tests could still miss issue semantics. Those observations inform the opt-in and exact-commit design; they do not establish ReproAssert outcomes.

## Milestone 3: launch assets

Prepare inside the repository:

- a 60-90 second terminal demo using a public fixture;
- three issue-to-report case studies with exact SHAs and commands;
- benchmark methodology and downloadable machine-readable results;
- a security threat model and residual-risk summary;
- comparison copy that distinguishes ReproAssert from coding agents, PR reviewers, telemetry debuggers, and research harnesses;
- Show HN, Python-community, and social launch drafts; and
- a maintainer-validation packet containing the patch, report, one-command reproduction, and short feedback form.

Preparation is authorized; posting to third-party communities, contacting maintainers, or opening third-party issues or pull requests is not authorized without separate exact approval.

## Milestone 4: maintainer and team validation

After approval to contact people:

- recruit approximately 10 qualified Python/pytest maintainers or teams;
- use on-demand runs only;
- record validity judgments, required edits, integration, time saved, repeat-use intent, and reasons for rejection;
- require at least one accepted or independently validated test and three participants willing to use it again; and
- test the $199 Hosted Team paid pilot only after useful results.

Do not count a benchmark pass, star, email compliment, or free trial as paid demand.

## Milestone 5: GitHub App and Marketplace

A public GitHub App can be shared with an install link before a paid Marketplace listing. GitHub recommends GitHub Apps over OAuth apps for granular permissions, and the [Checks API](https://docs.github.com/en/rest/guides/using-the-rest-api-to-interact-with-checks) supports rich commit-scoped results.

For a paid Marketplace listing, GitHub currently requires an organization-owned app, verified publisher status, and at least 100 GitHub App installations. See [Marketplace requirements](https://docs.github.com/en/enterprise-cloud%40latest/apps/github-marketplace/creating-apps-for-github-marketplace/requirements-for-listing-an-app) and the [Marketplace overview](https://docs.github.com/en/apps/github-marketplace/github-marketplace-overview/about-github-marketplace-for-apps).

The 100-install threshold is a listing prerequisite, not evidence of 51 paying accounts. Do not accept Marketplace agreements, complete financial onboarding, or enable billing without separate exact approval.

## Launch scorecard

Track weekly:

- clean-install completion rate;
- issue-to-first-report activation rate;
- semantic success, wrong-reason failure, setup failure, abstention, and flakiness rates;
- median wall time and aggregate model/compute cost;
- report reruns and shares;
- accepted or independently validated tests;
- participants willing to run another issue;
- qualified trial-to-paid conversion; and
- 30-, 60-, and 90-day account retention once paid pilots exist.

Current verdict: launch the verified open-source slice when Milestone 1 is genuinely complete. Defer hosted and Marketplace claims until the evidence gates pass.
