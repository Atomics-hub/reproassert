# Outreach drafts

Status: **draft copy only — do not send without Tom's separate exact approval**

## Maintainer validation request

Subject: Five-minute check of a failing test for `<issue URL>`

> I maintain ReproAssert, an open-source tool that creates a candidate failing pytest reproduction
> without changing production code. It generated one candidate against the exact buggy commit for
> `<issue URL>` without access to the historical fix. The commit is
> `<base SHA>`. Would you be willing to spend about five minutes checking whether the test captures
> the issue faithfully? The packet includes the patch, one sandboxed command, bounded run evidence,
> and its limitations. I will not open a pull request or post the result unless you separately ask.

## Show HN draft

Title: Show HN: ReproAssert — the failing test before the fix

> ReproAssert takes a public GitHub issue and exact commit, asks a pluggable generator for one pytest
> candidate, then verifies it in locked-down containers. It rejects setup/import failures, generic
> crashes, unrelated failures, timeouts, and flaky one-offs, and emits a patch, replay command, and
> machine-readable evidence report. The local tool is useful without a hosted account. Historical
> benchmark results, wrong-reason failures, cost, and maintainer judgments are published as evidence,
> including abstentions; a fail-to-pass transition alone is not called semantic correctness.

Before posting, replace the final sentence with exact measured counts and links. If the 20-case
campaign is incomplete, do not post benchmark language that implies otherwise.

## Short launch post

> The annoying first hour of a bug is often proving it exists. ReproAssert turns an issue plus an
> exact commit into one sandbox-verified failing pytest patch, a replay command, and an auditable
> report—without editing production code. Open source, opt-in, and deliberately willing to abstain.
> `<repository link>` `<measured benchmark link>`

Do not add “state of the art,” “production safe,” success-rate, time-saved, cost, or maintainer-demand
claims until the linked public evidence directly supports them.
