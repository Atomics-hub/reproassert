# 0010 — Keep required CI path-aware and bounded

Status: accepted and implemented locally, pending public PR verification, on 2026-07-10

## Context

The original required pull-request workflow started nine hosted jobs on every change: quality, five
Python versions, another distribution build, the site, and Docker. That is strong coverage but poor
feedback economics for documentation or isolated surfaces. Repeated matrix pushes also create more
noise and artifact storage even though standard hosted runners are currently free for this public
repository.

GitHub warns that a required workflow skipped by event-level path filtering can remain pending.
Individual jobs skipped by a job condition report success. The workflow therefore must still start
on every pull request while optional jobs decide from the complete Git diff.

## Decision

- Run the quality/benchmark-contract job on every pull request.
- Run unit and wheel smoke on the supported-version extremes, Python 3.10 and 3.14, on every pull
  request. Local/release verification may cover the intermediate interpreters.
- Run the distribution job only when Python, tests, schemas, scripts, project metadata, the lockfile,
  or the workflow changes.
- Run the site job only when the site, canonical public report schema, or workflow changes.
- Run Docker only when sandbox, verifier, dependency, candidate-workspace, semantic-evaluator,
  v0.2 benchmark, integration-test, asset, or workflow surfaces change.
- Derive scope with a repository script over `base...HEAD`, not the event path filter. Invalid or
  manual context fails safe by enabling every optional lane.
- Keep concurrency cancellation, pinned Action SHAs, seven-day artifacts, no scheduled full matrix,
  and one deliberate push per coherent pull request.

The protected-branch ruleset must require only the six stable contexts produced by the reduced
workflow: quality, Python 3.10, Python 3.14, distribution, site, and Docker. Skipped optional jobs are
still visible successful checks; they are not silently absent.

## Consequences

A documentation-only pull request uses three runner jobs instead of nine. A core evaluator change
uses at most five because the site stays skipped; a site-only change uses four. Changes to the
workflow itself deliberately run every lane.

This policy saves feedback and storage but does not replace release verification. Before a tag, the
exact source still needs the full package, schema, site, Docker, and clean-install gates. If an
intermediate Python version exposes a compatibility bug, restore a targeted required lane or add a
release-only compatibility check based on evidence rather than defaulting every PR back to five
full copies of the same suite.
