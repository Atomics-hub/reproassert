# ADR 0001: Use ReproAssert as the working public name

Date: 2026-07-09

Status: accepted as the working product and CLI name; formal legal clearance remains pending.

## Context

The repository began under the name ReproKit. A separate live developer product at [reprokit.app](https://reprokit.app/) already uses ReproKit for a closely adjacent promise: turning frontend runtime signals into reproducible issues. A public launch directory recorded that product in June 2026 at [VibeCrowd](https://vibecrowd.fund/prelaunch/reprokit).

This is enough to create search, package, support, and category confusion even without reaching a legal conclusion.

## Decision

Use **ReproAssert** as the working public product name and `reproassert` as the CLI/package command.

Use the bounded positioning:

> The test before the fix.

The intended public contract is an independently verified reproduction artifact, not autonomous bug fixing.

Generated machine-readable output should use `reproassert-report.json`. The report schema must remain versioned independently of branding so that a future rename does not silently change semantics.

## Point-in-time collision check

On 2026-07-09, lightweight exact-name checks found:

- zero GitHub repository name-search results for `ReproAssert`;
- no exact `reproassert` project at the PyPI JSON endpoint;
- no active exact-name software product in quoted web searches; and
- not-found responses from `.dev` and `.com` RDAP lookups.

These checks are directional only. They are not a trademark search, legal opinion, domain reservation, package reservation, or guarantee that another unindexed or jurisdiction-specific use does not exist.

## Alternatives considered

- **Keep ReproKit:** rejected because the live same-name developer product creates avoidable confusion.
- **IssueWitness:** clean point-in-time signals and strong evidence language, but less direct about executable reproduction.
- **ReproWitness:** preserves the reproduction concept, but is longer and less directly connected to pytest assertions.
- **BugWitness:** rejected because an overlapping public testing/evidence project already exists at [llm-case-studies/BugWitness](https://github.com/llm-case-studies/BugWitness).
- **ReproAudit:** rejected because [ReproAudit](https://reproaudit.com/) is an active reproducibility product.

## Consequences

Positive:

- avoids the known ReproKit collision;
- communicates reproduction plus an executable assertion;
- works as a concise CLI command; and
- supports evidence-first positioning without an AI-branded name.

Negative:

- sounds technical and may be mistaken for a narrow assertion library without supporting copy;
- requires consistent replacement of working ReproKit references; and
- may still fail a formal clearance process.

## Follow-up requirements

1. Complete formal trademark and commercial-name review before a paid launch.
2. Obtain explicit approval before buying or registering any domain, package name, or external service.
3. Keep repository, package, CLI, docs, report filenames, and demo assets consistent once the rename is implemented.
4. If clearance fails, revisit IssueWitness and ReproWitness using fresh searches.
