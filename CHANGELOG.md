# Changelog

All notable changes to ReproAssert will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-09

### Added

- Initial Python and pytest issue-to-reproduction workflow.
- Docker sandbox boundary with disabled verification-time networking and bounded resources.
- Deterministic report, candidate patch, and replay artifacts.
- Preregistered historical benchmark contract and validation tooling.
- Least-privilege CI, clean-package smoke tests, and tag-only attested GitHub releases.
- Explicit opt-in OpenAI Responses adapter with strict structured output and bounded usage metadata.
- Proof-first public site, static GitHub Pages export, and desktop/mobile browser QA.
- Adversarial regressions for false assertions, generic crashes, forged pytest output, and nested
  secret-like context paths.

### Changed

- Grouped routine dependency updates into a monthly, one-PR-per-ecosystem budget and disabled
  redundant full CI after protected pull-request checks have passed.
- Reduced repository Actions artifact and log retention from 90 days to 7 days, retained the
  included 10 GB cache hard cap, and removed stale closed-PR caches.
- Required maintainer approval before workflows from any external contributor's fork can execute.
- Enforced full-length commit SHA pinning for every referenced GitHub Action at repository level.

### Security

- Updated the public site's runtime and build dependencies to patched versions; both the full and
  production-only npm audits report zero known vulnerabilities for the release candidate.

[Unreleased]: https://github.com/Atomics-hub/reproassert/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Atomics-hub/reproassert/releases/tag/v0.1.0
