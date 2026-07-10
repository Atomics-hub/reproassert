# Changelog

All notable changes to ReproAssert will be documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases use [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Exact Git-object benchmark preparation and replay commands with complete Trees API
  reconstruction, bounded codeload transport, exact raw-blob repair, root-confined tracked
  symlinks, empty gitlink boundaries, deterministic receipts, and a public 20/20 no-model baseline.
- Offline historical snapshot production from complete GitHub edit-history evidence with strict
  pre-publication selection, fixing-PR redaction, privacy-review commitments, durable-file
  rederivation, and a self-owned live proof record.
- A causal dependency executor for hash-locked wheel closures, with fresh byte/inode-bounded tmpfs
  volumes, inspected networked-download and offline-install phases, installed-tree attestation,
  typed read-only verifier handles, strict cleanup, and an independently verifiable receipt.
- Fail-closed v0.2 evaluator-package, preregistration, semantic-receipt, provenance, and publication
  leak-audit contracts. No cohort or official semantic capability issuer is included yet.
- Capability-gated interleaved base/fixed differential verification with exact structured JUnit
  evidence. This is evaluator infrastructure, not a published benchmark result.

### Changed

- Documented a local-first CI budget: batch coherent pull-request updates, diagnose failures locally,
  and require an explicit cost rationale for new workflows, triggers, matrices, or metered services.
- Report schema 1.1 now binds the exact candidate-applied tree that entered the sandbox; replay
  recomputes that overlay while retaining read support for schema 1.0 reports.

### Fixed

- Made tag-release staging remove the `uv build`-generated `dist/.gitignore` sentinel and added a
  guarded manual recovery path that rebuilds an existing immutable tag at its exact verified commit,
  with a signed attestation binding the tag to that commit alongside workflow provenance.

### Security

- Added adversarial Git-object, codeload, raw-blob, symlink-chain, snapshot-history, wheel-archive,
  resource-policy, receipt-tampering, and private-I/O regressions. Red-team review found no remaining
  P0/P1 in the reviewed causal dependency, candidate-overlay, JUnit transport, or differential
  paths. Dependency bytes and inodes are bounded, and missing structured test evidence fails closed.

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
