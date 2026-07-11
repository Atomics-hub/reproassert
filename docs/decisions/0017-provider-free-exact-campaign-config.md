# ADR 0017: provider-free exact campaign config controller

The exact v0.2 campaign uses one generated private config rather than a hand-authored 20-case JSON
file. `prepare-v02-exact-campaign-config` freshly verifies the case preparation, chronology,
mapping consensus, exact preregistration, runtime/capability/gold evidence, campaign freeze,
execution freeze, and exact authorization. It derives projections, object-source receipts, the
copied cohort plan, and builder-owned source-evidence paths from canonical verified artifacts.

Preparation has no provider adapter, does not inspect environment credentials, and reports zero
provider calls. It creates the complete private workspace in a staging directory, fsyncs it, and
publishes it with one directory rename. An identical existing workspace is reverified and accepted;
no mutable run state is overwritten.

The config binds its raw bytes and self-hash, all upstream artifact hashes, the 20-case binding-set
hash, campaign/request/freeze identities, final tool SHA, model, authorization/config/execution
times, and the fixed USD 5.00 total and USD 0.25 per-case zero-overage caps. The public runner first
obtains a fresh verifier-issued authority and then reloads only the exact raw hash that authority
approved. This closes the verification-to-load replacement window before provider-capable code.

Object-source receipts may predate the final tool revision. They are the sole revision exception:
the controller freshly rederives their upstream Git-object provenance and requires the independent
receipt hash captured by the verified preparation package. Every mutable generated authority,
including gold smoke, must use the final tool SHA.
