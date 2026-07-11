# 0016: Preregister the exact-image successor evidence chain

Status: accepted

## Decision

The scored v0.2 successor uses a distinct exact-image preregistration. It does not relabel the
legacy salted-package capability contract. Before a freeze can be written, the controller freshly
verifies the final provider-disabled case preparation, the complete chronology receipt, an approved
mapping consensus for every case, and the 20-entry exact-image capability index.

Each public-safe case row binds its issue and base identity, exact request hashes, source projection
commitment, candidate/command profile, opaque evaluator commitment, and mapping selection
commitment. Hidden patch bytes and patch hashes are not copied into the preregistration. The
controller cross-checks them privately between the mapping packets and evaluator capability.

Case `rk-v0.2-014` remains in the 20-case freeze with its recorded no-network infrastructure
failure. It is not removed, relabeled ready, or allowed to become a semantic success.

The case preparation and exact capability index must name the same final controller Git SHA as the
preregistration. Provider execution remains disabled.

## Consequences

- Missing, rejected, empty, or cross-case-swapped mapping decisions fail closed.
- A self-consistent edited preregistration still fails fresh evidence rederivation.
- The exact scored runner can consume this contract without pretending that legacy evaluator
  packages or dependency volumes exist.
