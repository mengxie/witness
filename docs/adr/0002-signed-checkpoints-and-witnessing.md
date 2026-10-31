# ADR 0002: Signed checkpoints and witnessing

- Status: Accepted
- Date: 2026-10-30

## Context

A hash chain alone does not stop someone with database access from editing an event and recomputing
every later hash. The server cannot prove its own honesty to a customer who does not trust it.

## Decision

The server periodically signs `(tenant, seq, head hash)` with Ed25519 and publishes the public key.
A rewrite then contradicts the signed checkpoints. Customers are encouraged to save checkpoints
outside Witness (`witness verify --save-checkpoint`), as in Certificate Transparency: with a saved
copy, even someone holding the database and the signing key cannot rewrite history past that point
without detection. Auditors can pin the public key so it cannot be swapped.

## Consequences

- Detection guarantees are stated per threat in the README, and each one is tested.
- Saved checkpoints are only as good as where customers keep them; the CLI makes saving one a flag.
- Key rotation needs old public keys to stay published by key id.
