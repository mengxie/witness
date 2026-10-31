# ADR 0001: A hash chain per tenant, appended under a row lock

- Status: Accepted
- Date: 2026-10-30

## Context

An audit log must make silent edits, deletions and reordering detectable. Tenants (customer
companies) must be isolated, and appends must stay fast under concurrent load.

## Decision

Each tenant has its own chain: event N stores the hash of event N-1, and its own hash covers its
contents and that link. Appends run in a transaction that first takes `SELECT ... FOR UPDATE` on the
tenant's `chain_heads` row, so appends for one tenant are serialised and gap-free while other
tenants proceed in parallel. Idempotency keys are checked after the lock is taken, so concurrent
retries cannot both insert. A database trigger refuses updates and deletes, except erasing personal
data.

## Consequences

- Any change breaks verification at exactly the changed event.
- Throughput per tenant is bounded by one transaction at a time; batches of up to 100 events amortise it.
- Different tenants never contend.
