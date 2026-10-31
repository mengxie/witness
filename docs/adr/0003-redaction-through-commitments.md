# ADR 0003: Redaction through salted commitments

- Status: Accepted
- Date: 2026-10-30

## Context

Audit logs hold personal data (names, IP addresses), and privacy law can require erasing it. Deleting
data from a hash chain would normally break verification, forcing a choice between privacy and integrity.

## Decision

Split each event into a hashed envelope (who by id, what, when, which target by id) and personal data
(names, context, metadata). The envelope's hash includes a salted SHA-256 digest of the personal data,
not the data itself. Redaction deletes the personal data and its salt; the digest stays, so the event
and the chain still verify. The random salt stops anyone confirming a guess of the erased data.

## Consequences

- GDPR-style erasure without losing the integrity proof for the rest of the record.
- Identifiers in the envelope (actor and target ids) are not erasable; use pseudonymous ids for people.
