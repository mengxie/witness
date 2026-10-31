# ADR 0004: One shared core package for the log format

- Status: Accepted
- Date: 2026-10-30

## Context

The server computes hashes and signatures; the SDK and CLI recompute them to verify. If two
implementations differ by one byte of serialisation, every verification fails.

## Decision

`@witness/core` owns the format: canonical JSON (sorted keys, no whitespace, ECMAScript number
formatting, in the style of RFC 8785), the hash inputs including a format version, the redaction
digest, checkpoint payloads and the streaming verifier. The server, SDK and CLI all import it.

## Consequences

- The format is defined once and tested once, including property-based tests.
- The version field allows a future format change without ambiguity.
- Implementations in other languages must follow the documented canonicalisation exactly.
