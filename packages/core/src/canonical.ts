/**
 * Canonical JSON: the exact bytes that get hashed. Object keys are sorted by UTF-16 code unit,
 * there is no whitespace, and numbers use ECMAScript formatting, as in RFC 8785 (JCS) for the JSON
 * subset Witness accepts. Keys whose value is `undefined` are omitted, exactly as JSON does.
 * Any two implementations that follow these rules produce identical hashes.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Only finite numbers can be canonicalised.');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item: unknown) => canonicalize(item)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalize(item)}`).join(',')}}`;
  }
  throw new TypeError(`Cannot canonicalise a value of type ${typeof value}.`);
}
