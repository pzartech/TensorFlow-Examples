/**
 * Deterministic JSON serialization (recursively sorted object keys) so the same
 * logical payload always produces the same bytes — and therefore the same hash.
 */
export function canonical(value: unknown): string {
  // Mirror JSON.stringify's primitive handling. `undefined` only reaches here
  // for top-level / array values; JSON renders those as null.
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  // Honor toJSON (e.g. Date) exactly as JSON.stringify would, so such values
  // don't collapse to an empty object.
  if (typeof (value as { toJSON?: unknown }).toJSON === 'function') {
    return canonical((value as { toJSON: () => unknown }).toJSON());
  }
  if (Array.isArray(value)) {
    // undefined array elements become null, matching JSON.stringify.
    return '[' + value.map((v) => canonical(v === undefined ? null : v)).join(',') + ']';
  }
  const obj = value as Record<string, unknown>;
  return (
    '{' +
    Object.keys(obj)
      .sort()
      // JSON.stringify omits properties whose value is undefined.
      .filter((k) => obj[k] !== undefined)
      .map((k) => JSON.stringify(k) + ':' + canonical(obj[k]))
      .join(',') +
    '}'
  );
}
