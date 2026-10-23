/**
 * Deterministic JSON serialization used for hashing and signing.
 *
 * Rules (a strict subset of RFC 8785 / JCS that is sufficient for our payloads):
 * - Object keys are sorted by UTF-16 code unit order.
 * - `undefined` object members are omitted; `undefined` elsewhere is rejected.
 * - Only safe integers are allowed as numbers. Money is always integer minor
 *   units, so we never need to canonicalize floating point values.
 * - Strings are serialized with JSON.stringify (standard escaping).
 */
export type CanonicalValue =
  | string
  | number
  | boolean
  | null
  | CanonicalValue[]
  | { [key: string]: CanonicalValue | undefined };

export function canonicalJson(value: unknown): string {
  return serialize(value, '$');
}

function serialize(value: unknown, path: string): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isSafeInteger(value)) {
        throw new TypeError(`canonicalJson: non-integer or unsafe number at ${path}`);
      }
      return String(value);
    case 'object': {
      if (Array.isArray(value)) {
        return `[${value.map((v, i) => {
          if (v === undefined) throw new TypeError(`canonicalJson: undefined at ${path}[${i}]`);
          return serialize(v, `${path}[${i}]`);
        }).join(',')}]`;
      }
      if (value instanceof Date) {
        throw new TypeError(`canonicalJson: Date at ${path}; convert to ISO string first`);
      }
      const obj = value as Record<string, unknown>;
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${serialize(obj[k], `${path}.${k}`)}`).join(',')}}`;
    }
    default:
      throw new TypeError(`canonicalJson: unsupported type ${typeof value} at ${path}`);
  }
}
