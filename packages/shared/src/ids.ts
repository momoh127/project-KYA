import { randomBytes } from 'node:crypto';

/** Prefixed random identifiers, e.g. `agt_3f9a...`. 128 bits of entropy. */
export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(16).toString('hex')}`;
}

export const IdPrefix = {
  organization: 'org',
  user: 'usr',
  agent: 'agt',
  credential: 'akc',
  session: 'ags',
  supplierVersion: 'spv',
  attempt: 'tat',
  signal: 'sig',
  instruction: 'pin',
  instructionLine: 'pil',
  instructionVersion: 'piv',
  receipt: 'rcp',
  invoiceLine: 'inl',
  integration: 'int',
  delegation: 'dlg',
  policy: 'pol',
  supplier: 'sup',
  purchaseOrder: 'po',
  invoice: 'inv',
  authorization: 'auth',
  approval: 'apr',
  reservation: 'rsv',
  transaction: 'txn',
  auditEvent: 'evt',
} as const;
