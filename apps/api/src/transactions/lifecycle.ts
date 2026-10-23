import type { TransactionStatus } from '@prisma/client';

/** A provider-observed state (from a webhook, a status query, or an execute response). */
export type ObservedStatus = 'accepted' | 'processing' | 'settled' | 'failed' | 'returned' | 'reversed';

/**
 * Allowed transitions. Anything not listed is ignored as stale or after a
 * terminal state, so late, duplicate or out-of-order provider events can never
 * move a payment backwards (e.g. "processing" arriving after "settled").
 *
 * Provider ACCEPTANCE is not finality: only `settled` marks an invoice paid,
 * and a settled payment can still be `returned` / `reversed` later.
 */
const TRANSITIONS: Record<TransactionStatus, ObservedStatus[]> = {
  requested: ['accepted', 'processing', 'settled', 'failed', 'returned', 'reversed'],
  unknown: ['accepted', 'processing', 'settled', 'failed', 'returned', 'reversed'],
  reconciliation_required: ['accepted', 'processing', 'settled', 'failed', 'returned', 'reversed'],
  accepted: ['processing', 'settled', 'failed', 'returned', 'reversed'],
  processing: ['settled', 'failed', 'returned', 'reversed'],
  settled: ['returned', 'reversed'],
  failed: [],
  returned: [],
  reversed: [],
};

export function canTransition(from: TransactionStatus, to: ObservedStatus): boolean {
  return TRANSITIONS[from].includes(to);
}

export function isTerminal(s: TransactionStatus): boolean {
  return TRANSITIONS[s].length === 0;
}

/** States whose outcome still needs provider confirmation (reconcilable). */
export const IN_FLIGHT: TransactionStatus[] = ['requested', 'unknown', 'accepted', 'processing', 'reconciliation_required'];

/** States that end the execute call with HTTP 200 (everything else returns 202). */
export const HTTP_FINAL: TransactionStatus[] = ['settled', 'failed', 'returned', 'reversed'];

/** Payment problems after money may have moved: never auto-released for another payment. */
export const EXCEPTION_STATES: TransactionStatus[] = ['returned', 'reversed'];
