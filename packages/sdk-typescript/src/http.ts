import type { ApiErrorBody } from './types';

export type FetchFn = typeof fetch;

export class AgentTrustError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
    this.name = 'AgentTrustError';
  }
}

/**
 * Sends a request and parses the uniform error shape. Any non-2xx response
 * throws: callers must treat a thrown error as "not authorized" (fail closed).
 */
export async function send<T>(fetchFn: FetchFn, url: string, init: RequestInit): Promise<T> {
  const res = await fetchFn(url, init);
  const text = await res.text();
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    throw new AgentTrustError(res.status, 'INVALID_RESPONSE', `Non-JSON response (HTTP ${res.status})`);
  }
  if (!res.ok) {
    const err = (body as ApiErrorBody | undefined)?.error;
    throw new AgentTrustError(res.status, err?.code ?? 'HTTP_ERROR', err?.message ?? res.statusText, err?.details);
  }
  return body as T;
}
