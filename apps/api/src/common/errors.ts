import { HttpException, HttpStatus } from '@nestjs/common';

/** Uniform API error: `{ error: { code, message, details? } }`. */
export class ApiError extends HttpException {
  constructor(status: HttpStatus, readonly code: string, message: string, readonly details?: unknown) {
    super({ error: { code, message, details } }, status);
  }
}

export const Errors = {
  unauthenticated: (msg = 'Authentication required') => new ApiError(HttpStatus.UNAUTHORIZED, 'UNAUTHENTICATED', msg),
  forbidden: (code: string, msg: string) => new ApiError(HttpStatus.FORBIDDEN, code, msg),
  notFound: (what: string) => new ApiError(HttpStatus.NOT_FOUND, 'NOT_FOUND', `${what} not found`),
  conflict: (code: string, msg: string, details?: unknown) => new ApiError(HttpStatus.CONFLICT, code, msg, details),
  invalid: (msg: string, details?: unknown) => new ApiError(HttpStatus.BAD_REQUEST, 'INVALID_REQUEST', msg, details),
  unavailable: (msg = 'Service temporarily unavailable; request was not authorized') =>
    new ApiError(HttpStatus.SERVICE_UNAVAILABLE, 'UNAVAILABLE', msg),
};
