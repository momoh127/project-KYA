import { ArgumentsHost, Catch, ExceptionFilter, HttpException, Logger } from '@nestjs/common';
import { ThrottlerException } from '@nestjs/throttler';
import { Prisma } from '@prisma/client';
import type { Response } from 'express';

/**
 * Maps all errors to the uniform error shape. Unknown errors become a generic
 * 500 (no internals leaked). Note: an error never produces an authorization;
 * callers must treat any non-2xx response as "not authorized" (fail closed).
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('Exceptions');

  catch(exception: unknown, host: ArgumentsHost): void {
    const res = host.switchToHttp().getResponse<Response>();

    if (exception instanceof ThrottlerException) {
      res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many requests' } });
      return;
    }
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const body = exception.getResponse();
      if (typeof body === 'object' && body !== null && 'error' in body) {
        res.status(status).json(body);
      } else {
        const message = typeof body === 'string' ? body : (body as { message?: unknown }).message;
        res.status(status).json({ error: { code: httpCode(status), message: String(message ?? 'Error') } });
      }
      return;
    }
    if (exception instanceof Prisma.PrismaClientKnownRequestError) {
      if (exception.code === 'P2002') {
        res.status(409).json({ error: { code: 'CONFLICT', message: 'A record with these unique fields already exists' } });
        return;
      }
      if (exception.code === 'P2034') {
        res.status(409).json({ error: { code: 'RETRY', message: 'Concurrent update conflict; retry the request' } });
        return;
      }
    }
    this.logger.error(exception instanceof Error ? exception.stack : String(exception));
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Internal error; the request was not authorized' } });
  }
}

function httpCode(status: number): string {
  switch (status) {
    case 400: return 'INVALID_REQUEST';
    case 401: return 'UNAUTHENTICATED';
    case 403: return 'FORBIDDEN';
    case 404: return 'NOT_FOUND';
    case 409: return 'CONFLICT';
    case 413: return 'PAYLOAD_TOO_LARGE';
    default: return 'ERROR';
  }
}
