// src/core/errors.ts
import type { Response } from 'express';
import { ZodError } from 'zod';

/** Errors whose message is safe to show to API clients. Everything else becomes a generic 500. */
export class DomainError extends Error {
  constructor(
    message: string,
    public readonly status: number = 400,
    public readonly code: string = 'ERR_101',
  ) {
    super(message);
    this.name = 'DomainError';
  }
}

export function sendError(res: Response, e: unknown): void {
  if (res.headersSent) return;
  if (e instanceof DomainError) {
    res.status(e.status).json({ code: e.code, message: e.message });
    return;
  }
  if (e instanceof ZodError) {
    const message = e.issues.map((i) => `${i.path.join('.') || 'body'}: ${i.message}`).join('; ');
    res.status(400).json({ code: 'ERR_101', message: `Validation failed: ${message}` });
    return;
  }
  console.error('[unhandled]', e); // details stay server-side
  res.status(500).json({ code: 'ERR_500', message: 'Internal server error' });
}