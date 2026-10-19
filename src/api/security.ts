// src/api/security.ts
import type { NextFunction, Request, RequestHandler, Response } from 'express';

export function securityHeaders(isProd: boolean): RequestHandler {
  return (_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store'); // responses contain PII
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    if (isProd) res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
    next();
  };
}

/** Small in-memory fixed-window limiter. Swap for express-rate-limit behind multiple instances. */
export function rateLimit(opts: { windowMs: number; max: number; message?: string }): RequestHandler {
  const hits = new Map<string, { count: number; reset: number }>();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset <= now) hits.delete(k);
  }, opts.windowMs).unref();

  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip ?? 'unknown';
    const now = Date.now();
    let entry = hits.get(key);
    if (!entry || entry.reset <= now) {
      entry = { count: 0, reset: now + opts.windowMs };
      hits.set(key, entry);
    }
    entry.count += 1;
    if (entry.count > opts.max) {
      res.setHeader('Retry-After', Math.ceil((entry.reset - now) / 1000).toString());
      res.status(429).json({ code: 'ERR_429', message: opts.message ?? 'Too many requests' });
      return;
    }
    next();
  };
}