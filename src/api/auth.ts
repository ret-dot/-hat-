import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Request, RequestHandler, Response } from 'express';
import type { UserRole } from '../core/types.js';

export interface AuthIdentity {
  sub: string;
  role: UserRole;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthIdentity;
    }
  }
}

const userRoles = new Set<UserRole>([
  'BENEFICIARY',
  'REGISTRATION_OPERATOR',
  'DISTRIBUTION_OPERATOR',
  'SUPERVISOR',
  'ADMINISTRATOR',
  'RECONCILIATION_OFFICER',
  'AUDITOR',
  'SECURITY_TESTER',
  'SYSTEM_OPERATOR',
]);

function isUserRole(value: unknown): value is UserRole {
  return typeof value === 'string' && userRoles.has(value as UserRole);
}

function decodeSegment(segment: string): unknown {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function createAuthMiddleware(secret?: string): RequestHandler {
  return (req, res, next) => {
    if (!secret || Buffer.byteLength(secret, 'utf8') < 32) {
      return res.status(503).json({
        code: 'AUTH_NOT_CONFIGURED',
        message: 'API authentication is unavailable until AUTH_TOKEN_SECRET is configured with at least 32 bytes',
      });
    }

    const authorization = req.headers.authorization;
    const match = typeof authorization === 'string'
      ? /^Bearer\s+(.+)$/i.exec(authorization)
      : null;
    if (!match || match[1].length > 8192) {
      return res.status(401).json({ code: 'ERR_AUTH_REQUIRED', message: 'A valid bearer token is required' });
    }

    const token = match[1];
    const [encodedHeader, encodedPayload, encodedSignature] = token.split('.');
    const expectedSignature = createHmac('sha256', secret).update(`${encodedHeader}.${encodedPayload}`).digest();
    const suppliedSignature = Buffer.from(encodedSignature, 'base64url');
    if (suppliedSignature.length !== expectedSignature.length || !timingSafeEqual(suppliedSignature, expectedSignature)) {
      return res.status(401).json({ code: 'ERR_AUTH_INVALID', message: 'Bearer token is invalid' });
    }

    try {
      const header: unknown = decodeSegment(encodedHeader);
      const payload: unknown = decodeSegment(encodedPayload);
      if (!isRecord(header) || header.alg !== 'HS256' || header.typ !== 'JWT' || !isRecord(payload)) {
        return res.status(401).json({ code: 'ERR_AUTH_INVALID', message: 'Bearer token is invalid' });
      }

      const now = Math.floor(Date.now() / 1000);
      if (
        typeof payload.sub !== 'string' ||
        payload.sub.length === 0 ||
        !isUserRole(payload.role) ||
        payload.aud !== 'grain-api' ||
        typeof payload.iat !== 'number' ||
        !Number.isFinite(payload.iat) ||
        payload.iat > now ||
        typeof payload.exp !== 'number' ||
        !Number.isFinite(payload.exp) ||
        payload.exp <= now ||
        payload.exp <= payload.iat ||
        payload.exp - payload.iat > 3600 ||
        (payload.nbf !== undefined && (
          typeof payload.nbf !== 'number' ||
          !Number.isFinite(payload.nbf) ||
          payload.nbf > now
        ))
      ) {
        return res.status(401).json({ code: 'ERR_AUTH_INVALID', message: 'Bearer token is invalid or expired' });
      }

      req.auth = { sub: payload.sub, role: payload.role };
      return next();
    } catch {
      return res.status(401).json({ code: 'ERR_AUTH_INVALID', message: 'Bearer token is invalid' });
    }
  };
}

export function createAccessToken(secret: string, identity: AuthIdentity, now = Math.floor(Date.now() / 1000)): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = encode({ alg: 'HS256', typ: 'JWT' });
  const payload = encode({
    sub: identity.sub,
    role: identity.role,
    aud: 'grain-api',
    iat: now,
    exp: now + 3600,
  });
  const signature = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function isLoopbackAddress(address: string | undefined): boolean {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
}

function isLoopbackOrigin(origin: string | undefined): boolean {
  if (!origin) return false;
  try {
    const hostname = new URL(origin).hostname.replace(/^\[|\]$/g, '');
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  } catch {
    return false;
  }
}

export function createLocalDemoLogin(secret: string): RequestHandler {
  return (req: Request, res: Response) => {
    if (!isLoopbackAddress(req.socket.remoteAddress) || !isLoopbackOrigin(req.get('origin'))) {
      return res.status(403).json({ code: 'ERR_DEMO_LOCAL_ONLY', message: 'Demo login is available only from localhost' });
    }

    return res.json({
      access_token: createAccessToken(secret, { sub: 'local-demo-admin', role: 'ADMINISTRATOR' }),
      token_type: 'Bearer',
      expires_in: 3600,
    });
  };
}

export function requireRoles(...roles: UserRole[]): RequestHandler {
  return (req, res, next) => {
    if (!req.auth || !roles.includes(req.auth.role)) {
      return res.status(403).json({ code: 'ERR_FORBIDDEN', message: 'Insufficient permissions' });
    }
    return next();
  };
}
