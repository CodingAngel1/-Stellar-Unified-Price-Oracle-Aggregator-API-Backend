import { Request, Response, NextFunction } from 'express';
import { IncomingMessage } from 'http';
import { apiKeyManager, type ApiKeyManager } from './api-key-manager';
import { logger } from '../observability/logger';
import { auditLog } from './audit-logger';
import type { Role } from './rbac';
import { decryptSecret } from './crypto';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      apiKey?: string;
      userRole?: Role;
      rateLimitInfo?: {
        allowed: boolean;
        remaining: number;
        resetTime: number;
        retryAfter?: number;
        /** The effective tenant allowance that was enforced (limit model). */
        limit: number;
        degraded?: boolean;
      };
    }
  }
}

function requestContext(req: Request) {
  return {
    ip: req.ip,
    method: req.method,
    path: req.path,
    userAgent: req.headers['user-agent'],
  };
}

export function extractApiKey(req: Request | IncomingMessage): string | null {
  const headers = req.headers;

  const authHeader = headers['authorization'];
  if (typeof authHeader === 'string' && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  const apiKeyHeader = headers['x-api-key'];
  if (typeof apiKeyHeader === 'string') {
    return apiKeyHeader;
  }

  return null;
}

function applyRateLimitHeaders(
  res: Response,
  limit: number,
  remaining: number,
  resetTime: number,
  degraded?: boolean,
): void {
  res.set('X-RateLimit-Limit', limit.toString());
  res.set('X-RateLimit-Remaining', remaining.toString());
  res.set('X-RateLimit-Reset', Math.ceil(resetTime / 1000).toString());
  res.set('X-RateLimit-Consumed', Math.max(0, limit - remaining).toString());
  if (degraded) res.set('X-RateLimit-Degraded', 'local');
  else res.removeHeader('X-RateLimit-Degraded');
}

export interface AuthDependencies {
  manager?: ApiKeyManager;
}

/**
 * The authoritative rate-limit enforcement point: every authenticated request
 * consumes one slot from the shared tenant window using the effective limit
 * from `platform/limit-model.ts`, and `X-RateLimit-Limit` reports exactly that
 * number. `manager` is injectable so tests can model multiple replicas.
 */
export function createAuthMiddleware(deps: AuthDependencies = {}) {
  return async function authMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const manager = deps.manager ?? apiKeyManager;
      const apiKey = extractApiKey(req);
      const ctx = requestContext(req);

      if (!apiKey) {
        auditLog('auth.failure', { ...ctx, details: { reason: 'MISSING_API_KEY', path: req.path } });
        res.status(401).json({
          success: false,
          error: {
            code: 'MISSING_API_KEY',
            message: 'API key required. Use Authorization: Bearer <key> or X-Api-Key header.',
          },
        });
        return;
      }

      const validation = manager.validateKey(apiKey);
      if (!validation.valid) {
        logger.warn(`Invalid API key attempt: ${apiKey.substring(0, 8)}...`);
        auditLog('auth.failure', {
          ...ctx,
          apiKeyPrefix: apiKey.substring(0, 8),
          details: { reason: 'INVALID_API_KEY', path: req.path },
        });
        res.status(401).json({
          success: false,
          error: {
            code: 'INVALID_API_KEY',
            message: validation.error || 'Invalid API key',
          },
        });
        return;
      }

      const rateLimitInfo = await manager.checkRateLimit(apiKey);
      if (!rateLimitInfo.allowed) {
        logger.warn(`Rate limit exceeded for API key: ${apiKey.substring(0, 8)}...`);
        res.set('Retry-After', String(rateLimitInfo.retryAfter ?? 60));
        applyRateLimitHeaders(res, rateLimitInfo.limit, 0, rateLimitInfo.resetTime, rateLimitInfo.degraded);
        res.status(429).json({
          success: false,
          error: {
            code: 'RATE_LIMITED',
            message: `Rate limit exceeded. Retry after ${rateLimitInfo.retryAfter ?? 60} seconds.`,
            retryAfter: rateLimitInfo.retryAfter,
            resetTime: new Date(rateLimitInfo.resetTime).toISOString(),
          },
        });
        return;
      }

      req.apiKey = apiKey;
      req.userRole = validation.metadata?.role || 'viewer';
      req.rateLimitInfo = rateLimitInfo;
      applyRateLimitHeaders(res, rateLimitInfo.limit, rateLimitInfo.remaining, rateLimitInfo.resetTime, rateLimitInfo.degraded);

      next();
    } catch (err) {
      next(err);
    }
  };
}

export const authMiddleware = createAuthMiddleware();

export function adminAuthMiddleware(_adminKeyPrefix: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const apiKey = extractApiKey(req);
    const ctx = requestContext(req);

    if (!apiKey) {
      auditLog('auth.failure', { ...ctx, details: { reason: 'MISSING_ADMIN_KEY', path: req.path } });
      res.status(401).json({
        success: false,
        error: { code: 'MISSING_API_KEY', message: 'Admin API key required.' },
      });
      return;
    }

    const validation = apiKeyManager.validateKey(apiKey);
    if (!validation.valid) {
      logger.warn(`Invalid admin key attempt: ${apiKey.substring(0, 8)}...`);
      res.status(401).json({
        success: false,
        error: { code: 'INVALID_API_KEY', message: validation.error || 'Invalid API key' },
      });
      return;
    }

    const adminApiKey = process.env.ADMIN_API_KEY ? decryptSecret(process.env.ADMIN_API_KEY) : '';
    const isAdmin = apiKeyManager.isAdminKey(apiKey) || adminApiKey === apiKey;
    if (!isAdmin) {
      logger.warn(`Unauthorized admin access: ${apiKey.substring(0, 8)}...`);
      res.status(403).json({
        success: false,
        error: { code: 'FORBIDDEN', message: 'This operation requires admin privileges.' },
      });
      return;
    }

    req.apiKey = apiKey;
    req.userRole = 'admin';
    next();
  };
}

export function createOptionalAuthMiddleware(deps: AuthDependencies = {}) {
  return async function optionalAuthMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const manager = deps.manager ?? apiKeyManager;
      const apiKey = extractApiKey(req);

      if (!apiKey) {
        next();
        return;
      }

      const validation = manager.validateKey(apiKey);
      if (!validation.valid) {
        res.status(401).json({
          success: false,
          error: { code: 'INVALID_API_KEY', message: validation.error || 'Invalid API key' },
        });
        return;
      }

      const rateLimitInfo = await manager.checkRateLimit(apiKey);
      if (!rateLimitInfo.allowed) {
        res.set('Retry-After', String(rateLimitInfo.retryAfter ?? 60));
        applyRateLimitHeaders(res, rateLimitInfo.limit, 0, rateLimitInfo.resetTime, rateLimitInfo.degraded);
        res.status(429).json({
          success: false,
          error: {
            code: 'RATE_LIMITED',
            message: `Rate limit exceeded. Retry after ${rateLimitInfo.retryAfter ?? 60} seconds.`,
            retryAfter: rateLimitInfo.retryAfter,
          },
        });
        return;
      }

      req.apiKey = apiKey;
      req.userRole = validation.metadata?.role || 'viewer';
      req.rateLimitInfo = rateLimitInfo;
      applyRateLimitHeaders(res, rateLimitInfo.limit, rateLimitInfo.remaining, rateLimitInfo.resetTime, rateLimitInfo.degraded);

      next();
    } catch (err) {
      next(err);
    }
  };
}

export const optionalAuthMiddleware = createOptionalAuthMiddleware();

export function validateWebSocketApiKey(req: IncomingMessage): { valid: boolean; error?: string } {
  const apiKey = extractApiKey(req);

  if (!apiKey) {
    return { valid: false, error: 'API key required for WebSocket connections' };
  }

  const validation = apiKeyManager.validateKey(apiKey);
  if (!validation.valid) {
    return { valid: false, error: validation.error || 'Invalid API key' };
  }

  return { valid: true };
}
