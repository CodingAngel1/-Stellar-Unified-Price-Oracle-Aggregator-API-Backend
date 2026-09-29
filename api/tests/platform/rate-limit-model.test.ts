import { describe, it, expect, beforeEach, beforeAll, afterAll } from 'vitest';
import request from 'supertest';
import express, { Express } from 'express';
import {
  TIER_RATE_LIMITS,
  TIER_RATE_LIMIT_CEILINGS,
  effectiveTenantLimit,
  clampOverride,
} from '../../src/platform/limit-model';
import { TenantWindow, type SharedCountStore } from '../../src/platform/tenant-window';
import { ApiKeyManager, apiKeyManager } from '../../src/governance/api-key-manager';
import { createAuthMiddleware } from '../../src/governance/auth';
import adminRouter from '../../src/governance/admin';

function sharedStore(): SharedCountStore {
  const counts = new Map<string, number>();
  return {
    async increment(identity: string, windowStart: number): Promise<number> {
      const key = `${identity}:${windowStart}`;
      const next = (counts.get(key) ?? 0) + 1;
      counts.set(key, next);
      return next;
    },
  };
}

function failingStore(): SharedCountStore {
  return {
    async increment(): Promise<number> {
      throw new Error('store unavailable');
    },
  };
}

function buildApp(manager: ApiKeyManager): Express {
  const app = express();
  app.get('/protected', createAuthMiddleware({ manager }), (_req, res) => {
    res.status(200).json({ ok: true });
  });
  return app;
}

describe('Issue #595: the limit model', () => {
  describe('effectiveTenantLimit()', () => {
    it('falls back to the tier default when no override exists', () => {
      expect(effectiveTenantLimit('free')).toBe(TIER_RATE_LIMITS.free);
      expect(effectiveTenantLimit('free', undefined)).toBe(TIER_RATE_LIMITS.free);
      expect(effectiveTenantLimit('pro', Number.NaN)).toBe(TIER_RATE_LIMITS.pro);
      expect(effectiveTenantLimit('free', -5)).toBe(TIER_RATE_LIMITS.free);
    });

    it('keeps a valid override and preserves the deny-all value of 0', () => {
      expect(effectiveTenantLimit('free', 120)).toBe(120);
      expect(effectiveTenantLimit('free', 4.9)).toBe(4);
      expect(effectiveTenantLimit('free', 0)).toBe(0);
    });

    it('clamps overrides to the tier ceiling', () => {
      expect(effectiveTenantLimit('free', 999999)).toBe(TIER_RATE_LIMIT_CEILINGS.free);
      expect(effectiveTenantLimit('pro', 12000)).toBe(TIER_RATE_LIMIT_CEILINGS.pro);
      expect(effectiveTenantLimit('enterprise', 90000)).toBe(TIER_RATE_LIMIT_CEILINGS.enterprise);
      expect(effectiveTenantLimit('admin', 1000000)).toBe(TIER_RATE_LIMIT_CEILINGS.admin);
    });

    it('rejects overrides above the ceiling at the admin boundary', () => {
      const over = clampOverride('free', 999999);
      expect(over.effective).toBe(TIER_RATE_LIMIT_CEILINGS.free);
      expect(over.ceiling).toBe(TIER_RATE_LIMIT_CEILINGS.free);
      expect(over.clamped).toBe(true);

      const fine = clampOverride('pro', 120);
      expect(fine.effective).toBe(120);
      expect(fine.clamped).toBe(false);
    });

    it('stamps generateKey with the effective limit', () => {
      const manager = new ApiKeyManager();
      const clamped = manager.generateKey(999999, 'over ceiling', 'free', 'viewer');
      expect(clamped.rateLimitPerMin).toBe(TIER_RATE_LIMIT_CEILINGS.free);

      const untouched = manager.generateKey(120, 'within ceiling', 'free', 'viewer');
      expect(untouched.rateLimitPerMin).toBe(120);

      const denied = manager.generateKey(0, 'deny all', 'free', 'viewer');
      expect(denied.rateLimitPerMin).toBe(0);
    });
  });

  describe('TenantWindow', () => {
    it('shares one budget across replicas when a store is configured', async () => {
      const store = sharedStore();
      const replicaA = new TenantWindow(store);
      const replicaB = new TenantWindow(store);

      let allowed = 0;
      for (let i = 0; i < TIER_RATE_LIMITS.free * 2; i++) {
        const window = i % 2 === 0 ? replicaA : replicaB;
        const result = await window.consume('key-hash', TIER_RATE_LIMITS.free);
        if (result.allowed) allowed++;
        expect(result.mode).toBe('shared-redis');
      }

      expect(allowed).toBe(TIER_RATE_LIMITS.free);
      const denied = await replicaA.consume('key-hash', TIER_RATE_LIMITS.free);
      expect(denied.allowed).toBe(false);
      expect(denied.remaining).toBe(0);
    });

    it('documents per-pod multiplication when no store is configured', async () => {
      const podA = new TenantWindow(null);
      const podB = new TenantWindow(null);

      let allowed = 0;
      for (let i = 0; i < TIER_RATE_LIMITS.free * 2; i++) {
        const window = i % 2 === 0 ? podA : podB;
        const result = await window.consume('key-hash', TIER_RATE_LIMITS.free);
        if (result.allowed) allowed++;
      }

      expect(allowed).toBe(TIER_RATE_LIMITS.free * 2);
      const local = await podA.consume('key-hash', TIER_RATE_LIMITS.free);
      expect(local.mode).toBe('local-per-pod');
      expect(local.shared).toBe(false);
    });

    it('degrades to a local counter when the store is unreachable', async () => {
      const window = new TenantWindow(failingStore());
      const first = await window.consume('key-hash', TIER_RATE_LIMITS.free);
      expect(first.allowed).toBe(true);
      expect(first.shared).toBe(false);
      expect(first.mode).toBe('local-per-pod');
    });
  });

  describe('auth path enforcement', () => {
    let manager: ApiKeyManager;
    let appA: Express;
    let appB: Express;
    let apiKey: string;

    beforeEach(() => {
      manager = new ApiKeyManager(new TenantWindow(sharedStore()));
      appA = buildApp(manager);
      appB = buildApp(manager);
      apiKey = manager.generateKey(TIER_RATE_LIMITS.free, 'http enforcement', 'free', 'viewer').key;
    });

    it('reports the effective limit and stops the shared budget at the tier limit', async () => {
      let allowed = 0;
      for (let i = 0; i < TIER_RATE_LIMITS.free + 1; i++) {
        const app = i % 2 === 0 ? appA : appB;
        const response = await request(app)
          .get('/protected')
          .set('Authorization', `Bearer ${apiKey}`);

        if (i < TIER_RATE_LIMITS.free) {
          expect(response.status).toBe(200);
          expect(response.headers['x-ratelimit-limit']).toBe(String(TIER_RATE_LIMITS.free));
          expect(response.headers['x-ratelimit-remaining']).toBe(
            String(TIER_RATE_LIMITS.free - (i + 1)),
          );
          allowed++;
        } else {
          expect(response.status).toBe(429);
          expect(response.headers['x-ratelimit-limit']).toBe(String(TIER_RATE_LIMITS.free));
          expect(response.headers['x-ratelimit-remaining']).toBe('0');
          expect(response.headers['retry-after']).toBeDefined();
        }
      }
      expect(allowed).toBe(TIER_RATE_LIMITS.free);
    });
  });

  describe('admin override', () => {
    const app = express();
    let adminKey: string;
    let adminKeyHash: string;
    let targetKeyHash: string;

    beforeAll(() => {
      app.use(express.json());
      app.use('/admin', adminRouter);
      const admin = apiKeyManager.generateKey(TIER_RATE_LIMITS.admin, 'limit model admin', 'admin', 'admin');
      adminKey = admin.key;
      adminKeyHash = admin.keyHash;
    });

    afterAll(() => {
      apiKeyManager.deleteKey(adminKeyHash);
      if (targetKeyHash) apiKeyManager.deleteKey(targetKeyHash);
    });

    it('clamps an override above the ceiling and reports the effective limit', async () => {
      const target = apiKeyManager.generateKey(TIER_RATE_LIMITS.free, 'limit model target', 'free', 'viewer');
      targetKeyHash = target.keyHash;

      const response = await request(app)
        .put(`/admin/keys/${target.keyHash}/rate-limit`)
        .set('Authorization', `Bearer ${adminKey}`)
        .send({ rateLimitPerMin: 999999 });

      expect(response.status).toBe(200);
      expect(response.body.data.tier).toBe('free');
      expect(response.body.data.rateLimitPerMin).toBe(TIER_RATE_LIMIT_CEILINGS.free);
      expect(response.body.data.ceiling).toBe(TIER_RATE_LIMIT_CEILINGS.free);
      expect(response.body.data.clamped).toBe(true);
      expect(apiKeyManager.findByHash(target.keyHash)?.rateLimitPerMin).toBe(
        TIER_RATE_LIMIT_CEILINGS.free,
      );
    });

    it('stores an override that is within the ceiling unchanged', async () => {
      const target = apiKeyManager.generateKey(TIER_RATE_LIMITS.free, 'limit model target 2', 'free', 'viewer');
      targetKeyHash = target.keyHash;

      const response = await request(app)
        .put(`/admin/keys/${target.keyHash}/rate-limit`)
        .set('Authorization', `Bearer ${adminKey}`)
        .send({ rateLimitPerMin: 120 });

      expect(response.status).toBe(200);
      expect(response.body.data.rateLimitPerMin).toBe(120);
      expect(response.body.data.clamped).toBe(false);
      expect(apiKeyManager.findByHash(target.keyHash)?.rateLimitPerMin).toBe(120);
    });

    it('rejects a non-positive override', async () => {
      const target = apiKeyManager.generateKey(TIER_RATE_LIMITS.free, 'limit model target 3', 'free', 'viewer');
      targetKeyHash = target.keyHash;

      const response = await request(app)
        .put(`/admin/keys/${target.keyHash}/rate-limit`)
        .set('Authorization', `Bearer ${adminKey}`)
        .send({ rateLimitPerMin: 0 });

      expect(response.status).toBe(400);
      expect(response.body.error.code).toBe('INVALID_RATE_LIMIT');
    });
  });
});
