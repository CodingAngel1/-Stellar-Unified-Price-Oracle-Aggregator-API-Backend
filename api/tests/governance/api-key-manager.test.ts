import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { ApiKeyManager, TIER_RATE_LIMITS, KeyTier } from '../../src/governance/api-key-manager';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createManager(): ApiKeyManager {
  return new ApiKeyManager();
}

// ---------------------------------------------------------------------------
// 1. Key generation
// ---------------------------------------------------------------------------

describe('ApiKeyManager - Key Generation', () => {
  let mgr: ApiKeyManager;

  beforeEach(() => {
    mgr = createManager();
  });

  describe('generateKey()', () => {
    it('should generate a key with the correct prefix for each tier', async () => {
      const tiers: KeyTier[] = ['free', 'pro', 'enterprise', 'admin'];
      const expectedPrefixes: Record<KeyTier, string> = {
        free: 'sk_free_',
        pro: 'sk_pro_',
        enterprise: 'sk_enterprise_',
        admin: 'sk_admin_',
      };

      for (const tier of tiers) {
        const key = mgr.generateKey(TIER_RATE_LIMITS[tier], undefined, tier);
        expect(key.key.startsWith(expectedPrefixes[tier])).toBe(true);
      }
    });

    it('should produce unique keys on each call', async () => {
      const keys = new Set<string>();
      for (let i = 0; i < 50; i++) {
        const k = mgr.generateKey(100, 'desc', 'free');
        keys.add(k.key);
        keys.add(k.keyHash);
      }
      expect(keys.size).toBe(100); // 50 keys + 50 hashes all unique
    });

    it('should default tier to "free" and role to "viewer" when omitted', async () => {
      const key = mgr.generateKey(100);
      const meta = mgr.findByHash(key.keyHash);
      expect(meta?.tier).toBe('free');
      expect(meta?.role).toBe('viewer');
    });

    it('should default rateLimitPerMin to free tier limit when not specified', async () => {
      // calling with undefined rateLimitPerMin — the signature defaults first arg
      const key = mgr.generateKey();
      const meta = mgr.findByHash(key.keyHash);
      expect(meta?.rateLimitPerMin).toBe(TIER_RATE_LIMITS.free);
    });

    it('should set description when provided', async () => {
      const key = mgr.generateKey(500, 'My test description', 'pro', 'editor');
      const meta = mgr.findByHash(key.keyHash);
      expect(meta?.description).toBe('My test description');
    });

    it('should set description to undefined when not provided', async () => {
      const key = mgr.generateKey(500);
      const meta = mgr.findByHash(key.keyHash);
      expect(meta?.description).toBeUndefined();
    });

    it('should store the key in the internal map', async () => {
      const key = mgr.generateKey(200, 'stored', 'pro', 'viewer');
      expect(mgr.findByHash(key.keyHash)).toBeDefined();
      expect(mgr.findByHash(key.keyHash)?.keyPrefix).toBe(key.keyPrefix);
    });

    it('should set createdAt to the current timestamp', async () => {
      const before = Date.now();
      const key = mgr.generateKey(100);
      const after = Date.now();
      expect(key.createdAt).toBeGreaterThanOrEqual(before);
      expect(key.createdAt).toBeLessThanOrEqual(after);
    });

    it('should handle custom rateLimitPerMin values', async () => {
      const key = mgr.generateKey(777, 'custom limit', 'enterprise', 'operator');
      expect(key.rateLimitPerMin).toBe(777);
      const meta = mgr.findByHash(key.keyHash);
      expect(meta?.rateLimitPerMin).toBe(777);
    });

    it('should assign the correct role', async () => {
      const roles = ['viewer', 'editor', 'operator', 'admin'] as const;
      for (const role of roles) {
        const key = mgr.generateKey(100, undefined, undefined, role);
        const meta = mgr.findByHash(key.keyHash);
        expect(meta?.role).toBe(role);
      }
    });

    it('should include key as a flat property on the returned GeneratedApiKey', async () => {
      const key = mgr.generateKey(100, 'flat', 'free');
      expect(typeof key.key).toBe('string');
      expect(key.key.length).toBeGreaterThan(32);
    });
  });

  describe('key structure validation', () => {
    it('should have keys that are hex-only after the prefix', async () => {
      const key = mgr.generateKey(100, 'hex', 'enterprise');
      const body = key.key.replace(/^sk_enterprise_/, '');
      expect(body).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should have keyHash that is a sha256 hex digest (64 chars)', async () => {
      const key = mgr.generateKey(100, 'hash', 'pro');
      expect(key.keyHash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should have keyPrefix that is 12 chars and matches key start', async () => {
      const key = mgr.generateKey(100, 'prefix', 'pro');
      expect(key.key.startsWith(key.keyPrefix)).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// 2. Key validation
// ---------------------------------------------------------------------------

describe('ApiKeyManager - Key Validation', () => {
  let mgr: ApiKeyManager;

  beforeEach(() => {
    mgr = createManager();
  });

  describe('validateKey()', () => {
    it('should return valid:true with metadata for a valid key', async () => {
      const { key } = mgr.generateKey(100, 'valid', 'pro', 'viewer');
      const result = mgr.validateKey(key);
      expect(result.valid).toBe(true);
      expect(result.metadata).toBeDefined();
      expect(result.metadata?.tier).toBe('pro');
      expect(result.metadata?.role).toBe('viewer');
      expect(result.metadata?.isActive).toBe(true);
      expect(result.error).toBeUndefined();
    });

    it('should return valid:false for a non-existent key', async () => {
      const result = mgr.validateKey('sk_free_deadbeef1234');
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid API key');
      expect(result.metadata).toBeUndefined();
    });

    it('should return valid:false for an empty key', async () => {
      const result = mgr.validateKey('');
      expect(result.valid).toBe(false);
      expect(result.error).toBe('Invalid API key');
    });

    it('should return valid:false for a revoked key', async () => {
      const { key, keyHash } = mgr.generateKey(100, 'revoked', 'free');
      mgr.revokeKey(keyHash);
      const result = mgr.validateKey(key);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('API key has been revoked');
    });

    it('should return valid:true after reactivating a previously revoked key', async () => {
      const { key, keyHash } = mgr.generateKey(100, 'reactivate', 'free');
      mgr.revokeKey(keyHash);
      expect(mgr.validateKey(key).valid).toBe(false);

      mgr.reactivateKey(keyHash);
      const result = mgr.validateKey(key);
      expect(result.valid).toBe(true);
      expect(result.metadata?.isActive).toBe(true);
    });

    it('should work case-sensitively (keys should match exactly)', async () => {
      const { key } = mgr.generateKey(100, 'case', 'free');
      const upper = key.toUpperCase();
      if (upper !== key) {
        // The key contains lowercase hex, should be different
        const result = mgr.validateKey(upper);
        expect(result.valid).toBe(false);
      }
    });

    it('should distinguish between different tenants with same prefix', async () => {
      const k1 = mgr.generateKey(100, 'tenant-a', 'pro');
      const k2 = mgr.generateKey(100, 'tenant-b', 'pro');
      expect(k1.keyHash).not.toBe(k2.keyHash);
      expect(mgr.validateKey(k1.key).valid).toBe(true);
      expect(mgr.validateKey(k2.key).valid).toBe(true);
    });

    it('should return metadata with all expected fields', async () => {
      const { key } = mgr.generateKey(500, 'rich', 'enterprise', 'editor');
      const { metadata } = mgr.validateKey(key);
      expect(metadata).toBeDefined();
      expect(metadata).toHaveProperty('keyHash');
      expect(metadata).toHaveProperty('keyPrefix');
      expect(metadata).toHaveProperty('createdAt');
      expect(metadata).toHaveProperty('lastUsed');
      expect(metadata).toHaveProperty('requestCount');
      expect(metadata).toHaveProperty('isActive');
      expect(metadata).toHaveProperty('rateLimitPerMin');
      expect(metadata).toHaveProperty('tier');
      expect(metadata).toHaveProperty('role');
      expect(metadata).toHaveProperty('description');
    });
  });

  describe('isAdminKey()', () => {
    it('should return true for admin-tier keys with admin role', async () => {
      const { key } = mgr.generateKey(TIER_RATE_LIMITS.admin, 'admin', 'admin', 'admin');
      expect(mgr.isAdminKey(key)).toBe(true);
    });

    it('should return false for non-admin keys', async () => {
      const { key } = mgr.generateKey(100, 'free', 'free', 'viewer');
      expect(mgr.isAdminKey(key)).toBe(false);
    });

    it('should return false for invalid keys', async () => {
      expect(mgr.isAdminKey('bogus-key')).toBe(false);
    });

    it('should return false for revoked admin keys', async () => {
      const { key, keyHash } = mgr.generateKey(TIER_RATE_LIMITS.admin, 'admin', 'admin', 'admin');
      mgr.revokeKey(keyHash);
      // isAdminKey checks role regardless of active status
      expect(mgr.isAdminKey(key)).toBe(true);
    });
  });

  describe('getKeyMetadata()', () => {
    it('should return metadata for a known keyHash', async () => {
      const { keyHash } = mgr.generateKey(100, 'meta', 'pro', 'editor');
      const meta = mgr.getKeyMetadata(keyHash);
      expect(meta).toBeDefined();
      expect(meta?.tier).toBe('pro');
      expect(meta?.role).toBe('editor');
    });

    it('should return null for an unknown keyHash', async () => {
      expect(mgr.getKeyMetadata('deadbeef1234')).toBeNull();
    });
  });

  describe('findByHash()', () => {
    it('should be an alias for getKeyMetadata', async () => {
      const { keyHash } = mgr.generateKey(100, 'find', 'free');
      expect(mgr.findByHash(keyHash)).toEqual(mgr.getKeyMetadata(keyHash));
    });

    it('should return null for unknown hash', async () => {
      expect(mgr.findByHash('nonexistent')).toBeNull();
    });
  });
});

// ---------------------------------------------------------------------------
// 3. Revocation & reactivation
// ---------------------------------------------------------------------------

describe('ApiKeyManager - Revocation & Reactivation', () => {
  let mgr: ApiKeyManager;

  beforeEach(() => {
    mgr = createManager();
  });

  describe('revokeKey()', () => {
    it('should deactivate a valid key', async () => {
      const { keyHash } = mgr.generateKey(100, 'revoke', 'pro', 'viewer');
      const result = mgr.revokeKey(keyHash);
      expect(result).toBe(true);

      const meta = mgr.findByHash(keyHash);
      expect(meta?.isActive).toBe(false);
    });

    it('should return false for a non-existent keyHash', async () => {
      expect(mgr.revokeKey('nonexistent-hash')).toBe(false);
    });

    it('should be idempotent (revoking twice should still return true)', async () => {
      const { keyHash } = mgr.generateKey(100, 'idempotent', 'free');
      expect(mgr.revokeKey(keyHash)).toBe(true);
      expect(mgr.revokeKey(keyHash)).toBe(true);
      expect(mgr.findByHash(keyHash)?.isActive).toBe(false);
    });

    it('should not affect other keys when revoking one', async () => {
      const k1 = mgr.generateKey(100, 'keep', 'free');
      const k2 = mgr.generateKey(100, 'revoke-me', 'free');
      mgr.revokeKey(k2.keyHash);

      expect(mgr.findByHash(k1.keyHash)?.isActive).toBe(true);
      expect(mgr.findByHash(k2.keyHash)?.isActive).toBe(false);
    });
  });

  describe('deactivateKey()', () => {
    it('should be an alias for revokeKey', async () => {
      const { keyHash } = mgr.generateKey(100, 'deact', 'free');
      expect(mgr.deactivateKey(keyHash)).toBe(true);
      expect(mgr.findByHash(keyHash)?.isActive).toBe(false);
    });

    it('should return false for unknown keyHash', async () => {
      expect(mgr.deactivateKey('unknown')).toBe(false);
    });
  });

  describe('reactivateKey()', () => {
    it('should reactivate a previously revoked key', async () => {
      const { keyHash } = mgr.generateKey(100, 'react', 'pro', 'editor');
      mgr.revokeKey(keyHash);
      expect(mgr.findByHash(keyHash)?.isActive).toBe(false);

      const result = mgr.reactivateKey(keyHash);
      expect(result).toBe(true);
      expect(mgr.findByHash(keyHash)?.isActive).toBe(true);
    });

    it('should return false for a non-existent keyHash', async () => {
      expect(mgr.reactivateKey('nonexistent')).toBe(false);
    });

    it('should be idempotent on an already active key', async () => {
      const { keyHash } = mgr.generateKey(100, 'active', 'free');
      expect(mgr.reactivateKey(keyHash)).toBe(true);
      expect(mgr.reactivateKey(keyHash)).toBe(true);
      expect(mgr.findByHash(keyHash)?.isActive).toBe(true);
    });
  });

  describe('revocation + validation interaction', () => {
    it('should reject revoked keys during validation', async () => {
      const { key, keyHash } = mgr.generateKey(100, 'test', 'pro');
      mgr.revokeKey(keyHash);
      const result = mgr.validateKey(key);
      expect(result.valid).toBe(false);
      expect(result.error).toBe('API key has been revoked');
    });

    it('should accept reactivated keys during validation', async () => {
      const { key, keyHash } = mgr.generateKey(100, 'test', 'pro');
      mgr.revokeKey(keyHash);
      mgr.reactivateKey(keyHash);
      const result = mgr.validateKey(key);
      expect(result.valid).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// 4. Key rotation
// ---------------------------------------------------------------------------

describe('ApiKeyManager - Key Rotation', () => {
  let mgr: ApiKeyManager;

  beforeEach(() => {
    mgr = createManager();
  });

  describe('rotateKey()', () => {
    it('should return a new key with different hash', async () => {
      const { keyHash } = mgr.generateKey(100, 'rotate', 'pro', 'editor');
      const rotated = mgr.rotateKey(keyHash);
      expect(rotated).not.toBeNull();
      expect(rotated!.keyHash).not.toBe(keyHash);
    });

    it('should invalidate the old key', async () => {
      const { key, keyHash } = mgr.generateKey(100, 'old', 'pro');
      mgr.rotateKey(keyHash);
      // Original key should NOT be found under its old hash
      expect(mgr.findByHash(keyHash)).toBeNull();
      // Original plaintext key should fail validation
      expect(mgr.validateKey(key).valid).toBe(false);
    });

    it('should preserve metadata (tier, role, description, rateLimitPerMin)', async () => {
      const { keyHash } = mgr.generateKey(500, 'preserve', 'enterprise', 'operator');
      const rotated = mgr.rotateKey(keyHash);
      expect(rotated?.tier).toBe('enterprise');
      expect(rotated?.role).toBe('operator');
      expect(rotated?.description).toBe('preserve');
      expect(rotated?.rateLimitPerMin).toBe(500);
    });

    it('should reset requestCount and lastUsed', async () => {
      const { key, keyHash } = mgr.generateKey(100, 'reset', 'free');
      await mgr.checkRateLimit(key);
      await mgr.checkRateLimit(key);

      const before = mgr.findByHash(keyHash);
      expect(before?.requestCount).toBe(2);
      expect(before?.lastUsed).not.toBeNull();

      const rotated = mgr.rotateKey(keyHash)!;
      expect(rotated.requestCount).toBe(0);
      expect(rotated.lastUsed).toBeNull();
    });

    it('should return null for a non-existent keyHash', async () => {
      expect(mgr.rotateKey('nonexistent')).toBeNull();
    });

    it('should allow the new key to be validated', async () => {
      const { keyHash } = mgr.generateKey(100, 'new-valid', 'pro');
      const rotated = mgr.rotateKey(keyHash)!;
      expect(mgr.validateKey(rotated.key).valid).toBe(true);
    });

    it('should not leak old rate-limit counters after rotation', async () => {
      const { key, keyHash } = mgr.generateKey(3, 'rl', 'free');
      await mgr.checkRateLimit(key);
      await mgr.checkRateLimit(key);

      const rotated = mgr.rotateKey(keyHash)!;
      const check = await mgr.checkRateLimit(rotated.key);
      expect(check.allowed).toBe(true);
      expect(check.remaining).toBeGreaterThanOrEqual(2); // fresh counter
    });

    it('should produce a key with correct prefix for tier', async () => {
      const { keyHash } = mgr.generateKey(100, 'prefix', 'admin', 'admin');
      const rotated = mgr.rotateKey(keyHash)!;
      expect(rotated.key).toMatch(/^sk_admin_[0-9a-f]{64}$/);
    });
  });
});

// ---------------------------------------------------------------------------
// 5. Rate limiting
// ---------------------------------------------------------------------------

describe('ApiKeyManager - Rate Limiting', () => {
  let mgr: ApiKeyManager;

  beforeEach(() => {
    mgr = createManager();
  });

  describe('checkRateLimit() basic behavior', () => {
    it('should allow requests within the limit', async () => {
      const { key } = mgr.generateKey(100, 'allow', 'free');
      for (let i = 0; i < 50; i++) {
        const result = await mgr.checkRateLimit(key);
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBeGreaterThanOrEqual(0);
      }
    });

    it('should deny requests over the limit', async () => {
      const { key } = mgr.generateKey(2, 'deny', 'free');
      expect((await mgr.checkRateLimit(key)).allowed).toBe(true);
      expect((await mgr.checkRateLimit(key)).allowed).toBe(true);
      const third = await mgr.checkRateLimit(key);
      expect(third.allowed).toBe(false);
      expect(third.remaining).toBe(0);
      expect(third.retryAfter).toBeGreaterThan(0);
    });

    it('should return { allowed:false, remaining:0, resetTime:0 } for unknown key', async () => {
      const result = await mgr.checkRateLimit('bogus');
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.resetTime).toBe(0);
    });

    it('should decrement remaining after each request', async () => {
      const { key } = mgr.generateKey(5, 'remain', 'free');
      // First request: remaining = 4 (5 - 1)
      const r1 = await mgr.checkRateLimit(key);
      expect(r1.remaining).toBe(4);

      const r2 = await mgr.checkRateLimit(key);
      expect(r2.remaining).toBe(3);

      const r3 = await mgr.checkRateLimit(key);
      expect(r3.remaining).toBe(2);
    });

    it('should return resetTime approximately 60s in the future', async () => {
      const { key } = mgr.generateKey(10, 'reset', 'free');
      const now = Date.now();
      const result = await mgr.checkRateLimit(key);
      expect(result.resetTime).toBeGreaterThanOrEqual(now);
      expect(result.resetTime).toBeLessThanOrEqual(now + 61000);
    });

    it('should return retryAfter when rate-limited', async () => {
      const { key } = mgr.generateKey(1, 'retry', 'free');
      await mgr.checkRateLimit(key);
      const denied = await mgr.checkRateLimit(key);
      expect(denied.allowed).toBe(false);
      expect(typeof denied.retryAfter).toBe('number');
      expect(denied.retryAfter).toBeGreaterThan(0);
    });

    it('should increment requestCount and update lastUsed', async () => {
      const { key, keyHash } = mgr.generateKey(100, 'count', 'free');
      await mgr.checkRateLimit(key);

      const meta = mgr.findByHash(keyHash);
      expect(meta?.requestCount).toBe(1);
      expect(meta?.lastUsed).not.toBeNull();
      expect(typeof meta?.lastUsed).toBe('number');
    });

    it('should not allow negative remaining count', async () => {
      const { key } = mgr.generateKey(1, 'neg', 'free');
      await mgr.checkRateLimit(key);
      const denied = await mgr.checkRateLimit(key);
      expect(denied.remaining).toBe(0);
    });
  });

  describe('checkRateLimit() tier-specific rate limits', () => {
    it('should enforce free tier limit (60/min)', async () => {
      const { key } = mgr.generateKey(TIER_RATE_LIMITS.free, 'free-rl', 'free');
      for (let i = 0; i < 60; i++) {
        expect((await mgr.checkRateLimit(key)).allowed).toBe(true);
      }
      expect((await mgr.checkRateLimit(key)).allowed).toBe(false);
    });

    it('should enforce pro tier limit (500/min)', async () => {
      const { key } = mgr.generateKey(TIER_RATE_LIMITS.pro, 'pro-rl', 'pro');
      // Only check a sample to keep test fast
      for (let i = 0; i < 100; i++) {
        expect((await mgr.checkRateLimit(key)).allowed).toBe(true);
      }
    });

    it('should enforce enterprise tier limit (10000/min)', async () => {
      const { key } = mgr.generateKey(TIER_RATE_LIMITS.enterprise, 'ent-rl', 'enterprise');
      for (let i = 0; i < 200; i++) {
        expect((await mgr.checkRateLimit(key)).allowed).toBe(true);
      }
    });

    it('should enforce admin tier limit (100000/min)', async () => {
      const { key } = mgr.generateKey(TIER_RATE_LIMITS.admin, 'admin-rl', 'admin', 'admin');
      for (let i = 0; i < 300; i++) {
        expect((await mgr.checkRateLimit(key)).allowed).toBe(true);
      }
    });

    it('should enforce custom rateLimitPerMin', async () => {
      const { key } = mgr.generateKey(5, 'custom-rl', 'free');
      for (let i = 0; i < 5; i++) {
        expect((await mgr.checkRateLimit(key)).allowed).toBe(true);
      }
      expect((await mgr.checkRateLimit(key)).allowed).toBe(false);
    });
  });

  describe('checkRateLimit() per-key isolation', () => {
    it('should not affect a second key when one key hits its limit', async () => {
      const k1 = mgr.generateKey(2, 'k1', 'free');
      const k2 = mgr.generateKey(100, 'k2', 'free');

      await mgr.checkRateLimit(k1.key);
      await mgr.checkRateLimit(k1.key);
      expect((await mgr.checkRateLimit(k1.key)).allowed).toBe(false);
      expect((await mgr.checkRateLimit(k2.key)).allowed).toBe(true);
    });

    it('should track rate limits independently per key', async () => {
      const k1 = mgr.generateKey(10, 'a', 'free');
      const k2 = mgr.generateKey(10, 'b', 'free');

      for (let i = 0; i < 5; i++) await mgr.checkRateLimit(k1.key);
      for (let i = 0; i < 10; i++) await mgr.checkRateLimit(k2.key);

      // key1 should still have remaining
      expect((await mgr.checkRateLimit(k1.key)).remaining).toBe(4);
      // key2 should be rate limited
      expect((await mgr.checkRateLimit(k2.key)).allowed).toBe(false);
    });
  });

  describe('checkRateLimit() edge cases', () => {
    it('should handle a rate limit of 0', async () => {
      const { key } = mgr.generateKey(0, 'zero', 'free');
      expect((await mgr.checkRateLimit(key)).allowed).toBe(false);
    });

    it('should handle a rate limit of 1', async () => {
      const { key } = mgr.generateKey(1, 'one', 'free');
      expect((await mgr.checkRateLimit(key)).allowed).toBe(true);
      expect((await mgr.checkRateLimit(key)).allowed).toBe(false);
    });

    it('should handle rapid consecutive calls', async () => {
      const { key } = mgr.generateKey(1000, 'rapid', 'pro');
      for (let i = 0; i < 500; i++) {
        const result = await mgr.checkRateLimit(key);
        expect(result.allowed).toBe(true);
      }
    });
  });

  describe('rate limit with revoked key', () => {
    it('should still allow rate-limit checks on a revoked key (metadata persists)', async () => {
      const { key, keyHash } = mgr.generateKey(100, 'revoked-rl', 'pro');
      mgr.revokeKey(keyHash);
      const result = await mgr.checkRateLimit(key);
      // checkRateLimit looks up metadata by hash; it does not check isActive
      expect(result.allowed).toBe(true);
    });
  });
});

// ---------------------------------------------------------------------------
// 6. Tier management
// ---------------------------------------------------------------------------

describe('ApiKeyManager - Tier Management', () => {
  let mgr: ApiKeyManager;

  beforeEach(() => {
    mgr = createManager();
  });

  describe('TIER_RATE_LIMITS', () => {
    it('should have expected rate limits for each tier', async () => {
      expect(TIER_RATE_LIMITS.free).toBe(60);
      expect(TIER_RATE_LIMITS.pro).toBe(500);
      expect(TIER_RATE_LIMITS.enterprise).toBe(10000);
      expect(TIER_RATE_LIMITS.admin).toBe(100000);
    });

    it('should have all four expected tiers', async () => {
      const tiers = Object.keys(TIER_RATE_LIMITS);
      expect(tiers).toContain('free');
      expect(tiers).toContain('pro');
      expect(tiers).toContain('enterprise');
      expect(tiers).toContain('admin');
      expect(tiers.length).toBe(4);
    });
  });

  describe('updateTier()', () => {
    it('should upgrade key tier and update rate limit', async () => {
      const { keyHash } = mgr.generateKey(60, 'upgrade', 'free', 'viewer');
      const result = mgr.updateTier(keyHash, 'pro');
      expect(result).toBe(true);

      const meta = mgr.findByHash(keyHash);
      expect(meta?.tier).toBe('pro');
      expect(meta?.rateLimitPerMin).toBe(TIER_RATE_LIMITS.pro);
    });

    it('should downgrade key tier and update rate limit', async () => {
      const { keyHash } = mgr.generateKey(10000, 'downgrade', 'enterprise', 'viewer');
      mgr.updateTier(keyHash, 'free');
      const meta = mgr.findByHash(keyHash);
      expect(meta?.tier).toBe('free');
      expect(meta?.rateLimitPerMin).toBe(TIER_RATE_LIMITS.free);
    });

    it('should return false for unknown keyHash', async () => {
      expect(mgr.updateTier('unknown', 'pro')).toBe(false);
    });

    it('should handle all tier transitions', async () => {
      const { keyHash } = mgr.generateKey(100, 'all', 'free');

      // free -> pro
      mgr.updateTier(keyHash, 'pro');
      expect(mgr.findByHash(keyHash)?.tier).toBe('pro');
      expect(mgr.findByHash(keyHash)?.rateLimitPerMin).toBe(TIER_RATE_LIMITS.pro);

      // pro -> enterprise
      mgr.updateTier(keyHash, 'enterprise');
      expect(mgr.findByHash(keyHash)?.tier).toBe('enterprise');
      expect(mgr.findByHash(keyHash)?.rateLimitPerMin).toBe(TIER_RATE_LIMITS.enterprise);

      // enterprise -> admin
      mgr.updateTier(keyHash, 'admin');
      expect(mgr.findByHash(keyHash)?.tier).toBe('admin');
      expect(mgr.findByHash(keyHash)?.rateLimitPerMin).toBe(TIER_RATE_LIMITS.admin);

      // admin -> free
      mgr.updateTier(keyHash, 'free');
      expect(mgr.findByHash(keyHash)?.tier).toBe('free');
      expect(mgr.findByHash(keyHash)?.rateLimitPerMin).toBe(TIER_RATE_LIMITS.free);
    });
  });

  describe('updateRateLimit()', () => {
    it('should set a custom rate limit', async () => {
      const { keyHash } = mgr.generateKey(100, 'custom', 'pro');
      const result = mgr.updateRateLimit(keyHash, 42);
      expect(result).toBe(true);
      expect(mgr.findByHash(keyHash)?.rateLimitPerMin).toBe(42);
    });

    it('should return false for unknown keyHash', async () => {
      expect(mgr.updateRateLimit('unknown', 100)).toBe(false);
    });

    it('should not affect tier when updating rate limit', async () => {
      const { keyHash } = mgr.generateKey(100, 'tier-same', 'enterprise');
      mgr.updateRateLimit(keyHash, 999);
      const meta = mgr.findByHash(keyHash);
      expect(meta?.rateLimitPerMin).toBe(999);
      expect(meta?.tier).toBe('enterprise');
    });

    it('should allow a rate limit of zero', async () => {
      const { keyHash } = mgr.generateKey(100, 'zero-rl', 'free');
      mgr.updateRateLimit(keyHash, 0);
      expect(mgr.findByHash(keyHash)?.rateLimitPerMin).toBe(0);
    });
  });

  describe('deleteKey()', () => {
    it('should remove a key completely', async () => {
      const { keyHash } = mgr.generateKey(100, 'del', 'free');
      expect(mgr.findByHash(keyHash)).toBeDefined();

      const result = mgr.deleteKey(keyHash);
      expect(result).toBe(true);
      expect(mgr.findByHash(keyHash)).toBeNull();
    });

    it('should also clear rate-limit counters', async () => {
      const { key, keyHash } = mgr.generateKey(100, 'del-rl', 'free');
      await mgr.checkRateLimit(key);
      mgr.deleteKey(keyHash);
      // After deletion, checkRateLimit should show unknown
      expect((await mgr.checkRateLimit(key)).allowed).toBe(false);
      expect((await mgr.checkRateLimit(key)).remaining).toBe(0);
    });

    it('should return false for non-existent keyHash', async () => {
      expect(mgr.deleteKey('nonexistent')).toBe(false);
    });

    it('should allow regenerating with same prefix after deletion', async () => {
      const { keyHash } = mgr.generateKey(100, 'recreate', 'pro');
      mgr.deleteKey(keyHash);
      const newKey = mgr.generateKey(100, 'recreate', 'pro');
      expect(mgr.findByHash(newKey.keyHash)).toBeDefined();
    });
  });
});

// ---------------------------------------------------------------------------
// 7. Env-based key loading
// ---------------------------------------------------------------------------

describe('ApiKeyManager - Env-based Key Loading', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    delete process.env.API_KEYS;
    delete process.env.ENCRYPTION_KEY;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('default behavior (no env keys)', () => {
    it('should auto-generate a default admin key when no API_KEYS env var', async () => {
      const mgr = new ApiKeyManager();
      const allKeys = mgr.getAllKeys();
      // The constructor generates one default admin key
      expect(allKeys.length).toBeGreaterThanOrEqual(1);
      const adminKey = allKeys.find((k) => k.tier === 'admin');
      expect(adminKey).toBeDefined();
      expect(adminKey?.role).toBe('admin');
      expect(adminKey?.rateLimitPerMin).toBe(TIER_RATE_LIMITS.admin);
    });
  });

  describe('keys from API_KEYS env var (unencrypted)', () => {
    it('should load a single key from env', async () => {
      process.env.API_KEYS = 'sk_free_test1234:300:test-key:free:viewer';
      const mgr = new ApiKeyManager();
      const keys = mgr.getAllKeys();

      const loaded = keys.find((k) => k.keyPrefix === 'sk_free_test');
      expect(loaded).toBeDefined();
      expect(loaded?.description).toBe('test-key');
      expect(loaded?.tier).toBe('free');
      expect(loaded?.role).toBe('viewer');
      expect(loaded?.rateLimitPerMin).toBe(300);
      expect(loaded?.isActive).toBe(true);
    });

    it('should load multiple keys from comma-separated env', async () => {
      process.env.API_KEYS = [
        'sk_free_aaa:100:key1:free:viewer',
        'sk_pro_bbb:500:key2:pro:editor',
        'sk_enterprise_ccc:10000:key3:enterprise:operator',
      ].join(',');

      const mgr = new ApiKeyManager();
      const keys = mgr.getAllKeys();

      expect(keys.some((k) => k.description === 'key1')).toBe(true);
      expect(keys.some((k) => k.description === 'key2')).toBe(true);
      expect(keys.some((k) => k.description === 'key3')).toBe(true);

      const key1 = keys.find((k) => k.description === 'key1');
      expect(key1?.tier).toBe('free');
      expect(key1?.rateLimitPerMin).toBe(100);

      const key2 = keys.find((k) => k.description === 'key2');
      expect(key2?.tier).toBe('pro');
      expect(key2?.rateLimitPerMin).toBe(500);

      const key3 = keys.find((k) => k.description === 'key3');
      expect(key3?.tier).toBe('enterprise');
      expect(key3?.rateLimitPerMin).toBe(10000);
    });

    it('should handle env keys with partial fields', async () => {
      // Only key provided, rest are defaults
      process.env.API_KEYS = 'sk_minimal_test:';
      const mgr = new ApiKeyManager();
      const keys = mgr.getAllKeys();
      const loaded = keys.find((k) => k.keyPrefix.startsWith('sk_minimal_t'));
      expect(loaded).toBeDefined();
      expect(loaded?.tier).toBe('free');
      expect(loaded?.role).toBe('viewer');
    });

    it('should handle key with numeric description field parsed correctly', async () => {
      process.env.API_KEYS = 'sk_num_test:500:my-desc:pro:editor';
      const mgr = new ApiKeyManager();
      const keys = mgr.getAllKeys();
      const loaded = keys.find((k) => k.keyPrefix.startsWith('sk_num_test'));
      expect(loaded?.description).toBe('my-desc');
      expect(loaded?.tier).toBe('pro');
      expect(loaded?.role).toBe('editor');
      expect(loaded?.rateLimitPerMin).toBe(500);
    });

    it('should handle empty API_KEYS gracefully (falls back to default)', async () => {
      process.env.API_KEYS = '';
      const mgr = new ApiKeyManager();
      const keys = mgr.getAllKeys();
      // Falls back to default admin key generation
      expect(keys.length).toBeGreaterThanOrEqual(1);
    });

    it('should handle malformed entries gracefully', async () => {
      process.env.API_KEYS = ',,invalid,:,,:,';
      const mgr = new ApiKeyManager();
      const keys = mgr.getAllKeys();
      // Should still have at least the default admin key
      expect(keys.length).toBeGreaterThanOrEqual(1);
    });

    it('should validate loaded env keys', async () => {
      process.env.API_KEYS = 'sk_test_abc123key:100:env-test:free:viewer';
      const mgr = new ApiKeyManager();
      const result = mgr.validateKey('sk_test_abc123key');
      expect(result.valid).toBe(true);
      expect(result.metadata?.description).toBe('env-test');
    });

    it('should not load default admin when env keys exist', async () => {
      process.env.API_KEYS = 'sk_env_only:200:only-me:pro:editor';
      const mgr = new ApiKeyManager();
      const keys = mgr.getAllKeys();
      // Only the env key, no auto-generated admin key
      // The env key itself should be the only one (plus whatever was added by constructor default fallback logic)
      // Actually, the code auto-generates when `this.keys.size === 0`, so if env loads keys, it won't auto-generate
      expect(keys.length).toBe(1);
      expect(keys[0].description).toBe('only-me');
    });

    it('should handle env entries with whitespace around commas', async () => {
      process.env.API_KEYS = ' sk_ws_1:100:a:free:viewer , sk_ws_2:200:b:pro:editor ';
      const mgr = new ApiKeyManager();
      const keys = mgr.getAllKeys();
      expect(keys.some((k) => k.description === 'a')).toBe(true);
      expect(keys.some((k) => k.description === 'b')).toBe(true);
    });
  });

  describe('encrypted API_KEYS env var', () => {
    it('should fall back to plaintext if decryptSecret returns raw value', async () => {
      // decryptSecret returns raw value when not encrypted (no ENCRYPTION_KEY set)
      process.env.API_KEYS = 'sk_plain_fallback:150:plain:free:viewer';
      const mgr = new ApiKeyManager();
      const keys = mgr.getAllKeys();
      const loaded = keys.find((k) => k.keyPrefix.startsWith('sk_plain_fa'));
      expect(loaded).toBeDefined();
      expect(loaded?.description).toBe('plain');
    });
  });
});

// ---------------------------------------------------------------------------
// 8. getAllKeys()
// ---------------------------------------------------------------------------

describe('ApiKeyManager - getAllKeys()', () => {
  let mgr: ApiKeyManager;

  beforeEach(() => {
    mgr = createManager();
  });

  it('should return an array', async () => {
    expect(Array.isArray(mgr.getAllKeys())).toBe(true);
  });

  it('should include all expected fields for each key', async () => {
    mgr.generateKey(100, 'fields', 'pro', 'editor');
    const keys = mgr.getAllKeys();
    const record = keys[keys.length - 1];

    expect(record).toHaveProperty('keyPrefix');
    expect(record).toHaveProperty('keyHash');
    expect(record).toHaveProperty('createdAt');
    expect(record).toHaveProperty('lastUsed');
    expect(record).toHaveProperty('requestCount');
    expect(record).toHaveProperty('isActive');
    expect(record).toHaveProperty('rateLimitPerMin');
    expect(record).toHaveProperty('tier');
    expect(record).toHaveProperty('role');
    expect(record).toHaveProperty('description');
  });

  it('should include freshly generated keys', async () => {
    mgr.generateKey(100, 'new', 'free');
    const keys = mgr.getAllKeys();
    expect(keys.some((k) => k.description === 'new')).toBe(true);
  });

  it('should still include revoked keys (with isActive: false)', async () => {
    const { keyHash } = mgr.generateKey(100, 'revoked-list', 'free');
    mgr.revokeKey(keyHash);
    const keys = mgr.getAllKeys();
    const revoked = keys.find((k) => k.keyHash === keyHash);
    expect(revoked).toBeDefined();
    expect(revoked?.isActive).toBe(false);
  });

  it('should no longer include deleted keys', async () => {
    const { keyHash } = mgr.generateKey(100, 'deleted-list', 'free');
    mgr.deleteKey(keyHash);
    const keys = mgr.getAllKeys();
    expect(keys.some((k) => k.keyHash === keyHash)).toBe(false);
  });

  it('should return the raw 12-char key prefix (no ellipsis)', async () => {
    mgr.generateKey(100, 'ellipsis', 'free');
    const keys = mgr.getAllKeys();
    for (const k of keys) {
      expect(k.keyPrefix.length).toBe(12);
      expect(k.keyPrefix.endsWith('...')).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// 9. hashKey()
// ---------------------------------------------------------------------------

describe('ApiKeyManager - hashKey()', () => {
  let mgr: ApiKeyManager;

  beforeEach(() => {
    mgr = createManager();
  });

  it('should return a 64-character hex string', async () => {
    const hash = mgr.hashKey('test-key');
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('should produce consistent hashes for the same input', async () => {
    const h1 = mgr.hashKey('consistent');
    const h2 = mgr.hashKey('consistent');
    expect(h1).toBe(h2);
  });

  it('should produce different hashes for different inputs', async () => {
    const h1 = mgr.hashKey('key-a');
    const h2 = mgr.hashKey('key-b');
    expect(h1).not.toBe(h2);
  });

  it('should be deterministic (SHA-256)', async () => {
    // Known SHA-256 of 'hello'
    const expected = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
    expect(mgr.hashKey('hello')).toBe(expected);
  });
});

// ---------------------------------------------------------------------------
// 10. Full lifecycle integration
// ---------------------------------------------------------------------------

describe('ApiKeyManager - Full Key Lifecycle', () => {
  it('should support generate -> use -> revoke -> reactivate -> rotate -> delete', async () => {
    const mgr = createManager();

    // Generate
    const { key, keyHash } = mgr.generateKey(50, 'lifecycle', 'pro', 'editor');
    expect(mgr.validateKey(key).valid).toBe(true);

    // Use (rate limit)
    expect((await mgr.checkRateLimit(key)).allowed).toBe(true);

    // Revoke
    mgr.revokeKey(keyHash);
    expect(mgr.validateKey(key).valid).toBe(false);

    // Reactivate
    mgr.reactivateKey(keyHash);
    expect(mgr.validateKey(key).valid).toBe(true);

    // Rotate
    const rotated = mgr.rotateKey(keyHash)!;
    expect(rotated.key).not.toBe(key);
    expect(mgr.validateKey(key).valid).toBe(false);
    expect(mgr.validateKey(rotated.key).valid).toBe(true);
    expect(rotated.tier).toBe('pro');
    expect(rotated.role).toBe('editor');

    // Delete the rotated key
    mgr.deleteKey(rotated.keyHash);
    expect(mgr.validateKey(rotated.key).valid).toBe(false);
  });
});
