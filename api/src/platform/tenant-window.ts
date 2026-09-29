import Redis from 'ioredis';
import { config } from '../infrastructure/config';

/**
 * The one window implementation behind the tenant (per-key) allowance
 * (issue #595). Replicas that point at the same store share counts, so a tier
 * limit is a cluster-wide budget instead of a per-pod multiplier. Without a
 * shared store the window degrades to a documented per-pod local counter.
 */

export interface SharedCountStore {
  /** Increment `identity` within the fixed window starting at `windowStart`. */
  increment(identity: string, windowStart: number): Promise<number>;
}

export interface ConsumeResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  consumed: number;
  reset: number;
  shared: boolean;
  mode: 'shared-redis' | 'local-per-pod';
}

export class TenantWindow {
  private local = new Map<string, { windowStart: number; count: number }>();

  constructor(private store: SharedCountStore | null = null) {}

  get configuredShared(): boolean {
    return this.store !== null;
  }

  async consume(identity: string, limit: number): Promise<ConsumeResult> {
    const windowMs = config.rateLimitWindowMs;
    const now = Date.now();
    const windowStart = now - (now % windowMs);
    const reset = Math.ceil((windowStart + windowMs) / 1000);

    let count: number | null = null;
    let shared = false;
    if (this.store) {
      try {
        count = await this.store.increment(identity, windowStart);
        shared = true;
      } catch {
        count = null;
      }
    }

    if (count === null) {
      const current = this.local.get(identity);
      count = !current || current.windowStart !== windowStart ? 1 : current.count + 1;
      this.local.set(identity, { windowStart, count });
      if (this.local.size > 5000) this.prune(windowStart);
    }

    return {
      allowed: count <= limit,
      limit,
      remaining: Math.max(0, limit - count),
      consumed: count,
      reset,
      shared,
      mode: shared ? 'shared-redis' : 'local-per-pod',
    };
  }

  private prune(windowStart: number): void {
    for (const [identity, entry] of this.local) {
      if (entry.windowStart !== windowStart) this.local.delete(identity);
    }
  }
}

export function redisSharedStore(url: string): SharedCountStore {
  const redis = new Redis(url, { lazyConnect: true, maxRetriesPerRequest: 1 });
  let healthy = false;

  async function ensure(): Promise<boolean> {
    if (healthy) return true;
    try {
      await redis.connect();
      healthy = true;
    } catch {
      healthy = false;
    }
    return healthy;
  }

  return {
    async increment(identity: string, windowStart: number): Promise<number> {
      if (!(await ensure())) throw new Error('rate-limit store unavailable');
      const key = `rl:tenant:${windowStart}:${identity}`;
      try {
        const count = await redis.incr(key);
        if (count === 1) await redis.pexpire(key, config.rateLimitWindowMs * 2);
        return count;
      } catch (err) {
        healthy = false;
        throw err;
      }
    },
  };
}

export function createTenantWindow(): TenantWindow {
  return config.redisUrl ? new TenantWindow(redisSharedStore(config.redisUrl)) : new TenantWindow(null);
}
