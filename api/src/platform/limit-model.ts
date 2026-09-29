/**
 * The single authoritative rate-limit model (issue #595).
 *
 * Everything that reports or stores a per-key allowance resolves it through
 * `effectiveTenantLimit`: the tier table below is the only place a tier number
 * is defined, and no request, header or admin call can exceed the tier
 * ceiling.
 */

export type RateTier = 'free' | 'pro' | 'enterprise' | 'admin';

/** Published tier defaults (requests per minute). */
export const TIER_RATE_LIMITS: Record<RateTier, number> = {
  free: 60,
  pro: 500,
  enterprise: 10000,
  admin: 100000,
};

/** Highest value an admin/self-service override may set for a tier. */
export const TIER_RATE_LIMIT_CEILINGS: Record<RateTier, number> = {
  free: 600,
  pro: 5000,
  enterprise: 50000,
  admin: 100000,
};

export function ceilingForTier(tier: RateTier): number {
  return TIER_RATE_LIMIT_CEILINGS[tier];
}

/**
 * The number that is actually enforced for a key: its stored override, never
 * above the tier ceiling, falling back to the tier default when no valid
 * override exists. `0` is preserved (deny-all), because it is a deliberate
 * stored value rather than a missing one.
 */
export function effectiveTenantLimit(tier: RateTier, requested?: number): number {
  const tierDefault = TIER_RATE_LIMITS[tier];
  if (typeof requested !== 'number' || !Number.isFinite(requested)) return tierDefault;
  const floored = Math.floor(requested);
  if (floored < 0) return tierDefault;
  return Math.min(floored, TIER_RATE_LIMIT_CEILINGS[tier]);
}

export interface OverrideDecision {
  requested: number;
  effective: number;
  ceiling: number;
  clamped: boolean;
}

/** Validates an operator-supplied override against the tier ceiling. */
export function clampOverride(tier: RateTier, requested: number): OverrideDecision {
  const ceiling = TIER_RATE_LIMIT_CEILINGS[tier];
  const normalized = Math.floor(requested);
  const effective = Math.min(normalized, ceiling);
  return { requested: normalized, effective, ceiling, clamped: effective !== normalized };
}

/** Human-readable description used by docs and status endpoints. */
export const LIMIT_MODEL = {
  authoritative: 'authMiddleware per-key window (api/src/governance/auth.ts via platform/tenant-window.ts)',
  table: 'platform/limit-model.ts (TIER_RATE_LIMITS + TIER_RATE_LIMIT_CEILINGS)',
  defenseInDepth: 'platform/rate-limiter.ts layered global/ip/endpoint caps — never tenant allowance',
  header: 'X-RateLimit-Limit is the enforced effective limit',
} as const;
