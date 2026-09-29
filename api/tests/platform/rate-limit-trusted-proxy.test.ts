import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { Request } from 'express';
import { adjustedLimit, setSystemLoadPressure } from '../../src/platform/rate-limiter';
import { clientIp, isTrustedProxy, trustedHeader } from '../../src/platform/trusted-proxy';
import { config } from '../../src/infrastructure/config';

const BASE = config.rateLimitMax;

function fakeReq(headers: Record<string, string>, remoteAddress: string): Request {
  return {
    headers,
    socket: { remoteAddress },
    method: 'GET',
    path: '/api/v1/prices',
    route: { path: '/api/v1/prices' },
  } as unknown as Request;
}

describe('Issue #594: client headers cannot change a caller\'s rate limit', () => {
  beforeEach(() => {
    delete process.env.TRUSTED_PROXY_IPS;
    setSystemLoadPressure(0.5);
  });

  afterEach(() => {
    delete process.env.TRUSTED_PROXY_IPS;
    setSystemLoadPressure(0.5);
  });

  it('ignores spoofed region and load headers from an untrusted peer', () => {
    const req = fakeReq({ 'x-geo-region': 'AF', 'x-system-load': '0' }, '203.0.113.9');
    expect(isTrustedProxy(req as never)).toBe(false);
    expect(adjustedLimit('ip', req, false)).toBe(BASE);
    expect(adjustedLimit('ip', req, false)).toBe(config.rateLimitMax);
    expect(adjustedLimit('endpoint', req, false)).toBe(Math.max(10, Math.floor(config.rateLimitMax / 2)));
  });

  it('does not let x-system-load raise the limit even via a trusted proxy', () => {
    process.env.TRUSTED_PROXY_IPS = '10.0.0.5';
    const req = fakeReq({ 'x-system-load': '0' }, '10.0.0.5');
    expect(adjustedLimit('ip', req, false)).toBe(BASE);
  });

  it('honours the edge region only from a trusted proxy', () => {
    process.env.TRUSTED_PROXY_IPS = '10.0.0.5';

    const elevated = fakeReq({ 'x-geo-region': 'AF' }, '10.0.0.5');
    expect(adjustedLimit('ip', elevated, false)).toBe(Math.floor(BASE * 1.25));

    const shaped = fakeReq({ 'x-geo-region': 'CN' }, '10.0.0.5');
    expect(adjustedLimit('ip', shaped, false)).toBe(Math.floor(BASE * 0.5));

    const spoofed = fakeReq({ 'x-geo-region': 'AF' }, '198.51.100.7');
    expect(isTrustedProxy(spoofed as never)).toBe(false);
    expect(adjustedLimit('ip', spoofed, false)).toBe(BASE);
  });

  it('supports CIDR entries and cf-ipcountry from the trusted edge', () => {
    process.env.TRUSTED_PROXY_IPS = '10.0.0.0/8, 192.0.2.10';
    const req = fakeReq({ 'cf-ipcountry': 'oc' }, '10.44.1.2');
    expect(isTrustedProxy(req as never)).toBe(true);
    expect(adjustedLimit('ip', req, false)).toBe(Math.floor(BASE * 1.25));
    expect(trustedHeader(req as never, 'cf-ipcountry')).toBe('oc');
  });

  it('uses the internal load-pressure signal instead of headers', () => {
    const req = fakeReq({ 'x-system-load': '0' }, '203.0.113.9');

    setSystemLoadPressure(0.9);
    expect(adjustedLimit('ip', req, false)).toBe(Math.floor(BASE * 0.75));

    setSystemLoadPressure(0.1);
    expect(adjustedLimit('ip', req, false)).toBe(Math.floor(BASE * 1.1));

    setSystemLoadPressure(0.5);
    expect(adjustedLimit('ip', req, false)).toBe(BASE);
  });

  it('believes X-Forwarded-For only behind a trusted proxy', () => {
    const forwarded = { 'x-forwarded-for': '198.51.100.20, 10.0.0.1' };

    const direct = fakeReq(forwarded, '203.0.113.9');
    expect(clientIp(direct as never)).toBe('203.0.113.9');
    expect(trustedHeader(direct as never, 'x-geo-region')).toBeUndefined();

    process.env.TRUSTED_PROXY_IPS = '10.0.0.0/8';
    const proxied = fakeReq(forwarded, '10.0.0.1');
    expect(clientIp(proxied as never)).toBe('198.51.100.20');
    expect(trustedHeader(proxied as never, 'x-geo-region')).toBeUndefined();
  });

  it('still halves the limit in degraded mode', () => {
    const req = fakeReq({}, '203.0.113.9');
    expect(adjustedLimit('ip', req, true)).toBe(Math.max(1, Math.floor(BASE * 0.5)));
  });
});
