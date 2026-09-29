import type { IncomingMessage } from 'http';

/**
 * Trust model for forwarded and edge-injected headers (issue #594).
 *
 * Headers such as `X-Forwarded-For`, `x-geo-region` or `cf-ipcountry` arrive
 * with the request either from the client (fully attacker-controlled) or from
 * a proxy that stripped and rewrote them. They are only honoured when the TCP
 * peer itself is listed in `TRUSTED_PROXY_IPS`; otherwise the connection is
 * treated as direct and the headers are ignored.
 *
 * The setting is read from the environment on every call so operators and
 * tests can change it without rebuilding the process image.
 */

function configuredProxies(): string[] {
  return (process.env.TRUSTED_PROXY_IPS || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeIp(ip: string): string {
  return ip.replace(/^::ffff:/i, '').trim();
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    value = (value << 8) | octet;
  }
  return value >>> 0;
}

function matchesEntry(ip: string, entry: string): boolean {
  if (!entry.includes('/')) return ip === entry;

  const [range, bitsRaw] = entry.split('/');
  const bits = Number(bitsRaw);
  const ipInt = ipv4ToInt(ip);
  const rangeInt = ipv4ToInt(range);
  if (ipInt === null || rangeInt === null || Number.isNaN(bits) || bits < 0 || bits > 32) {
    return false;
  }
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((ipInt & mask) >>> 0) === ((rangeInt & mask) >>> 0);
}

export function peerAddress(req: IncomingMessage): string {
  return normalizeIp(req.socket?.remoteAddress || '');
}

export function isTrustedProxy(req: IncomingMessage): boolean {
  const peer = peerAddress(req);
  if (!peer) return false;
  return configuredProxies().some((entry) => matchesEntry(peer, entry));
}

/** Real client address: the forwarded chain is only believed behind a trusted proxy. */
export function clientIp(req: IncomingMessage): string {
  if (isTrustedProxy(req)) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.length > 0) {
      return forwarded.split(',')[0].trim();
    }
  }
  return peerAddress(req) || 'unknown';
}

/** Edge-injected header value, or `undefined` when the peer is not a trusted proxy. */
export function trustedHeader(req: IncomingMessage, name: string): string | undefined {
  if (!isTrustedProxy(req)) return undefined;
  const value = req.headers[name];
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
