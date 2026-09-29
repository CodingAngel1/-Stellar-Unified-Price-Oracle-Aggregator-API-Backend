import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import winston from 'winston';
import { decryptSecret } from './crypto';
import { logger } from '../observability/logger';
import {
  auditChainValid,
  auditChainVerificationTotal,
  auditEventsTotal,
} from '../observability/metrics';

export type AuditEvent =
  | 'auth.success'
  | 'auth.failure'
  | 'auth.rate_limited'
  | 'admin.key_created'
  | 'admin.key_rotated'
  | 'admin.key_deactivated'
  | 'admin.key_deleted'
  | 'admin.key_reactivated'
  | 'admin.rate_limit_updated'
  | 'admin.role_assigned'
  | 'key.rotation_started'
  | 'key.rotation_completed'
  | 'archival.run'
  | 'archival.restore'
  | 'consistency.check'
  | 'backup.run'
  | 'backup.test-restore'
  | 'backup.restore'
  | 'governance.proposal_created'
  | 'governance.vote_cast'
  | 'governance.proposal_queued'
  | 'governance.proposal_executed'
  | 'governance.proposal_cancelled'
  | 'governance.emergency_execute'
  | 'multisig.proposal_created'
  | 'multisig.proposal_approved'
  | 'multisig.proposal_executed';

/**
 * Every entry carries the writer and key that produced it. Entries form one
 * chain per writer (identified by `writerId`, contiguous `seq`); a writer's
 * first entry anchors to an entry that already appears earlier in the log.
 * Cross-replica ordering is deliberately not claimed — see
 * docs/audit-log-retention.md for the property that actually holds.
 */
export interface AuditEntry {
  event: AuditEvent;
  timestamp: string;
  ip: string;
  userAgent: string;
  apiKeyPrefix: string;
  keyId?: string;
  writerId?: string;
  seq?: number;
  prevHmac?: string;
  details?: Record<string, unknown>;
  prevState?: Record<string, unknown>;
  newState?: Record<string, unknown>;
  hmac: string;
}

export const AUDIT_LOG_FILE = process.env.AUDIT_LOG_FILE
  ? path.resolve(process.env.AUDIT_LOG_FILE)
  : path.resolve(process.cwd(), 'logs/audit.log');

const EMIT_STDOUT = process.env.AUDIT_STDOUT !== 'false';

function openAuditLogger(file: string): winston.Logger {
  return winston.createLogger({
    level: 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json(),
    ),
    transports: [
      new winston.transports.File({ filename: file }),
    ],
  });
}

let activeAuditLogFile = AUDIT_LOG_FILE;
let auditFileLogger = openAuditLogger(activeAuditLogFile);

export function getAuditLogFile(): string {
  return activeAuditLogFile;
}

const writerId = `${os.hostname()}-${process.pid}-${crypto.randomBytes(3).toString('hex')}`;
let writerSeq = 0;
let lastHmac = '';

interface AuditSecrets {
  keyring: Map<string, string>;
  currentKeyId: string;
}

function fingerprint(secret: string): string {
  return crypto.createHash('sha256').update(secret).digest('hex').slice(0, 16);
}

/**
 * Loads the signing keyring. `AUDIT_SECRET` is the active key and
 * `AUDIT_SECRET_PREVIOUS` keeps retired keys so historical entries stay
 * verifiable after a rotation; each entry records the id of the key that
 * signed it. Outside production an ephemeral per-process key is generated, so
 * there is no shared default an attacker can know.
 */
export function loadAuditSecrets(env: NodeJS.ProcessEnv = process.env): AuditSecrets {
  const keyring = new Map<string, string>();
  const add = (raw?: string): string | null => {
    if (!raw) return null;
    const secret = decryptSecret(raw);
    keyring.set(fingerprint(secret), secret);
    return secret;
  };

  add(env.AUDIT_SECRET_PREVIOUS);
  const current = add(env.AUDIT_SECRET);
  if (current) return { keyring, currentKeyId: fingerprint(current) };

  if ((env.NODE_ENV || '').toLowerCase() === 'production') {
    throw new Error(
      'AUDIT_SECRET is required when NODE_ENV=production: refusing to start with a default audit signing key.',
    );
  }

  const ephemeral = crypto.randomBytes(32).toString('hex');
  keyring.set(fingerprint(ephemeral), ephemeral);
  return { keyring, currentKeyId: fingerprint(ephemeral) };
}

let secrets: AuditSecrets | null = null;

function getSecrets(): AuditSecrets {
  if (!secrets) secrets = loadAuditSecrets();
  return secrets;
}

export function currentAuditKeyId(): string {
  return getSecrets().currentKeyId;
}

function secretFor(keyId?: string): string | null {
  const state = getSecrets();
  if (!keyId) return state.keyring.get(state.currentKeyId) ?? null;
  return state.keyring.get(keyId) ?? null;
}

function canonicalPayload(entry: Partial<AuditEntry>, previousHmac: string): string {
  const payload: Record<string, unknown> = {};
  if (entry.event !== undefined) payload.event = entry.event;
  if (entry.timestamp !== undefined) payload.timestamp = entry.timestamp;
  if (entry.ip !== undefined) payload.ip = entry.ip;
  if (entry.userAgent !== undefined) payload.userAgent = entry.userAgent;
  if (entry.apiKeyPrefix !== undefined) payload.apiKeyPrefix = entry.apiKeyPrefix;
  if (entry.keyId !== undefined) payload.keyId = entry.keyId;
  if (entry.writerId !== undefined) payload.writerId = entry.writerId;
  if (entry.seq !== undefined) payload.seq = entry.seq;
  if (entry.details !== undefined) payload.details = entry.details;
  if (entry.prevState !== undefined) payload.prevState = entry.prevState;
  if (entry.newState !== undefined) payload.newState = entry.newState;
  payload.prevHmac = previousHmac;
  return JSON.stringify(payload);
}

function hmacWith(secret: string, entry: Partial<AuditEntry>, previousHmac: string): string {
  return crypto.createHmac('sha256', secret).update(canonicalPayload(entry, previousHmac)).digest('hex');
}

export function computeAuditHmac(
  data: Omit<AuditEntry, 'hmac'> | Partial<AuditEntry>,
  previousHmac = '',
  keyId?: string,
): string {
  const secret = secretFor(keyId ?? data.keyId);
  if (!secret) {
    throw new Error(`No audit signing key available for key id ${keyId ?? data.keyId ?? 'current'}`);
  }
  return hmacWith(secret, data, previousHmac);
}

export function readAuditEntries(file: string = activeAuditLogFile): AuditEntry[] {
  if (!fs.existsSync(file)) return [];
  return fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => {
      try {
        return JSON.parse(line) as AuditEntry;
      } catch {
        return null;
      }
    })
    .filter((entry): entry is AuditEntry => !!entry);
}

/**
 * Verifies per-writer chains: within a writer the sequence numbers are
 * contiguous and each hmac matches its predecessor, and the anchor of a
 * writer's first entry must resolve to an entry earlier in the file (the
 * exception is the first line of the file, whose history may have been
 * pruned by retention).
 */
export function verifyAuditLogChain(entries: AuditEntry[]): {
  valid: boolean;
  firstInvalidIndex: number | null;
} {
  const hmacIndex = new Map<string, number>();
  const byWriter = new Map<string, Array<{ entry: AuditEntry; index: number }>>();

  entries.forEach((entry, index) => {
    hmacIndex.set(entry.hmac, index);
    const writer = entry.writerId ?? 'legacy';
    const group = byWriter.get(writer) ?? [];
    group.push({ entry, index });
    byWriter.set(writer, group);
  });

  for (const group of byWriter.values()) {
    let previous: AuditEntry | null = null;

    for (const { entry, index } of group) {
      const expectedPrev = previous ? previous.hmac : (entry.prevHmac ?? '');
      if ((entry.prevHmac ?? '') !== expectedPrev) {
        return { valid: false, firstInvalidIndex: index };
      }

      if (previous && entry.seq != null && previous.seq != null && entry.seq !== previous.seq + 1) {
        return { valid: false, firstInvalidIndex: index };
      }

      const secret = secretFor(entry.keyId);
      if (!secret) {
        return { valid: false, firstInvalidIndex: index };
      }
      const fields: Partial<AuditEntry> = { ...entry };
      delete fields.hmac;
      if (hmacWith(secret, fields, entry.prevHmac ?? '') !== entry.hmac) {
        return { valid: false, firstInvalidIndex: index };
      }

      if (!previous && (entry.prevHmac ?? '') !== '') {
        const anchorIndex = hmacIndex.get(entry.prevHmac as string);
        if ((anchorIndex === undefined || anchorIndex > index) && index !== 0) {
          return { valid: false, firstInvalidIndex: index };
        }
      }

      previous = entry;
    }
  }

  return { valid: true, firstInvalidIndex: null };
}

/**
 * Loads the keyring and validates the existing log before the first append.
 * When the chain cannot be verified the log is forked: the broken chain is
 * preserved under a new file for forensics and new entries start a fresh
 * chain, so nothing is ever appended to an unverifiable chain. Set
 * `AUDIT_CHAIN_ON_BREAK=throw` to refuse startup instead.
 */
export function initializeAuditIntegrity(): void {
  secrets = loadAuditSecrets();
  const entries = readAuditEntries();
  let forked = false;

  if (entries.length > 0) {
    const result = verifyAuditLogChain(entries);
    if (!result.valid) {
      auditChainValid.set(0);
      auditChainVerificationTotal.inc({ result: 'forked' });
      const message = `Audit chain verification failed at entry ${result.firstInvalidIndex} in ${activeAuditLogFile}`;

      if (process.env.AUDIT_CHAIN_ON_BREAK === 'throw') {
        throw new Error(`${message}; refusing to append to an unverifiable audit log.`);
      }

      logger.error(`${message}; preserving it for forensics and starting a new chain`);
      const stamp = Date.now();
      fs.writeFileSync(
        `${activeAuditLogFile}.${stamp}`,
        entries.map((entry) => JSON.stringify(entry)).join('\n') + '\n',
        'utf8',
      );
      activeAuditLogFile = `${AUDIT_LOG_FILE}.${stamp}.forked`;
      auditFileLogger = openAuditLogger(activeAuditLogFile);
      forked = true;
    }
  }

  lastHmac = !forked && entries.length > 0 ? entries[entries.length - 1].hmac : '';
  writerSeq = 0;
  auditChainValid.set(forked ? 0 : 1);
}

export function startAuditChainVerification(
  intervalMs = parseInt(process.env.AUDIT_CHAIN_VERIFY_INTERVAL_MS || '3600000', 10),
): NodeJS.Timeout | null {
  if (intervalMs <= 0) return null;

  const run = (): void => {
    try {
      const entries = readAuditEntries();
      const result = entries.length > 0
        ? verifyAuditLogChain(entries)
        : { valid: true, firstInvalidIndex: null };

      auditChainValid.set(result.valid ? 1 : 0);
      auditChainVerificationTotal.inc({ result: result.valid ? 'passed' : 'failed' });

      if (!result.valid) {
        logger.error(
          `Audit chain verification failed at entry ${result.firstInvalidIndex} in ${activeAuditLogFile}; audit integrity is compromised`,
        );
      }
    } catch (error) {
      auditChainVerificationTotal.inc({ result: 'error' });
      logger.error('Audit chain verification could not run', error as Error);
    }
  };

  run();
  const timer = setInterval(run, intervalMs);
  timer.unref?.();
  return timer;
}

export function enforceAuditRetention(retentionDays = auditRetentionDays): number {
  try {
    if (!fs.existsSync(activeAuditLogFile)) return 0;
    const contents = fs.readFileSync(activeAuditLogFile, 'utf8');
    const entries = contents
      .split('\n')
      .filter((line) => line.trim())
      .map((line) => {
        try {
          return JSON.parse(line) as AuditEntry;
        } catch {
          return null;
        }
      })
      .filter((entry): entry is AuditEntry => !!entry)
      .filter((entry) => {
        const timestampMs = new Date(entry.timestamp).getTime();
        if (Number.isNaN(timestampMs)) return true;
        const cutoffMs = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
        return timestampMs >= cutoffMs;
      });

    const output = entries.map((entry) => JSON.stringify(entry)).join('\n') + (entries.length ? '\n' : '');
    fs.writeFileSync(activeAuditLogFile, output, 'utf8');
    return entries.length;
  } catch {
    return 0;
  }
}

export function auditLog(
  event: AuditEvent,
  context: {
    ip?: string;
    userAgent?: string;
    apiKeyPrefix?: string;
    details?: Record<string, unknown>;
    prevState?: Record<string, unknown>;
    newState?: Record<string, unknown>;
  },
): void {
  let state: AuditSecrets;
  try {
    state = getSecrets();
  } catch (error) {
    auditEventsTotal.inc({ result: 'refused' });
    logger.error('Audit entry refused: no signing key', error as Error);
    return;
  }

  const seq = writerSeq + 1;
  const data: Omit<AuditEntry, 'hmac'> = {
    event,
    timestamp: new Date().toISOString(),
    ip: context.ip || 'unknown',
    userAgent: context.userAgent || 'unknown',
    apiKeyPrefix: context.apiKeyPrefix || 'unknown',
    keyId: state.currentKeyId,
    writerId,
    seq,
    prevHmac: lastHmac,
    ...(context.details && { details: context.details }),
    ...(context.prevState && { prevState: context.prevState }),
    ...(context.newState && { newState: context.newState }),
  };

  const hmac = hmacWith(state.keyring.get(state.currentKeyId) as string, data, lastHmac);
  lastHmac = hmac;
  writerSeq = seq;

  const entry: AuditEntry = { ...data, hmac };
  auditFileLogger.info('audit', entry);
  if (EMIT_STDOUT) process.stdout.write(`${JSON.stringify(entry)}\n`);
  auditEventsTotal.inc({ result: 'appended' });
  enforceAuditRetention();
}

export const auditRetentionDays = parseInt(process.env.AUDIT_RETENTION_DAYS || '90', 10);
