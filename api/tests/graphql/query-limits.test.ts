import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import express, { type Express } from 'express';
import request from 'supertest';
import { parse, validate } from 'graphql';
import graphqlRouter from '../../src/graphql';
import { schema } from '../../src/graphql/schema';
import { depthLimitRule, withTimeout, QueryTimeoutError } from '../../src/graphql/validation';
import { config } from '../../src/infrastructure/config';
import { apiKeyManager } from '../../src/governance/api-key-manager';

const original = { ...config.graphql };
const proKey = apiKeyManager.generateKey(100, 'graphql pro key', 'pro', 'viewer').key;
const freeKey = apiKeyManager.generateKey(100, 'graphql free key', 'free', 'viewer').key;
const limitedKey = apiKeyManager.generateKey(1, 'graphql limited key', 'pro', 'viewer').key;

let app: Express;

beforeAll(() => {
  config.graphql.enabled = true;
  app = express();
  app.use(express.json());
  app.use('/graphql', graphqlRouter);
});

afterAll(() => {
  Object.assign(config.graphql, original);
});

function post(query: string, key?: string) {
  const req = request(app).post('/graphql').send({ query });
  return key ? req.set('x-api-key', key) : req;
}

describe('GraphQL preview gating (issue #607)', () => {
  it('is disabled by default and answers with a typed error', async () => {
    config.graphql.enabled = false;
    const response = await post('query { health }', proKey);
    config.graphql.enabled = true;

    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('GRAPHQL_DISABLED');
  });

  it('requires an API key', async () => {
    const response = await post('query { health }');
    expect(response.status).toBe(401);
    expect(response.body.error.code).toBe('MISSING_API_KEY');
  });

  it('rejects tiers that are not allowed on the preview surface', async () => {
    const response = await post('query { health }', freeKey);
    expect(response.status).toBe(403);
    expect(response.body.error.code).toBe('GRAPHQL_TIER_FORBIDDEN');
  });

  it('serves an allowed tier through the shared rate limiter', async () => {
    const ok = await post('query { health }', proKey);
    expect(ok.status).toBe(200);
    expect(ok.body.data).toEqual({ health: 'ok' });
  });

  it('rate limits GraphQL the same way REST is rate limited', async () => {
    const first = await post('query { health }', limitedKey);
    expect(first.status).toBe(200);
    const second = await post('query { health }', limitedKey);
    expect(second.status).toBe(429);
    expect(second.body.error.code).toBe('RATE_LIMITED');
  });
});

describe('GraphQL query limits (issue #607)', () => {
  it('rejects queries deeper than the depth budget', () => {
    const query = parse('query { prices { asset price } }');

    expect(validate(schema, query, [depthLimitRule(2)])).toHaveLength(0);
    const errors = validate(schema, query, [depthLimitRule(1)]);
    expect(errors).toHaveLength(1);
    expect(errors[0].extensions?.code).toBe('QUERY_TOO_DEEP');
  });

  it('rejects queries above the complexity budget', async () => {
    config.graphql.maxComplexity = 10;
    const response = await post('query { prices(limit: 25) { asset price source updatedAt } }', proKey);
    config.graphql.maxComplexity = original.maxComplexity;

    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('QUERY_TOO_COMPLEX');
  });

  it('rejects a limit above the REST clamp', async () => {
    const response = await post('query { prices(limit: 999) { asset } }', proKey);
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('LIMIT_EXCEEDS_MAX');
  });

  it('rejects introspection while introspection is disabled', async () => {
    const response = await post('query { __schema { queryType { name } } }', proKey);
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('INTROSPECTION_DISABLED');
  });

  it('reports syntax errors with a typed code', async () => {
    const response = await post('query { health', proKey);
    expect(response.status).toBe(400);
    expect(response.body.error.code).toBe('GRAPHQL_PARSE_ERROR');
  });

  it('enforces a per-query timeout with a typed error', async () => {
    await expect(withTimeout(new Promise(() => {}), 5)).rejects.toBeInstanceOf(QueryTimeoutError);
    await expect(withTimeout(new Promise(() => {}), 5)).rejects.toMatchObject({ code: 'QUERY_TIMEOUT' });
  });
});
