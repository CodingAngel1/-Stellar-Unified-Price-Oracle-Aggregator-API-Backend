import { Router, type Request, type Response } from 'express';
import { execute, parse, specifiedRules, validate, type DocumentNode } from 'graphql';
import { schema, initializeGraphqlCache } from './schema';
import { config } from '../infrastructure/config';
import { authMiddleware } from '../governance/auth';
import { usageTrackingMiddleware } from '../governance/usage-tracking';
import { apiKeyManager } from '../governance/api-key-manager';
import { graphqlRequestsTotal } from '../observability/metrics';
import {
  QueryTimeoutError,
  complexityLimitRule,
  depthLimitRule,
  introspectionRule,
  limitArgumentRule,
  withTimeout,
} from './validation';

const router = Router();

function errorResponse(res: Response, status: number, code: string, message: string): void {
  res.status(status).json({ success: false, error: { code, message } });
}

router.use((_req: Request, res: Response, next) => {
  if (!config.graphql.enabled) {
    graphqlRequestsTotal.inc({ result: 'disabled' });
    errorResponse(
      res,
      403,
      'GRAPHQL_DISABLED',
      'GraphQL is a preview surface and is disabled by default. Set GRAPHQL_ENABLED=true to enable it (see docs/api-versioning-policy.md).',
    );
    return;
  }
  next();
});

router.use((_req: Request, res: Response, next) => {
  res.set('X-API-Version', 'preview');
  next();
});

router.use(authMiddleware);
router.use(usageTrackingMiddleware);

router.use((req: Request, res: Response, next) => {
  const validation = req.apiKey ? apiKeyManager.validateKey(req.apiKey) : { valid: false };
  const tier = validation.metadata?.tier;
  if (!tier || !config.graphql.allowedTiers.includes(tier)) {
    graphqlRequestsTotal.inc({ result: 'tier_forbidden' });
    errorResponse(
      res,
      403,
      'GRAPHQL_TIER_FORBIDDEN',
      `GraphQL is limited to the following tiers: ${config.graphql.allowedTiers.join(', ')}.`,
    );
    return;
  }
  next();
});

router.get('/', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      endpoint: '/graphql',
      status: 'preview',
      schema: 'Price, Query',
      example: `query { prices(asset: "XLM", limit: 5) { asset price source updatedAt } }`,
      limits: {
        maxDepth: config.graphql.maxDepth,
        maxComplexity: config.graphql.maxComplexity,
        maxLimit: config.graphql.maxLimit,
        timeoutMs: config.graphql.timeoutMs,
        introspection: config.graphql.introspection,
      },
    },
  });
});

router.post('/', async (req: Request, res: Response) => {
  try {
    const payload = typeof req.body === 'string' ? safeParse(req.body) : (req.body ?? {});
    const query = payload.query || '';
    const variables = payload.variables ?? {};
    const operationName = payload.operationName ?? undefined;

    if (!query || typeof query !== 'string') {
      return errorResponse(res, 400, 'INVALID_QUERY', 'GraphQL query is required.');
    }

    if (query.length > config.graphql.maxQueryLength) {
      graphqlRequestsTotal.inc({ result: 'rejected' });
      return errorResponse(res, 413, 'QUERY_TOO_LARGE', 'GraphQL query exceeds the size limit.');
    }

    let document: DocumentNode;
    try {
      document = parse(query);
    } catch (error) {
      graphqlRequestsTotal.inc({ result: 'rejected' });
      return errorResponse(res, 400, 'GRAPHQL_PARSE_ERROR', (error as Error).message);
    }

    const validationErrors = validate(schema, document, [
      ...specifiedRules,
      depthLimitRule(config.graphql.maxDepth),
      complexityLimitRule(config.graphql.maxComplexity, config.graphql.maxLimit),
      limitArgumentRule(config.graphql.maxLimit),
      introspectionRule(config.graphql.introspection),
    ]);

    if (validationErrors.length > 0) {
      graphqlRequestsTotal.inc({ result: 'rejected' });
      const code = String(validationErrors[0].extensions?.code ?? 'QUERY_VALIDATION_FAILED');
      return res.status(400).json({
        success: false,
        error: { code, message: validationErrors[0].message },
        errors: validationErrors.map((error) => ({
          message: error.message,
          code: error.extensions?.code,
        })),
      });
    }

    const result = await withTimeout(
      Promise.resolve(
        execute({
          schema,
          document,
          variableValues: variables,
          operationName,
        }),
      ),
      config.graphql.timeoutMs,
    );

    if (result.errors?.length) {
      graphqlRequestsTotal.inc({ result: 'error' });
      return res.status(400).json({
        success: false,
        data: result.data ?? null,
        errors: result.errors.map((error) => ({ message: error.message })),
      });
    }

    graphqlRequestsTotal.inc({ result: 'success' });
    return res.json({ success: true, data: result.data });
  } catch (error) {
    if (error instanceof QueryTimeoutError) {
      graphqlRequestsTotal.inc({ result: 'timeout' });
      return errorResponse(res, 504, error.code, error.message);
    }
    graphqlRequestsTotal.inc({ result: 'error' });
    return errorResponse(res, 500, 'GRAPHQL_EXECUTION_ERROR', (error as Error).message);
  }
});

function safeParse(body: string): Record<string, unknown> {
  try {
    return JSON.parse(body || '{}');
  } catch {
    return {};
  }
}

export { initializeGraphqlCache };
export default router;
