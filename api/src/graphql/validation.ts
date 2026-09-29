import {
  GraphQLError,
  Kind,
  type FieldNode,
  type OperationDefinitionNode,
  type FragmentDefinitionNode,
  type SelectionSetNode,
  type ValidationContext,
  type ASTVisitor,
} from 'graphql';

function fieldCost(field: FieldNode, maxLimit: number): number {
  const limitArg = field.arguments?.find((arg) => arg.name.value === 'limit');
  if (!limitArg || limitArg.value.kind !== Kind.INT) return 1;
  const requested = Number.parseInt(limitArg.value.value, 10);
  if (!Number.isFinite(requested)) return 1;
  return 1 + Math.max(0, Math.min(requested, maxLimit));
}

function selectionSetCost(
  selectionSet: SelectionSetNode,
  context: ValidationContext,
  maxLimit: number,
  seenFragments: Set<string>,
): number {
  let cost = 0;
  for (const selection of selectionSet.selections) {
    if (selection.kind === Kind.FIELD) {
      cost += fieldCost(selection, maxLimit);
      if (selection.selectionSet) {
        cost += selectionSetCost(selection.selectionSet, context, maxLimit, seenFragments);
      }
    } else if (selection.kind === Kind.INLINE_FRAGMENT) {
      cost += selectionSetCost(selection.selectionSet, context, maxLimit, seenFragments);
    } else if (selection.kind === Kind.FRAGMENT_SPREAD) {
      const name = selection.name.value;
      if (seenFragments.has(name)) continue;
      seenFragments.add(name);
      const fragment = context.getFragment(name);
      if (fragment) cost += selectionSetCost(fragment.selectionSet, context, maxLimit, seenFragments);
    }
  }
  return cost;
}

function selectionSetDepth(
  selectionSet: SelectionSetNode,
  context: ValidationContext,
  level: number,
  seenFragments: Set<string>,
): number {
  let deepest = level;
  for (const selection of selectionSet.selections) {
    if (selection.kind === Kind.FIELD) {
      if (selection.selectionSet) {
        deepest = Math.max(deepest, selectionSetDepth(selection.selectionSet, context, level + 1, seenFragments));
      } else {
        deepest = Math.max(deepest, level + 1);
      }
    } else if (selection.kind === Kind.INLINE_FRAGMENT) {
      deepest = Math.max(deepest, selectionSetDepth(selection.selectionSet, context, level, seenFragments));
    } else if (selection.kind === Kind.FRAGMENT_SPREAD) {
      const name = selection.name.value;
      if (seenFragments.has(name)) continue;
      seenFragments.add(name);
      const fragment = context.getFragment(name);
      if (fragment) {
        deepest = Math.max(deepest, selectionSetDepth(fragment.selectionSet, context, level, seenFragments));
      }
    }
  }
  return deepest;
}

/** Rejects queries whose selection nesting exceeds `maxDepth`. */
export function depthLimitRule(maxDepth: number) {
  return (context: ValidationContext): ASTVisitor => ({
    OperationDefinition(node: OperationDefinitionNode) {
      const depth = selectionSetDepth(node.selectionSet, context, 0, new Set());
      if (depth > maxDepth) {
        context.reportError(
          new GraphQLError(`Query depth ${depth} exceeds the maximum of ${maxDepth}`, {
            extensions: { code: 'QUERY_TOO_DEEP', maxDepth, depth },
          }),
        );
      }
    },
    FragmentDefinition(node: FragmentDefinitionNode) {
      const depth = selectionSetDepth(node.selectionSet, context, 0, new Set());
      if (depth > maxDepth) {
        context.reportError(
          new GraphQLError(`Fragment depth ${depth} exceeds the maximum of ${maxDepth}`, {
            extensions: { code: 'QUERY_TOO_DEEP', maxDepth, depth },
          }),
        );
      }
    },
  });
}

/**
 * Rejects queries whose accumulated cost exceeds `maxComplexity`. A field
 * costs 1, plus its `limit` argument capped at the same clamp REST uses, so a
 * wide or deeply nested query cannot buy unbounded work per request.
 */
export function complexityLimitRule(maxComplexity: number, maxLimit: number) {
  return (context: ValidationContext): ASTVisitor => ({
    OperationDefinition(node: OperationDefinitionNode) {
      const cost = selectionSetCost(node.selectionSet, context, maxLimit, new Set());
      if (cost > maxComplexity) {
        context.reportError(
          new GraphQLError(`Query cost ${cost} exceeds the budget of ${maxComplexity}`, {
            extensions: { code: 'QUERY_TOO_COMPLEX', maxComplexity, complexity: cost },
          }),
        );
      }
    },
  });
}

/** Rejects `limit` arguments above the REST clamp instead of silently inflating them. */
export function limitArgumentRule(maxLimit: number) {
  return (context: ValidationContext): ASTVisitor => ({
    Field(node: FieldNode) {
      const limitArg = node.arguments?.find((arg) => arg.name.value === 'limit');
      if (!limitArg || limitArg.value.kind !== Kind.INT) return;
      const requested = Number.parseInt(limitArg.value.value, 10);
      if (Number.isFinite(requested) && requested > maxLimit) {
        context.reportError(
          new GraphQLError(`limit ${requested} exceeds the maximum page size of ${maxLimit}`, {
            extensions: { code: 'LIMIT_EXCEEDS_MAX', maxLimit, requested },
          }),
        );
      }
    },
  });
}

/** Rejects introspection fields unless introspection is explicitly enabled. */
export function introspectionRule(introspectionEnabled: boolean) {
  if (introspectionEnabled) return (): ASTVisitor => ({});
  return (context: ValidationContext): ASTVisitor => ({
    Field(node: FieldNode) {
      if (!node.name.value.startsWith('__')) return;
      context.reportError(
        new GraphQLError('Introspection is disabled for this endpoint', {
          nodes: node,
          extensions: { code: 'INTROSPECTION_DISABLED' },
        }),
      );
    },
  });
}

export class QueryTimeoutError extends Error {
  readonly code = 'QUERY_TIMEOUT';

  constructor(timeoutMs: number) {
    super(`GraphQL query exceeded the ${timeoutMs}ms budget`);
    this.name = 'QueryTimeoutError';
  }
}

export function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new QueryTimeoutError(timeoutMs)), timeoutMs);
  });
  return Promise.race([operation, timeout]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}
