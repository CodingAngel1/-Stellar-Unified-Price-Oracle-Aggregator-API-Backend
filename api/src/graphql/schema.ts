import {
  GraphQLFloat,
  GraphQLInt,
  GraphQLList,
  GraphQLObjectType,
  GraphQLSchema,
  GraphQLString,
  type GraphQLFieldConfig,
} from 'graphql';
import type { ApiPrice } from '@stellar-oracle/types';
import { readAssetPrices } from '../price-serving/price-store';
import type { HybridCache } from '../price-serving/cache';
import { config } from '../infrastructure/config';

let graphqlCache: HybridCache<unknown> | null = null;

export function initializeGraphqlCache(cache: HybridCache<unknown>): void {
  graphqlCache = cache;
}

export const PriceType = new GraphQLObjectType({
  name: 'Price',
  fields: {
    asset: { type: GraphQLString },
    price: { type: GraphQLFloat },
    source: { type: GraphQLString },
    updatedAt: { type: GraphQLString },
  },
});

function toPrice(price: ApiPrice) {
  const epochMs = price.timestamp > 1e12 ? price.timestamp : price.timestamp * 1000;
  return {
    asset: price.asset,
    price: Number(price.price),
    source: price.source,
    updatedAt: new Date(epochMs).toISOString(),
  };
}

const priceResolver = async (_root: unknown, args: { asset?: string; limit?: number }) => {
  const asset = args.asset?.toUpperCase();
  const limit = Math.max(1, Math.min(args.limit ?? 10, config.graphql.maxLimit));
  const cacheKey = `graphql:prices:${asset ?? '*'}:l${limit}`;

  if (graphqlCache) {
    const cached = await graphqlCache.get(cacheKey);
    if (cached) return cached;
  }

  const rows = await readAssetPrices();
  const prices = rows
    .filter((row) => !asset || row.asset.toUpperCase() === asset)
    .slice(0, limit)
    .map(toPrice);

  if (graphqlCache) await graphqlCache.set(cacheKey, prices, 'prices');
  return prices;
};

export const schema = new GraphQLSchema({
  query: new GraphQLObjectType({
    name: 'Query',
    fields: {
      health: {
        type: GraphQLString,
        resolve: () => 'ok',
      },
      prices: {
        type: new GraphQLList(PriceType),
        args: {
          asset: { type: GraphQLString },
          limit: { type: GraphQLInt },
        },
        resolve: priceResolver,
      } as GraphQLFieldConfig<unknown, unknown, { asset?: string; limit?: number }>,
    },
  }),
});
