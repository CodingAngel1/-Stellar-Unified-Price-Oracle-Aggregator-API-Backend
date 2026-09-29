import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import WebSocket from 'ws';
import { register } from 'prom-client';
import { PriceWebSocketServer } from '../../src/infrastructure/server';
import { apiKeyManager } from '../../src/governance/api-key-manager';
import { ServerMessageType, ClientMessageType } from '../../src/infrastructure/ws-messages';

const PORT = 19000 + Math.floor(Math.random() * 1000);

interface Frame {
  type: string;
  [key: string]: unknown;
}

let server: PriceWebSocketServer;
let apiKey: string;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(predicate: () => boolean, label: string, timeoutMs = 3000): Promise<void> {
  const start = Date.now();
  while (!predicate()) {
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${label}`);
    await sleep(20);
  }
}

async function connectClient(): Promise<{ ws: WebSocket; frames: Frame[] }> {
  let lastError: Error | undefined;
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      const ws = new WebSocket(`ws://127.0.0.1:${PORT}`, {
        headers: { 'x-api-key': apiKey, origin: 'http://localhost' },
      });
      const frames: Frame[] = [];
      ws.on('message', (data) => {
        try {
          frames.push(JSON.parse(String(data)) as Frame);
        } catch {
          /* ignore non-JSON */
        }
      });
      await new Promise<void>((resolve, reject) => {
        ws.once('open', () => resolve());
        ws.once('error', (err) => reject(err));
      });
      await waitFor(() => frames.some((f) => f.type === ServerMessageType.Connected), 'connected frame');
      return { ws, frames };
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      await sleep(100);
    }
  }
  throw lastError ?? new Error('could not connect');
}

function priceFrames(frames: Frame[]): Frame[] {
  return frames.filter((f) => f.type === ServerMessageType.PriceUpdate);
}

async function subscribe(ws: WebSocket, assets: string[]): Promise<void> {
  ws.send(JSON.stringify({ type: ClientMessageType.Subscribe, assets }));
}

describe('Issue #605: WebSocket subscription enforcement', () => {
  beforeAll(async () => {
    const generated = apiKeyManager.generateKey(1000, 'ws-subscription-enforcement', 'pro', 'viewer');
    apiKey = generated.key;
    server = new PriceWebSocketServer(PORT);
    server.start();
    await sleep(150);
  });

  afterAll(() => {
    server.stop();
  });

  it('delivers no price frames to a client that never subscribed', async () => {
    const { ws, frames } = await connectClient();

    server.broadcastToSubscribers({ asset: 'XLM', price: 0.5 });
    server.broadcastToSubscribers({ asset: 'BTC', price: 30000 });
    await sleep(200);

    expect(priceFrames(frames)).toHaveLength(0);
    const connected = frames.find((f) => f.type === ServerMessageType.Connected);
    expect(connected?.subscriptionRequired).toBe(true);
    ws.close();
    await sleep(50);
  });

  it('replays nothing for a client with no subscriptions', async () => {
    const { ws, frames } = await connectClient();

    server.broadcastToSubscribers({ asset: 'XLM', price: 0.5 });
    await sleep(100);

    ws.send(JSON.stringify({ type: ClientMessageType.Replay, lastSequenceId: 0 }));
    await waitFor(() => frames.some((f) => f.type === ServerMessageType.ReplayComplete), 'replay_complete');

    const complete = frames.find((f) => f.type === ServerMessageType.ReplayComplete)!;
    expect(complete.replayed).toBe(0);
    expect(complete.assets).toEqual([]);
    expect(complete.scope).toBe('subscriptions');
    expect(priceFrames(frames)).toHaveLength(0);

    ws.close();
    await sleep(50);
  });

  it('delivers only the assets the client subscribed to', async () => {
    const { ws, frames } = await connectClient();
    await subscribe(ws, ['XLM']);
    await waitFor(() => frames.some((f) => f.type === ServerMessageType.Subscribed), 'subscribed ack');

    server.broadcastToSubscribers({ asset: 'XLM', price: 0.5 });
    await waitFor(() => priceFrames(frames).length >= 1, 'XLM frame');

    server.broadcastToSubscribers({ asset: 'BTC', price: 30000 });
    server.broadcastToSubscribers({ asset: 'ETH', price: 2000 });
    await sleep(200);

    const delivered = priceFrames(frames);
    expect(delivered.length).toBe(1);
    expect((delivered[0].data as { asset: string }).asset).toBe('XLM');

    ws.close();
    await sleep(50);
  });

  it('produces documented sequence gaps for filtered clients', async () => {
    const { ws, frames } = await connectClient();
    await subscribe(ws, ['XLM']);
    await waitFor(() => frames.some((f) => f.type === ServerMessageType.Subscribed), 'subscribed ack');

    server.broadcastToSubscribers({ asset: 'XLM', price: 1 });
    server.broadcastToSubscribers({ asset: 'BTC', price: 30000 });
    server.broadcastToSubscribers({ asset: 'XLM', price: 2 });
    await waitFor(() => priceFrames(frames).length >= 2, 'two XLM frames');

    const sequences = priceFrames(frames).map((f) => f.sequenceId as number);
    expect(sequences[1]).toBeGreaterThan(sequences[0]);
    expect(sequences[1]).toBe(sequences[0] + 2);

    ws.close();
    await sleep(50);
  });

  it('scopes replay to the subscription set', async () => {
    const { ws, frames } = await connectClient();
    const head = frames.find((f) => f.type === ServerMessageType.Connected)!.sequenceId as number;
    await subscribe(ws, ['XLM']);
    await waitFor(() => frames.some((f) => f.type === ServerMessageType.Subscribed), 'subscribed ack');

    server.broadcastToSubscribers({ asset: 'BTC', price: 30000 });
    server.broadcastToSubscribers({ asset: 'XLM', price: 1 });
    await sleep(100);

    ws.send(JSON.stringify({ type: ClientMessageType.Replay, lastSequenceId: head }));
    await waitFor(
      () => frames.filter((f) => f.type === ServerMessageType.ReplayComplete).length >= 1,
      'first replay_complete',
    );
    const scoped = frames.find((f) => f.type === ServerMessageType.ReplayComplete)!;
    expect(scoped.assets).toEqual(['XLM']);
    expect(scoped.replayed).toBe(1);
    expect(priceFrames(frames).filter((f) => f.replayed === true).every((f) => (f.data as { asset: string }).asset === 'XLM')).toBe(true);

    ws.send(JSON.stringify({ type: ClientMessageType.Replay, lastSequenceId: head, assets: ['BTC'] }));
    await waitFor(
      () => frames.filter((f) => f.type === ServerMessageType.ReplayComplete).length >= 2,
      'second replay_complete',
    );
    const rejected = frames.filter((f) => f.type === ServerMessageType.ReplayComplete)[1];
    expect(rejected.assets).toEqual([]);
    expect(rejected.replayed).toBe(0);

    ws.close();
    await sleep(50);
  });

  it('exposes per-client delivered/dropped and subscription metrics', async () => {
    await sleep(400);
    const metrics = await register.getMetricsAsJSON();

    const messages = metrics.find((m) => m.name === 'ws_api_client_messages_total');
    expect(messages).toBeDefined();
    const delivered = messages!.values
      .filter((v) => v.labels.result === 'delivered')
      .reduce((sum, v) => sum + v.value, 0);
    const dropped = messages!.values
      .filter((v) => v.labels.result === 'dropped')
      .reduce((sum, v) => sum + v.value, 0);
    expect(delivered).toBeGreaterThan(0);
    expect(dropped).toBeGreaterThan(0);

    const subscriptions = metrics.find((m) => m.name === 'ws_api_client_subscriptions');
    expect(subscriptions).toBeDefined();
    expect(subscriptions!.values.every((v) => v.value === 0)).toBe(true);
  });
});
