import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import express from 'express';
import request from 'supertest';
import { createServer, type Server } from 'http';
import type { AddressInfo } from 'net';
import webhooksRouter from '../src/webhooks/webhooks';
import {
  webhookService,
  signWebhookPayload,
  verifyWebhookSignature,
  buildWebhookBody,
  WEBHOOK_SIGNATURE_HEADER,
} from '../src/webhooks/webhook-service';

const CONFORMANCE_SECRET = 'test-secret-0000000000000000000000000000';
const CONFORMANCE_BODY =
  '{"webhookId":"00000000-0000-4000-8000-000000000001","asset":"XLM","price":0.42,"timestamp":1700000000}';
const CONFORMANCE_SIG =
  'd285bbf58d70eff02a911f8bc9d9ce12592898054e5b52f868f7b1b53844c081';

function app(): express.Express {
  const instance = express();
  instance.use(express.json());
  instance.use('/api/v1/webhooks', webhooksRouter);
  return instance;
}

describe('Issue #604: webhook verification material', () => {
  beforeEach(() => {
    webhookService.reset();
  });

  it('publishes a fixed conformance vector that the signer reproduces', async () => {
    const built = buildWebhookBody('00000000-0000-4000-8000-000000000001', {
      asset: 'XLM',
      price: 0.42,
      timestamp: 1700000000,
    });
    expect(built).toBe(CONFORMANCE_BODY);
    expect(signWebhookPayload(CONFORMANCE_SECRET, built)).toBe(CONFORMANCE_SIG);

    const res = await request(app()).get('/api/v1/webhooks/verification-key');
    expect(res.status).toBe(200);
    expect(res.body.data.testVector.body).toBe(CONFORMANCE_BODY);
    expect(res.body.data.testVector.signature).toBe(CONFORMANCE_SIG);
    expect(res.body.data.testVector.headerValue).toBe(`sha256=${CONFORMANCE_SIG}`);
    expect(signWebhookPayload(CONFORMANCE_SECRET, res.body.data.testVector.body)).toBe(
      res.body.data.testVector.signature,
    );
  });

  it('advertises the signing scheme without disclosing any key material', async () => {
    const res = await request(app()).get('/api/v1/webhooks/verification-key');
    const data = res.body.data;

    expect(data.algorithm).toBe('HMAC-SHA256');
    expect(data.signatureHeader).toBe(WEBHOOK_SIGNATURE_HEADER);
    expect(data.signatureFormat).toBe('sha256=<lowercase hex>');
    expect(String(data.signedPayload)).toContain('JSON.stringify({ webhookId, ...payload })');
    expect(JSON.stringify(data)).not.toMatch(/"secret"\s*:\s*"[0-9a-f]{32,}"/);
    expect(data).not.toHaveProperty('verificationKey');
    expect(data).not.toHaveProperty('key');
    expect(data).not.toHaveProperty('verificationKeyHash');
  });

  it('verifies a real delivery with only the advertised material and the registration secret', async () => {
    const received: { body: string; headers: Record<string, string | undefined> } = {
      body: '',
      headers: {},
    };
    const receiver: Server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        received.body = Buffer.concat(chunks).toString('utf8');
        received.headers = req.headers as Record<string, string | undefined>;
        res.statusCode = 200;
        res.end('ok');
      });
    });
    await new Promise<void>((resolve) => receiver.listen(0, resolve));
    const port = (receiver.address() as AddressInfo).port;

    try {
      const register = await request(app())
        .post('/api/v1/webhooks')
        .send({ url: `http://127.0.0.1:${port}/hook`, trigger: { type: 'interval', asset: 'XLM', value: 1 } });
      expect(register.status).toBe(201);
      const secret = register.body.data.secret as string;
      expect(secret).toMatch(/^[0-9a-f]{64}$/);
      expect(register.body.data.secretReturnedOnce).toBe(true);
      expect(register.body.data.signature.algorithm).toBe('HMAC-SHA256');

      const webhook = webhookService.list()[0];
      await webhookService.deliver(webhook, { asset: 'XLM', price: 1.23, timestamp: 1700000000 });

      const scheme = (await request(app()).get('/api/v1/webhooks/verification-key')).body.data;
      const headerValue = received.headers['x-webhook-signature'];
      expect(headerValue).toBeDefined();
      expect(headerValue!.startsWith('sha256=')).toBe(true);
      expect(received.headers['x-webhook-id']).toBe(webhook.id);

      const expected =
        scheme.signatureFormat === 'sha256=<lowercase hex>'
          ? `sha256=${signWebhookPayload(secret, received.body)}`
          : 'mismatch';
      expect(headerValue).toBe(expected);
      expect(verifyWebhookSignature(secret, received.body, headerValue!)).toBe(true);
      expect(verifyWebhookSignature(secret, received.body, `sha256=${CONFORMANCE_SIG}`)).toBe(false);

      const fetched = await request(app()).get('/api/v1/webhooks');
      expect(JSON.stringify(fetched.body)).not.toContain(secret);
      const single = await request(app()).get(`/api/v1/webhooks/${webhook.id}`);
      expect(JSON.stringify(single.body)).not.toContain(secret);
      expect(single.body.data).not.toHaveProperty('secret');
    } finally {
      await new Promise<void>((resolve) => receiver.close(() => resolve()));
    }
  });

  it('never returns the secret again after registration', async () => {
    const created = await request(app())
      .post('/api/v1/webhooks')
      .send({ url: 'https://example.com/hook', trigger: { type: 'threshold', asset: 'XLM', value: 5 } });
    const secret = created.body.data.secret as string;
    const id = created.body.data.id as string;

    const list = await request(app()).get('/api/v1/webhooks');
    expect(list.body.data.some((w: Record<string, unknown>) => 'secret' in w)).toBe(false);
    const single = await request(app()).get(`/api/v1/webhooks/${id}`);
    expect(single.body.data).not.toHaveProperty('secret');
    expect(single.body.data).not.toHaveProperty('verificationKey');
    expect(JSON.stringify(single.body)).not.toContain(secret);
  });

  afterEach(() => {
    webhookService.reset();
  });
});
