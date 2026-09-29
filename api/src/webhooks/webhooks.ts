import { Router, Request, Response } from 'express';
import { z } from 'zod';
import {
  webhookService,
  WEBHOOK_SIGNATURE_ALGORITHM,
  WEBHOOK_SIGNATURE_FORMAT,
  WEBHOOK_SIGNATURE_HEADER,
  type WebhookRegistration,
} from './webhook-service';
import { links, withLinks } from '../price-serving/hypermedia';

const router = Router();

const RegisterSchema = z.object({
  url: z.string().url(),
  trigger: z.object({
    type: z.enum(['threshold', 'interval']),
    asset: z.string().min(1),
    value: z.number().positive(),
  }),
});

function keyPrefixOf(req: Request): string {
  return req.apiKey ? req.apiKey.substring(0, 8) : 'anonymous';
}

function publicView(webhook: WebhookRegistration): Omit<WebhookRegistration, 'secret'> {
  const view = { ...webhook };
  delete (view as Partial<WebhookRegistration>).secret;
  return view;
}

router.post('/', (req: Request, res: Response) => {
  const parsed = RegisterSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      success: false,
      error: { code: 'VALIDATION_ERROR', message: parsed.error.message },
    });
  }

  const webhook = webhookService.register(
    parsed.data.url,
    keyPrefixOf(req),
    { ...parsed.data.trigger, asset: parsed.data.trigger.asset.toUpperCase() },
  );

  res.status(201).json({
    success: true,
    data: {
      ...withLinks(publicView(webhook), links.webhook(webhook.id)),
      secret: webhook.secret,
      secretReturnedOnce: true,
      status: webhook.status,
      failureCount: webhook.failureCount,
      signature: {
        algorithm: WEBHOOK_SIGNATURE_ALGORITHM,
        header: WEBHOOK_SIGNATURE_HEADER,
        format: WEBHOOK_SIGNATURE_FORMAT,
      },
      message: 'Store the secret now: it is returned only in this response and is never readable again.',
    },
  });
});

router.get('/', (req: Request, res: Response) => {
  const data = webhookService.list(keyPrefixOf(req)).map((w: WebhookRegistration) => withLinks(publicView(w), links.webhook(w.id)));
  res.json({ success: true, data, _links: links.root() });
});

router.get('/verification-key', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      algorithm: WEBHOOK_SIGNATURE_ALGORITHM,
      signatureHeader: WEBHOOK_SIGNATURE_HEADER,
      signatureFormat: WEBHOOK_SIGNATURE_FORMAT,
      signedPayload:
        'The exact raw request body bytes (UTF-8) as delivered: JSON.stringify({ webhookId, ...payload }) with no spaces. Hash the bytes you received, never a re-serialised object.',
      signingKey:
        'Per-registration secret returned once by POST /api/v1/webhooks as "secret". This endpoint never returns key material.',
      verificationRecipe:
        'signature = "sha256=" + hex(HMAC-SHA256(secret, rawBody)); compare with a timing-safe equality against the X-Webhook-Signature header.',
      testVector: {
        secret: 'test-secret-0000000000000000000000000000',
        body: '{"webhookId":"00000000-0000-4000-8000-000000000001","asset":"XLM","price":0.42,"timestamp":1700000000}',
        signature: 'd285bbf58d70eff02a911f8bc9d9ce12592898054e5b52f868f7b1b53844c081',
        headerValue: 'sha256=d285bbf58d70eff02a911f8bc9d9ce12592898054e5b52f868f7b1b53844c081',
      },
      docs: 'docs/webhooks.md',
    },
  });
});

router.get('/:id', (req: Request, res: Response) => {
  const webhook = webhookService.get(req.params.id);
  if (!webhook || webhook.apiKeyPrefix !== keyPrefixOf(req)) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Webhook not found' } });
  }
  res.json({ success: true, data: withLinks(publicView(webhook), links.webhook(webhook.id)) });
});

router.delete('/:id', (req: Request, res: Response) => {
  const webhook = webhookService.get(req.params.id);
  if (!webhook || webhook.apiKeyPrefix !== keyPrefixOf(req)) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Webhook not found' } });
  }
  webhookService.remove(req.params.id);
  res.status(204).send();
});

router.get('/:id/deliveries', (req: Request, res: Response) => {
  const webhook = webhookService.get(req.params.id);
  if (!webhook || webhook.apiKeyPrefix !== keyPrefixOf(req)) {
    return res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Webhook not found' } });
  }
  res.json({ success: true, data: webhookService.deliveries(req.params.id) });
});

export default router;
