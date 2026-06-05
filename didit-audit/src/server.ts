import express from 'express';
import { pool } from './db.js';
import { capabilities } from './config.js';
import { createVerificationSession } from './didit-client.js';
import { handleDiditWebhook } from './didit-webhook.js';

/**
 * HTTP surface. Everything is wired; the KYC routes return 503 with a clear
 * message until Didit credentials are set, so the service is fully runnable now.
 */
export function createApp() {
  const app = express();

  app.get('/healthz', (_req, res) => res.json({ ok: true, capabilities: capabilities() }));

  // Start a verification (KYC). Inert until DIDIT_API_KEY is configured.
  app.post('/verifications', express.json(), async (req, res) => {
    const userId = req.body?.userId;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    try {
      const session = await createVerificationSession({
        vendorData: String(userId),
        callbackUrl: req.body?.callbackUrl,
      });
      res.json(session);
    } catch (e) {
      res.status(503).json({ error: (e as Error).message });
    }
  });

  // Didit webhook: verify signature -> corroborate -> append (chained/anchored/replicated).
  // express.raw keeps the exact signed bytes needed for HMAC verification.
  app.post('/webhooks/didit', express.raw({ type: '*/*' }), async (req, res) => {
    const secret = process.env.DIDIT_WEBHOOK_SECRET;
    if (!secret) return res.status(503).send('KYC not configured');
    const client = await pool.connect();
    try {
      await handleDiditWebhook(client, req.body as Buffer, req.header('x-signature') ?? '', secret);
      res.sendStatus(200);
    } catch (e) {
      res.status(400).send((e as Error).message);
    } finally {
      client.release();
    }
  });

  return app;
}
