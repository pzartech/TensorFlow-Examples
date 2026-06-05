import { createHmac, timingSafeEqual } from 'node:crypto';
import type { PoolClient } from 'pg';
import { appendAuditEvent } from './audit-log.js';
import { corroborate } from './corroborate.js';

/**
 * Verify Didit's HMAC-SHA256 webhook signature in constant time.
 * `rawBody` must be the exact bytes received — do not parse and re-stringify
 * before verifying, or the signature will not match.
 */
export function verifyDiditSignature(
  rawBody: Buffer,
  signatureHeader: string,
  secret: string,
): boolean {
  const expected = createHmac('sha256', secret).update(rawBody).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(signatureHeader || '');
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Handle a Didit webhook end-to-end: verify the signature, then append the
 * verification result to the tamper-evident log. We persist Didit's raw signed
 * payload verbatim, so the record carries an independent third party's
 * cryptographic attestation — not just our own say-so.
 */
export async function handleDiditWebhook(
  db: PoolClient,
  rawBody: Buffer,
  signatureHeader: string,
  secret: string,
) {
  if (!verifyDiditSignature(rawBody, signatureHeader, secret)) {
    throw new Error('invalid Didit webhook signature');
  }

  const event = JSON.parse(rawBody.toString('utf8'));

  // Cross-corroborate WHO/WHERE/WHEN from several independent methods. Done
  // before the DB write so the result is part of the hash-chained payload.
  const corroboration = event && typeof event === 'object' ? await corroborate(event) : null;

  await db.query('begin');
  try {
    // The payload is attacker-influenced and may be malformed; read fields
    // defensively so a bad body can't crash the handler before it's logged.
    const res = await appendAuditEvent(db, {
      eventType: `didit.${event?.status ?? 'event'}`,
      subjectRef: event?.vendor_data, // pseudonymous ICI user id you passed at session creation
      diditSessionId: event?.session_id,
      payload: {
        raw: rawBody.toString('base64'), // the exact bytes Didit signed
        signature: signatureHeader,
        decision: event,
        corroboration, // consensus over id/place/time from several tools
      },
    });
    await db.query('commit');
    return res;
  } catch (e) {
    await db.query('rollback');
    throw e;
  }
}
