import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { canonical } from './canonical.js';

const ZERO = Buffer.alloc(32);
const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();

export interface AuditEvent {
  eventType: string;
  subjectRef?: string;
  diditSessionId?: string;
  payload: Record<string, unknown>;
}

/**
 * Append one event to the hash-chained log.
 *
 * MUST run inside a transaction. We lock the tail row (`for update`) so concurrent
 * writers serialize and cannot fork the chain. The sequence value is reserved
 * before insert, so `record_hash` is computed once and the row is immutable from
 * the moment it exists.
 */
export async function appendAuditEvent(db: PoolClient, ev: AuditEvent) {
  const tail = await db.query(
    'select record_hash from audit_log order by seq desc limit 1 for update',
  );
  const prevHash: Buffer = tail.rows[0]?.record_hash ?? ZERO;

  const seqRow = await db.query("select nextval('audit_log_seq_seq') as seq");
  const seq: string = seqRow.rows[0].seq;

  const createdAt = new Date().toISOString();
  const payloadHash = sha256(Buffer.from(canonical(ev.payload)));
  const recordHash = sha256(
    Buffer.concat([
      Buffer.from(String(seq)),
      Buffer.from(ev.eventType),
      payloadHash,
      prevHash,
      Buffer.from(createdAt),
    ]),
  );

  await db.query(
    `insert into audit_log
       (seq, event_type, subject_ref, didit_session_id,
        payload_hash, payload, prev_hash, record_hash, created_at)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [
      seq,
      ev.eventType,
      ev.subjectRef ?? null,
      ev.diditSessionId ?? null,
      payloadHash,
      ev.payload,
      prevHash,
      recordHash,
      createdAt,
    ],
  );

  return { seq, recordHash, payloadHash };
}
