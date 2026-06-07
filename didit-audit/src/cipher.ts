/**
 * Replica confidentiality + GDPR crypto-shredding.
 *
 * When REPLICA_MASTER_KEY is set, every record is envelope-encrypted before it
 * leaves for a sink: a per-subject data key (DEK) encrypts the record, and the
 * DEK is wrapped by the master key and stored in `audit_subject_key`. To erase a
 * person you delete their DEK (crypto-shred) — all replica copies become
 * unrecoverable — and null their DB payload. Crucially, `payload_hash` and
 * `record_hash` remain, so the hash chain and every anchor still verify: erasure
 * does not break tamper-evidence.
 *
 * The envelope keeps `record_hash` in cleartext (a hash, not PII) so replica
 * integrity is still checkable after shredding. With no master key, records are
 * stored as plaintext JSON (backward compatible).
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { PoolClient } from 'pg';
import { serializeRecord } from './sinks.js';

const ALG = 'aes-256-gcm';

export function encryptionEnabled(): boolean {
  return !!process.env.REPLICA_MASTER_KEY;
}

function masterKey(): Buffer {
  const b64 = process.env.REPLICA_MASTER_KEY;
  if (!b64) throw new Error('REPLICA_MASTER_KEY not set');
  const k = Buffer.from(b64, 'base64');
  if (k.length !== 32) throw new Error('REPLICA_MASTER_KEY must be base64 of 32 bytes');
  return k;
}

function gcmEncrypt(key: Buffer, plaintext: Buffer) {
  const iv = randomBytes(12);
  const c = createCipheriv(ALG, key, iv);
  const ct = Buffer.concat([c.update(plaintext), c.final()]);
  return { iv, ct, tag: c.getAuthTag() };
}

function gcmDecrypt(key: Buffer, iv: Buffer, ct: Buffer, tag: Buffer): Buffer {
  const d = createDecipheriv(ALG, key, iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

const SUBJECTLESS = '__nosubject__';

async function getDek(db: PoolClient, subject: string): Promise<Buffer | null> {
  const r = await db.query('select dek_wrapped, iv, tag from audit_subject_key where subject_ref=$1', [subject]);
  if (!r.rows[0]) return null;
  return gcmDecrypt(masterKey(), r.rows[0].iv, r.rows[0].dek_wrapped, r.rows[0].tag);
}

async function getOrCreateDek(db: PoolClient, subject: string): Promise<Buffer> {
  const existing = await getDek(db, subject);
  if (existing) return existing;
  const dek = randomBytes(32);
  const w = gcmEncrypt(masterKey(), dek);
  await db.query(
    `insert into audit_subject_key (subject_ref, dek_wrapped, iv, tag) values ($1,$2,$3,$4)
     on conflict (subject_ref) do nothing`,
    [subject, w.ct, w.iv, w.tag],
  );
  const after = await getDek(db, subject); // re-read (covers a concurrent insert)
  if (!after) throw new Error('failed to persist subject key');
  return after;
}

type Row = Parameters<typeof serializeRecord>[0];

interface Envelope {
  v: 1;
  enc: true;
  seq: string;
  subject_ref: string | null;
  record_hash: string;
  iv: string;
  ct: string;
  tag: string;
}

/** Produce the bytes a sink should store (encrypted envelope, or plaintext). */
export async function sealRecord(db: PoolClient, row: Row): Promise<Buffer> {
  const plaintext = serializeRecord(row);
  if (!encryptionEnabled()) return plaintext;
  const subject = row.subject_ref ?? SUBJECTLESS;
  const dek = await getOrCreateDek(db, subject);
  const { iv, ct, tag } = gcmEncrypt(dek, plaintext);
  const env: Envelope = {
    v: 1,
    enc: true,
    seq: String(row.seq),
    subject_ref: row.subject_ref ?? null,
    record_hash: (row.record_hash as Buffer).toString('hex'),
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: tag.toString('base64'),
  };
  return Buffer.from(JSON.stringify(env));
}

/** Inverse of sealRecord. `shredded` = the subject key was erased (GDPR). */
export async function openRecord(
  db: PoolClient,
  data: Buffer,
): Promise<{ recordHash: string; record?: unknown; shredded: boolean }> {
  const parsed = JSON.parse(data.toString('utf8'));
  if (!parsed?.enc) return { recordHash: parsed.record_hash, record: parsed, shredded: false };
  const dek = await getDek(db, parsed.subject_ref ?? SUBJECTLESS);
  if (!dek) return { recordHash: parsed.record_hash, shredded: true };
  const pt = gcmDecrypt(
    dek,
    Buffer.from(parsed.iv, 'base64'),
    Buffer.from(parsed.ct, 'base64'),
    Buffer.from(parsed.tag, 'base64'),
  );
  return { recordHash: parsed.record_hash, record: JSON.parse(pt.toString('utf8')), shredded: false };
}

/**
 * GDPR erasure for one subject: delete the DEK (replicas become unrecoverable)
 * and null the DB payload. payload_hash/record_hash stay, so verification still
 * passes. Run as the table owner (the app role is append-only).
 */
export async function shredSubject(db: PoolClient, subject: string): Promise<{ keys: number; payloads: number }> {
  const k = await db.query('delete from audit_subject_key where subject_ref=$1', [subject]);
  const p = await db.query('update audit_log set payload = null where subject_ref=$1 and payload is not null', [subject]);
  return { keys: k.rowCount ?? 0, payloads: p.rowCount ?? 0 };
}
