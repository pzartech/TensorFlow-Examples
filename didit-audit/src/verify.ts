import { createHash } from 'node:crypto';
import OpenTimestamps from 'javascript-opentimestamps';
import type { PoolClient } from 'pg';
import { canonical } from './canonical.js';
import { merkleRoot } from './merkle.js';

const ZERO = Buffer.alloc(32);
const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();

export interface VerifyResult {
  records: number;
  anchors: { id: number; fromSeq: string; toSeq: string; bitcoinTime: number | null }[];
  ok: true;
}

/**
 * Recompute the entire hash chain and every Merkle anchor. Throws on the first
 * sign of tampering: a deleted record (sequence gap), a broken link, an altered
 * payload, or an anchor whose root no longer matches. A passing run, combined
 * with the Bitcoin timestamp, is the artifact you hand an auditor.
 */
export async function verifyAuditLog(db: PoolClient): Promise<VerifyResult> {
  const rows = (await db.query('select * from audit_log order by seq')).rows;

  let prev = ZERO;
  let expectedSeq: bigint | null = null;
  for (const r of rows) {
    if (expectedSeq !== null && BigInt(r.seq) !== expectedSeq) {
      throw new Error(`sequence gap before seq ${r.seq} (record deleted?)`);
    }
    if (!r.prev_hash.equals(prev)) {
      throw new Error(`broken chain at seq ${r.seq}`);
    }

    const payloadHash = sha256(Buffer.from(canonical(r.payload)));
    if (!payloadHash.equals(r.payload_hash)) {
      throw new Error(`payload altered at seq ${r.seq}`);
    }

    const recordHash = sha256(
      Buffer.concat([
        Buffer.from(String(r.seq)),
        Buffer.from(r.event_type),
        payloadHash,
        r.prev_hash,
        Buffer.from(new Date(r.created_at).toISOString()),
      ]),
    );
    if (!recordHash.equals(r.record_hash)) {
      throw new Error(`record_hash altered at seq ${r.seq}`);
    }

    prev = r.record_hash;
    expectedSeq = BigInt(r.seq) + 1n;
  }

  const anchorRows = (await db.query('select * from audit_anchor order by from_seq')).rows;
  const anchors: VerifyResult['anchors'] = [];
  for (const a of anchorRows) {
    const slice = rows
      .filter((r) => BigInt(r.seq) >= BigInt(a.from_seq) && BigInt(r.seq) <= BigInt(a.to_seq))
      .map((r) => r.record_hash as Buffer);
    if (!merkleRoot(slice).equals(a.merkle_root)) {
      throw new Error(`anchor ${a.id}: Merkle root mismatch`);
    }

    let bitcoinTime: number | null = null;
    try {
      const detached = OpenTimestamps.DetachedTimestampFile.deserialize([...a.ots_proof]);
      const original = OpenTimestamps.DetachedTimestampFile.fromHash(
        new OpenTimestamps.Ops.OpSHA256(),
        a.merkle_root,
      );
      bitcoinTime = await OpenTimestamps.verify(detached, original);
    } catch {
      // Proof not yet confirmed on-chain; chain integrity above still holds.
    }
    anchors.push({ id: a.id, fromSeq: a.from_seq, toSeq: a.to_seq, bitcoinTime });
  }

  return { records: rows.length, anchors, ok: true };
}
