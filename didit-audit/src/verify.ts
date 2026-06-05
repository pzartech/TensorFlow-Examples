import { createHash } from 'node:crypto';
import type { PoolClient } from 'pg';
import { canonical } from './canonical.js';
import { merkleRoot } from './merkle.js';
import { getProviders } from './providers.js';

const ZERO = Buffer.alloc(32);
const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();

export interface ProofResult {
  method: string;
  provider: string;
  ok: boolean;
  assertedTime: string | null;
  note?: string;
}

export interface AnchorResult {
  id: number;
  fromSeq: string;
  toSeq: string;
  proofs: ProofResult[];
}

export interface VerifyResult {
  records: number;
  anchors: AnchorResult[];
  ok: true;
}

/**
 * Recompute the entire hash chain and verify every anchor's every proof. Throws
 * on the first sign of tampering: a deleted record (sequence gap), a broken
 * link, an altered payload, an anchor whose root no longer matches, or any proof
 * that fails verification. A passing run, plus the proofs' asserted times, is the
 * artifact you hand an auditor.
 */
export async function verifyAuditLog(db: PoolClient): Promise<VerifyResult> {
  const rows = (await db.query('select * from audit_log order by seq')).rows;

  // 1. Chain integrity.
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

  // 2. Anchors + their proofs. Single pass over the ordered rows.
  const anchorRows = (await db.query('select * from audit_anchor order by from_seq')).rows;
  const byKey = new Map(getProviders().map((p) => [`${p.method}:${p.provider}`, p]));
  const anchors: AnchorResult[] = [];
  let rowIndex = 0;

  for (const a of anchorRows) {
    const fromSeq = BigInt(a.from_seq);
    const toSeq = BigInt(a.to_seq);
    while (rowIndex < rows.length && BigInt(rows[rowIndex].seq) < fromSeq) rowIndex++;

    const slice: Buffer[] = [];
    while (rowIndex < rows.length && BigInt(rows[rowIndex].seq) <= toSeq) {
      slice.push(rows[rowIndex].record_hash as Buffer);
      rowIndex++;
    }
    if (slice.length === 0) {
      throw new Error(`anchor ${a.id}: no records in range ${a.from_seq}-${a.to_seq}`);
    }
    if (!merkleRoot(slice).equals(a.merkle_root)) {
      throw new Error(`anchor ${a.id}: Merkle root mismatch`);
    }

    const proofRows = (
      await db.query(
        'select method, provider, proof from audit_anchor_proof where anchor_id=$1 order by id',
        [a.id],
      )
    ).rows;

    const proofs: ProofResult[] = [];
    for (const pr of proofRows) {
      const provider = byKey.get(`${pr.method}:${pr.provider}`);
      if (!provider) {
        // Can't verify a proof whose provider isn't configured in this run.
        proofs.push({
          method: pr.method,
          provider: pr.provider,
          ok: false,
          assertedTime: null,
          note: 'provider not configured in this environment',
        });
        continue;
      }
      const v = await provider.verify(a.merkle_root, pr.proof);
      if (!v.ok) {
        throw new Error(`anchor ${a.id}: proof ${pr.method}:${pr.provider} failed verification`);
      }
      proofs.push({
        method: pr.method,
        provider: pr.provider,
        ok: true,
        assertedTime: v.assertedTime?.toISOString() ?? null,
      });
    }

    anchors.push({ id: a.id, fromSeq: a.from_seq, toSeq: a.to_seq, proofs });
  }

  return { records: rows.length, anchors, ok: true };
}
