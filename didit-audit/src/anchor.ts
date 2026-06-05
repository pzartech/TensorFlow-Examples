import type { PoolClient } from 'pg';
import { merkleRoot } from './merkle.js';
import { getProviders } from './providers.js';

/**
 * Build a Merkle root over every not-yet-anchored record and prove it with every
 * configured provider (Bitcoin, each TSA, each EVM chain, signature keys). Each
 * provider is best-effort: one failing never loses the others. Only the root
 * hash leaves the system — never PII. Run on a schedule; one anchor covers
 * thousands of records.
 */
export async function anchorPending(db: PoolClient) {
  const last = await db.query('select coalesce(max(to_seq),0) as m from audit_anchor');
  const fromSeq = Number(last.rows[0].m) + 1;

  const rows = (
    await db.query('select seq, record_hash from audit_log where seq >= $1 order by seq', [fromSeq])
  ).rows;
  if (rows.length === 0) return null;

  const root = merkleRoot(rows.map((r) => r.record_hash as Buffer));
  const providers = getProviders();

  await db.query('begin');
  try {
    const ins = await db.query(
      'insert into audit_anchor (from_seq, to_seq, merkle_root) values ($1,$2,$3) returning id',
      [rows[0].seq, rows[rows.length - 1].seq, root],
    );
    const anchorId: string = ins.rows[0].id;

    const proofs: { method: string; provider: string; status: string }[] = [];
    for (const p of providers) {
      try {
        const out = await p.anchor(root);
        await db.query(
          `insert into audit_anchor_proof
             (anchor_id, method, provider, proof, asserted_time, status, detail)
           values ($1,$2,$3,$4,$5,$6,$7)`,
          [anchorId, p.method, p.provider, out.proof, out.assertedTime ?? null, out.status, out.detail ?? null],
        );
        proofs.push({ method: p.method, provider: p.provider, status: out.status });
      } catch (e) {
        console.error(`anchor provider ${p.method}:${p.provider} failed:`, (e as Error).message);
        proofs.push({ method: p.method, provider: p.provider, status: 'failed' });
      }
    }

    if (!proofs.some((r) => r.status !== 'failed')) {
      // Nothing succeeded — roll back so the anchor row doesn't exist and we retry.
      await db.query('rollback');
      throw new Error('all anchor providers failed; no proof recorded');
    }

    await db.query('commit');
    return {
      anchorId,
      fromSeq: rows[0].seq,
      toSeq: rows[rows.length - 1].seq,
      merkleRoot: root.toString('hex'),
      records: rows.length,
      proofs,
    };
  } catch (e) {
    await db.query('rollback').catch(() => {});
    throw e;
  }
}

/**
 * Advance pending proofs to confirmed where possible (OpenTimestamps Bitcoin
 * upgrade, EVM transaction confirmation). Marks them confirmed so they're not
 * re-processed every run.
 */
export async function upgradeProofs(db: PoolClient) {
  const byKey = new Map(getProviders().map((p) => [`${p.method}:${p.provider}`, p]));
  const rows = (
    await db.query(
      `select p.id, p.method, p.provider, p.proof, a.merkle_root
         from audit_anchor_proof p
         join audit_anchor a on a.id = p.anchor_id
        where p.status = 'pending'`,
    )
  ).rows;

  let confirmed = 0;
  for (const r of rows) {
    const provider = byKey.get(`${r.method}:${r.provider}`);
    if (!provider?.upgrade) continue;
    try {
      const out = await provider.upgrade(r.proof, r.merkle_root);
      if (!out) continue;
      await db.query(
        'update audit_anchor_proof set proof=$1, status=$2, asserted_time=coalesce($3, asserted_time) where id=$4',
        [out.proof, out.status, out.assertedTime ?? null, r.id],
      );
      if (out.status === 'confirmed') confirmed++;
    } catch (e) {
      console.error(`upgrade ${r.method}:${r.provider} failed:`, (e as Error).message);
    }
  }
  return confirmed;
}
