import OpenTimestamps from 'javascript-opentimestamps';
import type { PoolClient } from 'pg';
import { merkleRoot } from './merkle.js';

/**
 * Build a Merkle root over every not-yet-anchored record and timestamp it on
 * Bitcoin via OpenTimestamps. Only the root hash leaves your system — never PII.
 * Run on a schedule (e.g. daily); one anchor covers thousands of records.
 */
export async function anchorPending(db: PoolClient) {
  const last = await db.query('select coalesce(max(to_seq),0) as m from audit_anchor');
  const fromSeq = Number(last.rows[0].m) + 1;

  const rows = (
    await db.query('select seq, record_hash from audit_log where seq >= $1 order by seq', [
      fromSeq,
    ])
  ).rows;
  if (rows.length === 0) return null;

  const root = merkleRoot(rows.map((r) => r.record_hash as Buffer));

  const detached = OpenTimestamps.DetachedTimestampFile.fromHash(
    new OpenTimestamps.Ops.OpSHA256(),
    root,
  );
  await OpenTimestamps.stamp(detached);
  const proof = Buffer.from(detached.serializeToBytes());

  await db.query(
    `insert into audit_anchor (from_seq, to_seq, merkle_root, ots_proof)
     values ($1,$2,$3,$4)`,
    [rows[0].seq, rows[rows.length - 1].seq, root, proof],
  );

  return {
    fromSeq: rows[0].seq,
    toSeq: rows[rows.length - 1].seq,
    merkleRoot: root.toString('hex'),
    records: rows.length,
  };
}

/**
 * OpenTimestamps proofs are "incomplete" until the Bitcoin tx confirms (a few
 * hours). Re-run this periodically to upgrade pending proofs to full
 * Bitcoin-backed attestations.
 */
export async function upgradeAnchors(db: PoolClient) {
  const rows = (
    await db.query(
      'select id, merkle_root, ots_proof from audit_anchor where bitcoin_block is null',
    )
  ).rows;
  let upgraded = 0;
  for (const a of rows) {
    const detached = OpenTimestamps.DetachedTimestampFile.deserialize([...a.ots_proof]);
    const changed = await OpenTimestamps.upgrade(detached);

    // Once the proof verifies against Bitcoin, capture the block height (or fall
    // back to a sentinel) so this anchor is no longer re-processed on every run.
    let bitcoinBlock: number | null = null;
    try {
      const original = OpenTimestamps.DetachedTimestampFile.fromHash(
        new OpenTimestamps.Ops.OpSHA256(),
        a.merkle_root,
      );
      const result = await OpenTimestamps.verify(detached, original);
      if (result != null) {
        // Newer lib versions expose { bitcoin: { height, timestamp } }; older
        // ones return the Unix timestamp directly. Either confirms the anchor.
        bitcoinBlock =
          (result as { bitcoin?: { height?: number } })?.bitcoin?.height ??
          (typeof result === 'number' ? result : 1);
      }
    } catch {
      // Not yet confirmed on-chain.
    }

    if (changed || bitcoinBlock !== null) {
      await db.query('update audit_anchor set ots_proof=$1, bitcoin_block=$2 where id=$3', [
        Buffer.from(detached.serializeToBytes()),
        bitcoinBlock,
        a.id,
      ]);
      if (bitcoinBlock !== null) upgraded++;
    }
  }
  return upgraded;
}
