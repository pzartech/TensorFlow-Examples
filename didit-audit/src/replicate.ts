import type { PoolClient } from 'pg';
import { sealRecord, openRecord } from './cipher.js';
import { getSinks, recordKey } from './sinks.js';

export interface ReplicationStatus {
  sink: string;
  replicated: number;
  lastSeq: string;
  error?: string;
}

/**
 * Push every not-yet-replicated record to each configured sink. Records are
 * append-only and ordered by seq, so a per-sink high-water mark is enough.
 * Each sink is independent and best-effort: one failing never blocks the others,
 * and progress is saved up to the last record that landed, so the next run
 * resumes (puts are idempotent).
 */
export async function replicatePending(db: PoolClient): Promise<ReplicationStatus[]> {
  const sinks = getSinks();
  const summary: ReplicationStatus[] = [];

  for (const sink of sinks) {
    const hw = await db.query('select last_seq from audit_replication where sink=$1', [sink.name]);
    let last: string = hw.rows[0]?.last_seq ?? '0';

    const rows = (
      await db.query('select * from audit_log where seq > $1 order by seq', [last])
    ).rows;

    let replicated = 0;
    let error: string | undefined;
    try {
      for (const row of rows) {
        await sink.put(recordKey(row.seq), await sealRecord(db, row));
        last = String(row.seq);
        replicated++;
      }
    } catch (e) {
      error = (e as Error).message;
      console.error(`sink ${sink.name} failed after seq ${last}:`, error);
    }

    if (replicated > 0) {
      await db.query(
        `insert into audit_replication (sink, last_seq, updated_at) values ($1,$2, now())
         on conflict (sink) do update set last_seq=excluded.last_seq, updated_at=now()`,
        [sink.name, last],
      );
    }
    summary.push({ sink: sink.name, replicated, lastSeq: last, error });
  }

  return summary;
}

export interface ReplicaCheck {
  sink: string;
  checked: number;
  redacted: number; // records whose subject was crypto-shredded (content unrecoverable)
}

/**
 * Cross-check every sink against the authoritative log: each record must be
 * present and its (cleartext) record_hash must match. Encrypted replicas are
 * opened to confirm content too; crypto-shredded ones are counted as redacted
 * (still a valid, present record — just unrecoverable). Throws on divergence.
 */
export async function verifyReplicas(db: PoolClient): Promise<ReplicaCheck[]> {
  const sinks = getSinks();
  const rows = (await db.query('select seq, record_hash from audit_log order by seq')).rows;
  const results: ReplicaCheck[] = [];

  for (const sink of sinks) {
    let checked = 0;
    let redacted = 0;
    for (const row of rows) {
      const data = await sink.get(recordKey(row.seq));
      if (!data) throw new Error(`sink ${sink.name}: missing record seq ${row.seq}`);
      const opened = await openRecord(db, data);
      if (opened.recordHash !== (row.record_hash as Buffer).toString('hex')) {
        throw new Error(`sink ${sink.name}: record_hash mismatch at seq ${row.seq}`);
      }
      if (opened.shredded) redacted++;
      checked++;
    }
    results.push({ sink: sink.name, checked, redacted });
  }

  return results;
}
