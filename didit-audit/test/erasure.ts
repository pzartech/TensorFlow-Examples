/**
 * Encrypted-replica + GDPR crypto-shred test (requires REPLICA_MASTER_KEY,
 * DATABASE_URL, DIDIT_WEBHOOK_SECRET, FS_SINKS).
 *
 * Proves: replicas are ciphertext (no plaintext PII), verify passes, then
 * shredding a subject makes their replicas unrecoverable AND nulls their DB
 * payload — yet the hash chain and replica integrity still verify.
 */
import { createHmac } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import type { PoolClient } from 'pg';
import { pool } from '../src/db.js';
import { shredSubject } from '../src/cipher.js';
import { handleDiditWebhook } from '../src/didit-webhook.js';
import { replicatePending, verifyReplicas } from '../src/replicate.js';
import { verifyAuditLog } from '../src/verify.js';

const SECRET = process.env.DIDIT_WEBHOOK_SECRET ?? 'test-secret';
const SINK_DIR = (process.env.FS_SINKS ?? '').split(',')[0];

function signed(event: object) {
  const body = Buffer.from(JSON.stringify(event));
  return { body, sig: createHmac('sha256', SECRET).update(body).digest('hex') };
}

async function resetSchema(client: PoolClient) {
  await client.query('drop table if exists audit_anchor_proof, audit_anchor, audit_replication, audit_subject_key, audit_log cascade');
  await client.query('drop sequence if exists audit_log_seq_seq');
  await client.query(await readFile(new URL('../sql/001_audit_schema.sql', import.meta.url), 'utf8'));
}

async function main() {
  let pass = 0;
  let fail = 0;
  const ok = (c: boolean, m: string) => {
    c ? pass++ : fail++;
    console.log(`${c ? 'PASS' : 'FAIL'} ${m}`);
  };

  const client = await pool.connect();
  try {
    await resetSchema(client);

    for (const u of ['alice', 'alice', 'bob']) {
      const { body, sig } = signed({
        status: 'approved',
        vendor_data: u,
        session_id: `s-${u}-${Math.random()}`,
        id_verification: { status: 'approved', issuing_country: 'FR', full_name: `${u} SECRETNAME` },
        face_match: { status: 'match' },
        liveness: { status: 'passed' },
        ip_analysis: { country: 'FR', ip: '1.2.3.4' },
        phone: { country: 'FR' },
        timestamp: new Date().toISOString(),
      });
      await handleDiditWebhook(client, body, sig, SECRET);
    }
    ok((await client.query('select count(*)::int c from audit_log')).rows[0].c === 3, 'appended 3 records');

    await replicatePending(client);

    // Replica files must be ciphertext: no plaintext PII marker present.
    const files = (await readdir(path.join(SINK_DIR, 'audit'))).sort();
    const sample = (await readFile(path.join(SINK_DIR, 'audit', files[0]))).toString('utf8');
    ok(sample.includes('"enc":true'), 'replica is an encrypted envelope');
    ok(!sample.includes('SECRETNAME'), 'no plaintext PII in the replica');

    ok((await verifyAuditLog(client)).ok, 'verify chain: intact (encrypted)');
    let vr = await verifyReplicas(client);
    ok(vr.every((s) => s.checked === 3 && s.redacted === 0), 'replicas verify, 0 redacted');

    // GDPR erase "alice"
    const { keys, payloads } = await shredSubject(client, 'alice');
    ok(keys === 1 && payloads === 2, `shred alice: 1 key removed, 2 payloads nulled (got ${keys}/${payloads})`);

    ok((await client.query("select count(*)::int c from audit_log where subject_ref='alice' and payload is null")).rows[0].c === 2, 'alice payloads nulled in DB');
    ok((await verifyAuditLog(client)).ok, 'verify chain STILL intact after erasure');

    vr = await verifyReplicas(client);
    const total = vr[0];
    ok(total.checked === 3 && total.redacted === 2, `replicas verify; alice redacted (checked ${total.checked}, redacted ${total.redacted})`);

    console.log(`\n${pass} passed, ${fail} failed`);
    process.exit(fail ? 1 : 0);
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
