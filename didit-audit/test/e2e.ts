/**
 * End-to-end test of the full pipeline with KYC and blockchain OFF:
 * synthetic signed webhook -> corroboration -> hash-chained append ->
 * replication to a filesystem sink -> verify chain + replicas -> tamper detection.
 *
 * Proves everything *except* the Didit account/keys and the chain anchors is
 * ready and working. Requires DATABASE_URL (superuser, so it can reset/tamper)
 * and DIDIT_WEBHOOK_SECRET + FS_SINKS in the environment.
 */
import { createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { PoolClient } from 'pg';
import { pool } from '../src/db.js';
import { handleDiditWebhook } from '../src/didit-webhook.js';
import { replicatePending, verifyReplicas } from '../src/replicate.js';
import { verifyAuditLog } from '../src/verify.js';

const SECRET = process.env.DIDIT_WEBHOOK_SECRET ?? 'test-secret';

function signed(event: object): { body: Buffer; sig: string } {
  const body = Buffer.from(JSON.stringify(event));
  return { body, sig: createHmac('sha256', SECRET).update(body).digest('hex') };
}

async function resetSchema(client: PoolClient) {
  await client.query('drop table if exists audit_anchor_proof, audit_anchor, audit_replication, audit_log cascade');
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

    for (const u of ['u1', 'u2', 'u3']) {
      const { body, sig } = signed({
        status: 'approved',
        vendor_data: u,
        session_id: `s-${u}`,
        id_verification: { status: 'approved', issuing_country: 'FR' },
        face_match: { status: 'match' },
        liveness: { status: 'passed' },
        aml: { status: 'clear' },
        ip_analysis: { country: 'FR', ip: '1.2.3.4' },
        phone: { country: 'FR' },
        timestamp: new Date().toISOString(),
      });
      await handleDiditWebhook(client, body, sig, SECRET);
    }
    const n = (await client.query('select count(*)::int c from audit_log')).rows[0].c;
    ok(n === 3, `appended 3 chained records (got ${n})`);

    try {
      await handleDiditWebhook(client, Buffer.from('{}'), 'deadbeef', SECRET);
      ok(false, 'bad signature rejected');
    } catch {
      ok(true, 'bad signature rejected');
    }

    const row1 = (await client.query('select payload from audit_log order by seq limit 1')).rows[0];
    ok(row1.payload?.corroboration?.consensus?.identity?.agree === true, 'corroboration embedded; identity agreed');

    const rep = await replicatePending(client);
    ok(rep.length > 0 && rep.every((r) => r.replicated === 3 && !r.error), 'replicated 3 records to every sink');

    const v = await verifyAuditLog(client);
    ok(v.ok && v.records === 3, 'verifyAuditLog: chain + (no) anchors intact');

    const vr = await verifyReplicas(client);
    ok(vr.every((s) => s.checked === 3), 'verifyReplicas: every layer has every record');

    // Tamper as owner (bypassing the app's append-only grants) and expect detection.
    await client.query(`update audit_log set payload = jsonb_set(payload, '{decision,status}', '"declined"') where seq = 2`);
    try {
      await verifyAuditLog(client);
      ok(false, 'tamper detected');
    } catch (e) {
      ok(/altered|chain|mismatch|gap/.test((e as Error).message), `tamper detected: ${(e as Error).message}`);
    }

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
