import { pool } from './db.js';
import { verifyAuditLog } from './verify.js';
import { verifyReplicas } from './replicate.js';

/**
 * CLI verification entrypoint — the report you can run in front of an auditor.
 * Verifies the hash chain + every anchor proof, then cross-checks every
 * replication layer. Exit code 0 = all intact; non-zero = divergence detected.
 */
async function main() {
  const client = await pool.connect();
  try {
    const result = await verifyAuditLog(client);
    const replicas = await verifyReplicas(client);
    console.log(JSON.stringify({ ...result, replicas }, null, 2));
    console.log('\n✅ audit log intact, anchored, and replicated across all layers');
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((e) => {
  console.error('❌ VERIFICATION FAILED:', e.message);
  process.exit(1);
});
