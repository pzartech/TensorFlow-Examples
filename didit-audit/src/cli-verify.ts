import { pool } from './db.js';
import { verifyAuditLog } from './verify.js';

/**
 * CLI verification entrypoint — the report you can run in front of an auditor.
 * Exit code 0 = log intact; non-zero = tampering detected.
 */
async function main() {
  const client = await pool.connect();
  try {
    const result = await verifyAuditLog(client);
    console.log(JSON.stringify(result, null, 2));
    console.log('\n✅ audit log intact and anchored');
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((e) => {
  console.error('❌ VERIFICATION FAILED:', e.message);
  process.exit(1);
});
