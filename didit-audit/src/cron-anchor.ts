import { pool } from './db.js';
import { anchorPending, upgradeProofs } from './anchor.js';

/**
 * Scheduled entrypoint. Run on a timer (Supabase scheduled function, cron, etc.).
 * First advances any proofs that have since confirmed (Bitcoin / EVM), then
 * anchors the latest batch of records with every configured provider.
 */
async function main() {
  const client = await pool.connect();
  try {
    const confirmed = await upgradeProofs(client);
    if (confirmed) console.log(`confirmed ${confirmed} pending proof(s)`);

    const result = await anchorPending(client);
    if (!result) {
      console.log('nothing new to anchor');
    } else {
      const ok = result.proofs.filter((p) => p.status !== 'failed').map((p) => `${p.method}:${p.provider}`);
      console.log(
        `anchored ${result.records} record(s), seq ${result.fromSeq}-${result.toSeq} ` +
          `via [${ok.join(', ')}], root ${result.merkleRoot}`,
      );
    }
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

