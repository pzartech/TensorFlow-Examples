import { pool } from './db.js';
import { anchorPending, upgradeAnchors } from './anchor.js';

/**
 * Scheduled entrypoint. Run on a timer (Supabase scheduled function, cron, etc.).
 * First upgrades any proofs that have since confirmed on Bitcoin, then anchors
 * the latest batch of records.
 */
async function main() {
  const client = await pool.connect();
  try {
    const upgraded = await upgradeAnchors(client);
    if (upgraded) console.log(`upgraded ${upgraded} pending anchor(s)`);

    const result = await anchorPending(client);
    console.log(
      result
        ? `anchored ${result.records} record(s), seq ${result.fromSeq}-${result.toSeq}, root ${result.merkleRoot}`
        : 'nothing new to anchor',
    );
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
