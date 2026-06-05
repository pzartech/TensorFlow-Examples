import { pool } from './db.js';
import { anchorPending, upgradeProofs } from './anchor.js';
import { replicatePending } from './replicate.js';

/**
 * Scheduled entrypoint. Run on a timer (Supabase scheduled function, cron, etc.).
 * Replicates new records to every configured sink, advances any proofs that have
 * since confirmed (Bitcoin / EVM), then anchors the latest batch of records with
 * every configured provider.
 */
async function main() {
  const client = await pool.connect();
  try {
    const replicas = await replicatePending(client);
    for (const r of replicas) {
      if (r.replicated || r.error) {
        console.log(`replicated ${r.replicated} to ${r.sink} (lastSeq ${r.lastSeq})${r.error ? ` — error: ${r.error}` : ''}`);
      }
    }

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

