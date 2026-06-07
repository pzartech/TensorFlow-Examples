import { pool } from './db.js';
import { shredSubject } from './cipher.js';

/**
 * GDPR erasure CLI: `npm run shred -- <subject_ref>`.
 * Deletes the subject's data key (replicas become unrecoverable) and nulls their
 * DB payload. The hash chain and anchors still verify afterward.
 * Run with a DB role that may UPDATE audit_log (the app role is append-only).
 */
async function main() {
  const subject = process.argv[2];
  if (!subject) {
    console.error('usage: npm run shred -- <subject_ref>');
    process.exit(1);
  }
  const client = await pool.connect();
  try {
    await client.query('begin');
    const { keys, payloads } = await shredSubject(client, subject);
    await client.query('commit');
    console.log(`shredded "${subject}": removed ${keys} key(s), redacted ${payloads} payload(s)`);
  } catch (e) {
    await client.query('rollback');
    throw e;
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
