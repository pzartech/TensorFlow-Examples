import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool } from './db.js';

/** Apply every sql/*.sql migration in lexical order. Statements are idempotent. */
async function main() {
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'sql');
  const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
  const client = await pool.connect();
  try {
    for (const f of files) {
      console.log(`applying ${f}`);
      await client.query(await readFile(path.join(dir, f), 'utf8'));
    }
  } finally {
    client.release();
    await pool.end();
  }
  console.log(`done (${files.length} file(s))`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
