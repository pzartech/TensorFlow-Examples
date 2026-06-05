/**
 * Record sinks — independent stores that each hold a full copy of every audit
 * record. Where the anchor providers prove the *hash*, sinks replicate the
 * *information*, so the content survives even if the primary database is lost or
 * tampered with. Configure as many as you like; each is one more layer.
 *
 * Configure via env:
 *   FS_SINKS=/mnt/worm/audit,/backup/audit     one append-only dir per path
 *   S3_SINKS=my-audit-bucket,dr-audit-bucket   one S3 bucket per name (enable
 *                                              Object Lock on the bucket for WORM)
 *   AZURE_BLOB_SINKS=auditc1,auditc2           one container per name (set an
 *                                              immutability policy for WORM)
 *   AZURE_STORAGE_CONNECTION_STRING=...        used by Azure sinks
 *
 * GDPR: these layers hold full payloads (possibly PII). Keep them encrypted and
 * access-controlled. For any layer you cannot delete from (true WORM / public
 * storage), store payloads encrypted and erase by destroying the key
 * (crypto-shredding) — see README.
 */
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { canonical } from './canonical.js';

export interface RecordSink {
  name: string;
  /** Idempotent write of one record. Must not overwrite an existing object. */
  put(key: string, data: Buffer): Promise<void>;
  /** Fetch a record, or null if absent. Used by verification. */
  get(key: string): Promise<Buffer | null>;
}

/** Object key for a record, zero-padded so it sorts lexicographically by seq. */
export function recordKey(seq: string | number | bigint): string {
  return `audit/${String(seq).padStart(20, '0')}.json`;
}

/** Self-describing, canonical JSON of a record (hex hashes) — what each sink stores. */
export function serializeRecord(row: {
  seq: string;
  event_type: string;
  subject_ref: string | null;
  didit_session_id: string | null;
  payload_hash: Buffer;
  payload: unknown;
  prev_hash: Buffer;
  record_hash: Buffer;
  created_at: string | Date;
}): Buffer {
  return Buffer.from(
    canonical({
      seq: String(row.seq),
      event_type: row.event_type,
      subject_ref: row.subject_ref ?? null,
      didit_session_id: row.didit_session_id ?? null,
      payload_hash: row.payload_hash.toString('hex'),
      payload: row.payload,
      prev_hash: row.prev_hash.toString('hex'),
      record_hash: row.record_hash.toString('hex'),
      created_at: new Date(row.created_at).toISOString(),
    }),
  );
}

// Variable-specifier import so optional SDKs aren't required to typecheck/build.
async function load(moduleName: string): Promise<any> {
  return import(moduleName);
}

function fsSink(dir: string): RecordSink {
  return {
    name: `fs:${dir}`,
    async put(key, data) {
      const file = path.join(dir, key);
      await fs.mkdir(path.dirname(file), { recursive: true });
      try {
        await fs.writeFile(file, data, { flag: 'wx' }); // wx = fail if it exists
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      }
    },
    async get(key) {
      try {
        return await fs.readFile(path.join(dir, key));
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
        throw e;
      }
    },
  };
}

function s3Sink(bucket: string): RecordSink {
  return {
    name: `s3:${bucket}`,
    async put(key, data) {
      const { S3Client, PutObjectCommand } = await load('@aws-sdk/client-s3');
      await new S3Client({}).send(
        new PutObjectCommand({
          Bucket: bucket,
          Key: key,
          Body: data,
          ContentType: 'application/json',
          ServerSideEncryption: 'AES256',
        }),
      );
    },
    async get(key) {
      const { S3Client, GetObjectCommand } = await load('@aws-sdk/client-s3');
      try {
        const r = await new S3Client({}).send(new GetObjectCommand({ Bucket: bucket, Key: key }));
        return Buffer.from(await r.Body.transformToByteArray());
      } catch (e) {
        if ((e as { name?: string }).name === 'NoSuchKey') return null;
        throw e;
      }
    },
  };
}

function azureSink(container: string): RecordSink {
  const conn = process.env.AZURE_STORAGE_CONNECTION_STRING ?? '';
  async function client() {
    const { BlobServiceClient } = await load('@azure/storage-blob');
    return BlobServiceClient.fromConnectionString(conn).getContainerClient(container);
  }
  return {
    name: `azure:${container}`,
    async put(key, data) {
      const blob = (await client()).getBlockBlobClient(key);
      await blob.uploadData(data, { blobHTTPHeaders: { blobContentType: 'application/json' } });
    },
    async get(key) {
      try {
        return await (await client()).getBlockBlobClient(key).downloadToBuffer();
      } catch (e) {
        if ((e as { statusCode?: number }).statusCode === 404) return null;
        throw e;
      }
    },
  };
}

function csv(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Build the active replication sinks from the environment. */
export function getSinks(): RecordSink[] {
  const sinks: RecordSink[] = [];
  for (const dir of csv(process.env.FS_SINKS)) sinks.push(fsSink(dir));
  for (const bucket of csv(process.env.S3_SINKS)) sinks.push(s3Sink(bucket));
  for (const container of csv(process.env.AZURE_BLOB_SINKS)) sinks.push(azureSink(container));
  return sinks;
}
