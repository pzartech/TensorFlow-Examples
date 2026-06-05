# didit-audit

A tamper-evident, **multi-anchored** audit log for **Didit** identity verifications.

> ⚠️ **Staging note:** this module was scaffolded here because the ICI project
> (`C:\Users\jerem\code\github\ici`) is local and not reachable from the cloud
> session that generated it. Copy the `didit-audit/` folder into ICI, wire the
> webhook handler into ICI's Didit callback route, and run the migration.

## What problem this solves

**Threat model — "Case B":** prove to a *third party* (regulator, auditor, court)
that the verification records were not altered after the fact — **including by us**.
A log we fully control can't prove that on its own, so we:

1. **Hash-chain** every audit record (`record_hash = sha256(seq‖type‖payload_hash‖prev_hash‖created_at)`).
   Any retroactive edit, reorder, or deletion breaks the chain and is detected.
2. **Anchor** Merkle roots of the chain with **as many independent proofs as you
   configure** — Bitcoin, qualified RFC 3161 timestamps, EVM chains, signatures.
   The more independent witnesses, the harder any single point is to compromise
   or explain away.
3. **Replicate** every full record to **as many independent layers as you
   configure** (filesystem/WORM, S3 Object Lock, Azure immutable blob), so the
   *information* — not just its hash — survives loss or tampering of any one
   store. `verify` cross-checks every layer agrees.
4. Anchors publish **only hashes**. Replicas hold full payloads, so keep each
   replica encrypted/access-controlled; personal data stays erasable
   (GDPR-compatible — crypto-shred for any true-WORM/public layer).

## Anchor providers (stack as many as you like)

Each provider is one independent proof over the same Merkle root. Enable them via
env (`.env.example`); add more URLs/chains/keys to get more proofs per anchor with
no code changes.

| Provider | `method` | Proof | Strength |
|----------|----------|-------|----------|
| OpenTimestamps | `bitcoin-ots` | Bitcoin-backed timestamp | Trustless immutability; free |
| RFC 3161 TSA (×N) | `rfc3161` | Signed TimeStampToken per TSA | **eIDAS legal presumption** when the TSA is a QTSP on the EU Trusted List |
| EVM chain (×N) | `evm` | Root in tx calldata per chain | Independent public ledgers; smart-contract verifiable |
| Managed-key signature | `signature` | Ed25519 signature | Non-repudiation; put the key in an HSM/KMS |

`anchorPending()` runs **every** configured provider best-effort (one failing
never loses the others) and stores each proof as a row in `audit_anchor_proof`.
`verifyAuditLog()` checks **every** proof of **every** anchor.

## Replication layers (several copies of the same information)

Anchors prove the *hash*; sinks replicate the *record*. Each configured sink
holds a full, self-describing copy of every record (keyed `audit/<seq>.json`).
Add more sinks for more layers — no code change.

| Sink | env | WORM via | Notes |
|------|-----|----------|-------|
| Filesystem (×N) | `FS_SINKS` | WORM/NFS mount | write-once (`wx`); no extra deps |
| S3 (×N) | `S3_SINKS` | bucket Object Lock | optional `@aws-sdk/client-s3`, SSE on |
| Azure Blob (×N) | `AZURE_BLOB_SINKS` | container immutability policy | optional `@azure/storage-blob` |

`replicatePending()` fans new records out to every sink (per-sink high-water mark,
idempotent, best-effort). `verifyReplicas()` confirms each layer has every record
with a matching `record_hash`, and is included in `npm run verify`.

## Cross-corroboration (confirm id / place / time from several methods)

Each verification's core facts are confirmed by **multiple independent methods**,
and a consensus + disagreement flags are computed and embedded in the audit
payload (so they're hash-chained, anchored, and replicated like everything else):

| Fact | Methods (out of the box) | Consensus rule |
|------|--------------------------|----------------|
| **WHO** (identity) | Didit document, face match, liveness, AML | quorum of independent `pass` signals, no `fail` |
| **WHERE** (place) | Didit IP geo, document issuing country, phone country, + any `GEOIP_URLS` tools | majority country; dissenters flagged |
| **WHEN** (time) | Didit timestamp, server clock (+ TSA / Bitcoin / EVM anchor times later) | claims must agree within tolerance; median |

`corroborate(event)` (in `src/corroborate.ts`) collects the claims and
`evaluate()` derives the consensus. Add more tools (e.g. extra `GEOIP_URLS`) to
raise the witness count with no code change. Map the `pick()` path lists to your
exact Didit response shape.

### Witnesses beyond Didit and the blockchain

To keep the confirmations independent, these sources rely on neither Didit nor a
chain (all config-gated, best-effort, parallel):

| Fact | Independent source | env |
|------|--------------------|-----|
| WHERE | extra geo-IP providers (MaxMind, ipinfo, ipapi, …) | `GEOIP_URLS` |
| WHEN | HTTPS `Date` header from unrelated servers; **RFC 3161 TSA** is also non-blockchain time | `TIME_CHECK_URLS` |
| WHO | **OpenSanctions** sanctions/PEP screen (hosted or self-hosted yente) | `OPENSANCTIONS_URL` |

Further extensions (not bundled — need provider auth): a second IDV provider for
high-risk, open-banking bank-name match, MNO/SIM identity, NTP/Roughtime time,
device GPS. Each plugs in as one more `Claim` per dimension.

## Files

| File | Purpose |
|------|---------|
| `sql/001_audit_schema.sql` | Append-only `audit_log`; `audit_anchor` + `audit_anchor_proof` |
| `src/corroborate.ts` | Multi-method consensus over id / place / time |
| `src/audit-log.ts` | `appendAuditEvent()` — advisory-locked, hash-chained insert |
| `src/canonical.ts` | Deterministic JSON (toJSON-aware, `undefined`-omitting) |
| `src/merkle.ts` | Domain-separated Merkle root |
| `src/providers.ts` | Provider registry + OpenTimestamps; `getProviders()` from env |
| `src/tsa-anchor.ts` | RFC 3161 request/verify (PKI.js) |
| `src/evm-anchor.ts` | EVM anchor via `viem` (optional dep, lazy-loaded) |
| `src/signature-anchor.ts` | Ed25519 / KMS-style signature anchor |
| `src/anchor.ts` | `anchorPending()` + `upgradeProofs()` across all providers |
| `src/sinks.ts` | Replication sinks (filesystem, S3, Azure) + `getSinks()` |
| `src/replicate.ts` | `replicatePending()` + `verifyReplicas()` |
| `src/verify.ts` | Recompute chain + verify all proofs |
| `src/didit-webhook.ts` | HMAC-SHA256 signature check + append |
| `src/cron-anchor.ts` | Scheduled replicate + anchor job |
| `src/cli-verify.ts` | `npm run verify` — chain + proofs + replicas report |

## Run it (everything is ready; KYC + blockchain are switches)

Everything below runs today. **KYC (Didit)** and **blockchain anchors** are the
only pieces left off — both are fully coded and turn on by adding env vars.

```bash
cp .env.example .env        # set DATABASE_URL (KYC/blockchain can stay blank)
npm install
npm run migrate             # apply sql/*.sql
npm start                   # HTTP server; prints a capability summary
```

Or with Docker (Postgres + app): `docker compose up --build`.

`GET /healthz` reports what's on, e.g. before KYC/blockchain are configured:

```json
{ "ok": true, "capabilities": {
  "database": true, "kyc": false, "blockchain": false,
  "anchorProviders": [], "sinks": ["fs:/data/audit"],
  "corroboration": { "geoip": 0, "httpTime": 0, "openSanctions": false } } }
```

- `POST /verifications {"userId":"..."}` → starts a Didit session (503 with a
  clear message until `DIDIT_API_KEY` is set).
- `POST /webhooks/didit` → verifies the signature, corroborates id/place/time,
  appends to the chain, then replication + anchoring carry it onward.

**Switching the two remaining pieces on later:**
- **KYC** → set `DIDIT_API_KEY`, `DIDIT_WEBHOOK_SECRET` (`DIDIT_WORKFLOW_ID`).
- **Blockchain** → unset `OTS_DISABLED` (Bitcoin), and/or set `TSA_URLS` / `EVM_*`.

Verified end-to-end against Postgres with KYC + blockchain off
(`npm run test:e2e`): synthetic signed webhook → corroboration → chained append →
filesystem replication → verify chain + replicas → tamper detected (7/7).

## Integrate into ICI

1. In ICI's Didit webhook route, pass the **raw request body** (not a parsed
   object) and the signature header into `handleDiditWebhook()`:

   ```ts
   import { pool } from './didit-audit/src/db.js';
   import { handleDiditWebhook } from './didit-audit/src/didit-webhook.js';

   app.post('/webhooks/didit', express.raw({ type: '*/*' }), async (req, res) => {
     const client = await pool.connect();
     try {
       await handleDiditWebhook(
         client,
         req.body,                              // Buffer of raw bytes
         req.header('x-signature') ?? '',       // confirm exact header name in Didit console
         process.env.DIDIT_WEBHOOK_SECRET!,
       );
       res.sendStatus(200);
     } catch (e) {
       res.status(400).send((e as Error).message);
     } finally {
       client.release();
     }
   });
   ```

2. Schedule `npm run anchor` (daily is plenty — one root covers thousands of
   events; the job also confirms pending Bitcoin/EVM proofs).
3. Run `npm run verify` any time to prove integrity; exit code `0` = intact.

## Strengthening evidentiary value (what reinforces the proof in court)

Multiple anchors give *redundant* immutability, but courts also weigh **legal
presumption** and **methodology**. In rough priority order:

1. **eIDAS Qualified Electronic Timestamp (QTSP)** — list one or more qualified
   TSAs in `TSA_URLS`. Under eIDAS a qualified timestamp carries a **legal
   presumption** of integrity and time in EU courts and shifts the burden of
   proof. For full *qualification*, validate the TSA signer cert against the EU
   Trusted List (LOTL) — see the note in `tsa-anchor.ts` (`checkChain`).
2. **HSM/KMS-held signing key** — set `SIGNING_*` and move the private key into
   Azure Key Vault Managed HSM / AWS KMS. Adds non-repudiation + key custody.
3. **WORM / immutable storage** for the raw log and proofs (S3 Object Lock, Azure
   immutable blob). Regulator-grade retention; prevents silent deletion.
4. **Didit's raw signed webhook payload, stored verbatim** (this module already
   does) — an independent third party's cryptographic attestation.
5. **Independent verification + expert declaration** — `verify.ts` is reproducible
   by anyone; pair with documented procedure and, if needed, an auditor's
   attestation.
6. **Code provenance** — pin and code-sign the version that produced the hashes.
7. **Redaction discipline** — if a `payload` is erased for GDPR, record a
   `redaction` event rather than deleting the row, so the chain stays verifiable.
8. **Dual/triple anchoring** — already supported: configure Bitcoin **and**
   several TSAs **and** EVM chains so no single network is a dependency.

## Notes

- Validate the exact OpenTimestamps and PKI.js APIs against your installed
  versions, and confirm the Didit signature header name in the Didit console,
  before production.
- Never put PII on-chain. Only `record_hash` / Merkle roots are anchored.
- `viem` is an optional dependency; EVM anchoring is skipped if it isn't installed
  or `EVM_*` isn't configured.
