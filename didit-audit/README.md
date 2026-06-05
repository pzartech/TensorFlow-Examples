# didit-audit

A tamper-evident, blockchain-anchored audit log for **Didit** identity verifications.

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
2. **Anchor** Merkle roots of the chain to **Bitcoin** via OpenTimestamps. Because
   we can't rewrite Bitcoin, we can't have backdated the records either.
3. Publish **only hashes** on-chain. All personal data stays in our database and
   stays erasable (GDPR-compatible).

## Files

| File | Purpose |
|------|---------|
| `sql/001_audit_schema.sql` | Append-only `audit_log` + `audit_anchor` tables |
| `src/audit-log.ts` | `appendAuditEvent()` — hash-chained insert |
| `src/merkle.ts` | Domain-separated Merkle root |
| `src/anchor.ts` | `anchorPending()` + `upgradeAnchors()` (OpenTimestamps / Bitcoin) |
| `src/verify.ts` | `verifyAuditLog()` — recompute chain + verify anchors |
| `src/didit-webhook.ts` | HMAC-SHA256 signature check + append |
| `src/cron-anchor.ts` | Daily anchoring job entrypoint |
| `src/cli-verify.ts` | `npm run verify` — auditor-facing report |

## Setup

```bash
cp .env.example .env        # fill DATABASE_URL, DIDIT_API_KEY, DIDIT_WEBHOOK_SECRET
npm install
psql "$DATABASE_URL" -f sql/001_audit_schema.sql
```

## Integrate into ICI

1. In ICI's Didit webhook route, pass the **raw request body** (not a parsed object)
   and the signature header into `handleDiditWebhook()`:

   ```ts
   import { pool } from './didit-audit/src/db.js';
   import { handleDiditWebhook } from './didit-audit/src/didit-webhook.js';

   // express example — needs the raw body, e.g. express.raw({ type: '*/*' })
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

2. Schedule `npm run anchor` (daily is plenty — one root covers thousands of events).
3. Run `npm run verify` any time to prove integrity; exit code `0` = intact.

## Strengthening evidentiary value (what reinforces the proof in court)

Blockchain anchoring gives *trustless immutability*, but courts weigh **legal
presumption** and **methodology** too. In rough priority order:

1. **eIDAS Qualified Electronic Timestamp (QTSP)** — anchor the same Merkle root
   with a qualified timestamp authority *in addition to* Bitcoin. Under eIDAS, a
   qualified timestamp carries a **legal presumption** of integrity and time in
   EU courts and shifts the burden of proof to the challenger. Bitcoin is strong
   technically but needs an expert to explain; a QTSP is recognised by law. Belt
   **and** suspenders.
2. **Sign records/roots with an HSM-backed key** (Azure Key Vault Managed HSM or
   AWS KMS). Adds non-repudiation and documented key custody, so you can show
   *who* could have produced the hashes.
3. **WORM / immutable storage** for the raw log and proofs (S3 Object Lock, Azure
   immutable blob). Regulator-grade retention; prevents silent deletion.
4. **Store Didit's raw signed webhook payload verbatim** (this module already does).
   That embeds an independent third party's cryptographic attestation, not just
   your own records.
5. **Independent verification + expert declaration** — `verify.ts` is reproducible
   by anyone; pair it with documented procedure and, if needed, an auditor's
   attestation.
6. **Code provenance** — pin and code-sign the version that produced the hashes
   (reproducible build) so you can show exactly which logic generated them.
7. **Redaction discipline** — if a `payload` is erased for GDPR, record a
   `redaction` event rather than deleting the row, so the chain stays verifiable
   and the erasure is itself audited.
8. **Dual anchoring** — optionally anchor to a second independent chain (e.g.
   Polygon) so no single network is a dependency.

## Notes

- Verify the exact OpenTimestamps API against your installed
  `javascript-opentimestamps` version, and the Didit signature header name in the
  Didit console, before going to production.
- Never put PII on-chain. Only `record_hash` / Merkle roots are anchored.
