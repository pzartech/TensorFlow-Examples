# Integrating didit-audit into ICI

This folder is self-contained. Here are the two ways to get it wired into ICI —
pick one.

## Option A — let me (Claude) do the integration directly

Push `ici` to GitHub so I can read and edit it, then point me at it.

```bash
cd C:\Users\jerem\code\github\ici
git init                      # if it isn't a repo yet
git add -A && git commit -m "snapshot before didit-audit integration"
# create an empty private repo named ici under pzartech first, then:
git remote add origin https://github.com/pzartech/ici.git
git branch -M main
git push -u origin main
```

Then tell me: **"ici is at pzartech/ici, integrate didit-audit."** I'll add it to
the session, wire it into ICI's app/auth/DB, and open a PR on `ici`.

## Option B — run Claude locally inside ICI

1. Copy the `didit-audit/` folder into `C:\Users\jerem\code\github\ici\`
   (or unzip the artifact I sent you there).
2. In that folder run `claude`, then paste the prompt below.

> Integrate the `didit-audit/` module into this app. Read my stack first
> (package.json, server, auth, DB). Then: (1) mount its webhook handler at the
> route Didit calls — use `handleDiditWebhook` from `didit-audit/src/didit-webhook.ts`
> with the RAW request body and the `x-signature` header; (2) add a "Verify
> identity" action that calls `createVerificationSession` and redirects the user
> to the returned URL; (3) point `DATABASE_URL` at our database and run
> `npm --prefix didit-audit run migrate`; (4) schedule `npm --prefix didit-audit
> run anchor` daily; (5) add a `kyc_status` field to our user model updated from
> the webhook. Keep `DIDIT_API_KEY` / `DIDIT_WEBHOOK_SECRET` server-side only.
> Leave blockchain anchors off (OTS_DISABLED=1) until I say otherwise.

## Manual steps (if doing it by hand)

```bash
cp -r didit-audit /path/to/ici/        # vendor the folder
cd /path/to/ici/didit-audit
cp .env.example .env                    # set DATABASE_URL (KYC/blockchain can stay blank)
npm install
npm run migrate                         # apply sql/*.sql to ICI's DB
```

Then in ICI's backend:

```ts
import { pool } from './didit-audit/src/db.js';
import { handleDiditWebhook } from './didit-audit/src/didit-webhook.js';
import { createVerificationSession } from './didit-audit/src/didit-client.js';

// 1) Start verification (call from your "Verify identity" button)
const { url } = await createVerificationSession({ vendorData: currentUserId });
// redirect the user to `url`

// 2) Didit webhook — MUST receive the raw body (e.g. express.raw({ type: '*/*' }))
app.post('/webhooks/didit', express.raw({ type: '*/*' }), async (req, res) => {
  const c = await pool.connect();
  try {
    await handleDiditWebhook(c, req.body, req.header('x-signature') ?? '', process.env.DIDIT_WEBHOOK_SECRET!);
    res.sendStatus(200);
  } catch (e) { res.status(400).send((e as Error).message); }
  finally { c.release(); }
});
```

## Turning the two switches on (when ready)

- **KYC** → set `DIDIT_API_KEY`, `DIDIT_WEBHOOK_SECRET`, `DIDIT_WORKFLOW_ID`; confirm
  the field paths in `corroborate.ts` and the endpoint/headers in `didit-client.ts`
  against your Didit console.
- **Blockchain** → unset `OTS_DISABLED` (Bitcoin), and/or set `TSA_URLS` / `EVM_*`.

Verify any time with `npm run verify` (chain + every anchor proof + every replica).
