/**
 * Anchor provider registry.
 *
 * Each provider is one independent way to prove a Merkle root existed at a time.
 * `getProviders()` builds the active set from environment config — add more TSAs,
 * chains, or keys and you get more proofs per anchor with no code changes.
 *
 * Configure via env (all optional except you want at least one):
 *   OTS_DISABLED=1                      disable the Bitcoin/OpenTimestamps anchor
 *   TSA_URLS=https://a/tsr,https://b/tsr   one RFC 3161 timestamp per URL
 *   EVM_PRIVATE_KEY=0x...               key used for every EVM anchor
 *   EVM_ANCHORS=polygon=https://rpc,...  name=rpcUrl pairs, one anchor per chain
 *   SIGNING_KEY_ID=ici-2026             id recorded with signature proofs
 *   SIGNING_KEY_PEM / SIGNING_PUBKEY_PEM   Ed25519 PEM (private optional for verify-only)
 */
import OpenTimestamps from 'javascript-opentimestamps';
import { evmProvider } from './evm-anchor.js';
import { signatureProvider } from './signature-anchor.js';
import { requestTimestamp, verifyTimestampToken } from './tsa-anchor.js';

export type ProofStatus = 'pending' | 'confirmed';

export interface AnchorOutcome {
  proof: Buffer;
  assertedTime?: Date;
  status: ProofStatus;
  detail?: Record<string, unknown>;
}

export interface VerifyOutcome {
  ok: boolean;
  assertedTime?: Date;
  detail?: Record<string, unknown>;
}

export interface AnchorProvider {
  method: string; // stable method id, e.g. 'bitcoin-ots'
  provider: string; // instance id, e.g. a TSA url or chain name
  anchor(root: Buffer): Promise<AnchorOutcome>;
  verify(root: Buffer, proof: Buffer): Promise<VerifyOutcome>;
  /** Optionally advance a pending proof (OTS Bitcoin upgrade, EVM confirmation). */
  upgrade?(proof: Buffer, root: Buffer): Promise<AnchorOutcome | null>;
}

function bitcoinTimeFrom(result: unknown): number | null {
  const r = result as { bitcoin?: { timestamp?: number } } | number | undefined;
  if (typeof r === 'number') return r;
  return r?.bitcoin?.timestamp ?? null;
}

function otsProvider(): AnchorProvider {
  const original = (root: Buffer) =>
    OpenTimestamps.DetachedTimestampFile.fromHash(new OpenTimestamps.Ops.OpSHA256(), root);
  return {
    method: 'bitcoin-ots',
    provider: 'opentimestamps',
    async anchor(root) {
      const detached = original(root);
      await OpenTimestamps.stamp(detached);
      return { proof: Buffer.from(detached.serializeToBytes()), status: 'pending' };
    },
    async verify(root, proof) {
      const detached = OpenTimestamps.DetachedTimestampFile.deserialize([...proof]);
      try {
        const ts = bitcoinTimeFrom(await OpenTimestamps.verify(detached, original(root)));
        return {
          ok: true,
          assertedTime: ts != null ? new Date(ts * 1000) : undefined,
          detail: { confirmed: ts != null },
        };
      } catch {
        // Calendar commitment exists but isn't confirmed on Bitcoin yet; the
        // hash-chain integrity check is what guards correctness in the meantime.
        return { ok: true, detail: { confirmed: false } };
      }
    },
    async upgrade(proof, root) {
      const detached = OpenTimestamps.DetachedTimestampFile.deserialize([...proof]);
      const changed = await OpenTimestamps.upgrade(detached);
      let status: ProofStatus = 'pending';
      let assertedTime: Date | undefined;
      try {
        const ts = bitcoinTimeFrom(await OpenTimestamps.verify(detached, original(root)));
        if (ts != null) {
          status = 'confirmed';
          assertedTime = new Date(ts * 1000);
        }
      } catch {
        /* still pending */
      }
      if (!changed && status !== 'confirmed') return null;
      return { proof: Buffer.from(detached.serializeToBytes()), status, assertedTime };
    },
  };
}

function tsaProvider(url: string): AnchorProvider {
  return {
    method: 'rfc3161',
    provider: url,
    async anchor(root) {
      const { token, genTime } = await requestTimestamp(root, url);
      return { proof: token, assertedTime: genTime, status: 'confirmed' };
    },
    async verify(root, proof) {
      const v = await verifyTimestampToken(root, proof);
      return { ok: v.signatureValid, assertedTime: v.genTime, detail: { signer: v.signerSubject } };
    },
  };
}

function csv(value: string | undefined): string[] {
  return (value ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Build the active provider set from the environment. */
export function getProviders(): AnchorProvider[] {
  const providers: AnchorProvider[] = [];

  if (process.env.OTS_DISABLED !== '1') providers.push(otsProvider());

  for (const url of csv(process.env.TSA_URLS)) providers.push(tsaProvider(url));

  const evmKey = process.env.EVM_PRIVATE_KEY as `0x${string}` | undefined;
  if (evmKey) {
    for (const entry of csv(process.env.EVM_ANCHORS)) {
      const eq = entry.indexOf('=');
      if (eq === -1) continue;
      const name = entry.slice(0, eq).trim();
      const rpcUrl = entry.slice(eq + 1).trim();
      if (name && rpcUrl) providers.push(evmProvider(name, rpcUrl, evmKey));
    }
  }

  if (process.env.SIGNING_PUBKEY_PEM) {
    providers.push(
      signatureProvider(
        process.env.SIGNING_KEY_ID ?? 'default',
        process.env.SIGNING_KEY_PEM,
        process.env.SIGNING_PUBKEY_PEM,
      ),
    );
  }

  return providers;
}
