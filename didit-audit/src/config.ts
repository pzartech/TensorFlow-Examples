import { eidasEnabled } from './eidas.js';
import { getProviders } from './providers.js';
import { getSinks } from './sinks.js';

/**
 * Central configuration + capability reporting.
 *
 * Everything is wired and ready; the two switches that need external accounts are
 * KYC (Didit keys) and the blockchain anchors. `capabilities()` makes the on/off
 * state of each explicit, and `printStartupSummary()` prints it at boot.
 */
export interface Capabilities {
  database: boolean;
  kyc: boolean; // Didit configured (request + webhook)
  blockchain: boolean; // any chain anchor (Bitcoin/EVM) enabled
  anchorProviders: string[];
  sinks: string[];
  replicaEncryption: boolean; // per-subject encryption + crypto-shred enabled
  eidasTrustedRoots: boolean; // TSA qualification enforced against trusted roots
  corroboration: { geoip: number; httpTime: number; openSanctions: boolean };
}

function count(csv: string | undefined): number {
  return (csv ?? '').split(',').map((s) => s.trim()).filter(Boolean).length;
}

export function capabilities(): Capabilities {
  const anchorProviders = getProviders().map((p) => `${p.method}:${p.provider}`);
  return {
    database: !!process.env.DATABASE_URL,
    kyc: !!(process.env.DIDIT_API_KEY && process.env.DIDIT_WEBHOOK_SECRET),
    blockchain: anchorProviders.some((p) => p.startsWith('bitcoin-ots') || p.startsWith('evm')),
    anchorProviders,
    sinks: getSinks().map((s) => s.name),
    replicaEncryption: !!process.env.REPLICA_MASTER_KEY,
    eidasTrustedRoots: eidasEnabled(),
    corroboration: {
      geoip: count(process.env.GEOIP_URLS),
      httpTime: count(process.env.TIME_CHECK_URLS),
      openSanctions: !!process.env.OPENSANCTIONS_URL,
    },
  };
}

/** Throw if a required variable is missing. */
export function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing required env ${name}`);
  return v;
}

export function printStartupSummary(): void {
  const c = capabilities();
  const yn = (b: boolean) => (b ? 'ENABLED' : 'off');
  console.log('didit-audit capabilities:');
  console.log(`  database:        ${yn(c.database)}`);
  console.log(`  KYC (Didit):     ${yn(c.kyc)}${c.kyc ? '' : '  ← set DIDIT_API_KEY + DIDIT_WEBHOOK_SECRET to enable'}`);
  console.log(`  blockchain:      ${yn(c.blockchain)}${c.blockchain ? '' : '  ← set TSA_URLS / EVM_* / keep OTS to enable'}`);
  console.log(`  anchor proofs:   [${c.anchorProviders.join(', ') || 'none'}]${c.eidasTrustedRoots ? '  (eIDAS qualification enforced)' : ''}`);
  console.log(`  replication:     [${c.sinks.join(', ') || 'none'}]${c.replicaEncryption ? ' (encrypted, crypto-shred)' : ''}`);
  console.log(`  corroboration:   geoip=${c.corroboration.geoip} httpTime=${c.corroboration.httpTime} openSanctions=${c.corroboration.openSanctions}`);
}
