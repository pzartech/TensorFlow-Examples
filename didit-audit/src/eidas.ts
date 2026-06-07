/**
 * eIDAS Trusted List validation for RFC 3161 timestamps.
 *
 * A qualified electronic timestamp's signer certificate must chain to a CA on the
 * EU Trusted List (LOTL). Full automated LOTL parsing is out of scope here;
 * instead you supply the trusted anchor certificate(s) and we verify the signer
 * chains to one of them:
 *
 *   TSA_TRUSTED_ROOTS_PEM   inline PEM bundle (one or more certs), or
 *   TSA_TRUSTED_ROOTS_FILE  path to a PEM bundle
 *
 * Populate it by pinning your QTSP's root CA, or by extracting the QTSP CA certs
 * from the EU List of Trusted Lists (https://eidas.ec.europa.eu/efda/tl-browser/)
 * into a PEM bundle. When no roots are configured, qualification is simply not
 * asserted (the timestamp's signature is still verified).
 */
import { readFileSync } from 'node:fs';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import './pki-engine.js';

function toAb(view: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(view.byteLength);
  copy.set(view);
  return copy.buffer;
}

export function pemToCerts(pem: string): pkijs.Certificate[] {
  const out: pkijs.Certificate[] = [];
  const re = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(pem)) !== null) {
    const der = Buffer.from(m[1].replace(/\s+/g, ''), 'base64');
    out.push(new pkijs.Certificate({ schema: asn1js.fromBER(toAb(der)).result }));
  }
  return out;
}

export function eidasEnabled(): boolean {
  return !!(process.env.TSA_TRUSTED_ROOTS_PEM || process.env.TSA_TRUSTED_ROOTS_FILE);
}

export function loadTrustedRoots(): pkijs.Certificate[] {
  let pem = process.env.TSA_TRUSTED_ROOTS_PEM ?? '';
  if (!pem && process.env.TSA_TRUSTED_ROOTS_FILE) {
    pem = readFileSync(process.env.TSA_TRUSTED_ROOTS_FILE, 'utf8');
  }
  return pem ? pemToCerts(pem) : [];
}

/** True if `chain` (end-entity first, optional intermediates) chains to a root. */
export async function validateCertChain(
  chain: pkijs.Certificate[],
  roots: pkijs.Certificate[],
): Promise<boolean> {
  if (roots.length === 0 || chain.length === 0) return false;
  try {
    const engine = new pkijs.CertificateChainValidationEngine({ certs: chain, trustedCerts: roots });
    return (await engine.verify()).result === true;
  } catch {
    return false;
  }
}
