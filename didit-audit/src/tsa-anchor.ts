/**
 * eIDAS / RFC 3161 qualified-timestamp anchoring.
 *
 * A second, independent proof over the same Merkle root as the Bitcoin anchor.
 * Where Bitcoin gives trustless immutability, a *qualified* electronic timestamp
 * (from a QTSP on the EU Trusted List) carries a legal presumption of integrity
 * and time under eIDAS — which is what carries weight in an EU courtroom.
 *
 * The protocol is RFC 3161: we send the TSA the hash of our Merkle root and it
 * returns a signed TimeStampToken (a CMS SignedData) asserting the time. Only the
 * hash leaves our system — never PII.
 *
 * NOTE: validate the exact PKI.js calls against your installed version, and for
 * true eIDAS *qualification* validate the signer certificate against the relevant
 * EU Trusted List (LOTL) or pin your QTSP's root CA (see verifyTimestampToken).
 */
import { randomBytes } from 'node:crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import './pki-engine.js';
import { loadTrustedRoots, validateCertChain } from './eidas.js';

const SHA256_OID = '2.16.840.1.101.3.4.2.1';

/** Copy a Node Buffer/Uint8Array into a standalone ArrayBuffer. */
function toAb(view: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(view.byteLength);
  copy.set(view);
  return copy.buffer;
}

export interface TimestampResult {
  token: Buffer; // DER-encoded RFC 3161 TimeStampToken — the proof to persist
  genTime: Date; // time asserted by the TSA
}

/** Request an RFC 3161 timestamp over `rootHash` from a TSA endpoint. */
export async function requestTimestamp(rootHash: Buffer, tsaUrl: string): Promise<TimestampResult> {
  const nonce = randomBytes(8);
  const request = new pkijs.TimeStampReq({
    version: 1,
    messageImprint: new pkijs.MessageImprint({
      hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: SHA256_OID }),
      hashedMessage: new asn1js.OctetString({ valueHex: toAb(rootHash) }),
    }),
    certReq: true, // ask the TSA to embed its signing certificate
    nonce: new asn1js.Integer({ valueHex: toAb(nonce) }),
  });
  const requestBer = request.toSchema().toBER(false);

  const httpResp = await fetch(tsaUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body: Buffer.from(requestBer),
  });
  if (!httpResp.ok) throw new Error(`TSA HTTP ${httpResp.status}`);

  const respBytes = new Uint8Array(await httpResp.arrayBuffer());
  const response = new pkijs.TimeStampResp({ schema: asn1js.fromBER(toAb(respBytes)).result });

  // PKIStatus: 0 = granted, 1 = grantedWithMods; anything else is a rejection.
  const status = response.status.status;
  if (status !== 0 && status !== 1) throw new Error(`TSA rejected request (PKIStatus ${status})`);
  if (!response.timeStampToken) throw new Error('TSA returned no token');

  const token = Buffer.from(response.timeStampToken.toSchema().toBER(false));

  // Confirm the token actually commits to our root before we trust/store it.
  const verified = await verifyTimestampToken(rootHash, token);
  if (!verified.signatureValid) throw new Error('TSA returned an invalid signature');
  return { token, genTime: verified.genTime };
}

export interface TimestampVerification {
  genTime: Date;
  signerSubject: string;
  signatureValid: boolean;
  qualified: boolean; // signer chains to a configured EU-trusted (QTSP) root
}

/**
 * Verify a stored TimeStampToken against `rootHash`: the CMS signature is valid
 * and the token's message imprint equals our Merkle root. Returns the asserted
 * time. `checkChain` is false here — for eIDAS qualification, additionally
 * validate the signer certificate against the EU Trusted List (or a pinned QTSP
 * root) at this point.
 */
export async function verifyTimestampToken(
  rootHash: Buffer,
  token: Buffer,
): Promise<TimestampVerification> {
  const contentInfo = new pkijs.ContentInfo({ schema: asn1js.fromBER(toAb(token)).result });
  const signedData = new pkijs.SignedData({ schema: contentInfo.content });

  let signatureValid = false;
  try {
    const result: unknown = await signedData.verify({ signer: 0, checkChain: false });
    // Fail closed: only an explicit true (boolean or extendedMode.signatureVerified)
    // counts as valid, so an unexpected return shape can never default-accept.
    signatureValid =
      result === true || (result as { signatureVerified?: boolean })?.signatureVerified === true;
  } catch {
    signatureValid = false;
  }

  const eContent = signedData.encapContentInfo.eContent;
  if (!eContent) throw new Error('TimeStampToken has no eContent');
  const tstInfo = new pkijs.TSTInfo({
    schema: asn1js.fromBER(toAb(eContent.valueBlock.valueHexView)).result,
  });

  const imprint = Buffer.from(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView);
  if (!imprint.equals(rootHash)) {
    throw new Error('TSA message imprint does not match the Merkle root');
  }

  const cert = signedData.certificates?.[0];
  const signerSubject =
    cert instanceof pkijs.Certificate
      ? cert.subject.typesAndValues.map((t) => `${t.type}=${String(t.value.valueBlock.value)}`).join(', ')
      : 'unknown';

  // eIDAS qualification: signer must chain to a configured trusted root.
  const roots = loadTrustedRoots();
  let qualified = false;
  if (roots.length) {
    const certs = (signedData.certificates ?? []).filter(
      (c): c is pkijs.Certificate => c instanceof pkijs.Certificate,
    );
    qualified = await validateCertChain(certs, roots);
  }

  return { genTime: tstInfo.genTime, signerSubject, signatureValid, qualified };
}
