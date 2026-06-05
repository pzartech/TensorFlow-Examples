/**
 * Managed-key signature anchor.
 *
 * Signs the Merkle root with an Ed25519 key, adding non-repudiation: a proof that
 * a specific key holder attested to the root. Strongest when the private key lives
 * in an HSM / cloud KMS (Azure Key Vault Managed HSM, AWS KMS) — swap the local
 * sign() call below for a KMS sign API and keep verify() unchanged.
 *
 * Verification needs only the public key, so an external auditor can validate
 * without any secret material.
 */
import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import type { AnchorProvider } from './providers.js';

export function signatureProvider(
  keyId: string,
  privateKeyPem: string | undefined,
  publicKeyPem: string,
): AnchorProvider {
  const publicKey = createPublicKey(publicKeyPem);
  return {
    method: 'signature',
    provider: keyId,
    async anchor(root) {
      if (!privateKeyPem) {
        throw new Error(`signing key '${keyId}' has no private key configured`);
      }
      // Ed25519 takes a null algorithm; the digest is built in.
      const signature = nodeSign(null, root, createPrivateKey(privateKeyPem));
      return { proof: signature, status: 'confirmed', detail: { keyId } };
    },
    async verify(root, proof) {
      const ok = nodeVerify(null, root, publicKey, proof);
      return { ok, detail: { keyId } };
    },
  };
}
