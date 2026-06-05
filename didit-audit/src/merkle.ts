import { createHash } from 'node:crypto';

export const sha256 = (b: Buffer): Buffer => createHash('sha256').update(b).digest();

// Domain-separation tags guard against second-preimage attacks where an internal
// node could be reinterpreted as a leaf.
const LEAF = 0x00;
const NODE = 0x01;

/**
 * Merkle root over an ordered list of 32-byte hashes.
 * Odd levels duplicate their last node (Bitcoin-style).
 */
export function merkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) throw new Error('merkleRoot: empty input');
  let level = leaves.map((h) => sha256(Buffer.concat([Buffer.from([LEAF]), h])));
  while (level.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = level[i + 1] ?? level[i]; // duplicate last if odd
      next.push(sha256(Buffer.concat([Buffer.from([NODE]), left, right])));
    }
    level = next;
  }
  return level[0];
}
