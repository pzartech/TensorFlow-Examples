/**
 * EVM chain anchor (Ethereum, Polygon, Arbitrum, ...).
 *
 * Records the Merkle root as the calldata of a 0-value self-transaction, so the
 * root is permanently embedded in an independent public ledger with a smart-
 * contract-verifiable timestamp (the block time). Configure one provider per
 * chain to anchor to several at once.
 *
 * `viem` is an OPTIONAL dependency — loaded lazily so the module still works
 * without it when EVM anchoring isn't configured.
 *
 * NOTE: only the root hash goes on-chain. Never PII.
 */
import type { AnchorProvider } from './providers.js';

type Hex = `0x${string}`;

export function evmProvider(name: string, rpcUrl: string, privateKey: Hex): AnchorProvider {
  async function clients() {
    const viem = await import('viem');
    const { privateKeyToAccount } = await import('viem/accounts');
    const account = privateKeyToAccount(privateKey);
    const transport = viem.http(rpcUrl);
    return {
      viem,
      account,
      wallet: viem.createWalletClient({ account, transport }),
      pub: viem.createPublicClient({ transport }),
    };
  }

  return {
    method: 'evm',
    provider: name,
    async anchor(root) {
      const { viem, account, wallet } = await clients();
      const hash = await wallet.sendTransaction({
        account,
        chain: null, // chain id comes from the RPC; no on-client chain binding
        to: account.address,
        value: 0n,
        data: viem.toHex(root),
      });
      // Store the 32-byte tx hash as the proof; confirmation comes via upgrade().
      return {
        proof: Buffer.from(hash.slice(2), 'hex'),
        status: 'pending',
        detail: { chain: name, txHash: hash },
      };
    },
    async verify(root, proof) {
      const { viem, pub } = await clients();
      const txHash = (`0x${proof.toString('hex')}`) as Hex;
      const tx = await pub.getTransaction({ hash: txHash });
      const ok = tx.input.toLowerCase() === viem.toHex(root).toLowerCase();
      let assertedTime: Date | undefined;
      if (tx.blockNumber != null) {
        const block = await pub.getBlock({ blockNumber: tx.blockNumber });
        assertedTime = new Date(Number(block.timestamp) * 1000);
      }
      return { ok, assertedTime, detail: { chain: name, txHash } };
    },
    async upgrade(proof) {
      const { pub } = await clients();
      const txHash = (`0x${proof.toString('hex')}`) as Hex;
      const receipt = await pub.getTransactionReceipt({ hash: txHash }).catch(() => null);
      if (!receipt || receipt.status !== 'success') return null;
      const block = await pub.getBlock({ blockNumber: receipt.blockNumber });
      return { proof, status: 'confirmed', assertedTime: new Date(Number(block.timestamp) * 1000) };
    },
  };
}
