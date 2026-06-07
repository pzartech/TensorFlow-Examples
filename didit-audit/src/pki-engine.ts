// Shared PKI.js crypto engine (Node WebCrypto). Import for side effect.
import { webcrypto } from 'node:crypto';
import * as pkijs from 'pkijs';

const nodeCrypto = webcrypto as unknown as Crypto;
pkijs.setEngine(
  'nodeEngine',
  new pkijs.CryptoEngine({ name: 'nodeEngine', crypto: nodeCrypto, subtle: nodeCrypto.subtle }),
);
