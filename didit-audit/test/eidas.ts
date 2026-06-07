/**
 * eIDAS chain-validation test. Uses OpenSSL-generated certs (paths via env:
 * CA_PEM, LEAF_PEM, OTHER_PEM) to prove a TSA signer is accepted only when it
 * chains to a configured trusted root.
 */
import { readFileSync } from 'node:fs';
import { loadTrustedRoots, pemToCerts, validateCertChain } from '../src/eidas.js';

async function main() {
  let pass = 0;
  let fail = 0;
  const ok = (c: boolean, m: string) => {
    c ? pass++ : fail++;
    console.log(`${c ? 'PASS' : 'FAIL'} ${m}`);
  };

  const caPem = readFileSync(process.env.CA_PEM!, 'utf8');
  const leafPem = readFileSync(process.env.LEAF_PEM!, 'utf8');
  const otherPem = readFileSync(process.env.OTHER_PEM!, 'utf8');

  const [ca] = pemToCerts(caPem);
  const [leaf] = pemToCerts(leafPem);
  const [other] = pemToCerts(otherPem);

  ok((await validateCertChain([leaf], [ca])) === true, 'leaf chains to its CA -> qualified');
  ok((await validateCertChain([leaf], [other])) === false, 'leaf does NOT chain to an unrelated root');
  ok((await validateCertChain([leaf], [])) === false, 'no trusted roots -> not qualified');

  process.env.TSA_TRUSTED_ROOTS_PEM = caPem;
  ok(loadTrustedRoots().length === 1, 'loadTrustedRoots parses configured PEM');
  ok(pemToCerts(`${caPem}\n${otherPem}`).length === 2, 'pemToCerts parses a multi-cert bundle');

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
